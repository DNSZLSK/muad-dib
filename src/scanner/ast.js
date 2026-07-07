/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

const path = require('path');
const walk = require('acorn-walk');
const { safeParse } = require('../shared/constants.js');
const { analyzeWithDeobfuscation } = require('../shared/analyze-helper.js');
const {
  handleVariableDeclarator,
  handleCallExpression,
  handleImportExpression,
  handleNewExpression,
  handleLiteral,
  handleAssignmentExpression,
  handleMemberExpression,
  handleWithStatement,
  handlePostWalk
} = require('./ast-detectors');
const { detectAnalyzerHoneytoken, detectEnvMarkerEnumeration, countExitGuards, hasHostRecon } = require('./ast-detectors/anti-evasion.js');

// Check if credential keywords appear INSIDE regex literals or new RegExp() patterns.
// Only true when the keyword is part of the regex pattern itself, not just a string elsewhere in the file.
const CREDENTIAL_REGEX_KEYWORDS = /bearer|password|secret|token|credential|api.?key/i;
// axios call shapes — a network call the legacy regexes miss (caught only by ioc_string_match).
// Covers BOTH the identifier form (axios(...) / axios.get|post|...(...)) and the inline-require
// form (require('axios').get(...) — the chalk-pro/jsonkeeper staged-loader shape). Call-shaped
// only, so it never matches a bare `require('axios')` import, `import axios`, `myaxios.get`, or
// `axios` in a comment/string. Bare instance-var calls (const c = axios.create(); c.get()) are a
// known follow-up gap; the create() verb catches the create site itself.
const AXIOS_NETWORK_CALL_RE = /(?:\baxios|require\s*\(\s*['"]axios['"]\s*\))\s*(?:\(|\.\s*(?:get|post|put|patch|delete|request|head|options|create)\s*\()/;
function hasCredentialInsideRegex(content) {
  // Check regex literals: /...pattern.../flags
  const regexLiteralRe = /\/(?!\*)(?:[^/\\]|\\.)+\/[gimsuy]*/g;
  let m;
  while ((m = regexLiteralRe.exec(content)) !== null) {
    if (CREDENTIAL_REGEX_KEYWORDS.test(m[0])) return true;
  }
  // Check new RegExp('pattern') — keyword must be in the string argument
  const newRegExpRe = /new\s+RegExp\s*\(\s*(['"`])((?:[^\\]|\\.)*?)\1/g;
  while ((m = newRegExpRe.exec(content)) !== null) {
    if (CREDENTIAL_REGEX_KEYWORDS.test(m[2])) return true;
  }
  return false;
}

const EXCLUDED_FILES = [
  'src/scanner/ast.js',
  'src/scanner/shell.js',
  'src/scanner/package.js',
  'src/response/playbooks.js',
  // Meta-rule descriptions contain quoted threat keywords (e.g. "ru", LC_ALL,
  // LANG, process.exit in the AST-091 geo_evasion rule). Scanning the rule
  // catalog itself yields self-detections — exclude it.
  'src/rules/index.js'
];

async function analyzeAST(targetPath, options = {}) {
  return analyzeWithDeobfuscation(targetPath, analyzeFile, {
    deobfuscate: options.deobfuscate,
    excludedFiles: EXCLUDED_FILES
  });
}

function analyzeFile(content, filePath, basePath) {
  const threats = [];
  let ast;

  ast = safeParse(content);
  if (!ast) {
    // AST parse failed — apply regex fallback for known dangerous patterns

    // Workflow manipulation: reads + writes to .github/workflows
    if (/\.github/.test(content) && /workflows/.test(content) &&
        /writeFileSync|writeFile/.test(content) &&
        /readdirSync|readFileSync/.test(content)) {
      threats.push({
        type: 'workflow_write',
        severity: 'CRITICAL',
        message: 'File reads and modifies .github/workflows — GitHub Actions injection (regex fallback).',
        file: path.relative(basePath, filePath)
      });
    }

    if (content.length > 1000 && content.split(/\r?\n/).length < 10) {
      threats.push({
        type: 'possible_obfuscation',
        severity: 'MEDIUM',
        message: 'File difficult to parse, possibly obfuscated.',
        file: path.relative(basePath, filePath)
      });
    }

    // Blue Team v8b (A6): Detect Proxy + require('child_process') + exec in files that fail to parse
    // This covers 'use strict' + with(Proxy) evasion where acorn can't parse the with statement
    if (/\bnew\s+Proxy\b/.test(content) && /\brequire\s*\(\s*['"]child_process['"]\s*\)/.test(content)) {
      const hasExecInContent = /\bexec\s*\(/.test(content) || /\bexecSync\s*\(/.test(content) || /\bspawn\s*\(/.test(content);
      if (hasExecInContent) {
        threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: 'Proxy + require(\'child_process\') + exec in unparseable file — scope hijack evasion (regex fallback).',
          file: path.relative(basePath, filePath)
        });
      }
    }

    // Content-level: require('child_process') + exec/spawn with shell command patterns
    if (/\brequire\s*\(\s*['"]child_process['"]\s*\)/.test(content) &&
        /\bcurl\b.*\|\s*(sh|bash)\b/.test(content)) {
      threats.push({
        type: 'dangerous_exec',
        severity: 'CRITICAL',
        message: 'require(\'child_process\') + curl pipe to shell in unparseable file — remote code execution (regex fallback).',
        file: path.relative(basePath, filePath)
      });
    }

    return threats;
  }

  // Shared detection context
  const ctx = {
    threats,
    relFile: path.relative(basePath, filePath),
    // File source reference for the post-walk shadow classifier (Wave-4 MCP
    // site has no extractable written-content string — it classifies the file).
    // A reference to the already-held string: no copy, freed with the ctx.
    _content: content,
    dynamicRequireVars: new Set(),
    staticAssignments: new Set(),
    // v2.10.73 P2: AST-006 source qualification — tracks WHERE a variable's value came from.
    // Used by dynamic_require to distinguish plugin loaders (LOW: string_literal/array_literal/
    // object_literal/fs_readdir/require_json) from real obfuscation (HIGH: function_call/
    // computed_expression) or credential theft vectors (CRITICAL: env_var).
    varSource: new Map(),
    dangerousCmdVars: new Map(),
    workflowPathVars: new Set(),
    execPathVars: new Map(),
    globalThisAliases: new Set(),
    // FPR plan : prototype_hook on a name like `Request` or `WebSocket` is
    // a strong malice signal when it targets the *global* (Fetch / native)
    // class. When the file declares its OWN class with the same name, the
    // hook is just self-instrumentation (sl-request, ws's own Server, etc.).
    // Pre-compute the set of locally declared class / function-constructor
    // names via a cheap regex so handle-assignment-expression can skip the
    // self-hook pattern. Matches : `function X (`, `class X {`, `class X(`,
    // `const X = function`, `let X = class`, etc.
    localClassNames: (() => {
      const names = new Set();
      const re = /\b(?:function|class)\s+(\w+)\s*[({]|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:function|class)\b/g;
      let m;
      while ((m = re.exec(content)) !== null) {
        const id = m[1] || m[2];
        if (id) names.add(id);
      }
      return names;
    })(),
    evalAliases: new Map(),           // B1: variable name → 'eval'|'Function'
    envAliases: new Set(),            // AST-018 alias fix: names bound to process.env (`var env = process.env`)
    moduleLoadDirectAliases: new Set(), // B3: destructured _load from require('module')
    objectPropertyMap: new Map(),     // B5: objName → Map<propName, stringValue>
    concatValues: new Map(),          // B2: varName → { value, operands } for concat strings with ≥3 operands
    stringVarValues: new Map(),       // Variable reassignment tracking: varName → string value
    // MUADDIB-AST-097 electron_app_injection: injected-code variable taint + write-sink records +
    // foreign-Electron-app-discovery facts (os.homedir + .asar/electron-core sig + existsSync probe).
    injectedCodeVars: new Set(),      // vars whose value is injected Electron code (write payload)
    electronTargetVars: new Map(),    // varName → {sig,home,pathStr} for a path.join Electron target
    electronPayloadWrites: [],        // writeFile* calls whose CONTENT is an injected payload
    electronAsarTargetWrites: [],     // writeFile* calls whose TARGET is a home-rooted .asar/core file
    hasHomedirResolve: false,         // os.homedir() / process.env.{HOME,APPDATA,...} resolved
    hasElectronAppSig: false,         // a .asar / *_desktop_core / electron-core path constructed
    hasFsExistsProbe: false,          // fs.existsSync/accessSync/statSync (probe the victim install)
    hasOwnElectronMain: false,        // file IS an Electron main (app.whenReady/loadURL/...) — gates HIGH
    hasFromCharCode: content.includes('fromCharCode'),
    // Anti-analysis / sandbox evasion (2026, @longzy DPRK). Structural "detonation-gate wall"
    // magnitude + host recon + a charcode-hidden analyzer-honeytoken reference. Aggregated in
    // handlePostWalk. See ast-detectors/anti-evasion.js.
    antiAnalysisExitCount: countExitGuards(content),
    hasHostRecon: hasHostRecon(content),
    hasProcessEnvRead: /process\s*\.\s*env\b/.test(content),
    analyzerHoneytokenHit: detectAnalyzerHoneytoken(content),
    envMarkerEnumHit: detectEnvMarkerEnumeration(content),
    hasJsReverseShell: /\bnet\.Socket\b/.test(content) &&
      /\.connect\s*\(/.test(content) &&
      /\.pipe\b/.test(content) &&
      (/\bspawn\b/.test(content) || /\bstdin\b/.test(content) || /\bstdout\b/.test(content)),
    hasBinaryFileLiteral: /\.(png|jpg|jpeg|gif|bmp|ico|wasm)\b/i.test(content),
    hasEvalInFile: false,
    // SANDWORM_MODE: zlib inflate + base64 + eval co-occurrence
    hasZlibInflate: /\brequire\s*\(\s*['"]zlib['"]\s*\)/.test(content) || /\bzlib\s*\.\s*inflate/.test(content),
    hasBase64Decode: /Buffer\.from\s*\([^)]*,\s*['"]base64['"]/.test(content),
    hasDynamicExec: false,  // set in handleCallExpression for eval/Function/Module._compile
    // SANDWORM_MODE: write + execute + delete anti-forensics
    hasTempFileWrite: false,
    hasTempFileExec: false,
    hasFileDelete: false,
    hasDevShmInContent: /\/dev\/shm\b/.test(content),
    // v2.10.93: csec-style self-deletion — unlink/rename of __filename targets the
    // executing file itself. Distinct from hasFileDelete (any file). Combined with
    // hasDynamicExec in a compound to flag anti-forensics obfuscated stealers.
    hasSelfDelete: /\b(?:unlinkSync|unlink|rmSync|renameSync|rm)\s*\(\s*(?:__filename|module\.filename|require\.main\.filename)\b/.test(content),
    // SANDWORM_MODE P2: env harvesting co-occurrence
    hasEnvEnumeration: false,  // Object.entries/keys/values(process.env)
    hasEnvHarvestPattern: /\b(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|NPM|AWS|SSH|WEBHOOK)\b/.test(content),
    hasNetworkCallInFile: /\b(fetch|https?\.request|https?\.get|dns\.resolve)\b/.test(content) || AXIOS_NETWORK_CALL_RE.test(content),
    // C5: Non-fetch network calls indicate independent network channel (NOT WASM loading). axios is non-fetch.
    hasNonFetchNetworkCall: /\bhttps?\.request\b|\bhttps?\.get\b|\bdns\.resolve\b/.test(content) || AXIOS_NETWORK_CALL_RE.test(content),
    // Credential regex harvesting: regex literals or new RegExp() whose PATTERN contains credential keywords
    // Must check that the keyword is inside the regex, not just anywhere in the file
    hasCredentialRegex: hasCredentialInsideRegex(content),
    // Built-in method override: console.X = function or Object.defineProperty = function
    hasBuiltinOverride: /\bconsole\s*\.\s*\w+\s*=\s*function/.test(content) ||
                        /\bconsole\s*\[\s*\w+\s*\]\s*=\s*function/.test(content) ||
                        /\bObject\s*\.\s*defineProperty\s*=\s*function/.test(content),
    // Critical builtin override: Object.defineProperty itself is reassigned (global hook)
    hasBuiltinGlobalHook: /\bObject\s*\.\s*defineProperty\s*=\s*function/.test(content),
    // Stream interceptor: class extending Transform/Duplex/Writable (data wiretap pattern)
    hasStreamInterceptor: /\bextends\s+(Transform|Duplex|Writable)\b/.test(content),
    // SANDWORM_MODE P2: DNS exfiltration co-occurrence
    hasDnsRequire: /\brequire\s*\(\s*['"]dns['"]\s*\)/.test(content) || /\bdns\s*\.\s*resolve/.test(content),
    hasBase64Encode: /\.toString\s*\(\s*['"]base64(url)?['"]\s*\)/.test(content),
    hasDnsLoop: false,  // set when dns call inside loop context detected
    hasTimerDelayedPayload: false,  // set when setTimeout/setInterval >= 60s has dangerous sink in callback
    // SANDWORM_MODE P2: LLM API key harvesting
    llmApiKeyCount: 0,
    // Wave 4: path variable tracking for git hooks and IDE config injection
    gitHooksPathVars: new Map(),
    ideConfigPathVars: new Map(),
    // Wave 4: compound detection — fetch + decrypt + eval chain
    hasRemoteFetch: /\bhttps?\.(get|request)\b/.test(content) || /\bfetch\s*\(/.test(content) || AXIOS_NETWORK_CALL_RE.test(content),
    // Safe domain exclusion: if ALL URLs in file are from known registries, suppress download_exec_binary
    fetchOnlySafeDomains: false, // computed below after URL extraction
    hasCryptoDecipher: /\bcreateDecipher(iv)?\s*\(/.test(content),
    // crypto_exfil (RSA+AES hybrid exfil — litellm/Hades 2026): encrypt-side mirror of
    // hasCryptoDecipher. Set TRUE in handle-call-expression.js on a REAL call to an encryption
    // primitive (createCipher(iv) = AES, publicEncrypt = RSA pubkey-wrap, subtle.encrypt =
    // WebCrypto). AST-based on purpose, NOT a content regex: a detector/linter/doc that merely
    // contains the STRING "createCipheriv(" must not trip it (self-scan & meta-tooling FP).
    // Feeds the same-file crypto_exfil compound in handle-post-walk.js.
    hasCryptoEncipher: false,
    // Embedded RSA/EC public key (PEM SPKI/PKCS1) — an attacker's hardcoded recipient key for
    // the exfil envelope. Enrichment signal only (a PEM public key alone — JWT/JWK verify,
    // signature checks — is benign and extremely common, so it is never flagged on its own).
    hasEmbeddedPublicKey: /-----BEGIN (?:RSA |EC )?PUBLIC KEY-----/.test(content),
    // Wave 4: native addon camouflage signals
    hasRequireNodeFile: false,
    hasExecSyncCall: false,
    // Wave 4: IDE persistence (VS Code tasks.json, Code/User/ paths)
    hasIdePersistenceWrite: false,
    hasTasksJsonInContent: /\btasks\.json\b/.test(content),
    hasRunOnInContent: /\brunOn\b|\bfolderOpen\b/.test(content),
    hasWriteFileSyncInContent: /\bwriteFileSync\b|\bwriteFile\s*\(/.test(content),
    // Wave 4: MCP content keyword detection (must also have writeFileSync in same file)
    // Content-level MCP detection: MCP keyword + writeFileSync + MCP config path in same file
    // Path co-occurrence prevents FPs where a file reads MCP config but writes elsewhere.
    // Read-only pattern (readFileSync without writeFileSync to MCP) is not injection.
    // Module API context: require('module') or module.constructor usage
    hasModuleImport: /require\s*\(\s*['"]module['"]\s*\)/.test(content) || /module\.constructor/.test(content),
    hasMcpContentKeywords: (/\bmcpServers\b/.test(content) || /\bmcp\.json\b/.test(content) || /\bclaude_desktop_config\b/.test(content)) &&
      /\bwriteFileSync\b|\bwriteFile\s*\(/.test(content) &&
      (/\.claude[/\\]/.test(content) || /\.cursor[/\\]/.test(content) || /\.vscode[/\\]/.test(content) || /\.windsurf[/\\]/.test(content) || /\.codeium[/\\]/.test(content) || /\.continue[/\\]/.test(content) || /claude_desktop_config/.test(content) || /\bmcp\.json\b/.test(content)),
    // WASM payload detection: WebAssembly.compile/instantiate with host import sinks
    hasWasmLoad: /\bWebAssembly\s*\.\s*(compile|instantiate|compileStreaming|instantiateStreaming)\b/.test(content),
    hasWasmHostSink: false,  // set in handleCallExpression when WASM import object contains network/fs sinks
    hasProxyTrap: false,  // set in handleNewExpression when Proxy has set/get/apply trap
    hasProxySetTrap: false, // set when Proxy specifically has a 'set' trap (data interception)
    hasRequireCacheRead: false,  // set when require.cache is accessed (read)
    hasRequireCacheWrite: false, // set when require.cache exports are modified
    requireCacheVars: new Set(), // variables assigned from require.cache[...]
    proxyHandlerVars: new Set(),  // variables assigned object literals with set/get/apply/construct traps
    stringBuildVars: new Set(),   // variables assigned from BinaryExpression with '+' (string concat)
    // Audit v3 B2: Entropy split detection — high-entropy string concat + eval/decode
    highEntropyConcatFound: false, // set when a concat chain with >=3 leaves and high combined entropy is found
    // C10: Hash verification — legitimate binary installers verify checksums.
    // v2.10.95: file-level heuristic durcie par un check de comparaison. Requires
    // createHash+digest AND at least one comparison/assert/throw in the same file.
    // THIS IS NOT A PROOF that the hash is actually verified — a malicious author
    // can include a === or assert elsewhere in the file without comparing the
    // digest result. This gate is best-effort and gains value only through the
    // triple-gate in handle-post-walk.js (requires also fetchOnlySafeDomains).
    // Proper fix would require function-scope AST tracking to confirm the
    // comparison consumes the digest result — deferred until a dedicated
    // taint-tracking PR.
    hasHashVerification:
      /\bcreateHash\s*\(/.test(content) &&
      /\.digest\s*\(/.test(content) &&
      /\b(===|!==|\.equals\s*\(|assert\.(strictEqual|equal|deepEqual|deepStrictEqual)\s*\(|\bthrow\b)/.test(content),
    // GlassWorm: variation selector decoder pattern (.codePointAt + 0xFE00/0xE0100)
    hasCodePointAt: false,
    hasVariationSelectorConst: false,
    // GlassWorm: blockchain C2 resolution (Solana import + C2 method + dynamic exec)
    hasSolanaImport: false,
    hasSolanaC2Method: false,
    // Audit v3: uncaughtException/unhandledRejection handler for error hijacking detection
    hasUncaughtExceptionHandler: false,
    // Audit v3 B2: FinalizationRegistry deferred exec detection
    hasFinalizationRegistry: false,
    // Blue Team v8: SharedArrayBuffer + Worker IPC detection
    hasSharedArrayBuffer: false,
    hasWorkerThread: false,  // set when Worker (worker_threads) usage detected
    // Blue Team v8: dgram/UDP exfiltration
    hasDgramImport: /\brequire\s*\(\s*['"](?:node:)?dgram['"]\s*\)/.test(content),
    hasDgramSend: false,
    // Blue Team v8: WebSocket C2
    hasWebSocketNew: false,  // set when new WebSocket() detected
    // Blue Team v8: crontab/cron write detection
    hasCrontabWrite: false,
    // Blue Team v8b: Module internals hijack (Module._resolveFilename, _compile, _extensions)
    hasModuleInternalsHijack: false,
    // Blue Team v8b: JSON.parse reviver with __proto__ check
    hasJsonReviverProto: false,
    // Blue Team v8b: vm.runInContext/runInNewContext with dynamic code
    hasVmDynamicExec: false,
    // Blue Team v8b: binary file read + new Function/eval in same file (stego)
    hasBinaryFileRead: false,  // set when fs.readFileSync on .png/.jpg/.gif/.bmp/.ico
    // Blue Team v8b: AsyncLocalStorage usage
    hasAsyncLocalStorage: /\bAsyncLocalStorage\b/.test(content),
    // Blue Team v8b: image file reference for stego detection
    hasImageFileRef: /\.(png|jpg|jpeg|gif|bmp|ico)\b/i.test(content),
    // Blue Team v8b: net.Socket creation (for WebSocket C2 detection)
    hasNetSocketCreate: /\bnew\s+net\.Socket\b/.test(content) || /\bnet\.createConnection\b/.test(content),
    // Blue Team v8b: execSync/exec in callback contexts (set when exec inside .on('message'|'data'))
    hasCallbackExec: false,
    // Blue Team v8b (B2): CI environment fingerprinting — count of CI provider env vars referenced
    ciProviderCount: (() => {
      const CI_VARS = ['GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TRAVIS', 'JENKINS_URL', 'BUILDKITE', 'CONTINUOUS_INTEGRATION', 'TEAMCITY_VERSION', 'CODEBUILD_BUILD_ID', 'BITBUCKET_PIPELINE_UUID'];
      return CI_VARS.filter(v => content.includes(v)).length;
    })(),
    // Audit v3: source code reference for callback body analysis
    _sourceCode: content
  };

  // Compute fetchOnlySafeDomains: check if ALL URLs in file point to known registries
  if (ctx.hasRemoteFetch) {
    const urlMatches = content.match(/https?:\/\/[^\s'"`)]+/g) || [];
    const SAFE_FETCH_DOMAINS = [
      'registry.npmjs.org', 'npmjs.com',
      'github.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com',
      'nodejs.org', 'yarnpkg.com',
      'pypi.org', 'files.pythonhosted.org'
    ];
    if (urlMatches.length > 0 && urlMatches.every(u => {
      try {
        const hostname = new URL(u).hostname;
        return SAFE_FETCH_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
      } catch { return false; }
    })) {
      ctx.fetchOnlySafeDomains = true;
    }
    // v2.10.96: retain the URL set on ctx so post-walk detectors can attach
    // it to download/install-shaped threats. Consumed by ML feature
    // install_url_github_releases to avoid regex-on-message proxying.
    ctx.fetchUrls = urlMatches.slice(0, 32);
  }

  walk.simple(ast, {
    VariableDeclarator(node) { handleVariableDeclarator(node, ctx); },
    CallExpression(node) { handleCallExpression(node, ctx); },
    ImportExpression(node) { handleImportExpression(node, ctx); },
    NewExpression(node) { handleNewExpression(node, ctx); },
    Literal(node) { handleLiteral(node, ctx); },
    AssignmentExpression(node) { handleAssignmentExpression(node, ctx); },
    MemberExpression(node) { handleMemberExpression(node, ctx); },
    WithStatement(node) { handleWithStatement(node, ctx); }
  });

  // FIX 5: DNS chunk exfiltration — verify dns.resolve* is inside a loop body
  if (ctx.hasDnsRequire && ctx.hasBase64Encode && !ctx.hasDnsLoop) {
    walk.ancestor(ast, {
      CallExpression(node, _state, ancestors) {
        if (ctx.hasDnsLoop) return;
        if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
          const name = node.callee.property.name;
          if (['resolve', 'resolve4', 'resolveTxt', 'resolveCname'].includes(name)) {
            for (const anc of ancestors) {
              if (['ForStatement', 'WhileStatement', 'ForOfStatement',
                   'ForInStatement', 'DoWhileStatement'].includes(anc.type)) {
                ctx.hasDnsLoop = true;
                return;
              }
              // forEach/map callback = implicit loop
              if (anc.type === 'CallExpression' && anc.callee?.type === 'MemberExpression') {
                const m = anc.callee.property?.name;
                if (['forEach', 'map', 'reduce', 'filter'].includes(m)) {
                  ctx.hasDnsLoop = true;
                  return;
                }
              }
            }
          }
        }
      }
    });
  }

  // Geo-evasion CIS kill switch: locale check for "ru" + process.exit
  // Pattern: TeamPCP/Shai-Hulud isSystemRussian() — checks Intl.DateTimeFormat
  // locale or LC_ALL/LANG env vars for Russian locale, then process.exit(0).
  // Triple-gate: (1) locale API or env var check, (2) "ru" string comparison,
  // (3) process.exit in same file. No legitimate npm package does this.
  const hasLocaleCheck = /resolvedOptions\s*\(\s*\)\s*\.locale/.test(content) ||
                         (/\bLC_ALL\b/.test(content) && /\bLANG\b/.test(content));
  const hasRuCheck = /['"`]ru['"`]/.test(content) && /startsWith|===|==/.test(content);
  if (hasLocaleCheck && hasRuCheck && /process\.exit/.test(content)) {
    threats.push({
      type: 'geo_evasion_killswitch',
      severity: 'HIGH',
      message: 'Geo-evasion CIS kill switch: locale check for "ru" + process.exit — malware avoids targeting operator\'s country (TeamPCP pattern)',
      file: ctx.relFile
    });
  }

  handlePostWalk(ctx);

  return threats;
}

module.exports = { analyzeAST };
