const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { ACORN_OPTIONS, safeParse } = require('../shared/constants.js');
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
} = require('./ast-detectors.js');

const EXCLUDED_FILES = [
  'src/scanner/ast.js',
  'src/scanner/shell.js',
  'src/scanner/package.js',
  'src/response/playbooks.js'
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
    return threats;
  }

  // Shared detection context
  const ctx = {
    threats,
    relFile: path.relative(basePath, filePath),
    dynamicRequireVars: new Set(),
    staticAssignments: new Set(),
    dangerousCmdVars: new Map(),
    workflowPathVars: new Set(),
    execPathVars: new Map(),
    globalThisAliases: new Set(),
    hasFromCharCode: content.includes('fromCharCode'),
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
    // SANDWORM_MODE P2: env harvesting co-occurrence
    hasEnvEnumeration: false,  // Object.entries/keys/values(process.env)
    hasEnvHarvestPattern: /\b(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|NPM|AWS|SSH|WEBHOOK)\b/.test(content),
    hasNetworkCallInFile: /\b(fetch|https?\.request|https?\.get|dns\.resolve)\b/.test(content),
    // SANDWORM_MODE P2: DNS exfiltration co-occurrence
    hasDnsRequire: /\brequire\s*\(\s*['"]dns['"]\s*\)/.test(content) || /\bdns\s*\.\s*resolve/.test(content),
    hasBase64Encode: /\.toString\s*\(\s*['"]base64(url)?['"]\s*\)/.test(content),
    hasDnsLoop: false,  // set when dns call inside loop context detected
    // SANDWORM_MODE P2: LLM API key harvesting
    llmApiKeyCount: 0,
    // Wave 4: path variable tracking for git hooks and IDE config injection
    gitHooksPathVars: new Map(),
    ideConfigPathVars: new Map(),
    // Wave 4: compound detection — fetch + decrypt + eval chain
    hasRemoteFetch: /\bhttps?\.(get|request)\b/.test(content) || /\bfetch\s*\(/.test(content),
    // Safe domain exclusion: if ALL URLs in file are from known registries, suppress download_exec_binary
    fetchOnlySafeDomains: false, // computed below after URL extraction
    hasCryptoDecipher: /\bcreateDecipher(iv)?\s*\(/.test(content),
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
    hasMcpContentKeywords: (/\bmcpServers\b/.test(content) || /\bmcp\.json\b/.test(content) || /\bclaude_desktop_config\b/.test(content)) &&
      /\bwriteFileSync\b|\bwriteFile\s*\(/.test(content) &&
      (/\.claude[/\\]/.test(content) || /\.cursor[/\\]/.test(content) || /\.vscode[/\\]/.test(content) || /\.windsurf[/\\]/.test(content) || /\.codeium[/\\]/.test(content) || /\.continue[/\\]/.test(content) || /claude_desktop_config/.test(content) || /\bmcp\.json\b/.test(content))
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

  handlePostWalk(ctx);

  return threats;
}

module.exports = { analyzeAST };
