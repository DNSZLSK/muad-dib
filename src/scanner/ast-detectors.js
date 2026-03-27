const path = require('path');
const { getCallName } = require('../utils.js');

// ============================================
// AST DETECTION CONSTANTS
// ============================================

const DANGEROUS_CALLS = [
  'eval',
  'Function'
];

const SENSITIVE_STRINGS = [
  '.npmrc',
  '.ssh',
  'Shai-Hulud',
  'The Second Coming',
  'Goldox-T3chs',
  '/etc/passwd',
  '/etc/shadow'
];

// Env vars that are safe and should NOT be flagged (common config/runtime vars)
const SAFE_ENV_VARS = [
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'PWD', 'HOME', 'PATH',
  'LANG', 'TERM', 'CI', 'DEBUG', 'VERBOSE', 'LOG_LEVEL',
  'SHELL', 'USER', 'LOGNAME', 'EDITOR', 'TZ',
  'NODE_DEBUG', 'NODE_PATH', 'NODE_OPTIONS',
  'DISPLAY', 'COLORTERM', 'FORCE_COLOR', 'NO_COLOR', 'TERM_PROGRAM',
  // CI environment metadata (non-sensitive)
  'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_WORKSPACE',
  'GITHUB_RUN_ID', 'GITHUB_RUN_NUMBER', 'GITHUB_ACTOR', 'GITHUB_EVENT_NAME',
  'GITHUB_WORKFLOW', 'GITHUB_ACTION', 'GITHUB_JOB', 'GITHUB_SERVER_URL',
  'GITLAB_CI', 'TRAVIS', 'CIRCLECI', 'JENKINS_URL',
  // Build tool config
  'NODE_TLS_REJECT_UNAUTHORIZED', 'BABEL_ENV', 'WEBPACK_MODE'
];

// Env var prefixes that are safe (npm metadata, locale settings, framework public vars)
const SAFE_ENV_PREFIXES = [
  'npm_config_', 'npm_lifecycle_', 'npm_package_', 'lc_', 'muaddib_',
  'next_public_', 'vite_', 'react_app_'
];

// Env var keywords to detect sensitive environment access (separate from SENSITIVE_STRINGS)
const ENV_SENSITIVE_KEYWORDS = [
  'TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH'
];

// Non-sensitive qualifiers: when a keyword is preceded by one of these in the env var name,
// it is config metadata, not a real secret (e.g., PUBLIC_KEY, CACHE_KEY, SORT_KEY)
const ENV_NON_SENSITIVE_QUALIFIERS = new Set([
  'PUBLIC', 'CACHE', 'PRIMARY', 'FOREIGN', 'SORT', 'PARTITION', 'INDEX', 'ENCRYPTION'
]);

/**
 * Check if an env var name contains a sensitive keyword as a full _-delimited segment,
 * not preceded by a non-sensitive qualifier.
 * e.g., NPM_TOKEN → TOKEN is full segment → true
 *       PUBLIC_KEY → KEY preceded by PUBLIC → false
 *       CACHE_KEY → KEY preceded by CACHE → false
 *       GITHUB_TOKEN → TOKEN is full segment, preceded by GITHUB (not a qualifier) → true
 */
function isEnvSensitive(envVar) {
  const upper = envVar.toUpperCase();
  const segments = upper.split('_');
  for (let i = 0; i < segments.length; i++) {
    if (ENV_SENSITIVE_KEYWORDS.includes(segments[i])) {
      // Check if preceded by a non-sensitive qualifier
      if (i > 0 && ENV_NON_SENSITIVE_QUALIFIERS.has(segments[i - 1])) {
        continue;
      }
      return true;
    }
  }
  return false;
}

// AI agent dangerous flags — disable security controls (s1ngularity/Nx, Aug 2025)
const AI_AGENT_DANGEROUS_FLAGS = [
  '--dangerously-skip-permissions',
  '--yolo',
  '--trust-all-tools',
  '--yes-always',
  '--no-permission-check'
];

// AI agent binary names
const AI_AGENT_BINARIES = ['claude', 'gemini', 'q', 'aider', 'copilot', 'cursor'];

// Strings that are NOT suspicious
const SAFE_STRINGS = [
  'api.github.com',
  'registry.npmjs.org',
  'npmjs.com'
];

// Domains where fetch is legitimate (not C2) — used to suppress download_exec_binary compound
const SAFE_FETCH_DOMAINS = [
  'registry.npmjs.org', 'npmjs.com',
  'github.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com',
  'nodejs.org', 'yarnpkg.com',
  'pypi.org', 'files.pythonhosted.org'
];

// Credential-stealing CLI commands (s1ngularity/Nx, Shai-Hulud)
const CREDENTIAL_CLI_COMMANDS = [
  'gh auth token',
  'gcloud auth print-access-token',
  'aws sts get-session-token',
  'az account get-access-token',
  'heroku auth:token',
  'netlify api --data',
  'vercel whoami'
];

// Dangerous shell command patterns for variable tracking
const DANGEROUS_CMD_PATTERNS = [/\bcurl\b/, /\bwget\b/, /\bnc\s+-/, /\/dev\/tcp\//, /\bbash\s+-i/, /\bpowershell\b/, /\bpwsh\b/, /\bnslookup\b/, /\bdig\s+/];

// Native APIs targeted for prototype hooking (chalk Sept 2025, Sygnia)
const HOOKABLE_NATIVES = [
  'fetch', 'XMLHttpRequest', 'Request', 'Response',
  'WebSocket', 'EventSource'
];

// Node.js core module classes targeted for prototype hooking
const NODE_HOOKABLE_MODULES = ['http', 'https', 'net', 'tls', 'stream', 'events', 'dgram'];
const NODE_HOOKABLE_CLASSES = [
  'IncomingMessage', 'ServerResponse', 'ClientRequest',
  'OutgoingMessage', 'Socket', 'Server', 'Agent',
  'EventEmitter'
];

// AI/MCP config paths targeted for config injection (SANDWORM_MODE)
const MCP_CONFIG_PATHS = [
  '.claude/', 'claude_desktop_config',
  '.cursor/', 'mcp.json',
  '.continue/',
  '.vscode/',
  '.windsurf/', '.codeium/'
];

// MCP content indicators in written data
const MCP_CONTENT_PATTERNS = ['mcpServers', '"mcp"', '"server"', '"command"', '"args"'];

// Sensitive AI config files — writes to these are always suspicious regardless of content.
// Split into two tiers:
// - UNIQUE: filenames no legitimate plugin would use (always sensitive)
// - ROOT_ONLY: generic names (settings.json) that are sensitive ONLY when directly
//   at config dir root (e.g. ~/.claude/settings.json), not in subdirectories
//   (e.g. ~/.claude/my-plugin/settings.json which is legitimate plugin config)
const SENSITIVE_AI_CONFIG_FILES_UNIQUE = [
  'claude.md', 'claude_desktop_config.json',
  'mcp.json',
  '.cursorrules', '.windsurfrules',
  'copilot-instructions.md'
];
const SENSITIVE_AI_CONFIG_FILES_ROOT_ONLY = [
  'settings.json', 'settings.local.json'
];

// Git hooks names
const GIT_HOOKS = [
  'pre-commit', 'pre-push', 'post-checkout', 'post-merge',
  'pre-receive', 'post-receive', 'prepare-commit-msg', 'commit-msg',
  'pre-rebase', 'post-rewrite', 'pre-auto-gc'
];

// Suspicious C2/exfiltration domains (HIGH severity)
const SUSPICIOUS_DOMAINS_HIGH = [
  'oastify.com', 'oast.fun', 'oast.me', 'oast.live',
  'burpcollaborator.net', 'webhook.site', 'pipedream.net',
  'requestbin.com', 'hookbin.com', 'canarytokens.com',
  // GlassWorm C2 IPs (mars 2026)
  '217.69.3.218', '217.69.3.152',
  '199.247.10.166', '199.247.13.106',
  '140.82.52.31', '45.32.150.251',
  // TeamPCP/CanisterWorm C2 (mars 2026)
  'icp0.io', 'raw.icp0.io', 'ic0.app',        // ICP canister C2 (decentralized dead-drop)
  'hackmoltrepeat.com',                          // hackerbot-claw payload delivery
  'recv.hackmoltrepeat.com',                     // hackerbot-claw credential receiver
  'scan.aquasecurtiy.org',                       // Trivy exfil C2 (typosquat of aquasecurity)
  'api.telegram.org',                            // Telegram bot exfiltration (crypto typosquats)
  'checkmarx.zone',                              // Checkmarx/LiteLLM exfil C2
  '45.148.10.212', '83.142.209.11'               // TeamPCP C2 IPs
];

// Suspicious tunnel/proxy domains (MEDIUM severity)
const SUSPICIOUS_DOMAINS_MEDIUM = [
  'ngrok.io', 'ngrok-free.app', 'serveo.net', 'localhost.run', 'loca.lt',
  'trycloudflare.com'   // Cloudflare tunnel C2 (CanisterWorm kamikaze.sh stager)
];

// LLM API key environment variable names (3+ = harvesting)
const LLM_API_KEY_VARS = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
  'GROQ_API_KEY', 'TOGETHER_API_KEY', 'FIREWORKS_API_KEY',
  'REPLICATE_API_KEY', 'MISTRAL_API_KEY', 'COHERE_API_KEY'
];

// Env harvesting sensitive patterns (for Object.entries/keys/values filtering)
const ENV_HARVEST_PATTERNS = [
  'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL',
  'NPM', 'AWS', 'SSH', 'WEBHOOK'
];

// Paths indicating sandbox/container environment detection (anti-analysis)
const SANDBOX_INDICATORS = [
  '/.dockerenv',
  '/proc/1/cgroup',
  '/proc/self/cgroup'
];

// Blockchain RPC endpoints — potential C2 channel via blockchain (GlassWorm)
const BLOCKCHAIN_RPC_ENDPOINTS = [
  'api.mainnet-beta.solana.com',
  'api.devnet.solana.com',
  'api.testnet.solana.com',
  'mainnet.infura.io',
  'rpc.ankr.com'
];

// Solana/Web3 C2 methods — used for dead drop resolver (GlassWorm)
const SOLANA_C2_METHODS = [
  'getSignaturesForAddress', 'getAccountInfo', 'getTransaction',
  'getConfirmedSignaturesForAddress2', 'getParsedTransaction'
];

// Solana/Web3 package names
const SOLANA_PACKAGES = ['@solana/web3.js', 'solana-web3.js', '@solana/web3'];

// Variation selector constants (GlassWorm decoder signature)
const VARIATION_SELECTOR_CONSTS = [0xFE00, 0xFE0F, 0xE0100, 0xE01EF];

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Extract string value from a node if it's a Literal or TemplateLiteral with no expressions.
 */
function extractStringValue(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.raw).join('');
  }
  // Template literal with expressions — concatenate what we can
  if (node.type === 'TemplateLiteral') {
    return node.quasis.map(q => q.value.raw).join('***');
  }
  return null;
}

/**
 * Audit v3 B2: Shannon entropy calculation for split-entropy detection.
 * Replicates the algorithm from entropy.js for inline use in AST scanner.
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = Object.create(null);
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Audit v3 B2: Count the number of leaf string operands in a BinaryExpression chain.
 * Used to identify split payloads (≥3 chunks concatenated).
 */
function countConcatOperands(node) {
  if (!node) return 0;
  if (node.type === 'Literal' && typeof node.value === 'string') return 1;
  if (node.type === 'Identifier') return 1;
  if (node.type === 'TemplateLiteral') return 1;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return countConcatOperands(node.left) + countConcatOperands(node.right);
  }
  return 0;
}

/**
 * Recursively resolve BinaryExpression with '+' operator to reconstruct
 * concatenated strings like '.gi' + 't' → '.git' or 'ho' + 'oks' → 'hooks'.
 * Returns null if any part is non-literal.
 */
function resolveStringConcat(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.raw).join('');
  }
  // TemplateLiteral with resolvable expressions
  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
    const parts = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.raw);
      if (i < node.expressions.length) {
        const resolved = resolveStringConcat(node.expressions[i]);
        if (resolved === null) return null;
        parts.push(resolved);
      }
    }
    return parts.join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = resolveStringConcat(node.left);
    const right = resolveStringConcat(node.right);
    if (left !== null && right !== null) return left + right;
  }
  // ConditionalExpression — either branch is enough for detection
  if (node.type === 'ConditionalExpression') {
    const consequent = resolveStringConcat(node.consequent);
    const alternate = resolveStringConcat(node.alternate);
    return consequent !== null ? consequent : alternate;
  }
  return null;
}

/**
 * Like resolveStringConcat, but additionally resolves Identifier nodes via
 * a stringVarValues Map (variable name → known string value).
 * Used for double-indirection patterns: var a='ev',b='al'; globalThis[a+b]()
 */
function resolveStringConcatWithVars(node, stringVarValues) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier' && stringVarValues && stringVarValues.has(node.name)) {
    return stringVarValues.get(node.name);
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.raw).join('');
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
    const parts = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.raw);
      if (i < node.expressions.length) {
        const resolved = resolveStringConcatWithVars(node.expressions[i], stringVarValues);
        if (resolved === null) return null;
        parts.push(resolved);
      }
    }
    return parts.join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = resolveStringConcatWithVars(node.left, stringVarValues);
    const right = resolveStringConcatWithVars(node.right, stringVarValues);
    if (left !== null && right !== null) return left + right;
  }
  return null;
}

/**
 * Extract string value from a node, including BinaryExpression resolution.
 * Falls back to extractStringValue if concat resolution fails.
 */
function extractStringValueDeep(node) {
  const concat = resolveStringConcat(node);
  let result = concat !== null ? concat : extractStringValue(node);
  // Batch 2: strip node: prefix so require('node:child_process') normalizes to 'child_process'
  if (typeof result === 'string' && result.startsWith('node:')) {
    result = result.slice(5);
  }
  return result;
}

/**
 * Returns true if all arguments of a call/new expression are string literals.
 * Used to distinguish safe patterns like eval('1+2') or Function('return this')
 * from dangerous dynamic patterns like eval(userInput).
 */
function hasOnlyStringLiteralArgs(node) {
  if (!node.arguments || node.arguments.length === 0) return false;
  return node.arguments.every(arg => arg.type === 'Literal' && typeof arg.value === 'string');
}

/**
 * Returns true if a node is a decode call: atob(str) or Buffer.from(str,'base64').toString()
 * Used to detect staged eval/Function decode patterns.
 */
function hasDecodeArg(node) {
  if (!node || typeof node !== 'object') return false;
  // atob('...')
  if (node.type === 'CallExpression' &&
      node.callee?.type === 'Identifier' && node.callee.name === 'atob') {
    return true;
  }
  // Buffer.from('...', 'base64').toString()
  if (node.type === 'CallExpression' &&
      node.callee?.type === 'MemberExpression' &&
      node.callee.property?.name === 'toString') {
    const inner = node.callee.object;
    if (inner?.type === 'CallExpression' &&
        inner.callee?.type === 'MemberExpression' &&
        inner.callee.object?.name === 'Buffer' &&
        inner.callee.property?.name === 'from' &&
        inner.arguments?.length >= 2 &&
        inner.arguments[1]?.value === 'base64') {
      return true;
    }
  }
  return false;
}

/**
 * Checks if an AST subtree contains decode patterns (base64, atob, fromCharCode).
 */
function containsDecodePattern(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'Literal' && node.value === 'base64') return true;
  if (node.type === 'Identifier' && (node.name === 'atob' || node.name === 'fromCharCode')) return true;
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item.type === 'string' && containsDecodePattern(item)) return true;
      }
    } else if (child && typeof child === 'object' && typeof child.type === 'string') {
      if (containsDecodePattern(child)) return true;
    }
  }
  return false;
}

// ============================================
// VISITOR HANDLERS
// ============================================
// Each handler receives (node, ctx) where ctx contains:
//   threats, relFile, dynamicRequireVars, dangerousCmdVars,
//   workflowPathVars, execPathVars, globalThisAliases,
//   hasFromCharCode, hasEvalInFile (mutable)

function isStaticValue(node) {
  if (!node) return false;
  if (node.type === 'Literal' && typeof node.value === 'string') return true;
  if (node.type === 'ArrayExpression') {
    return node.elements.every(el => el && el.type === 'Literal' && typeof el.value === 'string');
  }
  if (node.type === 'ObjectExpression') {
    return node.properties.every(p =>
      p.value && p.value.type === 'Literal' && typeof p.value.value === 'string'
    );
  }
  return false;
}

function handleVariableDeclarator(node, ctx) {
  if (node.id?.type === 'Identifier') {
    // Track statically-assigned variables for dynamic_require qualification
    if (node.init && isStaticValue(node.init)) {
      ctx.staticAssignments.add(node.id.name);
    }

    // Track dynamic require vars + module aliases
    if (node.init?.type === 'CallExpression') {
      const initCallName = getCallName(node.init);
      if (initCallName === 'require' && node.init.arguments.length > 0) {
        const arg = node.init.arguments[0];
        if (arg.type !== 'Literal') {
          ctx.dynamicRequireVars.add(node.id.name);
        }
        // Track require('module') or require('node:module') aliases for Module._load detection
        const reqVal = extractStringValueDeep(arg);
        if (reqVal === 'module') {
          if (!ctx.moduleAliases) ctx.moduleAliases = new Set();
          ctx.moduleAliases.add(node.id.name);
        }
      }
    }
    // Track variables assigned dangerous command strings
    const strVal = extractStringValue(node.init);
    if (strVal && DANGEROUS_CMD_PATTERNS.some(p => p.test(strVal))) {
      ctx.dangerousCmdVars.set(node.id.name, strVal);
    }

    // Track variables assigned temp/executable file paths
    if (strVal && /^\/tmp\/|^\/var\/tmp\/|\\temp\\/i.test(strVal)) {
      ctx.execPathVars.set(node.id.name, strVal);
    }

    // Track variables that alias globalThis or global (e.g. const g = globalThis)
    if (node.init?.type === 'Identifier' &&
        (node.init.name === 'globalThis' || node.init.name === 'global' ||
         node.init.name === 'window' || node.init.name === 'self')) {
      ctx.globalThisAliases.add(node.id.name);
    }

    // B1: const E = eval; const F = Function;
    if (node.init?.type === 'Identifier' &&
        (node.init.name === 'eval' || node.init.name === 'Function')) {
      ctx.evalAliases.set(node.id.name, node.init.name);
    }
    // B1: const E = (x) => eval(x); const E = function(x) { return eval(x); }
    if ((node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression') &&
        node.init.params?.length >= 1) {
      const body = node.init.body;
      if (body?.type === 'CallExpression') {
        const cn = getCallName(body);
        if (cn === 'eval' || cn === 'Function') ctx.evalAliases.set(node.id.name, cn);
      }
      if (body?.type === 'BlockStatement' && body.body?.length === 1 &&
          body.body[0].type === 'ReturnStatement' && body.body[0].argument?.type === 'CallExpression') {
        const cn = getCallName(body.body[0].argument);
        if (cn === 'eval' || cn === 'Function') ctx.evalAliases.set(node.id.name, cn);
      }
    }
    // B1 fix: const getEval = () => eval; — 0-param arrow/function returning eval/Function as value (not call)
    if ((node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')) {
      const body = node.init.body;
      // () => eval
      if (body?.type === 'Identifier' && (body.name === 'eval' || body.name === 'Function')) {
        ctx.evalAliases.set(node.id.name, body.name + '_factory');
      }
      // () => { return eval; }
      if (body?.type === 'BlockStatement' && body.body?.length === 1 &&
          body.body[0].type === 'ReturnStatement' &&
          body.body[0].argument?.type === 'Identifier' &&
          (body.body[0].argument.name === 'eval' || body.body[0].argument.name === 'Function')) {
        ctx.evalAliases.set(node.id.name, body.body[0].argument.name + '_factory');
      }
    }

    // Audit v3 B3: const AF = Object.getPrototypeOf(async function(){}).constructor
    if (node.init?.type === 'MemberExpression') {
      const initProp = node.init.computed
        ? (node.init.property?.type === 'Literal' ? String(node.init.property.value) : null)
        : node.init.property?.name;
      if (initProp === 'constructor' && node.init.object?.type === 'CallExpression') {
        const innerCall = node.init.object;
        if (innerCall.callee?.type === 'MemberExpression') {
          const innerObj = innerCall.callee.object;
          const innerPropName = innerCall.callee.property?.name;
          if (innerObj?.type === 'Identifier' &&
              (innerObj.name === 'Object' || innerObj.name === 'Reflect') &&
              innerPropName === 'getPrototypeOf' &&
              innerCall.arguments?.length >= 1) {
            const arg = innerCall.arguments[0];
            if (arg.type === 'FunctionExpression' && (arg.async || arg.generator)) {
              const kind = arg.async ? 'AsyncFunction' : 'GeneratorFunction';
              ctx.evalAliases.set(node.id.name, 'Function');
              // Emit CRITICAL at declaration — extracting constructor via prototype chain is never benign
              ctx.hasDynamicExec = true;
              ctx.threats.push({
                type: 'dangerous_constructor',
                severity: 'CRITICAL',
                message: `${kind} constructor extracted via Object.getPrototypeOf() into "${node.id.name}" — prototype chain code execution evasion.`,
                file: ctx.relFile
              });
            }
          }
        }
      }
    }

    // B1 fix: const compiler = getCompiler() where getCompiler is eval_factory
    if (node.init?.type === 'CallExpression' &&
        node.init.callee?.type === 'Identifier' &&
        ctx.evalAliases?.has(node.init.callee.name)) {
      const aliased = ctx.evalAliases.get(node.init.callee.name);
      if (aliased.endsWith('_factory')) {
        const baseName = aliased.replace('_factory', '');
        ctx.evalAliases.set(node.id.name, baseName);
      }
    }

    // B5: Track object literal string properties
    if (node.init?.type === 'ObjectExpression') {
      const propMap = new Map();
      for (const prop of node.init.properties) {
        if (prop.type !== 'Property') continue;
        const key = prop.key?.type === 'Identifier' ? prop.key.name :
                    (prop.key?.type === 'Literal' ? String(prop.key.value) : null);
        const val = extractStringValueDeep(prop.value);
        if (key && val) propMap.set(key, val);
      }
      if (propMap.size > 0) ctx.objectPropertyMap.set(node.id.name, propMap);
    }

    // Track initial string values for reassignment tracking
    if (strVal !== null && strVal !== undefined) {
      ctx.stringVarValues.set(node.id.name, strVal);
    }

    // Track variables assigned from require.cache[...] (module cache references)
    // Used to detect writes to cached module exports (require.cache poisoning)
    if (node.init?.type === 'MemberExpression' && node.init.computed) {
      const obj = node.init.object;
      if (obj?.type === 'MemberExpression' &&
          obj.object?.type === 'Identifier' && obj.object.name === 'require' &&
          obj.property?.type === 'Identifier' && obj.property.name === 'cache') {
        ctx.requireCacheVars.add(node.id.name);
      }
    }

    // Track variables assigned from BinaryExpression with '+' (string concatenation building)
    // Used to detect setTimeout(concatVar, delay) — eval via timer with built string
    // FP fix: only track when at least one operand is demonstrably a string (literal, template,
    // or known string var). Filters out arithmetic `var e = a + 1` in minified code.
    if (node.init?.type === 'BinaryExpression' && node.init.operator === '+') {
      const left = node.init.left;
      const right = node.init.right;
      const isStringOperand = (n) =>
        (n.type === 'Literal' && typeof n.value === 'string') ||
        n.type === 'TemplateLiteral' ||
        (n.type === 'Identifier' && ctx.stringVarValues?.has(n.name)) ||
        (n.type === 'Identifier' && ctx.stringBuildVars?.has(n.name));
      if (isStringOperand(left) || isStringOperand(right)) {
        ctx.stringBuildVars.add(node.id.name);
        // Audit v3 B2: Resolve concat value and track for split-entropy detection
        const operands = countConcatOperands(node.init);
        if (operands >= 3) {
          const resolved = resolveStringConcatWithVars(node.init, ctx.stringVarValues);
          if (resolved && resolved.length >= 20) {
            ctx.concatValues.set(node.id.name, { value: resolved, operands });
          }
        }
      }
    }

    // Track object variables with Proxy trap properties (set/get/apply/construct)
    // Used to detect new Proxy(target, handlerVar) when handler is not inline
    if (node.init?.type === 'ObjectExpression') {
      const hasTrap = node.init.properties?.some(p =>
        p.key?.type === 'Identifier' && ['set', 'get', 'apply', 'construct'].includes(p.key.name)
      );
      if (hasTrap) {
        ctx.proxyHandlerVars.add(node.id.name);
      }
    }

    // Track variables assigned from path.join containing .github/workflows
    if (node.init?.type === 'CallExpression' && node.init.callee?.type === 'MemberExpression') {
      const obj = node.init.callee.object;
      const prop = node.init.callee.property;
      if (obj?.type === 'Identifier' && obj.name === 'path' &&
          prop?.type === 'Identifier' && (prop.name === 'join' || prop.name === 'resolve')) {
        const joinArgs = node.init.arguments.map(a => extractStringValueDeep(a) || '').join('/');
        if (/\.github[\\/\/]workflows/i.test(joinArgs) || /\.github[\\/\/]actions/i.test(joinArgs)) {
          ctx.workflowPathVars.add(node.id.name);
        }
        // Propagate: path.join(workflowPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.workflowPathVars.has(a.name))) {
          ctx.workflowPathVars.add(node.id.name);
        }
        // Track path.join that resolves to .git/hooks (concat fragments included)
        if (/\.git[\\/\/]hooks/i.test(joinArgs) ||
            (GIT_HOOKS.some(h => joinArgs.includes(h)) && joinArgs.includes('.git'))) {
          ctx.gitHooksPathVars.set(node.id.name, joinArgs);
        }
        // Propagate: path.join(gitHooksPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.gitHooksPathVars.has(a.name))) {
          const parentPath = node.init.arguments.map(a => {
            if (a.type === 'Identifier' && ctx.gitHooksPathVars.has(a.name)) return ctx.gitHooksPathVars.get(a.name);
            return extractStringValueDeep(a) || '';
          }).join('/');
          ctx.gitHooksPathVars.set(node.id.name, parentPath);
        }
        // Track path.join that resolves to IDE config paths (.claude/, .cursor/, etc.)
        const joinLower = joinArgs.toLowerCase();
        if (MCP_CONFIG_PATHS.some(p => joinLower.includes(p.toLowerCase()))) {
          ctx.ideConfigPathVars.set(node.id.name, joinArgs);
        }
        // Propagate: path.join(ideConfigPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.ideConfigPathVars.has(a.name))) {
          const parentPath = node.init.arguments.map(a => {
            if (a.type === 'Identifier' && ctx.ideConfigPathVars.has(a.name)) return ctx.ideConfigPathVars.get(a.name);
            return extractStringValueDeep(a) || '';
          }).join('/');
          ctx.ideConfigPathVars.set(node.id.name, parentPath);
        }
      }
    }
  }

  // Audit v3 bypass fix: Array destructuring eval alias: const [fn] = [eval]
  if (node.id?.type === 'ArrayPattern' && node.init?.type === 'ArrayExpression') {
    const elements = node.init.elements;
    const patterns = node.id.elements;
    for (let i = 0; i < Math.min(elements?.length || 0, patterns?.length || 0); i++) {
      const el = elements[i];
      const pat = patterns[i];
      if (el?.type === 'Identifier' && pat?.type === 'Identifier') {
        if (el.name === 'eval' || el.name === 'Function') {
          ctx.evalAliases.set(pat.name, el.name);
        }
      }
    }
  }

  // Audit v3 B3: Destructuring of require('module') → track _load as direct function alias
  if (node.id?.type === 'ObjectPattern' &&
      node.init?.type === 'CallExpression') {
    const initCallName = getCallName(node.init);
    if (initCallName === 'require' && node.init.arguments.length > 0) {
      const reqVal = extractStringValueDeep(node.init.arguments[0]);
      if (reqVal === 'module') {
        for (const prop of node.id.properties) {
          if (prop.type === 'Property' && prop.key?.type === 'Identifier') {
            const localName = prop.value?.type === 'Identifier' ? prop.value.name : prop.key.name;
            if (prop.key.name === '_load') {
              ctx.moduleLoadDirectAliases.add(localName);
            }
          }
        }
      }
    }
  }

  // Audit v3 B3: Destructuring of globalThis/global → track eval/Function aliases
  if (node.id?.type === 'ObjectPattern' &&
      node.init?.type === 'Identifier' &&
      (node.init.name === 'globalThis' || node.init.name === 'global' ||
       node.init.name === 'window' || node.init.name === 'self' ||
       ctx.globalThisAliases.has(node.init.name))) {
    for (const prop of node.id.properties) {
      if (prop.type === 'Property' && prop.key?.type === 'Identifier') {
        const originalName = prop.key.name;
        const localName = prop.value?.type === 'Identifier' ? prop.value.name : prop.key.name;
        if (originalName === 'eval' || originalName === 'Function') {
          ctx.evalAliases.set(localName, originalName);
        }
      }
    }
  }

  // Batch 2: Detect destructuring of process.env: const { TOKEN, SECRET } = process.env
  if (node.id?.type === 'ObjectPattern' &&
      node.init?.type === 'MemberExpression' &&
      node.init.object?.type === 'Identifier' && node.init.object.name === 'process' &&
      node.init.property?.type === 'Identifier' && node.init.property.name === 'env') {
    for (const prop of node.id.properties) {
      if (prop.type === 'Property' && prop.key?.type === 'Identifier') {
        const envVar = prop.key.name;
        if (SAFE_ENV_VARS.includes(envVar)) continue;
        const envLower = envVar.toLowerCase();
        if (SAFE_ENV_PREFIXES.some(p => envLower.startsWith(p))) continue;
        if (isEnvSensitive(envVar)) {
          ctx.threats.push({
            type: 'env_access',
            severity: 'HIGH',
            message: `Destructured access to sensitive env var: const { ${envVar} } = process.env.`,
            file: ctx.relFile
          });
        }
      }
      // RestElement: const { ...all } = process.env → env harvesting
      if (prop.type === 'RestElement') {
        ctx.threats.push({
          type: 'env_harvesting_dynamic',
          severity: 'HIGH',
          message: 'Environment variable harvesting via rest destructuring: const { ...rest } = process.env.',
          file: ctx.relFile
        });
      }
    }
  }
}

function handleCallExpression(node, ctx) {
  const callName = getCallName(node);

  // Detect require() with non-literal argument (obfuscation)
  if (callName === 'require' && node.arguments.length > 0) {
    const arg = node.arguments[0];
    if (arg.type === 'BinaryExpression' && arg.operator === '+') {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'Dynamic require() with string concatenation (module name obfuscation).',
        file: ctx.relFile
      });
    } else if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'Dynamic require() with template literal (module name obfuscation).',
        file: ctx.relFile
      });
    } else if (arg.type === 'CallExpression') {
      const argCallName = getCallName(arg);
      // Skip safe patterns: require(path.join(...)), require(path.resolve(...))
      if (argCallName !== 'path.join' && argCallName !== 'path.resolve') {
        const hasDecode = containsDecodePattern(arg);
        ctx.threats.push({
          type: 'dynamic_require',
          severity: hasDecode ? 'CRITICAL' : 'HIGH',
          message: hasDecode
            ? 'Dynamic require() with runtime decode (base64/atob obfuscation).'
            : 'Dynamic require() with computed argument (possible decode obfuscation).',
          file: ctx.relFile
        });
      }
    } else if (arg.type === 'Identifier') {
      // Check if variable was reassignment-tracked to a dangerous module
      const DANGEROUS_MODS_REQ = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
      const resolvedVal = ctx.stringVarValues?.get(arg.name);
      if (resolvedVal) {
        const norm = resolvedVal.startsWith('node:') ? resolvedVal.slice(5) : resolvedVal;
        if (DANGEROUS_MODS_REQ.includes(norm)) {
          ctx.threats.push({
            type: 'dynamic_require', severity: 'CRITICAL',
            message: `require(${arg.name}) resolves to "${norm}" via variable reassignment — module name obfuscation.`,
            file: ctx.relFile
          });
        } else {
          // If the variable was assigned from a static value (string literal,
          // array of strings, object with string values), it's a plugin loader pattern
          const severity = ctx.staticAssignments.has(arg.name) ? 'LOW' : 'HIGH';
          ctx.threats.push({
            type: 'dynamic_require',
            severity,
            message: severity === 'LOW'
              ? `Dynamic require() with statically-assigned variable "${arg.name}" (plugin loader pattern).`
              : 'Dynamic require() with variable argument (module name obfuscation).',
            file: ctx.relFile
          });
        }
      } else {
        // If the variable was assigned from a static value (string literal,
        // array of strings, object with string values), it's a plugin loader pattern
        const severity = ctx.staticAssignments.has(arg.name) ? 'LOW' : 'HIGH';
        ctx.threats.push({
          type: 'dynamic_require',
          severity,
          message: severity === 'LOW'
            ? `Dynamic require() with statically-assigned variable "${arg.name}" (plugin loader pattern).`
            : 'Dynamic require() with variable argument (module name obfuscation).',
          file: ctx.relFile
        });
      }
    }
    // B3 fix: require(/child_process/.source) — RegExpLiteral.source resolution
    else if (arg.type === 'MemberExpression' &&
             arg.object?.type === 'Literal' && arg.object.regex &&
             arg.property?.type === 'Identifier' && arg.property.name === 'source') {
      const regexSource = arg.object.regex.pattern;
      const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
      const norm = regexSource.startsWith('node:') ? regexSource.slice(5) : regexSource;
      if (DANGEROUS_MODS.includes(norm)) {
        ctx.threats.push({ type: 'dynamic_require', severity: 'CRITICAL',
          message: `require(/${regexSource}/.source) resolves to "${norm}" — regex .source evasion.`,
          file: ctx.relFile });
      } else {
        ctx.threats.push({ type: 'dynamic_require', severity: 'HIGH',
          message: `require() with regex .source argument (/${regexSource}/.source) — obfuscation technique.`,
          file: ctx.relFile });
      }
    }
    // B5: require(obj.prop) — MemberExpression argument
    else if (arg.type === 'MemberExpression') {
      const objName = arg.object?.type === 'Identifier' ? arg.object.name : null;
      const propName = arg.property?.type === 'Identifier' ? arg.property.name :
                       (arg.property?.type === 'Literal' ? String(arg.property.value) : null);
      const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
      let resolved = false;
      if (objName && propName && ctx.objectPropertyMap?.has(objName)) {
        const val = ctx.objectPropertyMap.get(objName).get(propName);
        if (val) {
          const norm = val.startsWith('node:') ? val.slice(5) : val;
          if (DANGEROUS_MODS.includes(norm)) {
            ctx.threats.push({ type: 'dynamic_require', severity: 'CRITICAL',
              message: `require(${objName}.${propName}) resolves to "${norm}" — object property indirection.`,
              file: ctx.relFile });
            resolved = true;
          }
        }
      }
      if (!resolved) {
        ctx.threats.push({ type: 'dynamic_require', severity: 'MEDIUM',
          message: 'Dynamic require() with member expression argument (object property obfuscation).',
          file: ctx.relFile });
      }
    }
    // Wave 4: detect require() of .node binary files (native addon camouflage)
    const reqStr = extractStringValueDeep(arg);
    if (reqStr && /\.node\s*$/.test(reqStr)) {
      ctx.hasRequireNodeFile = true;
    }
    // GlassWorm: track Solana/Web3 require imports for compound blockchain C2 detection
    if (reqStr && SOLANA_PACKAGES.some(pkg => reqStr === pkg)) {
      ctx.hasSolanaImport = true;
    }
  }

  // Detect process.mainModule.require('child_process') — module system bypass
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'require' &&
      node.callee.object?.type === 'MemberExpression' &&
      node.callee.object.object?.type === 'Identifier' &&
      node.callee.object.object.name === 'process' &&
      node.callee.object.property?.type === 'Identifier' &&
      node.callee.object.property.name === 'mainModule' &&
      node.arguments.length > 0) {
    const arg = node.arguments[0];
    const modName = extractStringValueDeep(arg);
    const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
    if (modName && DANGEROUS_MODS.includes(modName)) {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'CRITICAL',
        message: `process.mainModule.require('${modName}') — bypasses module system restrictions.`,
        file: ctx.relFile
      });
    } else {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: `process.mainModule.require() detected — module system bypass.`,
        file: ctx.relFile
      });
    }
  }

  // B8: require('process').mainModule.require('child_process') — indirect process access
  // Pattern: require('process').mainModule.require(mod)
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'require' &&
      node.callee.object?.type === 'MemberExpression' &&
      node.callee.object.property?.type === 'Identifier' && node.callee.object.property.name === 'mainModule' &&
      node.callee.object.object?.type === 'CallExpression' &&
      getCallName(node.callee.object.object) === 'require' &&
      node.callee.object.object.arguments?.[0]?.type === 'Literal' &&
      node.callee.object.object.arguments[0].value === 'process') {
    const arg = node.arguments?.[0];
    const modName = arg ? extractStringValueDeep(arg) : null;
    const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
    const severity = modName && DANGEROUS_MODS.includes(modName) ? 'CRITICAL' : 'HIGH';
    ctx.threats.push({
      type: 'require_process_mainmodule',
      severity,
      message: `require('process').mainModule.require(${modName ? "'" + modName + "'" : '...'}) — indirect process access bypasses direct process.mainModule detection.`,
      file: ctx.relFile
    });
  }

  // Detect exec/execSync with dangerous shell commands (direct or via MemberExpression)
  const execName = callName === 'exec' || callName === 'execSync' ? callName : null;
  const memberExec = !execName && node.callee.type === 'MemberExpression' &&
    node.callee.property?.type === 'Identifier' &&
    (node.callee.property.name === 'exec' || node.callee.property.name === 'execSync')
    ? node.callee.property.name : null;
  if ((execName || memberExec) && node.arguments.length > 0) {
    // Wave 4: track any execSync/exec call for compound detection
    ctx.hasExecSyncCall = true;
    const arg = node.arguments[0];
    let cmdStr = null;
    if (arg.type === 'Literal' && typeof arg.value === 'string') {
      cmdStr = arg.value;
    } else if (arg.type === 'Identifier' && ctx.dangerousCmdVars.has(arg.name)) {
      // Variable was assigned a dangerous command string
      cmdStr = ctx.dangerousCmdVars.get(arg.name);
    } else if (arg.type === 'Identifier' && ctx.execPathVars.has(arg.name)) {
      // Variable was assigned a temp/executable file path
      cmdStr = ctx.execPathVars.get(arg.name);
    } else if (arg.type === 'TemplateLiteral') {
      cmdStr = arg.quasis.map(q => q.value.raw).join('***');
    }

    if (cmdStr) {
      // Check for dangerous shell patterns
      if (/\|\s*(sh|bash)\b/.test(cmdStr) || /nc\s+-[elp]/.test(cmdStr) || /\/dev\/tcp\//.test(cmdStr) || /bash\s+-i/.test(cmdStr) || /\bcurl\b/.test(cmdStr) || /\bwget\b/.test(cmdStr) || /\bpowershell\b/.test(cmdStr) || /\bpwsh\b/.test(cmdStr) || /\bnslookup\b/.test(cmdStr) || /\bdig\s+/.test(cmdStr) || /\bhost\s+\S+\.\S+/.test(cmdStr)) {
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: `Dangerous shell command in exec(): "${cmdStr.substring(0, 80)}"`,
          file: ctx.relFile
        });
      }

      // Check for temp file execution (binary dropper pattern)
      if (/^\/tmp\/|^\/var\/tmp\//i.test(cmdStr)) {
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: `Execution of temp file "${cmdStr.substring(0, 80)}" — binary dropper pattern.`,
          file: ctx.relFile
        });
      }

      // Check for credential-stealing CLI commands
      for (const credCmd of CREDENTIAL_CLI_COMMANDS) {
        if (cmdStr.includes(credCmd)) {
          ctx.threats.push({
            type: 'credential_command_exec',
            severity: 'CRITICAL',
            message: `Credential theft via CLI tool: exec("${credCmd}") — steals auth tokens from installed tools.`,
            file: ctx.relFile
          });
          break;
        }
      }

      // Bun runtime evasion: exec/spawn using bun instead of node (Shai-Hulud 2.0)
      if (/\bbun\s+(run|exec|install|x)\b/.test(cmdStr)) {
        ctx.threats.push({
          type: 'bun_runtime_evasion',
          severity: 'HIGH',
          message: `Bun runtime invocation detected: "${cmdStr.slice(0, 80)}" — alternative runtime to evade Node.js monitoring/sandboxing.`,
          file: ctx.relFile
        });
      }

      // Worm propagation: npm publish / npm adduser / npm token create (Shai-Hulud)
      if (/\bnpm\s+(publish|adduser|token\s+create|login)\b/.test(cmdStr)) {
        ctx.threats.push({
          type: 'npm_publish_worm',
          severity: 'CRITICAL',
          message: `exec("${cmdStr.slice(0, 80)}") — worm propagation: publishing packages with stolen credentials.`,
          file: ctx.relFile
        });
      }

      // Token theft: npm config get _authToken / npm whoami (CanisterWorm findNpmTokens)
      if (/\bnpm\s+(config\s+get\b.*authToken|whoami)\b/i.test(cmdStr)) {
        ctx.threats.push({
          type: 'npm_token_steal',
          severity: 'CRITICAL',
          message: `exec("${cmdStr.slice(0, 80)}") — npm credential extraction (CanisterWorm findNpmTokens pattern).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect exec/execSync called on a dynamically-required module variable
  if ((execName || memberExec) && node.callee.type === 'MemberExpression' && node.callee.object?.type === 'Identifier') {
    if (ctx.dynamicRequireVars.has(node.callee.object.name)) {
      const method = execName || memberExec;
      ctx.threats.push({
        type: 'dynamic_require_exec',
        severity: 'CRITICAL',
        message: `${method}() called on dynamically-required module "${node.callee.object.name}" — obfuscated command execution.`,
        file: ctx.relFile
      });
    }
  }

  // Detect chained: require(non-literal).exec(...) — direct dynamic require + exec
  if ((execName || memberExec) && node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'CallExpression') {
    const innerCall = node.callee.object;
    const innerName = getCallName(innerCall);
    if (innerName === 'require' && innerCall.arguments.length > 0 &&
        innerCall.arguments[0]?.type !== 'Literal') {
      const method = execName || memberExec;
      ctx.threats.push({
        type: 'dynamic_require_exec',
        severity: 'CRITICAL',
        message: `${method}() chained on dynamic require() — obfuscated module + command execution.`,
        file: ctx.relFile
      });
    }
  }

  // Detect sandbox/container evasion
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const fsMethod = node.callee.property.name;
    if (['accessSync', 'existsSync', 'statSync', 'lstatSync', 'access', 'stat'].includes(fsMethod)) {
      const arg = node.arguments[0];
      if (arg?.type === 'Literal' && typeof arg.value === 'string') {
        if (SANDBOX_INDICATORS.some(ind => arg.value.includes(ind))) {
          ctx.threats.push({
            type: 'sandbox_evasion',
            severity: 'HIGH',
            message: `Sandbox/container detection via ${fsMethod}("${arg.value}") — anti-analysis technique.`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Detect spawn/execFile of shell processes
  if ((callName === 'spawn' || callName === 'execFile') && node.arguments.length >= 1) {
    const shellArg = node.arguments[0];
    if (shellArg.type === 'Literal' && typeof shellArg.value === 'string') {
      const shellBin = shellArg.value.toLowerCase();
      if (['/bin/sh', '/bin/bash', 'sh', 'bash', 'cmd.exe', 'powershell', 'pwsh', 'cmd'].includes(shellBin)) {
        ctx.threats.push({
          type: 'dangerous_call_exec',
          severity: 'MEDIUM',
          message: `${callName}('${shellArg.value}') — direct shell process spawn detected.`,
          file: ctx.relFile
        });
      }
    }
    // Also check when shell is computed via os.platform() ternary
    if (shellArg.type === 'ConditionalExpression') {
      const checkLiteral = (n) => n.type === 'Literal' && typeof n.value === 'string' &&
        ['/bin/sh', '/bin/bash', 'sh', 'bash', 'cmd.exe', 'powershell', 'pwsh', 'cmd'].includes(n.value.toLowerCase());
      if (checkLiteral(shellArg.consequent) || checkLiteral(shellArg.alternate)) {
        ctx.threats.push({
          type: 'dangerous_call_exec',
          severity: 'MEDIUM',
          message: `${callName}() with conditional shell binary (platform-aware) — direct shell process spawn detected.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect spawn('bun', ['run', ...]) — Bun runtime evasion via spawn
  if ((callName === 'spawn' || callName === 'execFile') && node.arguments.length >= 1) {
    const bunArg = node.arguments[0];
    if (bunArg.type === 'Literal' && typeof bunArg.value === 'string' && bunArg.value === 'bun') {
      // Check the args array for run/exec/install/x
      const argsArr = node.arguments[1];
      let bunCmd = 'bun';
      if (argsArr?.type === 'ArrayExpression' && argsArr.elements.length > 0) {
        const firstEl = argsArr.elements[0];
        if (firstEl?.type === 'Literal' && typeof firstEl.value === 'string') {
          bunCmd = `bun ${firstEl.value}`;
        }
      }
      if (/\bbun\s*(run|exec|install|x)?$/.test(bunCmd) || bunCmd === 'bun') {
        ctx.threats.push({
          type: 'bun_runtime_evasion',
          severity: 'HIGH',
          message: `spawn("bun", [...]) — Bun runtime invocation to evade Node.js monitoring/sandboxing.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect spawn/fork with {detached: true}
  if ((callName === 'spawn' || callName === 'fork') && node.arguments.length >= 2) {
    const lastArg = node.arguments[node.arguments.length - 1];
    if (lastArg.type === 'ObjectExpression') {
      const hasDetached = lastArg.properties.some(p =>
        p.key?.type === 'Identifier' && p.key.name === 'detached' &&
        p.value?.type === 'Literal' && p.value.value === true
      );
      if (hasDetached) {
        ctx.threats.push({
          type: 'detached_process',
          severity: 'HIGH',
          message: `${callName}() with {detached: true} — background process survives parent exit (evasion technique).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect fs.writeFileSync/writeFile to .github/workflows
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const writeMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(writeMethod) && node.arguments.length > 0) {
      const pathArg = node.arguments[0];
      const pathStr = extractStringValue(pathArg);
      let joinedPath = null;
      let hasWorkflowVar = false;
      if (pathArg?.type === 'CallExpression' && pathArg.arguments) {
        joinedPath = pathArg.arguments.map(a => {
          if (a.type === 'Identifier' && ctx.workflowPathVars.has(a.name)) {
            hasWorkflowVar = true;
            return '.github/workflows';
          }
          return extractStringValue(a) || '';
        }).join('/');
      }
      if (pathArg?.type === 'Identifier' && ctx.workflowPathVars.has(pathArg.name)) {
        hasWorkflowVar = true;
      }
      const checkPath = pathStr || joinedPath || '';
      if (hasWorkflowVar || /\.github[\\/]workflows/i.test(checkPath) || /\.github[\\/]actions/i.test(checkPath)) {
        ctx.threats.push({
          type: 'workflow_write',
          severity: 'CRITICAL',
          message: `${writeMethod}() writes to .github/workflows — GitHub Actions injection/persistence technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect writes to node_modules/ — worm propagation / package patching (Shai-Hulud 2.0)
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const nmWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile', 'appendFileSync'].includes(nmWriteMethod) && node.arguments.length >= 2) {
      const nmPathArg = node.arguments[0];
      let nmPathStr = extractStringValueDeep(nmPathArg);
      // Also resolve variable indirection
      if (!nmPathStr && nmPathArg?.type === 'Identifier' && ctx.stringVarValues?.has(nmPathArg.name)) {
        nmPathStr = ctx.stringVarValues.get(nmPathArg.name);
      }
      if (nmPathStr && /node_modules[/\\]/.test(nmPathStr)) {
        ctx.threats.push({
          type: 'node_modules_write',
          severity: 'CRITICAL',
          message: `${nmWriteMethod}() targeting node_modules/ path: "${nmPathStr.substring(0, 80)}" — package patching / worm propagation technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect writes to systemd service paths — persistence technique (CanisterWorm/TeamPCP T1543.002)
  // No legitimate npm package creates systemd services.
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const sdWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile', 'appendFileSync'].includes(sdWriteMethod) && node.arguments.length >= 2) {
      const sdPathArg = node.arguments[0];
      let sdPathStr = extractStringValueDeep(sdPathArg);
      if (!sdPathStr && sdPathArg?.type === 'Identifier' && ctx.stringVarValues?.has(sdPathArg.name)) {
        sdPathStr = ctx.stringVarValues.get(sdPathArg.name);
      }
      if (sdPathStr && (/systemd[/\\]/i.test(sdPathStr) || /\.service$/i.test(sdPathStr))) {
        ctx.threats.push({
          type: 'systemd_persistence',
          severity: 'CRITICAL',
          message: `${sdWriteMethod}() writes to systemd path: "${sdPathStr.substring(0, 80)}" — persistence technique (CanisterWorm/TeamPCP).`,
          file: ctx.relFile
        });
      }
      // Detect writes to .pth files — Python auto-exec persistence (LiteLLM/Checkmarx T1546.004)
      // .pth files in site-packages/ are executed automatically by the Python interpreter at startup.
      // No legitimate npm package creates .pth files.
      if (sdPathStr && /\.pth$/i.test(sdPathStr)) {
        ctx.threats.push({
          type: 'pth_persistence',
          severity: 'CRITICAL',
          message: `${sdWriteMethod}() writes to Python .pth file: "${sdPathStr.substring(0, 80)}" — auto-exec persistence technique (LiteLLM/Checkmarx).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect fs.mkdirSync creating .github/workflows
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const mkdirMethod = node.callee.property.name;
    if ((mkdirMethod === 'mkdirSync' || mkdirMethod === 'mkdir') && node.arguments.length > 0) {
      const pathArg = node.arguments[0];
      if (pathArg?.type === 'Identifier' && ctx.workflowPathVars.has(pathArg.name)) {
        ctx.threats.push({
          type: 'workflow_write',
          severity: 'CRITICAL',
          message: `${mkdirMethod}() creates .github/workflows directory — GitHub Actions persistence technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect fs.readdirSync on .github/workflows
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const readDirMethod = node.callee.property.name;
    if ((readDirMethod === 'readdirSync' || readDirMethod === 'readdir') && node.arguments.length > 0) {
      const pathArg = node.arguments[0];
      if (pathArg?.type === 'Identifier' && ctx.workflowPathVars.has(pathArg.name)) {
        ctx.threats.push({
          type: 'workflow_write',
          severity: 'CRITICAL',
          message: `${readDirMethod}() enumerates .github/workflows — workflow modification/injection technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // SANDWORM_MODE R5: MCP config injection — writeFileSync to AI config paths
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const mcpWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(mcpWriteMethod) && node.arguments.length >= 2) {
      const mcpPathArg = node.arguments[0];
      const mcpPathStr = extractStringValueDeep(mcpPathArg);
      // Also check path.join() calls — resolve concat fragments in each argument
      let mcpJoinedPath = '';
      if (mcpPathArg?.type === 'CallExpression' && mcpPathArg.arguments) {
        mcpJoinedPath = mcpPathArg.arguments.map(a => extractStringValueDeep(a) || '').join('/');
      }
      // Also check if path arg is a variable tracked as MCP/IDE config path
      let mcpVarPath = '';
      if (mcpPathArg?.type === 'Identifier' && ctx.ideConfigPathVars.has(mcpPathArg.name)) {
        mcpVarPath = ctx.ideConfigPathVars.get(mcpPathArg.name);
      }
      const mcpCheckPath = (mcpPathStr || mcpJoinedPath || mcpVarPath).toLowerCase();
      const isMcpPath = MCP_CONFIG_PATHS.some(p => mcpCheckPath.includes(p.toLowerCase()));
      if (isMcpPath) {
        // Check content argument for MCP-related patterns
        const contentArg = node.arguments[1];
        const contentStr = extractStringValue(contentArg);
        // Extract filename from path to distinguish sensitive config files from plugin state
        const mcpFileName = mcpCheckPath.split(/[/\\]/).filter(Boolean).pop() || '';
        const isUniqueSensitive = SENSITIVE_AI_CONFIG_FILES_UNIQUE.some(f => mcpFileName === f);
        // For generic names (settings.json), only sensitive at config dir root (1 level deep)
        // e.g. .claude/settings.json → sensitive, .claude/plugin/settings.json → not sensitive
        let isRootOnlySensitive = false;
        if (SENSITIVE_AI_CONFIG_FILES_ROOT_ONLY.some(f => mcpFileName === f)) {
          const matchedDir = MCP_CONFIG_PATHS.find(p => mcpCheckPath.includes(p.toLowerCase()));
          if (matchedDir) {
            const idx = mcpCheckPath.indexOf(matchedDir.toLowerCase());
            const afterDir = mcpCheckPath.slice(idx + matchedDir.length);
            // Direct child: no further path separators (e.g. "settings.json", not "sub/settings.json")
            isRootOnlySensitive = !afterDir.includes('/') && !afterDir.includes('\\');
          }
        }
        const isSensitiveConfigFile = isUniqueSensitive || isRootOnlySensitive;
        const hasContentPattern = contentStr
          ? MCP_CONTENT_PATTERNS.some(p => contentStr.includes(p.replace(/"/g, '')))
          : isSensitiveConfigFile; // dynamic content only suspicious for known config files
        if (hasContentPattern) {
          ctx.threats.push({
            type: 'mcp_config_injection',
            severity: 'CRITICAL',
            message: `MCP config injection: ${mcpWriteMethod}() writes to AI assistant configuration (${mcpCheckPath}). SANDWORM_MODE technique for AI toolchain poisoning.`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // SANDWORM_MODE R6: Git hooks injection — writeFileSync to .git/hooks/
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const gitWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(gitWriteMethod) && node.arguments.length >= 1) {
      const gitPathArg = node.arguments[0];
      const gitPathStr = extractStringValueDeep(gitPathArg);
      let gitJoinedPath = '';
      if (gitPathArg?.type === 'CallExpression' && gitPathArg.arguments) {
        gitJoinedPath = gitPathArg.arguments.map(a => extractStringValueDeep(a) || '').join('/');
      }
      // Also check if path arg is a variable tracked as git hooks path
      let gitVarPath = '';
      if (gitPathArg?.type === 'Identifier' && ctx.gitHooksPathVars.has(gitPathArg.name)) {
        gitVarPath = ctx.gitHooksPathVars.get(gitPathArg.name);
      }
      const gitCheckPath = gitPathStr || gitJoinedPath || gitVarPath;
      if (/\.git[\\/]hooks[\\/]/i.test(gitCheckPath) ||
          GIT_HOOKS.some(h => gitCheckPath.includes(h) && (gitCheckPath.includes('.git') || gitCheckPath.includes('hooks')))) {
        ctx.threats.push({
          type: 'git_hooks_injection',
          severity: 'HIGH',
          message: `Git hook injection: ${gitWriteMethod}() writes to .git/hooks/. Persistence technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // SANDWORM_MODE R6: Git hooks injection via exec — git config --global init.templateDir or git config hooks
  if ((execName || memberExec) && node.arguments.length > 0) {
    const gitExecArg = node.arguments[0];
    const gitExecStr = extractStringValue(gitExecArg);
    if (gitExecStr) {
      if (/git\s+config\s+.*init\.templateDir/i.test(gitExecStr)) {
        ctx.threats.push({
          type: 'git_hooks_injection',
          severity: 'HIGH',
          message: 'Git hook injection: modifying global git template directory via "git config init.templateDir". Persistence technique.',
          file: ctx.relFile
        });
      } else if (/git\s+config\b/.test(gitExecStr) && /hooks/i.test(gitExecStr)) {
        ctx.threats.push({
          type: 'git_hooks_injection',
          severity: 'HIGH',
          message: 'Git hook injection: modifying git hooks configuration. Persistence technique.',
          file: ctx.relFile
        });
      }
    }
  }

  // Wave 4: IDE persistence — writeFileSync to VS Code tasks.json or Code/User/ paths
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const ideWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(ideWriteMethod) && node.arguments.length >= 1) {
      const idePathArg = node.arguments[0];
      const idePathStr = extractStringValueDeep(idePathArg);
      let ideJoinedPath = '';
      if (idePathArg?.type === 'CallExpression' && idePathArg.arguments) {
        ideJoinedPath = idePathArg.arguments.map(a => extractStringValueDeep(a) || '').join('/');
      }
      let ideVarPath = '';
      if (idePathArg?.type === 'Identifier' && ctx.ideConfigPathVars.has(idePathArg.name)) {
        ideVarPath = ctx.ideConfigPathVars.get(idePathArg.name);
      }
      const ideCheckPath = (idePathStr || ideJoinedPath || ideVarPath).toLowerCase();
      if ((ideCheckPath.includes('tasks.json') || ideCheckPath.includes('code/user/') || ideCheckPath.includes('.vscode/')) &&
          !ctx.hasIdePersistenceWrite) {
        // Check content for task runner persistence patterns (runOn, folderOpen)
        const ideContentArg = node.arguments[1];
        const ideContentStr = extractStringValue(ideContentArg);
        const hasPersistencePattern = ideContentStr
          ? /runOn|folderOpen|reveal.*silent/.test(ideContentStr)
          : true; // dynamic content targeting IDE task paths = suspicious
        if (hasPersistencePattern) {
          ctx.hasIdePersistenceWrite = true;
          ctx.threats.push({
            type: 'ide_persistence',
            severity: 'HIGH',
            message: `IDE persistence: ${ideWriteMethod}() writes to IDE task configuration (${ideCheckPath}). Auto-execution on folder open.`,
            file: ctx.relFile
          });
        }
      }
    }
  }


  // Detect fs.chmodSync with executable permissions (deferred to postWalk for compound check)
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const chmodMethod = node.callee.property.name;
    if ((chmodMethod === 'chmodSync' || chmodMethod === 'chmod') && node.arguments.length >= 2) {
      const modeArg = node.arguments[1];
      if (modeArg?.type === 'Literal' && typeof modeArg.value === 'number') {
        // 0o755=493, 0o777=511, 0o700=448, 0o775=509
        if (modeArg.value === 493 || modeArg.value === 511 || modeArg.value === 448 || modeArg.value === 509) {
          ctx.hasChmodExecutable = true;
          ctx.chmodMessage = `${chmodMethod}() with executable permissions (0o${modeArg.value.toString(8)})`;
        }
      }
    }
  }

  // Detect AI agent weaponization
  if ((callName === 'spawn' || callName === 'exec' || callName === 'execSync' ||
       callName === 'execFile' || callName === 'execFileSync' || memberExec) &&
      node.arguments.length > 0) {
    const argStrings = [];
    for (const arg of node.arguments) {
      if (arg.type === 'Literal' && typeof arg.value === 'string') {
        argStrings.push(arg.value);
      } else if (arg.type === 'ArrayExpression') {
        for (const el of arg.elements) {
          if (el && el.type === 'Literal' && typeof el.value === 'string') {
            argStrings.push(el.value);
          }
        }
      }
    }

    const allArgText = argStrings.join(' ');
    const hasDangerousFlag = AI_AGENT_DANGEROUS_FLAGS.some(flag => allArgText.includes(flag));
    const firstArg = node.arguments[0];
    const cmdName = firstArg?.type === 'Literal' && typeof firstArg.value === 'string'
      ? firstArg.value.toLowerCase() : '';
    const cmdBasename = cmdName ? path.basename(cmdName) : '';
    const isAIAgent = AI_AGENT_BINARIES.some(bin => cmdBasename === bin);

    if (hasDangerousFlag) {
      const matchedFlag = AI_AGENT_DANGEROUS_FLAGS.find(flag => allArgText.includes(flag));
      ctx.threats.push({
        type: 'ai_agent_abuse',
        severity: 'CRITICAL',
        message: `AI agent invoked with security bypass flag "${matchedFlag}"${isAIAgent ? ` (agent: ${cmdName})` : ''} — weaponized AI coding assistant (s1ngularity/Nx pattern).`,
        file: ctx.relFile
      });
    } else if (isAIAgent) {
      ctx.threats.push({
        type: 'ai_agent_abuse',
        severity: 'HIGH',
        message: `AI coding agent "${cmdName}" invoked from package — potential AI agent weaponization.`,
        file: ctx.relFile
      });
    }
  }

  // Detect Object.defineProperty(process.env, ...) — env interception
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Object' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'defineProperty' &&
      node.arguments.length >= 2) {
    const target = node.arguments[0];
    if (target.type === 'MemberExpression' &&
        target.object?.name === 'process' &&
        target.property?.name === 'env') {
      ctx.threats.push({
        type: 'env_proxy_intercept',
        severity: 'CRITICAL',
        message: 'Object.defineProperty(process.env) detected — intercepts environment variable access for credential theft.',
        file: ctx.relFile
      });
    }
  }

  // B1: Alias call — E('code') where E = eval or F = Function
  if (node.callee.type === 'Identifier' && ctx.evalAliases?.has(node.callee.name)) {
    const aliased = ctx.evalAliases.get(node.callee.name);
    if (aliased.endsWith('_factory')) {
      // Factory pattern: getEval()('code') — the callee is detected at outer CallExpression level
      // Mark the identifier so we can detect the outer call
    } else {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      // Audit v3: elevate to CRITICAL when argument contains dangerous API calls
      let aliasSev = 'HIGH';
      let aliasMsg = `Indirect ${aliased} via alias "${node.callee.name}" — eval wrapper evasion.`;
      if (node.arguments.length >= 1) {
        const aliasArg = node.arguments[0];
        if (aliasArg?.type === 'Literal' && typeof aliasArg.value === 'string' &&
            /\b(require|import|exec|execSync|spawn|child_process|process\.env)\b/.test(aliasArg.value)) {
          aliasSev = 'CRITICAL';
          aliasMsg = `Indirect ${aliased} via alias "${node.callee.name}" with dangerous payload: "${aliasArg.value.substring(0, 80)}" — eval evasion + code execution.`;
        }
      }
      ctx.threats.push({
        type: aliased === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
        severity: aliasSev,
        message: aliasMsg,
        file: ctx.relFile
      });
    }
  }

  // B1 fix: Factory call — getEval()('code') where getEval = () => eval
  if (node.callee.type === 'CallExpression' &&
      node.callee.callee?.type === 'Identifier' &&
      ctx.evalAliases?.has(node.callee.callee.name)) {
    const aliased = ctx.evalAliases.get(node.callee.callee.name);
    if (aliased.endsWith('_factory')) {
      const baseName = aliased.replace('_factory', '');
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: baseName === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
        severity: 'HIGH',
        message: `Indirect ${baseName} via factory function "${node.callee.callee.name}()" — eval factory evasion.`,
        file: ctx.relFile
      });
    }
  }

  // Audit v3 B3: Bare call to destructured _load — e.g. const { _load } = require('module'); _load('child_process')
  if (node.callee.type === 'Identifier' && ctx.moduleLoadDirectAliases?.has(node.callee.name)) {
    ctx.threats.push({
      type: 'module_load_bypass',
      severity: 'CRITICAL',
      message: `Module._load() via destructured alias "${node.callee.name}" — internal module loader bypass.`,
      file: ctx.relFile
    });
  }

  if (callName === 'eval') {
    ctx.hasEvalInFile = true;
    // Detect staged eval decode
    if (node.arguments.length === 1 && hasDecodeArg(node.arguments[0])) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'staged_eval_decode',
        severity: 'CRITICAL',
        message: 'eval() with decode argument (atob/Buffer.from base64) — staged payload execution.',
        file: ctx.relFile
      });
    } else {
      const isConstant = hasOnlyStringLiteralArgs(node);
      let severity = isConstant ? 'LOW' : 'HIGH';
      let message = isConstant
        ? 'eval() with constant string literal (low risk, globalThis polyfill pattern).'
        : 'Dangerous call "eval" with dynamic expression detected.';

      // Audit fix: even string-literal eval is dangerous if content contains dangerous APIs
      if (isConstant && node.arguments[0]?.value) {
        const val = node.arguments[0].value;
        if (/\b(require|import|exec|execSync|spawn|child_process|\.readFile|\.writeFile|process\.env|\.homedir)\b/.test(val)) {
          severity = 'HIGH';
          message = `eval() with dangerous API in string literal: "${val.substring(0, 100)}"`;
          ctx.hasDynamicExec = true;
        }
      }

      // Only set hasDynamicExec for non-constant (dynamic) eval
      if (!isConstant) {
        ctx.hasDynamicExec = true;
      }

      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity,
        message,
        file: ctx.relFile
      });
    }
  } else if (callName === 'Function') {
    ctx.hasDynamicExec = true;
    // Detect staged Function decode
    if (node.arguments.length >= 1 && hasDecodeArg(node.arguments[node.arguments.length - 1])) {
      ctx.threats.push({
        type: 'staged_eval_decode',
        severity: 'CRITICAL',
        message: 'Function() with decode argument (atob/Buffer.from base64) — staged payload execution.',
        file: ctx.relFile
      });
    } else if (!hasOnlyStringLiteralArgs(node)) {
      // Only flag dynamic Function() calls — string literal args (e.g. Function('return this'))
      // are zero-risk globalThis polyfills used by every bundler
      ctx.threats.push({
        type: 'dangerous_call_function',
        severity: 'MEDIUM',
        message: 'Function() with dynamic expression (template/factory pattern).',
        file: ctx.relFile
      });
    }
  }

  // Audit v3 B2: Split entropy detection — concatenated strings passed to eval/Function/decode
  // Detects payloads split across ≥3 chunks to bypass per-string entropy thresholds.
  if (callName === 'eval' || callName === 'Function' || callName === 'atob') {
    // Threshold lower than standard (5.5) because the triple signal
    // (concat ≥3 + eval/decode + entropy) provides high confidence at 4.5.
    const SPLIT_ENTROPY_THRESHOLD = 4.5;
    const SPLIT_ENTROPY_MIN_OPERANDS = 3;
    for (const arg of node.arguments) {
      // Direct concat: eval('ch1' + 'ch2' + 'ch3')
      if (arg.type === 'BinaryExpression' && arg.operator === '+') {
        const operands = countConcatOperands(arg);
        if (operands >= SPLIT_ENTROPY_MIN_OPERANDS) {
          const resolved = resolveStringConcatWithVars(arg, ctx.stringVarValues);
          if (resolved && resolved.length >= 20 && calculateShannonEntropy(resolved) > SPLIT_ENTROPY_THRESHOLD) {
            ctx.threats.push({
              type: 'split_entropy_payload',
              severity: 'CRITICAL',
              message: `Split high-entropy string (${operands} chunks, ${calculateShannonEntropy(resolved).toFixed(2)} bits) passed to ${callName}() — payload fragmentation evasion.`,
              file: ctx.relFile
            });
            break;
          }
        }
      }
      // Variable indirection: eval(payload) where payload was built from concat
      if (arg.type === 'Identifier' && ctx.concatValues?.has(arg.name)) {
        const cv = ctx.concatValues.get(arg.name);
        if (calculateShannonEntropy(cv.value) > SPLIT_ENTROPY_THRESHOLD) {
          ctx.threats.push({
            type: 'split_entropy_payload',
            severity: 'CRITICAL',
            message: `Split high-entropy variable "${arg.name}" (${cv.operands} chunks, ${calculateShannonEntropy(cv.value).toFixed(2)} bits) passed to ${callName}() — payload fragmentation evasion.`,
            file: ctx.relFile
          });
          break;
        }
      }
    }
  }

  // Also check Buffer.from arguments for split entropy (decode context)
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.object?.name === 'Buffer' && node.callee.property?.name === 'from') {
    const SPLIT_ENTROPY_THRESHOLD = 4.5;
    const arg = node.arguments?.[0];
    if (arg?.type === 'BinaryExpression' && arg.operator === '+') {
      const operands = countConcatOperands(arg);
      if (operands >= 3) {
        const resolved = resolveStringConcatWithVars(arg, ctx.stringVarValues);
        if (resolved && resolved.length >= 20 && calculateShannonEntropy(resolved) > SPLIT_ENTROPY_THRESHOLD) {
          ctx.threats.push({
            type: 'split_entropy_payload',
            severity: 'CRITICAL',
            message: `Split high-entropy string (${operands} chunks, ${calculateShannonEntropy(resolved).toFixed(2)} bits) in Buffer.from() — payload fragmentation evasion.`,
            file: ctx.relFile
          });
        }
      }
    }
    if (arg?.type === 'Identifier' && ctx.concatValues?.has(arg.name)) {
      const cv = ctx.concatValues.get(arg.name);
      if (calculateShannonEntropy(cv.value) > SPLIT_ENTROPY_THRESHOLD) {
        ctx.threats.push({
          type: 'split_entropy_payload',
          severity: 'CRITICAL',
          message: `Split high-entropy variable "${arg.name}" (${cv.operands} chunks, ${calculateShannonEntropy(cv.value).toFixed(2)} bits) in Buffer.from() — payload fragmentation evasion.`,
          file: ctx.relFile
        });
      }
    }
  }

  // setTimeout/setInterval with string argument = eval equivalent
  // setTimeout("require('child_process').exec('whoami')", 100) executes the string as code
  // Only string Literal and TemplateLiteral are eval-equivalent; Identifier/MemberExpression
  // are function references (callbacks), not code strings.
  if ((callName === 'setTimeout' || callName === 'setInterval') && node.arguments.length >= 1) {
    const firstArg = node.arguments[0];
    if ((firstArg.type === 'Literal' && typeof firstArg.value === 'string') ||
        firstArg.type === 'TemplateLiteral') {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      // Audit v3: elevate to CRITICAL when string contains dangerous API calls
      let timerSeverity = 'HIGH';
      let timerMsg = `${callName}() with string argument — eval equivalent, executes the string as code.`;
      if (firstArg.type === 'Literal' && typeof firstArg.value === 'string') {
        if (/\b(require|import|exec|execSync|spawn|child_process|\.readFile|\.writeFile|process\.env|\.homedir)\b/.test(firstArg.value)) {
          timerSeverity = 'CRITICAL';
          timerMsg = `${callName}() with dangerous API in string: "${firstArg.value.substring(0, 80)}" — eval equivalent code execution.`;
        }
      }
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: timerSeverity,
        message: timerMsg,
        file: ctx.relFile
      });
    }
    // BinaryExpression with '+' as first arg = string concatenation for eval via timer
    else if (firstArg.type === 'BinaryExpression' && firstArg.operator === '+') {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: 'HIGH',
        message: `${callName}() with concatenated string argument — eval equivalent, dynamically built code string.`,
        file: ctx.relFile
      });
    }
    // Identifier arg that was tracked as string value or string concatenation result
    else if (firstArg.type === 'Identifier' &&
             (ctx.stringVarValues?.has(firstArg.name) || ctx.stringBuildVars?.has(firstArg.name))) {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: 'HIGH',
        message: `${callName}() with variable "${firstArg.name}" containing built string — eval equivalent, executes the string as code.`,
        file: ctx.relFile
      });
    }

    // Static timer bomb: setTimeout/setInterval with delay > 1 hour (PhantomRaven 48h delay)
    if (node.arguments.length >= 2) {
      const delayArg = node.arguments[1];
      let delayMs = null;
      if (delayArg.type === 'Literal' && typeof delayArg.value === 'number') {
        delayMs = delayArg.value;
      }
      if (delayMs !== null && delayMs > 3600000) { // > 1 hour
        const hours = (delayMs / 3600000).toFixed(1);
        ctx.threats.push({
          type: 'static_timer_bomb',
          severity: delayMs > 86400000 ? 'HIGH' : 'MEDIUM', // > 24h = HIGH
          message: `${callName}() with ${hours}h delay (${delayMs}ms) — time-bomb evasion: payload activates long after install.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect eval.call(null, code) / eval.apply(null, [code]) / Function.call/apply
  if (node.callee.type === 'MemberExpression' && !node.callee.computed &&
      node.callee.property?.type === 'Identifier' &&
      (node.callee.property.name === 'call' || node.callee.property.name === 'apply')) {
    const obj = node.callee.object;
    if (obj?.type === 'Identifier' && (obj.name === 'eval' || obj.name === 'Function')) {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: obj.name === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
        severity: 'HIGH',
        message: `${obj.name}.${node.callee.property.name}() — indirect execution via call/apply evasion technique.`,
        file: ctx.relFile
      });
    }
    // B2 fix: Function.prototype.call.call(eval, null, code) / X.call.call(eval, ...)
    // Deep MemberExpression: obj is itself a MemberExpression ending in .call/.apply
    if (obj?.type === 'MemberExpression' &&
        obj.property?.type === 'Identifier' &&
        (obj.property.name === 'call' || obj.property.name === 'apply') &&
        node.arguments.length >= 2) {
      const firstArg = node.arguments[0];
      if (firstArg?.type === 'Identifier' && (firstArg.name === 'eval' || firstArg.name === 'Function')) {
        ctx.hasEvalInFile = true;
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: firstArg.name === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
          severity: 'HIGH',
          message: `${firstArg.name} passed to .call.call() — nested call/apply evasion technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect array access pattern: [require][0]('child_process') or [eval][0](code)
  if (node.callee.type === 'MemberExpression' && node.callee.computed &&
      node.callee.object?.type === 'ArrayExpression' &&
      node.callee.property?.type === 'Literal' && typeof node.callee.property.value === 'number') {
    const elements = node.callee.object.elements;
    for (const el of elements) {
      if (el?.type === 'Identifier') {
        if (el.name === 'eval') {
          ctx.hasEvalInFile = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'dangerous_call_eval',
            severity: 'HIGH',
            message: '[eval][0]() — array access evasion technique for indirect eval execution.',
            file: ctx.relFile
          });
        } else if (el.name === 'require') {
          ctx.threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: '[require][0]() — array access evasion technique for indirect require.',
            file: ctx.relFile
          });
        } else if (el.name === 'Function') {
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'dangerous_call_function',
            severity: 'MEDIUM',
            message: '[Function][0]() — array access evasion technique for indirect Function construction.',
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Detect new Proxy(require, handler) — proxy wrapping require to intercept module loading
  if (node.callee.type === 'Identifier' && node.callee.name !== 'Proxy') {
    // handled below in handleNewExpression
  }

  // Detect template literals in exec/execSync: execSync(`${cmd}`)
  if ((execName || memberExec) && node.arguments.length > 0) {
    const arg = node.arguments[0];
    if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
      // Template literal with dynamic expressions in exec — bypass for string matching
      const staticParts = arg.quasis.map(q => q.value.raw).join('');
      if (DANGEROUS_CMD_PATTERNS.some(p => p.test(staticParts))) {
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: `Dangerous command in template literal exec(): "${staticParts.substring(0, 80)}" — template literal evasion.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect indirect eval/Function via computed property
  if (node.callee.type === 'MemberExpression' && node.callee.computed) {
    const prop = node.callee.property;
    if (prop.type === 'Literal' && typeof prop.value === 'string') {
      if (prop.value === 'eval') {
        ctx.hasEvalInFile = true;
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: 'HIGH',
          message: 'Indirect eval via computed property access (obj["eval"]) — evasion technique.',
          file: ctx.relFile
        });
      } else if (prop.value === 'Function') {
        ctx.threats.push({
          type: 'dangerous_call_function',
          severity: 'MEDIUM',
          message: 'Indirect Function via computed property access (obj["Function"]) — evasion technique.',
          file: ctx.relFile
        });
      }
    }
    // Detect computed call on globalThis/global alias with variable or expression property
    const obj = node.callee.object;
    if (obj?.type === 'Identifier' &&
        (ctx.globalThisAliases.has(obj.name) || obj.name === 'globalThis' || obj.name === 'global')) {
      if (prop.type === 'Identifier') {
        ctx.hasEvalInFile = true;
        // Resolve variable value via stringVarValues (e.g., const f = 'eval'; globalThis[f]())
        const resolvedValue = ctx.stringVarValues.get(prop.name);
        const isEvalOrFunction = resolvedValue === 'eval' || resolvedValue === 'Function';
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: isEvalOrFunction ? 'CRITICAL' : 'HIGH',
          message: isEvalOrFunction
            ? `Resolved indirect ${resolvedValue}() via computed property (${obj.name}[${prop.name}="${resolvedValue}"]) — confirmed eval evasion.`
            : `Dynamic global dispatch via computed property (${obj.name}[${prop.name}]) — likely indirect eval evasion.`,
          file: ctx.relFile
        });
      } else {
        // BinaryExpression, TemplateLiteral, or other computed expression
        // Try to resolve via stringVarValues (e.g., var a='ev',b='al'; globalThis[a+b]())
        const resolvedProp = resolveStringConcatWithVars(prop, ctx.stringVarValues);
        if (resolvedProp === 'eval' || resolvedProp === 'Function') {
          ctx.hasEvalInFile = true;
          ctx.threats.push({
            type: 'dangerous_call_eval',
            severity: 'CRITICAL',
            message: `Resolved indirect ${resolvedProp}() via computed expression (${obj.name}[...="${resolvedProp}"]) — concat evasion.`,
            file: ctx.relFile
          });
        } else if (resolvedProp !== null) {
          ctx.hasEvalInFile = true;
          ctx.threats.push({
            type: 'dangerous_call_eval',
            severity: 'HIGH',
            message: `Dynamic global dispatch via computed expression (${obj.name}[...="${resolvedProp}"]).`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Detect indirect eval/Function via sequence expression
  if (node.callee.type === 'SequenceExpression') {
    const exprs = node.callee.expressions;
    const last = exprs[exprs.length - 1];
    if (last && last.type === 'Identifier') {
      if (last.name === 'eval') {
        ctx.hasEvalInFile = true;
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: 'HIGH',
          message: 'Indirect eval via sequence expression ((0, eval)) — evasion technique.',
          file: ctx.relFile
        });
      } else if (last.name === 'Function') {
        ctx.threats.push({
          type: 'dangerous_call_function',
          severity: 'MEDIUM',
          message: 'Indirect Function via sequence expression ((0, Function)) — evasion technique.',
          file: ctx.relFile
        });
      }
    }
  }

  // Batch 2: Detect indirect eval/Function via logical expression: (false || eval)(code), (0 || Function)(code)
  if (node.callee.type === 'LogicalExpression' && node.callee.operator === '||') {
    const right = node.callee.right;
    if (right?.type === 'Identifier') {
      if (right.name === 'eval') {
        ctx.hasEvalInFile = true;
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: 'HIGH',
          message: 'Indirect eval via logical expression ((false || eval)) — evasion technique.',
          file: ctx.relFile
        });
      } else if (right.name === 'Function') {
        ctx.threats.push({
          type: 'dangerous_call_function',
          severity: 'MEDIUM',
          message: 'Indirect Function via logical expression ((false || Function)) — evasion technique.',
          file: ctx.relFile
        });
      }
    }
  }

  // Detect crypto.createDecipher/createDecipheriv and module._compile
  if (node.callee.type === 'MemberExpression') {
    const prop = node.callee.property;
    const propName = prop.type === 'Identifier' ? prop.name :
                     (prop.type === 'Literal' ? prop.value : null);
    if (propName === 'createDecipher' || propName === 'createDecipheriv') {
      ctx.threats.push({
        type: 'crypto_decipher',
        severity: 'HIGH',
        message: `${propName}() detected — runtime decryption of embedded payload (event-stream/flatmap-stream pattern).`,
        file: ctx.relFile
      });
    }
    if (propName === '_compile') {
      // Context-aware gating: only flag _compile when the Module API is plausibly in scope.
      // Custom class methods (e.g. blessed's Tput.prototype._compile) are not malware.
      const calleeObj = node.callee.object;
      const isThisCall = calleeObj.type === 'ThisExpression';
      const isModuleIdentifier = calleeObj.type === 'Identifier' &&
        (calleeObj.name === 'module' || calleeObj.name === 'Module' || calleeObj.name === 'm');
      const isConstructed = calleeObj.type === 'NewExpression' || calleeObj.type === 'CallExpression';
      const isMemberChain = calleeObj.type === 'MemberExpression';
      // Skip: this._compile() is always a custom instance method, not Node Module API
      // Detect: module/Module/m identifier, new X()._compile(), X()._compile(), X.Y._compile()
      // Other identifiers: only if require('module') or module.constructor is in file
      const shouldDetect = !isThisCall && (
        isModuleIdentifier || isConstructed || isMemberChain ||
        (calleeObj.type === 'Identifier' && ctx.hasModuleImport)
      );
      if (shouldDetect) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'module_compile',
          // P6: Baseline HIGH — single module._compile() in build tools (@babel/core, art-template)
          // is framework behavior. Compound detections (zlib_inflate_eval, fetch_decrypt_exec) stay CRITICAL.
          severity: 'HIGH',
          message: 'module._compile() detected — executes arbitrary code from string in module context (flatmap-stream pattern).',
          file: ctx.relFile
        });
        // SANDWORM_MODE: Module._compile with non-literal argument = dynamic code execution
        if (node.arguments.length >= 1 && !hasOnlyStringLiteralArgs(node)) {
          ctx.threats.push({
            type: 'module_compile_dynamic',
            severity: 'HIGH',
            message: 'In-memory code execution via Module._compile(). Common malware evasion technique.',
            file: ctx.relFile
          });
        }
        // Module._compile counts as temp file exec for write-execute-delete pattern
        ctx.hasTempFileExec = ctx.hasTempFileExec || ctx.hasDevShmInContent;
      }
    }

    // Module._load() — internal module loader bypass (security audit v2)
    if (propName === '_load') {
      const calleeObj = node.callee.object;
      const isModuleIdentifier = calleeObj.type === 'Identifier' &&
        (calleeObj.name === 'Module' || calleeObj.name === 'module' ||
         (ctx.moduleAliases && ctx.moduleAliases.has(calleeObj.name)));
      const isMemberChain = calleeObj.type === 'MemberExpression';
      const isConstructed = calleeObj.type === 'NewExpression' || calleeObj.type === 'CallExpression';
      if (isModuleIdentifier || isMemberChain || isConstructed || ctx.hasModuleImport) {
        ctx.threats.push({
          type: 'module_load_bypass',
          severity: 'CRITICAL',
          message: 'Module._load() detected — internal module loader bypass for dynamic code loading.',
          file: ctx.relFile
        });
      }
    }

    // Audit v3 B3: AsyncFunction/GeneratorFunction constructor via prototype chain
    // Pattern: Object.getPrototypeOf(async function(){}).constructor('code')()
    // or: Reflect.getPrototypeOf(function*(){}).constructor('code')()
    if (propName === 'constructor') {
      const obj = node.callee.object;
      if (obj?.type === 'CallExpression' && obj.callee?.type === 'MemberExpression') {
        const innerObj = obj.callee.object;
        const innerProp = obj.callee.property;
        if (innerObj?.type === 'Identifier' &&
            (innerObj.name === 'Object' || innerObj.name === 'Reflect') &&
            innerProp?.type === 'Identifier' && innerProp.name === 'getPrototypeOf' &&
            obj.arguments?.length >= 1) {
          const arg = obj.arguments[0];
          if (arg.type === 'FunctionExpression' && (arg.async || arg.generator)) {
            const kind = arg.async ? 'AsyncFunction' : 'GeneratorFunction';
            ctx.hasEvalInFile = true;
            ctx.hasDynamicExec = true;
            ctx.threats.push({
              type: 'dangerous_constructor',
              severity: 'CRITICAL',
              message: `${kind} constructor accessed via Object.getPrototypeOf() — prototype chain code execution bypass.`,
              file: ctx.relFile
            });
          }
        }
      }

      // Audit v3 bypass fix: .constructor.constructor('code')() — double constructor chain
      // Any expression.constructor.constructor is traversing to Function constructor
      if (obj?.type === 'MemberExpression') {
        const innerPropName = obj.computed
          ? (obj.property?.type === 'Literal' ? String(obj.property.value) : null)
          : (obj.property?.type === 'Identifier' ? obj.property.name : null);
        if (innerPropName === 'constructor') {
          ctx.hasEvalInFile = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'dangerous_constructor',
            severity: 'CRITICAL',
            message: 'Constructor chain traversal: .constructor.constructor() — accesses Function constructor via prototype chain.',
            file: ctx.relFile
          });
        }
      }

      // B3: (function(){}).constructor('code')() — direct prototype chain Function access
      // Also: [].constructor.constructor, ''.constructor.constructor, (0).constructor.constructor
      if (obj?.type === 'FunctionExpression' || obj?.type === 'ArrowFunctionExpression' ||
          obj?.type === 'ArrayExpression' || obj?.type === 'Literal') {
        if (!hasOnlyStringLiteralArgs(node)) {
          ctx.hasEvalInFile = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'function_prototype_constructor',
            severity: 'CRITICAL',
            message: `Function constructor via prototype chain: (${obj.type === 'FunctionExpression' ? 'function(){}' : obj.type === 'ArrayExpression' ? '[]' : 'literal'}).constructor(code) — bypasses Function/eval detection.`,
            file: ctx.relFile
          });
        }
      }
    }

    // SANDWORM_MODE: Track writeFileSync/writeFile to temp paths
    if (propName === 'writeFileSync' || propName === 'writeFile') {
      const arg = node.arguments && node.arguments[0];
      if (arg) {
        const strVal = extractStringValue(arg);
        if (strVal && /\/dev\/shm\b/.test(strVal)) {
          ctx.hasTempFileWrite = true;
        }
        // Variable reference to /dev/shm path
        if (!strVal && (arg.type === 'Identifier' || arg.type === 'CallExpression' || arg.type === 'MemberExpression')) {
          // Dynamic path — check if file content involves /dev/shm
          ctx.hasTempFileWrite = ctx.hasTempFileWrite || ctx.hasDevShmInContent;
        }
      }
    }

    // SANDWORM_MODE: Track unlinkSync/rmSync (file deletion)
    if (propName === 'unlinkSync' || propName === 'unlink' || propName === 'rmSync') {
      ctx.hasFileDelete = true;
    }
  }

  // SANDWORM_MODE: Track require() of temp path (execution of temp file)
  if (callName === 'require' && node.arguments.length > 0) {
    const arg = node.arguments[0];
    const strVal = extractStringValue(arg);
    if (strVal && /\/dev\/shm\b/.test(strVal)) {
      ctx.hasTempFileExec = true;
    } else if (!strVal && ctx.hasDevShmInContent) {
      // Variable argument in a file that references /dev/shm
      ctx.hasTempFileExec = true;
    }
  }

  // SANDWORM_MODE R7: Detect Object.entries/keys/values(process.env)
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Object' &&
      node.callee.property?.type === 'Identifier' &&
      ['entries', 'keys', 'values'].includes(node.callee.property.name) &&
      node.arguments.length >= 1) {
    const enumArg = node.arguments[0];
    // Check if argument is process.env
    if (enumArg.type === 'MemberExpression' &&
        enumArg.object?.type === 'Identifier' && enumArg.object.name === 'process' &&
        enumArg.property?.type === 'Identifier' && enumArg.property.name === 'env') {
      ctx.hasEnvEnumeration = true;
    }
  }

  // Audit v3: JSON.stringify(process.env) — bulk env serialization = env enumeration
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'JSON' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'stringify' &&
      node.arguments.length >= 1) {
    const strArg = node.arguments[0];
    if (strArg.type === 'MemberExpression' &&
        strArg.object?.type === 'Identifier' && strArg.object.name === 'process' &&
        strArg.property?.type === 'Identifier' && strArg.property.name === 'env') {
      ctx.hasEnvEnumeration = true;
    }
  }

  // Batch 1: vm.* code execution — vm.runInThisContext, vm.runInNewContext, vm.compileFunction, vm.Script
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const vmMethod = node.callee.property.name;
    if (['runInThisContext', 'runInNewContext', 'compileFunction'].includes(vmMethod)) {
      // Audit v3: elevate to CRITICAL when argument contains dangerous API calls
      let vmSeverity = 'HIGH';
      let vmMsg = `vm.${vmMethod}() — dynamic code execution via Node.js vm module bypasses eval detection.`;
      const vmArg = node.arguments?.[0];
      let vmContent = '';
      if (vmArg?.type === 'Literal' && typeof vmArg.value === 'string') {
        vmContent = vmArg.value;
      } else if (vmArg?.type === 'Identifier' && ctx.stringVarValues?.has(vmArg.name)) {
        vmContent = ctx.stringVarValues.get(vmArg.name);
      }
      if (/\b(require|import|exec|execSync|spawn|child_process|process\.env)\b/.test(vmContent)) {
        vmSeverity = 'CRITICAL';
        ctx.hasDynamicExec = true;
        vmMsg = `vm.${vmMethod}() with dangerous API in code: "${vmContent.substring(0, 80)}" — vm module code execution bypass.`;
      }
      // NOTE: Do NOT set ctx.hasDynamicExec for generic vm.* calls — legitimately used by bundlers
      // (webpack, jest, etc.) and must not trigger compound detections (zlib_inflate_eval,
      // fetch_decrypt_exec) which were designed for eval/Function patterns.
      ctx.threats.push({
        type: 'vm_code_execution',
        severity: vmSeverity,
        message: vmMsg,
        file: ctx.relFile
      });
    }
  }

  // Batch 1: Reflect.construct(Function, [...]) / Reflect.apply(eval, null, [...])
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Reflect' &&
      node.callee.property?.type === 'Identifier') {
    const reflectMethod = node.callee.property.name;
    if (reflectMethod === 'construct' && node.arguments.length >= 2) {
      const target = node.arguments[0];
      if (target.type === 'Identifier' && target.name === 'Function') {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'reflect_code_execution',
          severity: 'CRITICAL',
          message: 'Reflect.construct(Function, [...]) — indirect Function construction bypasses new Function() detection.',
          file: ctx.relFile
        });
      }
    } else if (reflectMethod === 'apply' && node.arguments.length >= 3) {
      const target = node.arguments[0];
      if (target.type === 'Identifier' && (target.name === 'eval' || target.name === 'Function')) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'reflect_code_execution',
          severity: 'CRITICAL',
          message: `Reflect.apply(${target.name}, ...) — indirect ${target.name} invocation bypasses direct call detection.`,
          file: ctx.relFile
        });
      }
      // B1: Reflect.apply(require, null, ['child_process']) — bypasses require() call detection
      if (target.type === 'Identifier' && target.name === 'require') {
        const argsArray = node.arguments[2];
        let modName = null;
        if (argsArray?.type === 'ArrayExpression' && argsArray.elements.length > 0) {
          modName = extractStringValueDeep(argsArray.elements[0]);
        }
        const severity = modName && ['child_process', 'fs', 'net', 'dns', 'http', 'https'].includes(modName)
          ? 'CRITICAL' : 'HIGH';
        ctx.threats.push({
          type: 'reflect_apply_require',
          severity,
          message: `Reflect.apply(require, null, [${modName ? "'" + modName + "'" : '...'}]) — indirect require() bypasses static call detection.`,
          file: ctx.relFile
        });
      }
    }
  }

  // B4: __defineGetter__ / __defineSetter__ — prototype pollution via legacy API
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' &&
      (node.callee.property.name === '__defineGetter__' || node.callee.property.name === '__defineSetter__')) {
    ctx.threats.push({
      type: 'prototype_pollution',
      severity: 'HIGH',
      message: `${node.callee.property.name}() called — legacy prototype pollution API can hijack property access on any object.`,
      file: ctx.relFile
    });
  }

  // Batch 1: process.binding('spawn_sync'/'fs') / process._linkedBinding(...)
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'process' &&
      node.callee.property?.type === 'Identifier' &&
      (node.callee.property.name === 'binding' || node.callee.property.name === '_linkedBinding') &&
      node.arguments.length >= 1) {
    const bindArg = node.arguments[0];
    const bindStr = bindArg?.type === 'Literal' && typeof bindArg.value === 'string' ? bindArg.value : null;
    const dangerousBindings = ['spawn_sync', 'fs', 'pipe_wrap', 'tcp_wrap', 'tls_wrap', 'udp_wrap', 'process_wrap'];
    if (bindStr && dangerousBindings.includes(bindStr)) {
      ctx.threats.push({
        type: 'process_binding_abuse',
        severity: 'CRITICAL',
        message: `process.${node.callee.property.name}('${bindStr}') — direct V8 binding access bypasses child_process/fs module detection.`,
        file: ctx.relFile
      });
    } else if (!bindStr) {
      // Dynamic binding argument — suspicious
      ctx.threats.push({
        type: 'process_binding_abuse',
        severity: 'HIGH',
        message: `process.${node.callee.property.name}() with dynamic argument — potential V8 binding abuse.`,
        file: ctx.relFile
      });
    }
  }

  // Audit v3 bypass fix: process.on('uncaughtException'/'unhandledRejection', handler)
  // Error handler hijacking for silent credential exfiltration
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'process' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'on' &&
      node.arguments.length >= 2) {
    const eventArg = node.arguments[0];
    if (eventArg?.type === 'Literal' &&
        (eventArg.value === 'uncaughtException' || eventArg.value === 'unhandledRejection')) {
      ctx.hasUncaughtExceptionHandler = true;
    }
  }

  // SANDWORM_MODE R8: dns.resolve detection moved to walk.ancestor() in ast.js (FIX 5)
}

function handleImportExpression(node, ctx) {
  if (node.source) {
    const src = node.source;
    if (src.type === 'Literal' && typeof src.value === 'string') {
      const dangerousModules = ['child_process', 'fs', 'http', 'https', 'net', 'dns', 'tls', 'worker_threads'];
      // Batch 2: strip node: prefix so import('node:child_process') normalizes
      const modName = src.value.startsWith('node:') ? src.value.slice(5) : src.value;
      if (dangerousModules.includes(modName)) {
        // Audit v3: dynamic import of code execution modules → CRITICAL (evasion technique)
        const CRITICAL_IMPORTS = ['child_process', 'net', 'dns', 'worker_threads'];
        ctx.threats.push({
          type: 'dynamic_import',
          severity: CRITICAL_IMPORTS.includes(modName) ? 'CRITICAL' : 'HIGH',
          message: `Dynamic import() of dangerous module "${src.value}".`,
          file: ctx.relFile
        });
      }
      // GlassWorm: track Solana/Web3 dynamic import for compound blockchain C2 detection
      if (SOLANA_PACKAGES.some(pkg => src.value === pkg)) {
        ctx.hasSolanaImport = true;
      }
    } else {
      ctx.threats.push({
        type: 'dynamic_import',
        severity: 'HIGH',
        message: 'Dynamic import() with computed argument (possible obfuscation).',
        file: ctx.relFile
      });
    }
  }
}

function handleNewExpression(node, ctx) {
  if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
    // Skip string literal args — zero-risk globalThis polyfills used by every bundler
    if (!hasOnlyStringLiteralArgs(node)) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_call_function',
        severity: 'MEDIUM',
        message: 'new Function() with dynamic expression (template/factory pattern).',
        file: ctx.relFile
      });
    }
  }

  // Batch 1: new vm.Script(code) — dynamic code compilation via vm module
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'Script' &&
      node.arguments.length >= 1 && !hasOnlyStringLiteralArgs(node)) {
    // NOTE: Do NOT set ctx.hasDynamicExec — same rationale as vm.runInThisContext above.
    ctx.threats.push({
      type: 'vm_code_execution',
      severity: 'HIGH',
      message: 'new vm.Script() with dynamic code — vm module code compilation bypasses eval detection.',
      file: ctx.relFile
    });
  }

  // Detect new Proxy(process.env, handler)
  if (node.callee.type === 'Identifier' && node.callee.name === 'Proxy' && node.arguments.length >= 2) {
    const target = node.arguments[0];
    if (target.type === 'MemberExpression' &&
        target.object?.name === 'process' &&
        target.property?.name === 'env') {
      ctx.threats.push({
        type: 'env_proxy_intercept',
        severity: 'CRITICAL',
        message: 'new Proxy(process.env) detected — intercepts all environment variable access.',
        file: ctx.relFile
      });
    }
    // Detect new Proxy(require, handler) — intercept module loading
    if (target.type === 'Identifier' && target.name === 'require') {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'new Proxy(require) — proxy wrapping require to intercept/redirect module loading.',
        file: ctx.relFile
      });
    }
    // Detect new Proxy(obj, handler) where handler has set/get traps — data interception
    // Real-world technique: export a Proxy that intercepts all property sets/gets to exfiltrate
    // data flowing through the module. Combined with network (hasNetworkInFile) → credential theft.
    if (!target.type?.includes('MemberExpression') || target.property?.name !== 'env') {
      const handler = node.arguments[1];
      if (handler?.type === 'ObjectExpression') {
        const hasTrap = handler.properties?.some(p =>
          p.key?.type === 'Identifier' && ['set', 'get', 'apply', 'construct'].includes(p.key.name)
        );
        if (hasTrap) {
          ctx.hasProxyTrap = true;
          const hasSetTrap = handler.properties?.some(p =>
            p.key?.type === 'Identifier' && p.key.name === 'set'
          );
          if (hasSetTrap) ctx.hasProxySetTrap = true;
        }
      }
      // Also detect when handler is a variable reference that was tracked as having trap properties
      if (handler?.type === 'Identifier' && ctx.proxyHandlerVars?.has(handler.name)) {
        ctx.hasProxyTrap = true;
        ctx.hasProxySetTrap = true; // proxyHandlerVars tracks objects with any trap including set
      }
    }
  }

  // Batch 2: new Worker(code, { eval: true }) — worker_threads code execution
  if (node.callee.type === 'Identifier' && node.callee.name === 'Worker' &&
      node.arguments.length >= 2) {
    const opts = node.arguments[1];
    if (opts?.type === 'ObjectExpression') {
      const evalProp = opts.properties?.find(p =>
        p.key?.name === 'eval' && p.value?.value === true);
      if (evalProp) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'worker_thread_exec',
          severity: 'HIGH',
          message: 'new Worker() with eval:true — executes arbitrary code in worker thread, bypasses main thread detection.',
          file: ctx.relFile
        });
      }
    }
  }

  // B2: new FinalizationRegistry(callback) — deferred execution after GC
  // Malicious pattern: callback contains require('child_process') or exec/spawn
  if (node.callee.type === 'Identifier' && node.callee.name === 'FinalizationRegistry' &&
      node.arguments.length >= 1) {
    const callback = node.arguments[0];
    if (callback) {
      // Check if callback body contains dangerous patterns
      let hasDangerousBody = false;
      const cbSource = callback.start !== undefined && callback.end !== undefined
        ? ctx._sourceCode?.slice(callback.start, callback.end) : null;
      if (cbSource && /\b(child_process|exec|execSync|spawn|spawnSync)\b/.test(cbSource)) {
        hasDangerousBody = true;
      }
      // Also flag if the callback is a variable known to be dangerous
      if (callback.type === 'Identifier' && ctx.evalAliases?.has(callback.name)) {
        hasDangerousBody = true;
      }
      if (hasDangerousBody) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'finalization_registry_exec',
          severity: 'CRITICAL',
          message: 'new FinalizationRegistry() with dangerous callback — deferred code execution triggered by garbage collection, evades synchronous analysis.',
          file: ctx.relFile
        });
      } else {
        ctx.hasFinalizationRegistry = true;
      }
    }
  }
}

function handleLiteral(node, ctx) {
  if (typeof node.value === 'string') {
    // Ignore safe strings
    if (SAFE_STRINGS.some(s => node.value.includes(s))) {
      return;
    }

    for (const sensitive of SENSITIVE_STRINGS) {
      if (node.value.includes(sensitive)) {
        ctx.threats.push({
          type: 'sensitive_string',
          severity: 'HIGH',
          message: `Reference to "${sensitive}" detected.`,
          file: ctx.relFile
        });
      }
    }

    // Detect AI agent dangerous flags as string literals (MEDIUM signal only —
    // CRITICAL reserved for CallExpression context where flag is actually used in exec/spawn)
    for (const flag of AI_AGENT_DANGEROUS_FLAGS) {
      if (node.value === flag) {
        // Skip if already detected in a CallExpression context (avoid double-counting)
        const alreadyDetected = ctx.threats.some(t =>
          t.type === 'ai_agent_abuse' && t.severity === 'CRITICAL' && t.file === ctx.relFile
        );
        if (!alreadyDetected) {
          ctx.threats.push({
            type: 'ai_agent_abuse',
            severity: 'MEDIUM',
            message: `AI agent security bypass flag "${flag}" referenced in code — verify it is not used in exec/spawn invocations.`,
            file: ctx.relFile
          });
        }
      }
    }

    // Detect suspicious C2/exfiltration domains in string literals
    const lowerVal = node.value.toLowerCase();
    for (const domain of SUSPICIOUS_DOMAINS_HIGH) {
      if (lowerVal.includes(domain)) {
        ctx.threats.push({
          type: 'suspicious_domain',
          severity: 'HIGH',
          message: `Suspicious C2/exfiltration domain "${domain}" found in string literal.`,
          file: ctx.relFile
        });
        break;
      }
    }
    for (const domain of SUSPICIOUS_DOMAINS_MEDIUM) {
      if (lowerVal.includes(domain)) {
        ctx.threats.push({
          type: 'suspicious_domain',
          severity: 'MEDIUM',
          message: `Suspicious tunnel/proxy domain "${domain}" found in string literal.`,
          file: ctx.relFile
        });
        break;
      }
    }

    // Ollama LLM local: polymorphic engine indicator (PhantomRaven Wave 4)
    // Port 11434 is Ollama's default port. Legitimate packages don't call local LLMs.
    if (/(?:localhost|127\.0\.0\.1):11434/.test(node.value)) {
      ctx.threats.push({
        type: 'ollama_local_llm',
        severity: 'HIGH',
        message: `Reference to Ollama LLM API (${node.value.slice(0, 60)}) — polymorphic malware engine: uses local LLM to rewrite code and evade detection.`,
        file: ctx.relFile
      });
    }

    // Blockchain RPC endpoints — potential C2 channel (GlassWorm)
    for (const endpoint of BLOCKCHAIN_RPC_ENDPOINTS) {
      if (lowerVal.includes(endpoint)) {
        ctx.threats.push({
          type: 'blockchain_rpc_endpoint',
          severity: 'MEDIUM',
          message: `Hardcoded blockchain RPC endpoint "${endpoint}" — potential blockchain C2 channel.`,
          file: ctx.relFile
        });
        break;
      }
    }

    // Track Solana C2 method names in string literals (for compound detection)
    for (const method of SOLANA_C2_METHODS) {
      if (node.value === method || node.value.includes(method)) {
        ctx.hasSolanaC2Method = true;
        break;
      }
    }
  }

  // Track variation selector constants in numeric literals (GlassWorm decoder)
  if (typeof node.value === 'number') {
    if (VARIATION_SELECTOR_CONSTS.includes(node.value)) {
      ctx.hasVariationSelectorConst = true;
    }
  }
}

function handleAssignmentExpression(node, ctx) {
  // Variable reassignment: x += 'process' or x = x + 'process'
  if (node.left?.type === 'Identifier') {
    if (node.operator === '+=' && ctx.stringVarValues.has(node.left.name)) {
      const rightVal = extractStringValueDeep(node.right);
      if (rightVal !== null) {
        const combined = ctx.stringVarValues.get(node.left.name) + rightVal;
        ctx.stringVarValues.set(node.left.name, combined);
        if (DANGEROUS_CMD_PATTERNS.some(p => p.test(combined))) {
          ctx.dangerousCmdVars.set(node.left.name, combined);
        }
      }
    }
    if (node.operator === '=' && node.right?.type === 'BinaryExpression') {
      const resolved = resolveStringConcat(node.right);
      if (resolved) {
        ctx.stringVarValues.set(node.left.name, resolved);
        if (DANGEROUS_CMD_PATTERNS.some(p => p.test(resolved))) {
          ctx.dangerousCmdVars.set(node.left.name, resolved);
        }
      }
    }
  }

  // B6: Symbol property hiding — obj[Symbol(...)] = require('child_process')
  if (node.left?.type === 'MemberExpression' && node.left.computed &&
      node.left.property?.type === 'CallExpression' &&
      node.left.property.callee?.type === 'Identifier' && node.left.property.callee.name === 'Symbol') {
    // Check if the right side is require('child_process') or similar dangerous module
    let isDangerous = false;
    let modName = null;
    if (node.right?.type === 'CallExpression' && getCallName(node.right) === 'require' &&
        node.right.arguments?.[0]?.type === 'Literal') {
      const rawMod = node.right.arguments[0].value;
      modName = typeof rawMod === 'string' && rawMod.startsWith('node:') ? rawMod.slice(5) : rawMod;
      if (['child_process', 'fs', 'net', 'dns', 'http', 'https'].includes(modName)) {
        isDangerous = true;
      }
    }
    // Also detect: obj[Symbol('x')] = eval / Function / exec
    if (node.right?.type === 'Identifier' && ['eval', 'Function'].includes(node.right.name)) {
      isDangerous = true;
    }
    if (isDangerous) {
      ctx.threats.push({
        type: 'symbol_property_hiding',
        severity: 'HIGH',
        message: `Dangerous module/function hidden behind Symbol property — obj[Symbol(...)] = ${modName ? "require('" + modName + "')" : node.right?.name || '...'}, evades string-based property enumeration.`,
        file: ctx.relFile
      });
    }
  }

  // B5: Module.wrap = ... or require('module').wrap = ... — module wrapper override
  if (node.left?.type === 'MemberExpression' &&
      node.left.property?.type === 'Identifier' && node.left.property.name === 'wrap') {
    const obj = node.left.object;
    // Direct: Module.wrap = ... (where Module was imported via require('module'))
    const isModuleObj = (obj?.type === 'Identifier' && ctx.moduleAliases?.has(obj.name)) ||
      (obj?.type === 'Identifier' && obj.name === 'Module');
    // Inline: require('module').wrap = ...
    const isInlineRequire = obj?.type === 'CallExpression' && getCallName(obj) === 'require' &&
      obj.arguments?.[0]?.type === 'Literal' && obj.arguments[0].value === 'module';
    if (isModuleObj || isInlineRequire) {
      ctx.threats.push({
        type: 'module_wrap_override',
        severity: 'CRITICAL',
        message: 'Module.wrap overridden — module wrapper function hijacked, allows injecting code into every loaded module.',
        file: ctx.relFile
      });
    }
  }

  // Detect object property indirection: obj.exec = require('child_process').exec
  // or obj.fn = eval — stashing dangerous functions in object properties
  if (node.left?.type === 'MemberExpression' && node.right) {
    const propName = node.left.property?.type === 'Identifier' ? node.left.property.name :
                     (node.left.property?.type === 'Literal' ? String(node.left.property.value) : null);

    if (propName) {
      // Assigning require('child_process') or its methods to an object property
      if (node.right.type === 'CallExpression' && getCallName(node.right) === 'require' &&
          node.right.arguments.length > 0 && node.right.arguments[0]?.type === 'Literal') {
        const rawMod = node.right.arguments[0].value;
        // Batch 2: strip node: prefix
        const mod = typeof rawMod === 'string' && rawMod.startsWith('node:') ? rawMod.slice(5) : rawMod;
        if (mod === 'child_process' || mod === 'fs' || mod === 'net' || mod === 'dns') {
          ctx.threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: `Object property indirection: ${propName} = require('${mod}') — hiding dangerous module in object property.`,
            file: ctx.relFile
          });
        }
      }
      // Assigning require('child_process').exec to an object property
      if (node.right.type === 'MemberExpression' && node.right.object?.type === 'CallExpression' &&
          getCallName(node.right.object) === 'require' &&
          node.right.object.arguments.length > 0 && node.right.object.arguments[0]?.type === 'Literal') {
        const reqModRaw = node.right.object.arguments[0].value;
        // Batch 2: strip node: prefix
        const reqMod = typeof reqModRaw === 'string' && reqModRaw.startsWith('node:') ? reqModRaw.slice(5) : reqModRaw;
        if (reqMod === 'child_process') {
          const method = node.right.property?.type === 'Identifier' ? node.right.property.name : null;
          if (method && ['exec', 'execSync', 'spawn', 'execFile'].includes(method)) {
            ctx.threats.push({
              type: 'dangerous_exec',
              severity: 'HIGH',
              message: `Object property indirection: ${propName} = require('child_process').${method} — hiding exec in object property.`,
              file: ctx.relFile
            });
          }
        }
      }
      // Assigning eval or Function to an object property
      if (node.right.type === 'Identifier' && (node.right.name === 'eval' || node.right.name === 'Function')) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: node.right.name === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
          severity: 'HIGH',
          message: `Object property indirection: ${propName} = ${node.right.name} — stashing dangerous function in object property.`,
          file: ctx.relFile
        });
      }
    }
  }

  // B4: Prototype pollution — __proto__ assignment
  if (node.left?.type === 'MemberExpression' && !node.left.computed &&
      node.left.property?.type === 'Identifier' && node.left.property.name === '__proto__') {
    ctx.threats.push({
      type: 'prototype_pollution',
      severity: 'HIGH',
      message: `__proto__ assignment on ${node.left.object?.name || 'object'} — prototype pollution can hijack inherited properties across all objects.`,
      file: ctx.relFile
    });
  }

  if (node.left?.type === 'MemberExpression') {
    const left = node.left;

    // require.cache[...].exports = ... — module cache poisoning WRITE (not just read)
    // This is always malicious: replacing a core module's exports to intercept all usage.
    // Also detects: mod.exports.X = ... where mod is from require.cache[...]
    if (left.property?.type === 'Identifier' && left.property.name === 'exports') {
      // Direct pattern: require.cache[...].exports = ...
      const obj = left.object;
      if (obj?.type === 'MemberExpression' && obj.computed) {
        const deep = obj.object;
        if (deep?.type === 'MemberExpression' &&
            deep.object?.type === 'Identifier' && deep.object.name === 'require' &&
            deep.property?.type === 'Identifier' && deep.property.name === 'cache') {
          ctx.hasRequireCacheWrite = true;
        }
      }
    }
    // Indirect pattern: mod.exports.X = ... where mod = require.cache[...]
    if (left.object?.type === 'MemberExpression' &&
        left.object.property?.type === 'Identifier' && left.object.property.name === 'exports' &&
        left.object.object?.type === 'Identifier' &&
        ctx.requireCacheVars?.has(left.object.object.name)) {
      ctx.hasRequireCacheWrite = true;
    }

    // globalThis.fetch = ... or globalThis.XMLHttpRequest = ... (B2: include aliases)
    if (left.object?.type === 'Identifier' &&
        (left.object.name === 'globalThis' || left.object.name === 'global' ||
         left.object.name === 'window' || left.object.name === 'self' ||
         ctx.globalThisAliases.has(left.object.name)) &&
        left.property?.type === 'Identifier') {
      if (HOOKABLE_NATIVES.includes(left.property.name)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'HIGH',
          message: `${left.object.name}.${left.property.name} overridden — native API hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
    }

    // JSON.stringify = ... or JSON.parse = ... — global API hooking
    // Real-world technique: override JSON.stringify to intercept all serialization and exfiltrate data
    if (left.object?.type === 'Identifier' && left.object.name === 'JSON' &&
        left.property?.type === 'Identifier' &&
        ['stringify', 'parse'].includes(left.property.name)) {
      ctx.threats.push({
        type: 'prototype_hook',
        severity: 'HIGH',
        message: `JSON.${left.property.name} overridden — global API hooking to intercept all JSON serialization/deserialization.`,
        file: ctx.relFile
      });
    }

    // XMLHttpRequest.prototype.send = ... or Response.prototype.json = ...
    if (left.object?.type === 'MemberExpression' &&
        left.object.property?.type === 'Identifier' &&
        left.object.property.name === 'prototype' &&
        left.object.object?.type === 'Identifier') {
      if (HOOKABLE_NATIVES.includes(left.object.object.name)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'HIGH',
          message: `${left.object.object.name}.prototype.${left.property?.name || '?'} overridden — native API hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
    }

    // http.request = ... or https.get = ...
    if (left.object?.type === 'Identifier' &&
        ['http', 'https'].includes(left.object.name) &&
        left.property?.type === 'Identifier' &&
        ['request', 'get', 'createServer'].includes(left.property.name) &&
        node.right?.type === 'FunctionExpression') {
      ctx.threats.push({
        type: 'prototype_hook',
        severity: 'HIGH',
        message: `${left.object.name}.${left.property.name} overridden — Node.js network module hooking for traffic interception.`,
        file: ctx.relFile
      });
    }

    // <module>.<Class>.prototype.<method> = ...
    if (left.object?.type === 'MemberExpression' &&
        left.object.property?.type === 'Identifier' && left.object.property.name === 'prototype' &&
        left.object.object?.type === 'MemberExpression' &&
        left.object.object.object?.type === 'Identifier' &&
        left.object.object.property?.type === 'Identifier') {
      const moduleName = left.object.object.object.name;
      const className = left.object.object.property.name;
      if (NODE_HOOKABLE_MODULES.includes(moduleName) && NODE_HOOKABLE_CLASSES.includes(className)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'CRITICAL',
          message: `${moduleName}.${className}.prototype.${left.property?.name || '?'} overridden — Node.js core module prototype hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
    }
  }
}

function handleMemberExpression(node, ctx) {
  // Detect require.cache access — set flag, defer threat emission to handlePostWalk
  // FP fix: distinguish READ (hot-reload, delete, introspection) from WRITE (.exports = ...)
  if (node.object?.type === 'Identifier' && node.object.name === 'require' &&
      node.property?.type === 'Identifier' && node.property.name === 'cache') {
    ctx.hasRequireCacheRead = true;
  }

  // GlassWorm: track .codePointAt() calls (variation selector decoder pattern)
  if (node.property?.type === 'Identifier' && node.property.name === 'codePointAt') {
    ctx.hasCodePointAt = true;
  }

  // GlassWorm: track Solana C2 method calls (e.g., connection.getSignaturesForAddress)
  if (node.property?.type === 'Identifier' && SOLANA_C2_METHODS.includes(node.property.name)) {
    ctx.hasSolanaC2Method = true;
  }

  if (
    node.object?.object?.name === 'process' &&
    node.object?.property?.name === 'env'
  ) {
    // Dynamic access: process.env[variable]
    if (node.computed) {
      if (ctx.hasFromCharCode) {
        ctx.threats.push({
          type: 'env_charcode_reconstruction',
          severity: 'HIGH',
          message: 'process.env accessed with dynamically reconstructed key (String.fromCharCode obfuscation).',
          file: ctx.relFile
        });
      }
      ctx.threats.push({
        type: 'env_access',
        severity: 'MEDIUM',
        message: 'Dynamic access to process.env (variable key).',
        file: ctx.relFile
      });
      return;
    }

    const envVar = node.property?.name;
    if (envVar) {
      if (SAFE_ENV_VARS.includes(envVar)) {
        return;
      }
      const envLower = envVar.toLowerCase();
      if (SAFE_ENV_PREFIXES.some(p => envLower.startsWith(p))) {
        return;
      }
      if (isEnvSensitive(envVar)) {
        ctx.threats.push({
          type: 'env_access',
          severity: 'HIGH',
          message: `Access to sensitive variable process.env.${envVar}.`,
          file: ctx.relFile
        });
      }
      // SANDWORM_MODE R9: Count LLM API key accesses
      if (LLM_API_KEY_VARS.includes(envVar)) {
        ctx.llmApiKeyCount++;
      }
    }
  }
}

function handlePostWalk(ctx) {
  // SANDWORM_MODE: zlib inflate + base64 decode + eval/Function/Module._compile = obfuscated payload
  if (ctx.hasZlibInflate && ctx.hasBase64Decode && ctx.hasDynamicExec) {
    // FIX 4: dist/build files get LOW severity (bundlers legitimately use zlib+base64+eval)
    const isDistFile = /^(dist|build)[/\\]/i.test(ctx.relFile) || /\.bundle\.js$/i.test(ctx.relFile);
    ctx.threats.push({
      type: 'zlib_inflate_eval',
      severity: isDistFile ? 'LOW' : 'CRITICAL',
      message: 'Obfuscated payload: zlib inflate + base64 decode + dynamic execution. No legitimate package uses this pattern.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE: write + execute + delete = anti-forensics staging
  if (ctx.hasTempFileWrite && ctx.hasTempFileExec && ctx.hasFileDelete) {
    ctx.threats.push({
      type: 'write_execute_delete',
      severity: 'HIGH',
      message: 'Anti-forensics: write, execute, then delete. Typical malware staging pattern.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE R7: env harvesting = Object.entries/keys/values(process.env) + sensitive pattern in file
  if (ctx.hasEnvEnumeration && ctx.hasEnvHarvestPattern && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'env_harvesting_dynamic',
      severity: 'HIGH',
      message: 'Dynamic environment variable harvesting with sensitive pattern matching. Credential theft technique.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE R8: DNS exfiltration = dns require + base64 encode + dns call (loop implied by co-occurrence)
  if (ctx.hasDnsLoop) {
    ctx.threats.push({
      type: 'dns_chunk_exfiltration',
      severity: 'HIGH',
      message: 'DNS exfiltration: data encoded in DNS queries. Covert channel for firewall bypass.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE R9: LLM API key harvesting (3+ different providers = harvesting)
  if (ctx.llmApiKeyCount >= 3) {
    ctx.threats.push({
      type: 'llm_api_key_harvesting',
      severity: 'MEDIUM',
      message: `LLM API key harvesting: accessing ${ctx.llmApiKeyCount} AI provider keys. Monetization vector.`,
      file: ctx.relFile
    });
  }

  // JS reverse shell pattern
  if (ctx.hasJsReverseShell) {
    ctx.threats.push({
      type: 'reverse_shell',
      severity: 'CRITICAL',
      message: 'JavaScript reverse shell: net.Socket + connect() + pipe to shell process stdin/stdout.',
      file: ctx.relFile
    });
  }

  // Binary dropper: chmod executable + exec/spawn in same file = CRITICAL
  if (ctx.hasChmodExecutable) {
    const execTypes = ['dangerous_exec', 'dangerous_call_exec', 'detached_process'];
    const hasExecInFile = ctx.threats.some(t =>
      t.file === ctx.relFile && execTypes.includes(t.type)
    );
    if (hasExecInFile) {
      ctx.threats.push({
        type: 'binary_dropper',
        severity: 'CRITICAL',
        message: `${ctx.chmodMessage} + exec/spawn in same file — binary dropper pattern.`,
        file: ctx.relFile
      });
    }
  }

  // Steganographic/binary payload execution
  if (ctx.hasBinaryFileLiteral && ctx.hasEvalInFile) {
    ctx.threats.push({
      type: 'staged_binary_payload',
      severity: 'HIGH',
      message: 'Binary file reference (.png/.jpg/.wasm/etc.) + eval() in same file — possible steganographic payload execution.',
      file: ctx.relFile
    });
  }

  // Remote code loading: fetch + eval/Function in same file = multi-stage payload
  // Distinct from fetch_decrypt_exec which also requires crypto. This catches SVG/HTML payload extraction.
  if (ctx.hasRemoteFetch && ctx.hasDynamicExec && !ctx.hasCryptoDecipher) {
    ctx.threats.push({
      type: 'remote_code_load',
      severity: 'CRITICAL',
      message: 'Remote code loading: network fetch + dynamic eval/Function in same file — multi-stage payload execution.',
      file: ctx.relFile
    });
  }

  // Wave 4: Remote fetch + crypto decrypt + dynamic eval = steganographic payload chain
  if (ctx.hasRemoteFetch && ctx.hasCryptoDecipher && ctx.hasDynamicExec) {
    ctx.threats.push({
      type: 'fetch_decrypt_exec',
      severity: 'CRITICAL',
      message: 'Steganographic payload chain: remote fetch + crypto decryption + dynamic execution. No legitimate package uses this pattern.',
      file: ctx.relFile
    });
  }

  // Wave 4: Download-execute-cleanup — https download + chmod executable + execSync + unlink
  // Exclude when all URLs in the file point to safe registries (npm, GitHub, nodejs.org)
  // B4: removed fetchOnlySafeDomains guard — compound requires fetch+chmod+exec, which is never legitimate
  // C10: If file also contains hash/checksum verification, downgrade to HIGH — real droppers
  // don't verify payload integrity; legitimate installers (esbuild, sharp) do.
  if (ctx.hasRemoteFetch && ctx.hasChmodExecutable && ctx.hasExecSyncCall) {
    ctx.threats.push({
      type: 'download_exec_binary',
      severity: ctx.hasHashVerification ? 'HIGH' : 'CRITICAL',
      message: 'Download-execute pattern: remote fetch + chmod executable + execSync in same file.' +
        (ctx.hasHashVerification ? ' Hash verification detected — likely legitimate binary installer.' : ' Binary dropper camouflaged as native addon build.'),
      file: ctx.relFile
    });
  }

  // Wave 4: IDE persistence via content co-occurrence — tasks.json + runOn + writeFileSync
  if (!ctx.hasIdePersistenceWrite && ctx.hasTasksJsonInContent && ctx.hasRunOnInContent && ctx.hasWriteFileSyncInContent) {
    ctx.hasIdePersistenceWrite = true;
    ctx.threats.push({
      type: 'ide_persistence',
      severity: 'HIGH',
      message: 'IDE persistence: writes tasks.json with auto-execution trigger (runOn/folderOpen). VS Code task persistence technique.',
      file: ctx.relFile
    });
  }

  // WASM payload detection: WebAssembly.compile/instantiate + network in same file
  // C5+C6: Only emit CRITICAL wasm_host_sink if corroborating exfil signals exist
  // (env_access, sensitive_string, credential reads). WASM + fetch alone is likely
  // just WASM module loading via fetch() (standard pattern: fetch('mod.wasm').then(WebAssembly.instantiateStreaming))
  if (ctx.hasWasmLoad && ctx.hasNetworkCallInFile) {
    // C5/C6: Distinguish fetch-for-WASM-loading from independent network channels
    // https.request, http.get, dns.resolve are NEVER used for WASM loading — they indicate
    // an independent network channel (e.g., WASM host callbacks for C2 exfiltration)
    const hasExfilSignal = ctx.threats.some(t =>
      t.file === ctx.relFile && (
        t.type === 'env_access' || t.type === 'sensitive_string' ||
        t.type === 'suspicious_dataflow' || t.type === 'credential_regex_harvest'
      )
    );
    if (ctx.hasNonFetchNetworkCall || hasExfilSignal) {
      ctx.threats.push({
        type: 'wasm_host_sink',
        severity: 'CRITICAL',
        message: 'WebAssembly module with network-capable host imports and credential/env access. WASM can invoke host callbacks to exfiltrate data while hiding control flow.',
        file: ctx.relFile
      });
    } else {
      // WASM + network but no credential/env signals → standalone MEDIUM (likely fetch for WASM loading)
      ctx.threats.push({
        type: 'wasm_standalone',
        severity: 'MEDIUM',
        message: 'WebAssembly module with network calls but no credential/env access signals. Likely WASM loading via fetch(). Verify .wasm file purpose.',
        file: ctx.relFile
      });
    }
  }

  // WASM standalone: WebAssembly.compile/instantiate WITHOUT network sinks.
  // Legitimate: crypto, image processing, codecs. Still warrants investigation
  // because WASM hides control flow from static analysis.
  if (ctx.hasWasmLoad && !ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'wasm_standalone',
      severity: 'MEDIUM',
      message: 'WebAssembly module loaded without detectable network sinks. WASM hides control flow — verify .wasm file purpose.',
      file: ctx.relFile
    });
  }

  // Credential regex harvesting: credential-matching regex + network call in same file
  // Real-world pattern: Transform/stream that scans data for tokens/passwords and exfiltrates
  if (ctx.hasCredentialRegex && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'credential_regex_harvest',
      severity: 'HIGH',
      message: 'Credential regex patterns (token/password/secret/Bearer) + network call in same file — stream data credential harvesting.',
      file: ctx.relFile
    });
  }

  // Built-in method override + network: console.X = function or Object.defineProperty = function
  // combined with network calls. Monkey-patching built-in APIs for data interception.
  // CRITICAL when Object.defineProperty itself is reassigned (global hook on all property defs).
  if (ctx.hasBuiltinOverride && ctx.hasNetworkCallInFile) {
    const isGlobalHook = ctx.hasBuiltinGlobalHook;
    ctx.threats.push({
      type: 'builtin_override_exfil',
      severity: isGlobalHook ? 'CRITICAL' : 'HIGH',
      message: isGlobalHook
        ? 'Object.defineProperty reassigned + network call — global hook intercepts all property definitions for credential exfiltration.'
        : 'Built-in method override (console/Object.defineProperty) + network call — runtime API hijacking for data interception and exfiltration.',
      file: ctx.relFile
    });
  }

  // Stream credential interception: Transform/Duplex/Writable stream + credential regex + network
  // Wiretap pattern: intercepts data in transit, scans for credentials, exfiltrates matches.
  if (ctx.hasStreamInterceptor && ctx.hasCredentialRegex && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'stream_credential_intercept',
      severity: 'HIGH',
      message: 'Stream class (Transform/Duplex/Writable) with credential regex scanning + network call — data-in-transit credential wiretap.',
      file: ctx.relFile
    });
  }

  // Proxy data interception: new Proxy(obj, { set/get }) + network in same file
  // Real-world pattern: export a Proxy that exfiltrates all property assignments via network
  // CRITICAL only when credential signals co-occur (env_access, suspicious_dataflow),
  // otherwise HIGH — bare Proxy + fetch is insufficient evidence.
  if (ctx.hasProxyTrap && ctx.hasNetworkCallInFile) {
    const hasCredentialSignal = ctx.threats.some(t =>
      t.type === 'env_access' || t.type === 'suspicious_dataflow'
    );
    // CRITICAL when: credential signals co-occur, OR set trap (intercepts all property writes)
    // A set trap with network call = universal data capture + exfiltration
    const isCritical = hasCredentialSignal || ctx.hasProxySetTrap;
    ctx.threats.push({
      type: 'proxy_data_intercept',
      severity: isCritical ? 'CRITICAL' : 'HIGH',
      message: ctx.hasProxySetTrap
        ? 'Proxy set trap with network call — intercepts ALL property writes for exfiltration via Proxy handler.'
        : 'Proxy trap (set/get/apply) with network call in same file — data interception and exfiltration via Proxy handler.',
      file: ctx.relFile
    });
  }

  // Wave 4: MCP content keywords in file with writeFileSync = MCP injection signal
  if (ctx.hasMcpContentKeywords && !ctx.threats.some(t => t.type === 'mcp_config_injection')) {
    ctx.threats.push({
      type: 'mcp_config_injection',
      severity: 'CRITICAL',
      message: 'MCP config injection: code contains MCP server configuration keywords (mcpServers/mcp.json/claude_desktop_config) with filesystem writes. AI toolchain poisoning.',
      file: ctx.relFile
    });
  }

  // require.cache: distinguish WRITE (actual poisoning) from READ-only (hot-reload, introspection)
  // FP fix: READ-only emits LOW (informational), WRITE emits CRITICAL (malicious module replacement).
  if (ctx.hasRequireCacheWrite) {
    ctx.threats.push({
      type: 'require_cache_poison',
      severity: 'CRITICAL',
      message: 'require.cache[...].exports = ... — module cache write: replaces core module exports to intercept all callers.',
      file: ctx.relFile
    });
  } else if (ctx.hasRequireCacheRead) {
    ctx.threats.push({
      type: 'require_cache_poison',
      severity: 'LOW',
      message: 'require.cache accessed — module cache read (hot-reload/introspection pattern).',
      file: ctx.relFile
    });
  }

  // DPRK/Lazarus compound: detached background process + credential env access + network
  // Pattern: spawn({detached:true}) reads secrets then exfils via network.
  // This combination is never legitimate — daemons don't read API keys and send them out.
  const hasDetachedInFile = ctx.threats.some(t =>
    t.file === ctx.relFile && t.type === 'detached_process'
  );
  const hasSensitiveEnvInFile = ctx.threats.some(t =>
    t.file === ctx.relFile && t.type === 'env_access' && t.severity === 'HIGH'
  );
  if (hasDetachedInFile && hasSensitiveEnvInFile && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'detached_credential_exfil',
      severity: 'CRITICAL',
      message: 'Detached process + sensitive env access + network call — credential exfiltration via background process (DPRK/Lazarus evasion pattern).',
      file: ctx.relFile
    });
  }

  // Audit v3 bypass fix: uncaughtException + env access + network = silent exfiltration
  // Pattern: process.on('uncaughtException', handler) that reads env vars and sends to network.
  // Never legitimate — error handlers don't need to send credentials to external servers.
  if (ctx.hasUncaughtExceptionHandler && hasSensitiveEnvInFile && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'uncaught_exception_exfil',
      severity: 'CRITICAL',
      message: 'process.on("uncaughtException") + sensitive env access + network — silent credential exfiltration via error handler hijacking.',
      file: ctx.relFile
    });
  }
  // Also: uncaughtException + env enumeration (Object.entries/keys(process.env)) + network
  if (ctx.hasUncaughtExceptionHandler && ctx.hasEnvEnumeration && ctx.hasNetworkCallInFile) {
    if (!ctx.threats.some(t => t.type === 'uncaught_exception_exfil' && t.file === ctx.relFile)) {
      ctx.threats.push({
        type: 'uncaught_exception_exfil',
        severity: 'CRITICAL',
        message: 'process.on("uncaughtException") + bulk env enumeration + network — silent credential exfiltration via error handler hijacking.',
        file: ctx.relFile
      });
    }
  }

  // GlassWorm: Unicode variation selector decoder = .codePointAt + variation selector constants
  // CRITICAL if combined with eval/exec (GlassWorm always uses dynamic execution),
  // MEDIUM otherwise (.codePointAt + 0xFE00 is legitimate Unicode processing in fonts/text libs)
  if (ctx.hasCodePointAt && ctx.hasVariationSelectorConst) {
    ctx.threats.push({
      type: 'unicode_variation_decoder',
      severity: ctx.hasDynamicExec ? 'CRITICAL' : 'MEDIUM',
      message: ctx.hasDynamicExec
        ? 'Unicode variation selector decoder: .codePointAt() + 0xFE00/0xE0100 constants + dynamic execution — GlassWorm payload reconstruction from invisible characters.'
        : 'Unicode variation selector decoder: .codePointAt() + 0xFE00/0xE0100 constants — likely legitimate Unicode processing (text formatting, font rendering).',
      file: ctx.relFile
    });
  }

  // GlassWorm: Blockchain C2 resolution = Solana import + C2 method
  // CRITICAL if combined with eval/exec, HIGH otherwise
  if (ctx.hasSolanaImport && ctx.hasSolanaC2Method) {
    ctx.threats.push({
      type: 'blockchain_c2_resolution',
      severity: ctx.hasDynamicExec ? 'CRITICAL' : 'HIGH',
      message: 'Solana/Web3 import + blockchain C2 method (getSignaturesForAddress/getTransaction) — ' +
        (ctx.hasDynamicExec
          ? 'dead drop resolver with dynamic execution. GlassWorm blockchain C2 pattern confirmed.'
          : 'potential dead drop resolver. GlassWorm technique: C2 address rotated via Solana memo field.'),
      file: ctx.relFile
    });
  }

  // B2 compound: FinalizationRegistry + exec/network in same file = deferred malicious execution
  if (ctx.hasFinalizationRegistry && ctx.hasDynamicExec) {
    ctx.threats.push({
      type: 'finalization_registry_exec',
      severity: 'CRITICAL',
      message: 'FinalizationRegistry + dynamic execution in same file — deferred code execution triggered by garbage collection.',
      file: ctx.relFile
    });
  }
}

function handleWithStatement(node, ctx) {
  // with(require('child_process')) exec(cmd) — scope injection evasion
  // The with() statement makes all properties of the object available as local variables.
  // When used with require(), it allows calling exec(), spawn() etc. without explicit reference.
  if (node.object?.type === 'CallExpression' && getCallName(node.object) === 'require') {
    const arg = node.object.arguments[0];
    const rawModName = arg?.type === 'Literal' ? arg.value : null;
    // Batch 2: strip node: prefix
    const modName = typeof rawModName === 'string' && rawModName.startsWith('node:') ? rawModName.slice(5) : rawModName;
    const dangerousModules = ['child_process', 'fs', 'http', 'https', 'net', 'dns', 'worker_threads'];
    if (modName && dangerousModules.includes(modName)) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_exec',
        severity: 'CRITICAL',
        message: `with(require('${modName}')) — scope injection evasion: all module methods available as local variables.`,
        file: ctx.relFile
      });
    } else if (!modName) {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'with(require(...)) — scope injection with dynamic module. Evasion technique.',
        file: ctx.relFile
      });
    }
    return; // Already handled as direct with(require(...))
  }

  // B7: with(obj) { ... require('child_process') ... } — body contains dangerous require/exec
  // The with statement itself is rare in modern code; combined with dangerous APIs in body = evasion
  if (node.body) {
    const bodySource = node.body.start !== undefined && node.body.end !== undefined
      ? ctx._sourceCode?.slice(node.body.start, node.body.end) : null;
    if (bodySource && /\b(require\s*\(\s*['"]child_process['"]\s*\)|child_process|exec\s*\(|execSync\s*\(|spawn\s*\()/.test(bodySource)) {
      ctx.threats.push({
        type: 'with_body_dangerous',
        severity: 'HIGH',
        message: 'with() statement body contains require/exec/spawn — scope injection used to obscure dangerous API calls.',
        file: ctx.relFile
      });
    }
  }
}

module.exports = {
  handleVariableDeclarator,
  handleCallExpression,
  handleImportExpression,
  handleNewExpression,
  handleLiteral,
  handleAssignmentExpression,
  handleMemberExpression,
  handleWithStatement,
  handlePostWalk
};
