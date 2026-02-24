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
  'DISPLAY', 'COLORTERM', 'FORCE_COLOR', 'NO_COLOR', 'TERM_PROGRAM'
];

// Env var prefixes that are safe (npm metadata, locale settings)
const SAFE_ENV_PREFIXES = ['npm_config_', 'npm_lifecycle_', 'npm_package_', 'lc_'];

// Env var keywords to detect sensitive environment access (separate from SENSITIVE_STRINGS)
const ENV_SENSITIVE_KEYWORDS = [
  'TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH'
];

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
const DANGEROUS_CMD_PATTERNS = [/\bcurl\b/, /\bwget\b/, /\bnc\s+-/, /\/dev\/tcp\//, /\bbash\s+-i/];

// Native APIs targeted for prototype hooking (chalk Sept 2025, Sygnia)
const HOOKABLE_NATIVES = [
  'fetch', 'XMLHttpRequest', 'Request', 'Response',
  'WebSocket', 'EventSource'
];

// Node.js core module classes targeted for prototype hooking
const NODE_HOOKABLE_MODULES = ['http', 'https', 'net', 'tls', 'stream'];
const NODE_HOOKABLE_CLASSES = [
  'IncomingMessage', 'ServerResponse', 'ClientRequest',
  'OutgoingMessage', 'Socket', 'Server', 'Agent'
];

// Paths indicating sandbox/container environment detection (anti-analysis)
const SANDBOX_INDICATORS = [
  '/.dockerenv',
  '/proc/1/cgroup',
  '/proc/self/cgroup'
];

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

function handleVariableDeclarator(node, ctx) {
  if (node.id?.type === 'Identifier') {
    // Track dynamic require vars
    if (node.init?.type === 'CallExpression') {
      const initCallName = getCallName(node.init);
      if (initCallName === 'require' && node.init.arguments.length > 0) {
        const arg = node.init.arguments[0];
        if (arg.type !== 'Literal') {
          ctx.dynamicRequireVars.add(node.id.name);
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

    // Track variables assigned from path.join containing .github/workflows
    if (node.init?.type === 'CallExpression' && node.init.callee?.type === 'MemberExpression') {
      const obj = node.init.callee.object;
      const prop = node.init.callee.property;
      if (obj?.type === 'Identifier' && obj.name === 'path' &&
          prop?.type === 'Identifier' && (prop.name === 'join' || prop.name === 'resolve')) {
        const joinArgs = node.init.arguments.map(a => extractStringValue(a) || '').join('/');
        if (/\.github[\\/\/]workflows/i.test(joinArgs) || /\.github[\\/\/]actions/i.test(joinArgs)) {
          ctx.workflowPathVars.add(node.id.name);
        }
        // Propagate: path.join(workflowPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.workflowPathVars.has(a.name))) {
          ctx.workflowPathVars.add(node.id.name);
        }
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
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'Dynamic require() with variable argument (module name obfuscation).',
        file: ctx.relFile
      });
    }
  }

  // Detect exec/execSync with dangerous shell commands (direct or via MemberExpression)
  const execName = callName === 'exec' || callName === 'execSync' ? callName : null;
  const memberExec = !execName && node.callee.type === 'MemberExpression' &&
    node.callee.property?.type === 'Identifier' &&
    (node.callee.property.name === 'exec' || node.callee.property.name === 'execSync')
    ? node.callee.property.name : null;
  if ((execName || memberExec) && node.arguments.length > 0) {
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
      if (/\|\s*(sh|bash)\b/.test(cmdStr) || /nc\s+-[elp]/.test(cmdStr) || /\/dev\/tcp\//.test(cmdStr) || /bash\s+-i/.test(cmdStr) || /\bcurl\b/.test(cmdStr) || /\bwget\b/.test(cmdStr)) {
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

  if (callName === 'eval') {
    ctx.hasEvalInFile = true;
    ctx.hasDynamicExec = true;
    // Detect staged eval decode
    if (node.arguments.length === 1 && hasDecodeArg(node.arguments[0])) {
      ctx.threats.push({
        type: 'staged_eval_decode',
        severity: 'CRITICAL',
        message: 'eval() with decode argument (atob/Buffer.from base64) — staged payload execution.',
        file: ctx.relFile
      });
    } else {
      const isConstant = hasOnlyStringLiteralArgs(node);
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: isConstant ? 'LOW' : 'HIGH',
        message: isConstant
          ? 'eval() with constant string literal (low risk, globalThis polyfill pattern).'
          : 'Dangerous call "eval" with dynamic expression detected.',
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
    } else {
      const isConstant = hasOnlyStringLiteralArgs(node);
      ctx.threats.push({
        type: 'dangerous_call_function',
        severity: isConstant ? 'LOW' : 'MEDIUM',
        message: isConstant
          ? 'Function() with constant string literal (low risk, globalThis polyfill pattern).'
          : 'Function() with dynamic expression (template/factory pattern).',
        file: ctx.relFile
      });
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
    // Detect computed call on globalThis/global alias with variable property
    const obj = node.callee.object;
    if (prop.type === 'Identifier' && obj?.type === 'Identifier' &&
        (ctx.globalThisAliases.has(obj.name) || obj.name === 'globalThis' || obj.name === 'global')) {
      ctx.hasEvalInFile = true;
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: 'HIGH',
        message: `Dynamic global dispatch via computed property (${obj.name}[${prop.name}]) — likely indirect eval evasion.`,
        file: ctx.relFile
      });
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
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'module_compile',
        severity: 'CRITICAL',
        message: 'module._compile() detected — executes arbitrary code from string in module context (flatmap-stream pattern).',
        file: ctx.relFile
      });
      // SANDWORM_MODE: Module._compile with non-literal argument = dynamic code execution
      if (node.arguments.length >= 1 && !hasOnlyStringLiteralArgs(node)) {
        ctx.threats.push({
          type: 'module_compile_dynamic',
          severity: 'CRITICAL',
          message: 'In-memory code execution via Module._compile(). Common malware evasion technique.',
          file: ctx.relFile
        });
      }
      // Module._compile counts as temp file exec for write-execute-delete pattern
      ctx.hasTempFileExec = ctx.hasTempFileExec || ctx.hasTmpdirInContent;
    }

    // SANDWORM_MODE: Track writeFileSync/writeFile to temp paths
    if (propName === 'writeFileSync' || propName === 'writeFile') {
      const arg = node.arguments && node.arguments[0];
      if (arg) {
        const strVal = extractStringValue(arg);
        if (strVal && (/\/dev\/shm\b/.test(strVal) || /\btmp\b/i.test(strVal) || /\btemp\b/i.test(strVal))) {
          ctx.hasTempFileWrite = true;
        }
        // Variable reference to tmpdir/temp path
        if (!strVal && (arg.type === 'Identifier' || arg.type === 'CallExpression' || arg.type === 'MemberExpression')) {
          // Dynamic path — check if file content involves tmpdir patterns
          ctx.hasTempFileWrite = ctx.hasTempFileWrite || ctx.hasTmpdirInContent;
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
    if (strVal && (/\/dev\/shm\b/.test(strVal) || /\btmp\b/i.test(strVal) || /\btemp\b/i.test(strVal))) {
      ctx.hasTempFileExec = true;
    } else if (!strVal && ctx.hasTmpdirInContent) {
      // Variable argument in a file that references tmpdir paths
      ctx.hasTempFileExec = true;
    }
  }
}

function handleImportExpression(node, ctx) {
  if (node.source) {
    const src = node.source;
    if (src.type === 'Literal' && typeof src.value === 'string') {
      const dangerousModules = ['child_process', 'fs', 'http', 'https', 'net', 'dns', 'tls'];
      if (dangerousModules.includes(src.value)) {
        ctx.threats.push({
          type: 'dynamic_import',
          severity: 'HIGH',
          message: `Dynamic import() of dangerous module "${src.value}".`,
          file: ctx.relFile
        });
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
    const isConstant = hasOnlyStringLiteralArgs(node);
    ctx.threats.push({
      type: 'dangerous_call_function',
      severity: isConstant ? 'LOW' : 'MEDIUM',
      message: isConstant
        ? 'new Function() with constant string literal (low risk, globalThis polyfill pattern).'
        : 'new Function() with dynamic expression (template/factory pattern).',
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

    // Detect AI agent dangerous flags as string literals
    for (const flag of AI_AGENT_DANGEROUS_FLAGS) {
      if (node.value === flag) {
        ctx.threats.push({
          type: 'ai_agent_abuse',
          severity: 'CRITICAL',
          message: `AI agent security bypass flag "${flag}" found — weaponized AI coding assistant (s1ngularity/Nx pattern).`,
          file: ctx.relFile
        });
      }
    }
  }
}

function handleAssignmentExpression(node, ctx) {
  if (node.left?.type === 'MemberExpression') {
    const left = node.left;

    // globalThis.fetch = ... or globalThis.XMLHttpRequest = ...
    if (left.object?.type === 'Identifier' && left.object.name === 'globalThis' &&
        left.property?.type === 'Identifier') {
      if (HOOKABLE_NATIVES.includes(left.property.name)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'HIGH',
          message: `globalThis.${left.property.name} overridden — native API hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
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
  // Detect require.cache access
  if (node.object?.type === 'Identifier' && node.object.name === 'require' &&
      node.property?.type === 'Identifier' && node.property.name === 'cache') {
    ctx.threats.push({
      type: 'require_cache_poison',
      severity: 'CRITICAL',
      message: 'require.cache accessed — module cache poisoning to hijack or replace core Node.js modules.',
      file: ctx.relFile
    });
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
      if (ENV_SENSITIVE_KEYWORDS.some(s => envVar.toUpperCase().includes(s))) {
        ctx.threats.push({
          type: 'env_access',
          severity: 'HIGH',
          message: `Access to sensitive variable process.env.${envVar}.`,
          file: ctx.relFile
        });
      }
    }
  }
}

function handlePostWalk(ctx) {
  // SANDWORM_MODE: zlib inflate + base64 decode + eval/Function/Module._compile = obfuscated payload
  if (ctx.hasZlibInflate && ctx.hasBase64Decode && ctx.hasDynamicExec) {
    ctx.threats.push({
      type: 'zlib_inflate_eval',
      severity: 'CRITICAL',
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
}

module.exports = {
  handleVariableDeclarator,
  handleCallExpression,
  handleImportExpression,
  handleNewExpression,
  handleLiteral,
  handleAssignmentExpression,
  handleMemberExpression,
  handlePostWalk
};
