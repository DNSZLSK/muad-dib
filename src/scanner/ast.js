const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { isDevFile, findJsFiles, getCallName } = require('../utils.js');

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const EXCLUDED_FILES = [
  'src/scanner/ast.js',
  'src/scanner/shell.js',
  'src/scanner/package.js',
  'src/response/playbooks.js'
];

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
  'LANG', 'TERM', 'CI', 'DEBUG', 'VERBOSE', 'LOG_LEVEL'
];

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

async function analyzeAST(targetPath) {
  const threats = [];
  const files = findJsFiles(targetPath);

  for (const file of files) {
    const relativePath = path.relative(targetPath, file).replace(/\\/g, '/');
    
    if (EXCLUDED_FILES.includes(relativePath)) {
      continue;
    }
    
    // Ignore files in dev folders
    if (isDevFile(relativePath)) {
      continue;
    }
    
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) continue;
    } catch { continue; }

    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const fileThreats = analyzeFile(content, file, targetPath);
    threats.push(...fileThreats);
  }

  return threats;
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

function analyzeFile(content, filePath, basePath) {
  const threats = [];
  let ast;

  try {
    ast = acorn.parse(content, { 
      ecmaVersion: 2024,
      sourceType: 'module',
      allowHashBang: true
    });
  } catch {
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

    if (content.length > 1000 && content.split('\n').length < 10) {
      threats.push({
        type: 'possible_obfuscation',
        severity: 'MEDIUM',
        message: 'File difficult to parse, possibly obfuscated.',
        file: path.relative(basePath, filePath)
      });
    }
    return threats;
  }

  // Track variables assigned from dynamic require() calls (non-literal arg)
  const dynamicRequireVars = new Set();
  // Track variables assigned dangerous command strings (curl, wget, etc.)
  const dangerousCmdVars = new Map();
  // Track variables assigned paths containing .github/workflows
  const workflowPathVars = new Set();
  // Track variables assigned temp/executable file paths
  const execPathVars = new Map();

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

  // Pre-scan for fromCharCode pattern (env var name obfuscation)
  const hasFromCharCode = content.includes('fromCharCode');

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id?.type === 'Identifier') {
        // Track dynamic require vars
        if (node.init?.type === 'CallExpression') {
          const initCallName = getCallName(node.init);
          if (initCallName === 'require' && node.init.arguments.length > 0) {
            const arg = node.init.arguments[0];
            if (arg.type !== 'Literal') {
              dynamicRequireVars.add(node.id.name);
            }
          }
        }
        // Track variables assigned dangerous command strings
        const strVal = extractStringValue(node.init);
        if (strVal && DANGEROUS_CMD_PATTERNS.some(p => p.test(strVal))) {
          dangerousCmdVars.set(node.id.name, strVal);
        }

        // Track variables assigned temp/executable file paths
        if (strVal && /^\/tmp\/|^\/var\/tmp\/|\\temp\\/i.test(strVal)) {
          execPathVars.set(node.id.name, strVal);
        }

        // Track variables assigned from path.join containing .github/workflows
        if (node.init?.type === 'CallExpression' && node.init.callee?.type === 'MemberExpression') {
          const obj = node.init.callee.object;
          const prop = node.init.callee.property;
          if (obj?.type === 'Identifier' && obj.name === 'path' &&
              prop?.type === 'Identifier' && (prop.name === 'join' || prop.name === 'resolve')) {
            const joinArgs = node.init.arguments.map(a => extractStringValue(a) || '').join('/');
            if (/\.github[\\/\/]workflows/i.test(joinArgs) || /\.github[\\/\/]actions/i.test(joinArgs)) {
              workflowPathVars.add(node.id.name);
            }
            // Propagate: path.join(workflowPathVar, ...) inherits tracking
            else if (node.init.arguments.some(a => a.type === 'Identifier' && workflowPathVars.has(a.name))) {
              workflowPathVars.add(node.id.name);
            }
          }
        }
      }
    },

    CallExpression(node) {
      const callName = getCallName(node);

      // Detect require() with non-literal argument (obfuscation)
      if (callName === 'require' && node.arguments.length > 0) {
        const arg = node.arguments[0];
        if (arg.type === 'BinaryExpression' && arg.operator === '+') {
          threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: 'Dynamic require() with string concatenation (module name obfuscation).',
            file: path.relative(basePath, filePath)
          });
        } else if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
          threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: 'Dynamic require() with template literal (module name obfuscation).',
            file: path.relative(basePath, filePath)
          });
        } else if (arg.type === 'CallExpression') {
          const argCallName = getCallName(arg);
          // Skip safe patterns: require(path.join(...)), require(path.resolve(...))
          if (argCallName !== 'path.join' && argCallName !== 'path.resolve') {
            const hasDecode = containsDecodePattern(arg);
            threats.push({
              type: 'dynamic_require',
              severity: hasDecode ? 'CRITICAL' : 'HIGH',
              message: hasDecode
                ? 'Dynamic require() with runtime decode (base64/atob obfuscation).'
                : 'Dynamic require() with computed argument (possible decode obfuscation).',
              file: path.relative(basePath, filePath)
            });
          }
        } else if (arg.type === 'Identifier') {
          threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: 'Dynamic require() with variable argument (module name obfuscation).',
            file: path.relative(basePath, filePath)
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
        } else if (arg.type === 'Identifier' && dangerousCmdVars.has(arg.name)) {
          // Variable was assigned a dangerous command string
          cmdStr = dangerousCmdVars.get(arg.name);
        } else if (arg.type === 'Identifier' && execPathVars.has(arg.name)) {
          // Variable was assigned a temp/executable file path
          cmdStr = execPathVars.get(arg.name);
        } else if (arg.type === 'TemplateLiteral') {
          cmdStr = arg.quasis.map(q => q.value.raw).join('***');
        }

        if (cmdStr) {
          // Check for dangerous shell patterns
          if (/\|\s*(sh|bash)\b/.test(cmdStr) || /nc\s+-[elp]/.test(cmdStr) || /\/dev\/tcp\//.test(cmdStr) || /bash\s+-i/.test(cmdStr) || /\bcurl\b/.test(cmdStr) || /\bwget\b/.test(cmdStr)) {
            threats.push({
              type: 'dangerous_exec',
              severity: 'CRITICAL',
              message: `Dangerous shell command in exec(): "${cmdStr.substring(0, 80)}"`,
              file: path.relative(basePath, filePath)
            });
          }

          // Check for temp file execution (binary dropper pattern)
          if (/^\/tmp\/|^\/var\/tmp\//i.test(cmdStr)) {
            threats.push({
              type: 'dangerous_exec',
              severity: 'CRITICAL',
              message: `Execution of temp file "${cmdStr.substring(0, 80)}" — binary dropper pattern.`,
              file: path.relative(basePath, filePath)
            });
          }

          // Check for credential-stealing CLI commands
          for (const credCmd of CREDENTIAL_CLI_COMMANDS) {
            if (cmdStr.includes(credCmd)) {
              threats.push({
                type: 'credential_command_exec',
                severity: 'CRITICAL',
                message: `Credential theft via CLI tool: exec("${credCmd}") — steals auth tokens from installed tools.`,
                file: path.relative(basePath, filePath)
              });
              break;
            }
          }
        }
      }

      // Detect exec/execSync called on a dynamically-required module variable
      // Pattern: const mod = require(obfuscated); mod.exec(...) → obfuscated command execution
      // Note: getCallName returns 'exec' for both exec() and mod.exec(), so we check execName too
      if ((execName || memberExec) && node.callee.type === 'MemberExpression' && node.callee.object?.type === 'Identifier') {
        if (dynamicRequireVars.has(node.callee.object.name)) {
          const method = execName || memberExec;
          threats.push({
            type: 'dynamic_require_exec',
            severity: 'CRITICAL',
            message: `${method}() called on dynamically-required module "${node.callee.object.name}" — obfuscated command execution.`,
            file: path.relative(basePath, filePath)
          });
        }
      }

      // Detect sandbox/container evasion: fs.accessSync('/.dockerenv'), fs.existsSync('/.dockerenv'), etc.
      if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
        const fsMethod = node.callee.property.name;
        if (['accessSync', 'existsSync', 'statSync', 'lstatSync', 'access', 'stat'].includes(fsMethod)) {
          const arg = node.arguments[0];
          if (arg?.type === 'Literal' && typeof arg.value === 'string') {
            if (SANDBOX_INDICATORS.some(ind => arg.value.includes(ind))) {
              threats.push({
                type: 'sandbox_evasion',
                severity: 'HIGH',
                message: `Sandbox/container detection via ${fsMethod}("${arg.value}") — anti-analysis technique.`,
                file: path.relative(basePath, filePath)
              });
            }
          }
        }
      }

      // Detect spawn/fork with {detached: true} — background process evasion
      if ((callName === 'spawn' || callName === 'fork') && node.arguments.length >= 2) {
        const lastArg = node.arguments[node.arguments.length - 1];
        if (lastArg.type === 'ObjectExpression') {
          const hasDetached = lastArg.properties.some(p =>
            p.key?.type === 'Identifier' && p.key.name === 'detached' &&
            p.value?.type === 'Literal' && p.value.value === true
          );
          if (hasDetached) {
            threats.push({
              type: 'detached_process',
              severity: 'HIGH',
              message: `${callName}() with {detached: true} — background process survives parent exit (evasion technique).`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }

      // Detect fs.writeFileSync/writeFile to .github/workflows — workflow injection persistence
      if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
        const writeMethod = node.callee.property.name;
        if (['writeFileSync', 'writeFile'].includes(writeMethod) && node.arguments.length > 0) {
          const pathArg = node.arguments[0];
          const pathStr = extractStringValue(pathArg);
          // Also check path.join() arguments
          let joinedPath = null;
          let hasWorkflowVar = false;
          if (pathArg?.type === 'CallExpression' && pathArg.arguments) {
            joinedPath = pathArg.arguments.map(a => {
              if (a.type === 'Identifier' && workflowPathVars.has(a.name)) {
                hasWorkflowVar = true;
                return '.github/workflows';
              }
              return extractStringValue(a) || '';
            }).join('/');
          }
          // Direct Identifier reference to a tracked workflow path variable
          if (pathArg?.type === 'Identifier' && workflowPathVars.has(pathArg.name)) {
            hasWorkflowVar = true;
          }
          const checkPath = pathStr || joinedPath || '';
          if (hasWorkflowVar || /\.github[\\/]workflows/i.test(checkPath) || /\.github[\\/]actions/i.test(checkPath)) {
            threats.push({
              type: 'workflow_write',
              severity: 'CRITICAL',
              message: `${writeMethod}() writes to .github/workflows — GitHub Actions injection/persistence technique.`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }

      // Detect fs.mkdirSync creating .github/workflows — part of workflow injection
      if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
        const mkdirMethod = node.callee.property.name;
        if ((mkdirMethod === 'mkdirSync' || mkdirMethod === 'mkdir') && node.arguments.length > 0) {
          const pathArg = node.arguments[0];
          // Check if it's a tracked workflow path variable
          if (pathArg?.type === 'Identifier' && workflowPathVars.has(pathArg.name)) {
            threats.push({
              type: 'workflow_write',
              severity: 'CRITICAL',
              message: `${mkdirMethod}() creates .github/workflows directory — GitHub Actions persistence technique.`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }

      // Detect fs.readdirSync on .github/workflows — workflow enumeration for injection
      if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
        const readDirMethod = node.callee.property.name;
        if ((readDirMethod === 'readdirSync' || readDirMethod === 'readdir') && node.arguments.length > 0) {
          const pathArg = node.arguments[0];
          if (pathArg?.type === 'Identifier' && workflowPathVars.has(pathArg.name)) {
            threats.push({
              type: 'workflow_write',
              severity: 'CRITICAL',
              message: `${readDirMethod}() enumerates .github/workflows — workflow modification/injection technique.`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }

      // Detect fs.chmodSync with executable permissions — binary dropper pattern
      if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
        const chmodMethod = node.callee.property.name;
        if ((chmodMethod === 'chmodSync' || chmodMethod === 'chmod') && node.arguments.length >= 2) {
          const modeArg = node.arguments[1];
          if (modeArg?.type === 'Literal' && typeof modeArg.value === 'number') {
            // 0o755=493, 0o777=511, 0o700=448, 0o775=509
            if (modeArg.value === 493 || modeArg.value === 511 || modeArg.value === 448 || modeArg.value === 509) {
              threats.push({
                type: 'binary_dropper',
                severity: 'CRITICAL',
                message: `${chmodMethod}() with executable permissions (0o${modeArg.value.toString(8)}) — binary dropper pattern.`,
                file: path.relative(basePath, filePath)
              });
            }
          }
        }
      }

      // Detect AI agent weaponization: spawn/exec of AI agents with dangerous flags
      // s1ngularity/Nx pattern (Aug 2025): invoke local AI coding agents to steal credentials
      if ((callName === 'spawn' || callName === 'exec' || callName === 'execSync' ||
           callName === 'execFile' || callName === 'execFileSync' || memberExec) &&
          node.arguments.length > 0) {
        // Collect all string literals in arguments (including arrays)
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
        const isAIAgent = AI_AGENT_BINARIES.some(bin => cmdName === bin || cmdName.endsWith('/' + bin));

        if (hasDangerousFlag) {
          const matchedFlag = AI_AGENT_DANGEROUS_FLAGS.find(flag => allArgText.includes(flag));
          threats.push({
            type: 'ai_agent_abuse',
            severity: 'CRITICAL',
            message: `AI agent invoked with security bypass flag "${matchedFlag}"${isAIAgent ? ` (agent: ${cmdName})` : ''} — weaponized AI coding assistant (s1ngularity/Nx pattern).`,
            file: path.relative(basePath, filePath)
          });
        } else if (isAIAgent) {
          // AI agent binary called without known dangerous flag — still suspicious in a package
          threats.push({
            type: 'ai_agent_abuse',
            severity: 'HIGH',
            message: `AI coding agent "${cmdName}" invoked from package — potential AI agent weaponization.`,
            file: path.relative(basePath, filePath)
          });
        }
      }

      // Detect Object.defineProperty(process.env, ...) — env interception via property descriptors
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Object' &&
          node.callee.property?.type === 'Identifier' && node.callee.property.name === 'defineProperty' &&
          node.arguments.length >= 2) {
        const target = node.arguments[0];
        if (target.type === 'MemberExpression' &&
            target.object?.name === 'process' &&
            target.property?.name === 'env') {
          threats.push({
            type: 'env_proxy_intercept',
            severity: 'CRITICAL',
            message: 'Object.defineProperty(process.env) detected — intercepts environment variable access for credential theft.',
            file: path.relative(basePath, filePath)
          });
        }
      }

      if (callName === 'eval') {
        const isConstant = hasOnlyStringLiteralArgs(node);
        threats.push({
          type: 'dangerous_call_eval',
          severity: isConstant ? 'LOW' : 'HIGH',
          message: isConstant
            ? 'eval() with constant string literal (low risk, globalThis polyfill pattern).'
            : 'Dangerous call "eval" with dynamic expression detected.',
          file: path.relative(basePath, filePath)
        });
      } else if (callName === 'Function') {
        const isConstant = hasOnlyStringLiteralArgs(node);
        // Function() creates a new scope (unlike eval), so dynamic usage is MEDIUM not HIGH.
        // Common in template engines (lodash, handlebars) and globalThis polyfills.
        threats.push({
          type: 'dangerous_call_function',
          severity: isConstant ? 'LOW' : 'MEDIUM',
          message: isConstant
            ? 'Function() with constant string literal (low risk, globalThis polyfill pattern).'
            : 'Function() with dynamic expression (template/factory pattern).',
          file: path.relative(basePath, filePath)
        });
      }
    },

    ImportExpression(node) {
      // import() dynamic — same concern as dynamic require()
      if (node.source) {
        const src = node.source;
        if (src.type === 'Literal' && typeof src.value === 'string') {
          // Static import('fs') — flag dangerous modules
          const dangerousModules = ['child_process', 'fs', 'http', 'https', 'net', 'dns', 'tls'];
          if (dangerousModules.includes(src.value)) {
            threats.push({
              type: 'dynamic_import',
              severity: 'HIGH',
              message: `Dynamic import() of dangerous module "${src.value}".`,
              file: path.relative(basePath, filePath)
            });
          }
        } else {
          // Non-literal import source — obfuscation
          threats.push({
            type: 'dynamic_import',
            severity: 'HIGH',
            message: 'Dynamic import() with computed argument (possible obfuscation).',
            file: path.relative(basePath, filePath)
          });
        }
      }
    },

    NewExpression(node) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        const isConstant = hasOnlyStringLiteralArgs(node);
        threats.push({
          type: 'dangerous_call_function',
          severity: isConstant ? 'LOW' : 'MEDIUM',
          message: isConstant
            ? 'new Function() with constant string literal (low risk, globalThis polyfill pattern).'
            : 'new Function() with dynamic expression (template/factory pattern).',
          file: path.relative(basePath, filePath)
        });
      }

      // Detect new Proxy(process.env, handler) — env interception
      if (node.callee.type === 'Identifier' && node.callee.name === 'Proxy' && node.arguments.length >= 2) {
        const target = node.arguments[0];
        if (target.type === 'MemberExpression' &&
            target.object?.name === 'process' &&
            target.property?.name === 'env') {
          threats.push({
            type: 'env_proxy_intercept',
            severity: 'CRITICAL',
            message: 'new Proxy(process.env) detected — intercepts all environment variable access.',
            file: path.relative(basePath, filePath)
          });
        }
      }
    },

    Literal(node) {
      if (typeof node.value === 'string') {
        // Ignore safe strings
        if (SAFE_STRINGS.some(s => node.value.includes(s))) {
          return;
        }

        for (const sensitive of SENSITIVE_STRINGS) {
          if (node.value.includes(sensitive)) {
            threats.push({
              type: 'sensitive_string',
              severity: 'HIGH',
              message: `Reference to "${sensitive}" detected.`,
              file: path.relative(basePath, filePath)
            });
          }
        }

        // Detect AI agent dangerous flags as string literals anywhere in code
        for (const flag of AI_AGENT_DANGEROUS_FLAGS) {
          if (node.value === flag) {
            threats.push({
              type: 'ai_agent_abuse',
              severity: 'CRITICAL',
              message: `AI agent security bypass flag "${flag}" found — weaponized AI coding assistant (s1ngularity/Nx pattern).`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }
    },

    AssignmentExpression(node) {
      // Detect prototype hooking of native browser/network APIs
      // Pattern: globalThis.fetch = function(...) or XMLHttpRequest.prototype.send = function(...)
      if (node.left?.type === 'MemberExpression') {
        const left = node.left;

        // globalThis.fetch = ... or globalThis.XMLHttpRequest = ...
        if (left.object?.type === 'Identifier' && left.object.name === 'globalThis' &&
            left.property?.type === 'Identifier') {
          if (HOOKABLE_NATIVES.includes(left.property.name)) {
            threats.push({
              type: 'prototype_hook',
              severity: 'HIGH',
              message: `globalThis.${left.property.name} overridden — native API hooking for traffic interception.`,
              file: path.relative(basePath, filePath)
            });
          }
        }

        // XMLHttpRequest.prototype.send = ... or Response.prototype.json = ...
        if (left.object?.type === 'MemberExpression' &&
            left.object.property?.type === 'Identifier' &&
            left.object.property.name === 'prototype' &&
            left.object.object?.type === 'Identifier') {
          if (HOOKABLE_NATIVES.includes(left.object.object.name)) {
            threats.push({
              type: 'prototype_hook',
              severity: 'HIGH',
              message: `${left.object.object.name}.prototype.${left.property?.name || '?'} overridden — native API hooking for traffic interception.`,
              file: path.relative(basePath, filePath)
            });
          }
        }

        // http.request = ... or https.get = ... (Node.js module hooking)
        if (left.object?.type === 'Identifier' &&
            ['http', 'https'].includes(left.object.name) &&
            left.property?.type === 'Identifier' &&
            ['request', 'get', 'createServer'].includes(left.property.name) &&
            node.right?.type === 'FunctionExpression') {
          threats.push({
            type: 'prototype_hook',
            severity: 'HIGH',
            message: `${left.object.name}.${left.property.name} overridden — Node.js network module hooking for traffic interception.`,
            file: path.relative(basePath, filePath)
          });
        }

        // <module>.<Class>.prototype.<method> = ... (Node.js core module prototype hooking)
        // e.g. http.IncomingMessage.prototype.emit = function(...)
        if (left.object?.type === 'MemberExpression' &&
            left.object.property?.type === 'Identifier' && left.object.property.name === 'prototype' &&
            left.object.object?.type === 'MemberExpression' &&
            left.object.object.object?.type === 'Identifier' &&
            left.object.object.property?.type === 'Identifier') {
          const moduleName = left.object.object.object.name;
          const className = left.object.object.property.name;
          if (NODE_HOOKABLE_MODULES.includes(moduleName) && NODE_HOOKABLE_CLASSES.includes(className)) {
            threats.push({
              type: 'prototype_hook',
              severity: 'CRITICAL',
              message: `${moduleName}.${className}.prototype.${left.property?.name || '?'} overridden — Node.js core module prototype hooking for traffic interception.`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }
    },

    MemberExpression(node) {
      if (
        node.object?.object?.name === 'process' &&
        node.object?.property?.name === 'env'
      ) {
        // Dynamic access: process.env[variable] — always flag as MEDIUM
        if (node.computed) {
          // Escalate if env key was built via String.fromCharCode (obfuscation)
          if (hasFromCharCode) {
            threats.push({
              type: 'env_charcode_reconstruction',
              severity: 'HIGH',
              message: 'process.env accessed with dynamically reconstructed key (String.fromCharCode obfuscation).',
              file: path.relative(basePath, filePath)
            });
          }
          threats.push({
            type: 'env_access',
            severity: 'MEDIUM',
            message: 'Dynamic access to process.env (variable key).',
            file: path.relative(basePath, filePath)
          });
          return;
        }

        const envVar = node.property?.name;
        if (envVar) {
          // Skip safe/common env vars
          if (SAFE_ENV_VARS.includes(envVar)) {
            return;
          }
          // Flag only vars containing sensitive keywords
          if (ENV_SENSITIVE_KEYWORDS.some(s => envVar.toUpperCase().includes(s))) {
            threats.push({
              type: 'env_access',
              severity: 'HIGH',
              message: `Access to sensitive variable process.env.${envVar}.`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }
    }
  });

  return threats;
}

module.exports = { analyzeAST };