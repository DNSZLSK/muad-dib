const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { getCallName } = require('../utils.js');
const { ACORN_OPTIONS, safeParse } = require('../shared/constants.js');
const { analyzeWithDeobfuscation } = require('../shared/analyze-helper.js');

// Module classification maps for intra-file taint tracking
const MODULE_SOURCE_METHODS = {
  os: {
    homedir: 'fingerprint_read', hostname: 'fingerprint_read',
    networkInterfaces: 'fingerprint_read', userInfo: 'fingerprint_read',
    platform: 'telemetry_read', arch: 'telemetry_read'
  },
  fs: {
    readFileSync: 'credential_read', readFile: 'credential_read',
    readdirSync: 'credential_read', readdir: 'credential_read'
  },
  child_process: {
    exec: 'command_output', execSync: 'command_output',
    spawn: 'command_output', spawnSync: 'command_output'
  }
};

const MODULE_SINK_METHODS = {
  child_process: { exec: 'exec_sink', execSync: 'exec_sink', spawn: 'exec_sink' },
  http: { request: 'network_send', get: 'network_send' },
  https: { request: 'network_send', get: 'network_send' },
  net: { connect: 'network_send', createConnection: 'network_send' },
  tls: { connect: 'network_send', createConnection: 'network_send' },
  dns: { resolve: 'network_send', lookup: 'network_send', resolve4: 'network_send', resolve6: 'network_send', resolveTxt: 'network_send' },
  fs: { writeFileSync: 'file_tamper', writeFile: 'file_tamper' }
};

// All tracked module names (for filtering in buildTaintMap)
const TRACKED_MODULES = new Set([
  ...Object.keys(MODULE_SOURCE_METHODS),
  ...Object.keys(MODULE_SINK_METHODS)
]);

// Methods that execute commands — used for exec result capture detection
const EXEC_METHODS = new Set(['exec', 'execSync', 'spawn', 'spawnSync']);

/**
 * Pre-pass: builds a taint map from require() assignments.
 * Maps variable names to { source: moduleName, detail: 'module.method' }
 * Only tracks modules in MODULE_SOURCE_METHODS or MODULE_SINK_METHODS.
 */
function buildTaintMap(ast) {
  const taintMap = new Map();

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (!node.init) return;

      // Pattern: const x = require("os")
      if (node.id.type === 'Identifier' && node.init.type === 'CallExpression') {
        const callee = node.init.callee;
        if (callee.type === 'Identifier' && callee.name === 'require' && node.init.arguments.length > 0) {
          const arg = node.init.arguments[0];
          if (arg.type === 'Literal' && typeof arg.value === 'string' && TRACKED_MODULES.has(arg.value)) {
            taintMap.set(node.id.name, { source: arg.value, detail: arg.value });
          }
        }
      }

      // Pattern: const { exec, spawn } = require("child_process")
      if (node.id.type === 'ObjectPattern' && node.init.type === 'CallExpression') {
        const callee = node.init.callee;
        if (callee.type === 'Identifier' && callee.name === 'require' && node.init.arguments.length > 0) {
          const arg = node.init.arguments[0];
          if (arg.type === 'Literal' && typeof arg.value === 'string' && TRACKED_MODULES.has(arg.value)) {
            for (const prop of node.id.properties) {
              if (prop.type === 'Property' && prop.value?.type === 'Identifier') {
                const methodName = prop.key?.type === 'Identifier' ? prop.key.name : (prop.key?.value || '');
                taintMap.set(prop.value.name, { source: arg.value, detail: `${arg.value}.${methodName}` });
              }
            }
          }
        }
      }

      // Pattern: const e = process.env
      if (node.id.type === 'Identifier' && node.init.type === 'MemberExpression') {
        const obj = node.init.object;
        const prop = node.init.property;
        if (obj?.type === 'Identifier' && obj.name === 'process' &&
            prop?.type === 'Identifier' && prop.name === 'env') {
          taintMap.set(node.id.name, { source: 'process.env', detail: 'process.env' });
        }
      }

      // Pattern: const h = x.homedir where x is tainted as "os"
      if (node.id.type === 'Identifier' && node.init.type === 'MemberExpression') {
        const obj = node.init.object;
        const prop = node.init.property;
        if (obj?.type === 'Identifier' && prop?.type === 'Identifier') {
          const parentTaint = taintMap.get(obj.name);
          if (parentTaint && TRACKED_MODULES.has(parentTaint.source)) {
            taintMap.set(node.id.name, { source: parentTaint.source, detail: `${parentTaint.source}.${prop.name}` });
          }
        }
      }
    }
  });

  return taintMap;
}

async function analyzeDataFlow(targetPath, options = {}) {
  return analyzeWithDeobfuscation(targetPath, analyzeFile, {
    deobfuscate: options.deobfuscate
  });
}

function analyzeFile(content, filePath, basePath) {
  const threats = [];
  let ast;

  ast = safeParse(content, { locations: true });
  if (!ast) return threats;

  const sources = [];
  const sinks = [];

  // Pre-scan: detect raw socket module import (net/tls) for instance .connect() detection
  const hasRawSocketModule = /require\s*\(\s*['"](?:net|tls)['"]\s*\)/.test(content);

  // Track variables assigned from sensitive path expressions
  const sensitivePathVars = new Set();

  // Build taint map for aliased require tracking
  const taintMap = buildTaintMap(ast);

  // Track exec calls whose result is captured (for command_output source detection)
  const execResultNodes = new Set();

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id?.type === 'Identifier' && node.init) {
        if (containsSensitiveLiteral(node.init)) {
          sensitivePathVars.add(node.id.name);
        }
        // Propagate sensitive vars through path.join/resolve
        if (node.init?.type === 'CallExpression' && node.init.callee?.type === 'MemberExpression') {
          const obj = node.init.callee.object;
          const prop = node.init.callee.property;
          if (obj?.type === 'Identifier' && obj.name === 'path' &&
              prop?.type === 'Identifier' && (prop.name === 'join' || prop.name === 'resolve')) {
            if (node.init.arguments.some(a =>
              (a.type === 'Identifier' && sensitivePathVars.has(a.name)) ||
              (a.type === 'MemberExpression' && a.object?.type === 'Identifier' && sensitivePathVars.has(a.object.name))
            )) {
              sensitivePathVars.add(node.id.name);
            }
          }
        }
        // Track exec result capture: const output = execSync('cmd')
        if (node.init.type === 'CallExpression') {
          let execName = null;
          const initCallee = node.init.callee;
          if (initCallee?.type === 'Identifier' && EXEC_METHODS.has(initCallee.name)) {
            const taint = taintMap.get(initCallee.name);
            if (taint && taint.source === 'child_process') {
              execName = taint.detail;
            }
          } else if (initCallee?.type === 'MemberExpression' &&
                     initCallee.object?.type === 'Identifier' &&
                     initCallee.property?.type === 'Identifier' &&
                     EXEC_METHODS.has(initCallee.property.name)) {
            const taint = taintMap.get(initCallee.object.name);
            if (taint && taint.source === 'child_process') {
              execName = `child_process.${initCallee.property.name}`;
            }
          }
          if (execName) {
            execResultNodes.add(node.init);
            sources.push({
              type: 'command_output',
              name: execName,
              line: node.loc?.start?.line,
              taint_tracked: true
            });
          }
        }
      }
    },

    CallExpression(node) {
      const callName = getCallName(node);

      if (callName === 'readFileSync' || callName === 'readFile' ||
          callName === 'fs.readFileSync' || callName === 'fs.readFile') {
        const arg = node.arguments[0];
        if (arg && isCredentialPath(arg, sensitivePathVars)) {
          sources.push({
            type: 'credential_read',
            name: callName,
            line: node.loc?.start?.line
          });
        }
      }

      if (callName === 'request' || callName === 'fetch' || callName === 'post' || callName === 'get') {
        sinks.push({
          type: 'network_send',
          name: callName,
          line: node.loc?.start?.line
        });
      }

      if (callName === 'exec' || callName === 'execSync') {
        const arg = node.arguments[0];
        if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
          if (arg.value.includes('curl') || arg.value.includes('wget')) {
            sinks.push({
              type: 'exec_network',
              name: callName,
              line: node.loc?.start?.line
            });
          }
        }
      }

      // os.hostname(), os.networkInterfaces(), os.userInfo(), os.homedir() as fingerprint sources
      // os.platform(), os.arch() as telemetry sources (lower severity)
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (obj?.type === 'Identifier' && obj.name === 'os' && prop?.type === 'Identifier') {
          if (['hostname', 'networkInterfaces', 'userInfo', 'homedir'].includes(prop.name)) {
            sources.push({
              type: 'fingerprint_read',
              name: `os.${prop.name}`,
              line: node.loc?.start?.line
            });
          } else if (['platform', 'arch'].includes(prop.name)) {
            sources.push({
              type: 'telemetry_read',
              name: `os.${prop.name}`,
              line: node.loc?.start?.line
            });
          }
        }
      }

      // fs.readdirSync as credential source when reading sensitive directories
      if (node.callee.type === 'MemberExpression') {
        const prop = node.callee.property;
        if (prop?.type === 'Identifier' && (prop.name === 'readdirSync' || prop.name === 'readdir')) {
          const arg = node.arguments[0];
          if (arg && isCredentialPath(arg, sensitivePathVars)) {
            sources.push({
              type: 'credential_read',
              name: prop.name,
              line: node.loc?.start?.line
            });
          }
        }
      }

      // MemberExpression network sinks: http.request, https.get, dns.resolve, net.connect, etc.
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (obj.type === 'Identifier' && prop.type === 'Identifier') {
          // DNS resolution as exfiltration sink
          if (obj.name === 'dns' && ['resolve', 'lookup', 'resolve4', 'resolve6', 'resolveTxt'].includes(prop.name)) {
            sinks.push({ type: 'network_send', name: `dns.${prop.name}`, line: node.loc?.start?.line });
          }
          // HTTP/HTTPS request/get as network sink
          if ((obj.name === 'http' || obj.name === 'https') && ['request', 'get'].includes(prop.name)) {
            sinks.push({ type: 'network_send', name: `${obj.name}.${prop.name}`, line: node.loc?.start?.line });
          }
          // net.connect / net.createConnection / tls.connect as network sink
          if ((obj.name === 'net' || obj.name === 'tls') && ['connect', 'createConnection'].includes(prop.name)) {
            sinks.push({ type: 'network_send', name: `${obj.name}.${prop.name}`, line: node.loc?.start?.line });
          }
          // Instance socket.connect(port, host) when file imports net/tls
          if (hasRawSocketModule && prop.name === 'connect' && node.arguments.length >= 2) {
            sinks.push({ type: 'network_send', name: 'socket.connect', line: node.loc?.start?.line });
          }
        }
      }

      // Detect writeFileSync/writeFile on sensitive paths → cache poisoning / credential tampering
      if (node.callee.type === 'MemberExpression') {
        const prop = node.callee.property;
        if (prop?.type === 'Identifier' && (prop.name === 'writeFileSync' || prop.name === 'writeFile')) {
          const arg = node.arguments[0];
          if (arg && isCredentialPath(arg, sensitivePathVars)) {
            sinks.push({
              type: 'file_tamper',
              name: prop.name,
              line: node.loc?.start?.line
            });
          }
        }
      }

      // Taint resolution: aliased module calls (e.g., const myOs = require("os"); myOs.homedir())
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (obj?.type === 'Identifier' && prop?.type === 'Identifier') {
          const taint = taintMap.get(obj.name);
          // Dedup guard: skip when varName === moduleName (already handled by hard-coded checks above)
          if (taint && obj.name !== taint.source) {
            const moduleName = taint.source;
            const methodName = prop.name;
            // Check source methods (skip command_output — handled by VariableDeclarator capture)
            const sourceMethods = MODULE_SOURCE_METHODS[moduleName];
            if (sourceMethods && sourceMethods[methodName] && sourceMethods[methodName] !== 'command_output') {
              sources.push({
                type: sourceMethods[methodName],
                name: `${moduleName}.${methodName}`,
                line: node.loc?.start?.line,
                taint_tracked: true
              });
            }
            // Check sink methods
            const sinkMethods = MODULE_SINK_METHODS[moduleName];
            if (sinkMethods && sinkMethods[methodName]) {
              sinks.push({
                type: sinkMethods[methodName],
                name: `${moduleName}.${methodName}`,
                line: node.loc?.start?.line,
                taint_tracked: true
              });
            }
          }
        }
      }

      // Taint resolution: bare destructured calls (e.g., const { exec } = require("child_process"); exec("cmd"))
      if (node.callee.type === 'Identifier') {
        const taint = taintMap.get(node.callee.name);
        if (taint && taint.detail.includes('.')) {
          const [moduleName, methodName] = taint.detail.split('.');
          // Check sink methods for destructured calls
          const sinkMethods = MODULE_SINK_METHODS[moduleName];
          if (sinkMethods && sinkMethods[methodName]) {
            sinks.push({
              type: sinkMethods[methodName],
              name: `${moduleName}.${methodName}`,
              line: node.loc?.start?.line,
              taint_tracked: true
            });
          }
          // Check source methods for destructured calls (skip command_output — handled by VariableDeclarator capture)
          const sourceMethods = MODULE_SOURCE_METHODS[moduleName];
          if (sourceMethods && sourceMethods[methodName] && sourceMethods[methodName] !== 'command_output') {
            sources.push({
              type: sourceMethods[methodName],
              name: `${moduleName}.${methodName}`,
              line: node.loc?.start?.line,
              taint_tracked: true
            });
          }
        }
      }

      // Exec callback: exec('cmd', (err, stdout) => {...}) — output will be used
      if (!execResultNodes.has(node) && node.arguments.length >= 2) {
        const lastArg = node.arguments[node.arguments.length - 1];
        if (lastArg.type === 'FunctionExpression' || lastArg.type === 'ArrowFunctionExpression') {
          let isExecCb = false;
          if (node.callee?.type === 'Identifier' && EXEC_METHODS.has(node.callee.name)) {
            const taint = taintMap.get(node.callee.name);
            isExecCb = !!(taint && taint.source === 'child_process');
          } else if (node.callee?.type === 'MemberExpression' &&
                     node.callee.object?.type === 'Identifier' &&
                     node.callee.property?.type === 'Identifier' &&
                     EXEC_METHODS.has(node.callee.property.name)) {
            const taint = taintMap.get(node.callee.object.name);
            isExecCb = !!(taint && taint.source === 'child_process');
          }
          if (isExecCb) {
            sources.push({
              type: 'command_output',
              name: 'child_process.exec',
              line: node.loc?.start?.line,
              taint_tracked: true
            });
          }
        }
      }

      // Track eval calls for staged payload detection
      if (callName === 'eval') {
        sinks.push({
          type: 'eval_exec',
          name: 'eval',
          line: node.loc?.start?.line
        });
      }
    },

    MemberExpression(node) {
      // Taint resolution: aliased process.env (e.g., const env = process.env; env.NPM_TOKEN)
      if (node.object?.type === 'Identifier' && node.property) {
        const taint = taintMap.get(node.object.name);
        if (taint && taint.source === 'process.env') {
          if (node.computed) {
            sources.push({
              type: 'env_read',
              name: 'process.env[dynamic]',
              line: node.loc?.start?.line,
              taint_tracked: true
            });
          } else {
            const envVar = node.property?.name || '';
            if (isSensitiveEnv(envVar)) {
              sources.push({
                type: 'env_read',
                name: envVar,
                line: node.loc?.start?.line,
                taint_tracked: true
              });
            }
          }
        }
      }

      if (
        node.object?.object?.name === 'process' &&
        node.object?.property?.name === 'env'
      ) {
        // Dynamic bracket access: process.env[variable]
        if (node.computed) {
          sources.push({
            type: 'env_read',
            name: 'process.env[dynamic]',
            line: node.loc?.start?.line
          });
          return;
        }
        const envVar = node.property?.name || '';
        if (isSensitiveEnv(envVar)) {
          sources.push({
            type: 'env_read',
            name: envVar,
            line: node.loc?.start?.line
          });
        }
      }

      // Detect property access to secret key material
      const propName = node.property?.type === 'Identifier' ? node.property.name :
                       (node.property?.type === 'Literal' ? node.property.value : null);
      if (propName && ['secretKey', '_secretKey', 'privateKey', '_privateKey', 'mnemonic', 'seedPhrase'].includes(propName)) {
        sources.push({
          type: 'credential_read',
          name: propName,
          line: node.loc?.start?.line
        });
      }
    }
  });

  // Check if any source or sink was resolved via taint tracking
  const hasTaintTracked = sources.some(s => s.taint_tracked) || sinks.some(s => s.taint_tracked);

  // Detect staged payload: network fetch + eval in same file (no credential source needed)
  const hasNetworkSink = sinks.some(s => s.type === 'network_send' || s.type === 'exec_network');
  const hasEvalSink = sinks.some(s => s.type === 'eval_exec');
  if (hasNetworkSink && hasEvalSink) {
    threats.push({
      type: 'staged_payload',
      severity: 'CRITICAL',
      message: 'Network fetch + eval() in same file (staged payload execution).',
      file: path.relative(basePath, filePath),
      ...(hasTaintTracked && { taint_tracked: true })
    });
  }

  // Separate exfiltration sinks from file tampering sinks
  // When command output is captured, exclude exec_sink (the exec itself is the source, not an exfil sink)
  const hasCommandOutput = sources.some(s => s.type === 'command_output');
  const exfilSinks = sinks.filter(s => s.type !== 'file_tamper' && !(hasCommandOutput && s.type === 'exec_sink'));
  const fileTamperSinks = sinks.filter(s => s.type === 'file_tamper');

  if (sources.length > 0 && exfilSinks.length > 0) {
    // Determine severity by scope proximity: if source and sink are < 50 lines apart -> CRITICAL, else HIGH
    let severity = 'HIGH';
    for (const src of sources) {
      for (const sink of exfilSinks) {
        if (src.line && sink.line && Math.abs(src.line - sink.line) < 50) {
          severity = 'CRITICAL';
          break;
        }
      }
      if (severity === 'CRITICAL') break;
    }

    // Downgrade: if ALL sources are pure telemetry (os.platform, os.arch), cap at HIGH
    const allTelemetryOnly = sources.every(s => s.type === 'telemetry_read');
    if (allTelemetryOnly && severity === 'CRITICAL') severity = 'HIGH';

    const sourceDesc = hasCommandOutput ? 'command output' : 'credentials read';
    threats.push({
      type: 'suspicious_dataflow',
      severity: severity,
      message: `Suspicious flow: ${sourceDesc} (${sources.map(s => s.name).join(', ')}) + network send (${exfilSinks.map(s => s.name).join(', ')})`,
      file: path.relative(basePath, filePath),
      ...(hasTaintTracked && { taint_tracked: true })
    });
  }

  // Detect cache poisoning: credential source + write to sensitive path
  if (sources.length > 0 && fileTamperSinks.length > 0) {
    threats.push({
      type: 'credential_tampering',
      severity: 'CRITICAL',
      message: `Cache poisoning: sensitive data access (${sources.map(s => s.name).join(', ')}) + write to sensitive path (${fileTamperSinks.map(s => s.name).join(', ')})`,
      file: path.relative(basePath, filePath),
      ...(hasTaintTracked && { taint_tracked: true })
    });
  }

  return threats;
}

const SENSITIVE_PATH_PATTERNS = [
  '.npmrc', '.ssh', '.aws', '.gitconfig', '.env',
  '/etc/passwd', '/etc/shadow', '/etc/hosts',
  '.ethereum', '.electrum', '.config/solana', '.exodus',
  '.atomic', '.metamask', '.ledger-live', '.trezor',
  '.bitcoin', '.monero', '.gnupg',
  '_cacache', '.cache/yarn', '.cache/pip',
  'discord', 'leveldb'
];

function isSensitivePath(val) {
  const lower = val.toLowerCase();
  return SENSITIVE_PATH_PATTERNS.some(p => lower.includes(p));
}

/**
 * Checks if an expression tree contains any sensitive path literal.
 * Used to determine if a variable assignment should be tracked.
 */
function containsSensitiveLiteral(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return isSensitivePath(node.value);
  }
  if (node.type === 'TemplateLiteral') {
    const quasiText = (node.quasis || []).map(q => q.value.raw).join('');
    return isSensitivePath(quasiText);
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return containsSensitiveLiteral(node.left) || containsSensitiveLiteral(node.right);
  }
  if (node.type === 'CallExpression' && node.arguments) {
    return node.arguments.some(a => containsSensitiveLiteral(a));
  }
  if (node.type === 'ObjectExpression' && node.properties) {
    return node.properties.some(p => p.value && containsSensitiveLiteral(p.value));
  }
  return false;
}

function isCredentialPath(arg, sensitivePathVars) {
  if (arg.type === 'Literal' && typeof arg.value === 'string') {
    return isSensitivePath(arg.value);
  }
  if (arg.type === 'TemplateLiteral') {
    const quasiText = (arg.quasis || []).map(q => q.value.raw).join('');
    return isSensitivePath(quasiText);
  }
  // Handle string concatenation: homedir() + '/.npmrc'
  if (arg.type === 'BinaryExpression' && arg.operator === '+') {
    return isCredentialPath(arg.left, sensitivePathVars) || isCredentialPath(arg.right, sensitivePathVars);
  }
  // Handle variable references: fs.readFileSync(npmrcPath) where npmrcPath was assigned a sensitive path
  if (arg.type === 'Identifier' && sensitivePathVars && sensitivePathVars.has(arg.name)) {
    return true;
  }
  // Handle property access on tracked objects: _0x.a where _0x is tracked as sensitive
  if (arg.type === 'MemberExpression' && arg.object?.type === 'Identifier' &&
      sensitivePathVars && sensitivePathVars.has(arg.object.name)) {
    return true;
  }
  // Handle path.join(dir, '.npmrc') or path.join(sshDir, 'id_rsa') where sshDir is tracked
  if (arg.type === 'CallExpression' && arg.callee.type === 'MemberExpression') {
    const obj = arg.callee.object;
    const prop = arg.callee.property;
    if (obj.type === 'Identifier' && obj.name === 'path' &&
        prop.type === 'Identifier' && (prop.name === 'join' || prop.name === 'resolve')) {
      return arg.arguments.some(a => isCredentialPath(a, sensitivePathVars));
    }
  }
  return false;
}

// System identity env vars used for fingerprinting/exfiltration
const SYSTEM_IDENTITY_ENVS = new Set([
  'USER', 'USERNAME', 'LOGNAME', 'HOME', 'HOSTNAME',
  'USERPROFILE', 'COMPUTERNAME', 'WHOAMI'
]);

function isSensitiveEnv(name) {
  const upper = name.toUpperCase();
  if (SYSTEM_IDENTITY_ENVS.has(upper)) return true;
  const sensitive = ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH', 'NPM', 'AWS', 'AZURE', 'GCP'];
  return sensitive.some(s => upper.includes(s));
}

module.exports = { analyzeDataFlow };