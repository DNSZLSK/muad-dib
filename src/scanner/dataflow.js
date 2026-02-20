const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { isDevFile, findJsFiles, getCallName } = require('../utils.js');

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

async function analyzeDataFlow(targetPath) {
  const threats = [];
  const files = findJsFiles(targetPath);

  for (const file of files) {
    const relativePath = path.relative(targetPath, file).replace(/\\/g, '/');

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

    // Respect // muaddib-ignore directive in first 5 lines (like eslint-disable)
    const headerLines = content.slice(0, 1024).split('\n').slice(0, 5);
    if (headerLines.some(line => line.includes('muaddib-ignore'))) {
      continue;
    }

    const fileThreats = analyzeFile(content, file, targetPath);
    threats.push(...fileThreats);
  }

  return threats;
}

function analyzeFile(content, filePath, basePath) {
  const threats = [];
  let ast;

  try {
    ast = acorn.parse(content, {
      ecmaVersion: 2024,
      sourceType: 'module',
      allowHashBang: true,
      locations: true
    });
  } catch {
    return threats;
  }

  const sources = [];
  const sinks = [];

  // Track variables assigned from sensitive path expressions
  const sensitivePathVars = new Set();

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id?.type === 'Identifier' && node.init) {
        if (containsSensitiveLiteral(node.init)) {
          sensitivePathVars.add(node.id.name);
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

      // os.hostname(), os.networkInterfaces(), os.userInfo() as fingerprint sources
      if (node.callee.type === 'MemberExpression') {
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (obj?.type === 'Identifier' && obj.name === 'os' && prop?.type === 'Identifier') {
          if (['hostname', 'networkInterfaces', 'userInfo', 'cpus', 'totalmem', 'platform', 'arch', 'homedir'].includes(prop.name)) {
            sources.push({
              type: 'fingerprint_read',
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
          if (obj.name === 'dns' && ['resolve', 'lookup', 'resolve4', 'resolve6'].includes(prop.name)) {
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
      if (
        node.object?.object?.name === 'process' &&
        node.object?.property?.name === 'env'
      ) {
        const envVar = node.property?.name || '';
        if (isSensitiveEnv(envVar)) {
          sources.push({
            type: 'env_read',
            name: envVar,
            line: node.loc?.start?.line
          });
        }
      }
    }
  });

  // Detect staged payload: network fetch + eval in same file (no credential source needed)
  const hasNetworkSink = sinks.some(s => s.type === 'network_send' || s.type === 'exec_network');
  const hasEvalSink = sinks.some(s => s.type === 'eval_exec');
  if (hasNetworkSink && hasEvalSink) {
    threats.push({
      type: 'staged_payload',
      severity: 'CRITICAL',
      message: 'Network fetch + eval() in same file (staged payload execution).',
      file: path.relative(basePath, filePath)
    });
  }

  if (sources.length > 0 && sinks.length > 0) {
    // Determine severity by scope proximity: if source and sink are < 50 lines apart -> CRITICAL, else HIGH
    let severity = 'HIGH';
    for (const src of sources) {
      for (const sink of sinks) {
        if (src.line && sink.line && Math.abs(src.line - sink.line) < 50) {
          severity = 'CRITICAL';
          break;
        }
      }
      if (severity === 'CRITICAL') break;
    }

    threats.push({
      type: 'suspicious_dataflow',
      severity: severity,
      message: `Suspicious flow: credentials read (${sources.map(s => s.name).join(', ')}) + network send (${sinks.map(s => s.name).join(', ')})`,
      file: path.relative(basePath, filePath)
    });
  }

  return threats;
}

const SENSITIVE_PATH_PATTERNS = [
  '.npmrc', '.ssh', '.aws', '.gitconfig', '.env',
  '/etc/passwd', '/etc/shadow', '/etc/hosts',
  '.ethereum', '.electrum', '.config/solana', '.exodus',
  '.atomic', '.metamask', '.ledger-live', '.trezor',
  '.bitcoin', '.monero', '.gnupg'
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

function isSensitiveEnv(name) {
  const sensitive = ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH', 'NPM', 'AWS', 'AZURE', 'GCP'];
  return sensitive.some(s => name.toUpperCase().includes(s));
}

module.exports = { analyzeDataFlow };