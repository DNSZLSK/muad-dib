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
  'Goldox-T3chs'
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

// Strings that are NOT suspicious
const SAFE_STRINGS = [
  'api.github.com',
  'registry.npmjs.org',
  'npmjs.com'
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

  walk.simple(ast, {
    CallExpression(node) {
      const callName = getCallName(node);
      
      if (DANGEROUS_CALLS.includes(callName)) {
        threats.push({
          type: 'dangerous_call_' + callName.toLowerCase(),
          severity: 'HIGH',
          message: `Dangerous call "${callName}" detected.`,
          file: path.relative(basePath, filePath)
        });
      }
    },

    NewExpression(node) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        threats.push({
          type: 'dangerous_call_function',
          severity: 'HIGH',
          message: 'Dangerous call "new Function()" detected.',
          file: path.relative(basePath, filePath)
        });
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
      }
    },

    MemberExpression(node) {
      if (
        node.object?.object?.name === 'process' &&
        node.object?.property?.name === 'env'
      ) {
        // Dynamic access: process.env[variable] — always flag as MEDIUM
        if (node.computed) {
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