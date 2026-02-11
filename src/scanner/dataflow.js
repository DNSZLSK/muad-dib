const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { isDevFile, findJsFiles, getCallName } = require('../utils.js');

async function analyzeDataFlow(targetPath) {
  const threats = [];
  const files = findJsFiles(targetPath);

  for (const file of files) {
    const relativePath = path.relative(targetPath, file).replace(/\\/g, '/');

    if (isDevFile(relativePath)) {
      continue;
    }

    const content = fs.readFileSync(file, 'utf8');
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

  walk.simple(ast, {
    CallExpression(node) {
      const callName = getCallName(node);
      
      if (callName === 'readFileSync' || callName === 'readFile' ||
          callName === 'fs.readFileSync' || callName === 'fs.readFile') {
        const arg = node.arguments[0];
        if (arg && isCredentialPath(arg)) {
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

function isCredentialPath(arg) {
  if (arg.type === 'Literal' && typeof arg.value === 'string') {
    const val = arg.value.toLowerCase();
    return val.includes('.npmrc') ||
           val.includes('.ssh') ||
           val.includes('.aws') ||
           val.includes('.gitconfig') ||
           val.includes('.env');
  }
  if (arg.type === 'TemplateLiteral') {
    // Check quasis (string parts) of template literal
    const quasiText = (arg.quasis || []).map(q => q.value.raw).join('').toLowerCase();
    return quasiText.includes('.npmrc') ||
           quasiText.includes('.ssh') ||
           quasiText.includes('.aws') ||
           quasiText.includes('.gitconfig') ||
           quasiText.includes('.env');
  }
  return false;
}

function isSensitiveEnv(name) {
  const sensitive = ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH', 'NPM', 'AWS', 'AZURE', 'GCP'];
  return sensitive.some(s => name.toUpperCase().includes(s));
}

module.exports = { analyzeDataFlow };