const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { loadCachedIOCs } = require('../ioc/updater.js');

async function scanHashes(targetPath) {
  const threats = [];
  const iocs = loadCachedIOCs();
  const knownHashes = iocs.hashes || [];

  if (knownHashes.length === 0) {
    return threats;
  }

  const nodeModulesPath = path.join(targetPath, 'node_modules');
  
  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  const jsFiles = findAllJsFiles(nodeModulesPath);

  for (const file of jsFiles) {
    const hash = computeHash(file);
    
    if (knownHashes.includes(hash)) {
      threats.push({
        type: 'known_malicious_hash',
        severity: 'CRITICAL',
        message: `Hash malveillant detecte: ${hash.substring(0, 16)}...`,
        file: path.relative(targetPath, file)
      });
    }
  }

  return threats;
}

function computeHash(filePath) {
  const content = fs.readFileSync(filePath);
  return nodeCrypto.createHash('sha256').update(content).digest('hex');
}

function findAllJsFiles(dir, results = []) {
  if (!fs.existsSync(dir)) return results;

  const items = fs.readdirSync(dir);

  for (const item of items) {
    const fullPath = path.join(dir, item);
    
    try {
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        findAllJsFiles(fullPath, results);
      } else if (item.endsWith('.js')) {
        results.push(fullPath);
      }
    } catch {
      // Ignore les erreurs de permission
    }
  }

  return results;
}

module.exports = { scanHashes, computeHash };