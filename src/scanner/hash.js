const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { findFiles } = require('../utils.js');

// Hash cache: filePath -> { hash, mtime }
const hashCache = new Map();

async function scanHashes(targetPath) {
  const threats = [];
  const iocs = loadCachedIOCs();

  // Use Set for O(1) lookup if available, otherwise create a Set
  const knownHashes = iocs.hashesSet instanceof Set
    ? iocs.hashesSet
    : new Set(iocs.hashes || []);

  if (knownHashes.size === 0) {
    return threats;
  }

  const nodeModulesPath = path.join(targetPath, 'node_modules');

  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  // Use shared findFiles utility (with symlink protection and depth limit)
  const jsFiles = findFiles(nodeModulesPath, { extensions: ['.js'], excludedDirs: [], maxDepth: 50 });

  for (const file of jsFiles) {
    const hash = computeHashCached(file);

    if (hash && knownHashes.has(hash)) {
      threats.push({
        type: 'known_malicious_hash',
        severity: 'CRITICAL',
        message: `Malicious hash detected: ${hash.substring(0, 16)}...`,
        file: path.relative(targetPath, file)
      });
    }
  }

  return threats;
}

/**
 * Computes the SHA256 hash of a file with caching
 * Cache is invalidated if the file mtime changes
 * @param {string} filePath - File path
 * @returns {string|null} SHA256 hash or null on error
 */
function computeHashCached(filePath) {
  try {
    const stat = fs.statSync(filePath);
    const mtime = stat.mtimeMs;

    // Check the cache
    const cached = hashCache.get(filePath);
    if (cached && cached.mtime === mtime) {
      return cached.hash;
    }

    // Compute the hash
    const hash = computeHash(filePath);

    // Store in cache
    hashCache.set(filePath, { hash, mtime });

    return hash;
  } catch {
    return null;
  }
}

/**
 * Computes the SHA256 hash of a file
 * @param {string} filePath - File path
 * @returns {string} SHA256 hash
 */
function computeHash(filePath) {
  const content = fs.readFileSync(filePath);
  return nodeCrypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Clears the hash cache (useful for tests)
 */
function clearHashCache() {
  hashCache.clear();
}

/**
 * Returns the cache size (useful for debug/monitoring)
 * @returns {number}
 */
function getHashCacheSize() {
  return hashCache.size;
}

module.exports = {
  scanHashes,
  computeHash,
  computeHashCached,
  clearHashCache,
  getHashCacheSize
};
