const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { loadCachedIOCs } = require('../ioc/updater.js');

// Hash cache: filePath -> { hash, mtime }
const hashCache = new Map();

// Depth limit to avoid infinite recursion
const MAX_DEPTH = 50;

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

  // Set to track visited inodes (avoids symlink loops)
  const visitedInodes = new Set();

  const jsFiles = findAllJsFiles(nodeModulesPath, [], visitedInodes, 0);

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
 * Recursive search for JS files with symlink protection
 * @param {string} dir - Directory to scan
 * @param {string[]} results - Accumulator array
 * @param {Set<number>} visitedInodes - Already visited inodes
 * @param {number} depth - Current depth
 * @returns {string[]} List of .js files
 */
function findAllJsFiles(dir, results = [], visitedInodes = new Set(), depth = 0) {
  // Protection against infinite recursion
  if (depth > MAX_DEPTH) {
    return results;
  }

  if (!fs.existsSync(dir)) return results;

  try {
    const items = fs.readdirSync(dir);

    for (const item of items) {
      const fullPath = path.join(dir, item);

      try {
        // Use lstatSync to detect symlinks WITHOUT following them
        const lstat = fs.lstatSync(fullPath);

        // Check if it's a symlink
        if (lstat.isSymbolicLink()) {
          // Resolve the symlink and check the target
          try {
            const realPath = fs.realpathSync(fullPath);
            const realStat = fs.statSync(realPath);

            // Check if we already visited this inode (avoids loops)
            if (visitedInodes.has(realStat.ino)) {
              continue; // Loop detected, skip
            }

            // If it's a directory, traverse it
            if (realStat.isDirectory()) {
              visitedInodes.add(realStat.ino);
              findAllJsFiles(realPath, results, visitedInodes, depth + 1);
            } else if (item.endsWith('.js')) {
              visitedInodes.add(realStat.ino);
              results.push(realPath);
            }
          } catch {
            // Broken or inaccessible symlink, ignore
          }
          continue;
        }

        // Mark the inode as visited
        visitedInodes.add(lstat.ino);

        if (lstat.isDirectory()) {
          findAllJsFiles(fullPath, results, visitedInodes, depth + 1);
        } else if (item.endsWith('.js')) {
          results.push(fullPath);
        }
      } catch {
        // Ignore permission errors
      }
    }
  } catch {
    // Ignore directory read errors
  }

  return results;
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
