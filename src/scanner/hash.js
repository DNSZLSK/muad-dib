/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { findFiles } = require('../utils.js');
const { getMaxFileSize } = require('../shared/constants.js');

// Hash cache: filePath -> { hash, mtime }
const hashCache = new Map();
const MAX_CACHE_SIZE = 10000;

// Extensions a published payload actually ships as. Worm builds copy the same
// file verbatim into every package they infect (CHAINDROP Math_Symbol.js,
// tensorlake lib/setup.mjs), which is exactly where an exact hash is decisive.
// .py/.pth cover import and interpreter start-up hooks (LiteLLM 1.107.0
// cook.pth), .node covers prebuilt native addons, .sh lifecycle shell droppers,
// .dat/.bin staged second-stage blobs (keypairs.dat, identical across 9+ packages).
const HASH_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.py', '.pth', '.sh', '.node', '.dat', '.bin'];

// Unlike the heuristic scanners, nothing is excluded for false-positive reasons:
// an exact SHA-256 match on a known payload cannot be a coincidence. The
// package's own files, dist/ build/ out/ (where @subql/common@5.8.3 hid its
// loader) and node_modules/ (transitive dependencies) are all hashed; only the
// VCS directory and our own cache are skipped.
const HASH_EXCLUDED_DIRS = ['.git', '.muaddib-cache'];

async function scanHashes(targetPath) {
  const threats = [];
  hashCache.clear(); // Clear stale cache between scans
  const iocs = loadCachedIOCs();

  // Use Set for O(1) lookup if available, otherwise create a Set
  const knownHashes = iocs.hashesSet instanceof Set
    ? iocs.hashesSet
    : new Set(iocs.hashes || []);

  if (knownHashes.size === 0 || !fs.existsSync(targetPath)) {
    return threats;
  }

  // Shared findFiles: symlink protection, depth limit, and a file-count cap that
  // keeps the shallowest files first (entry points over deep dependency trees).
  const files = findFiles(targetPath, { extensions: HASH_EXTENSIONS, excludedDirs: HASH_EXCLUDED_DIRS, maxDepth: 100 });

  for (const file of files) {
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
    if (stat.size > getMaxFileSize()) return null;
    const mtime = stat.mtimeMs;

    // Check the cache
    const cached = hashCache.get(filePath);
    if (cached && cached.mtime === mtime) {
      return cached.hash;
    }

    // Compute the hash
    const hash = computeHash(filePath);

    // FIFO eviction if cache is full
    if (hashCache.size >= MAX_CACHE_SIZE) {
      const firstKey = hashCache.keys().next().value;
      hashCache.delete(firstKey);
    }

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
