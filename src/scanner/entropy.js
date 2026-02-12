const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');

const ENTROPY_EXCLUDED_DIRS = ['.git', '.muaddib-cache'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Minimum string length to analyze (short strings naturally have low entropy)
const MIN_STRING_LENGTH = 50;

// Thresholds
const FILE_ENTROPY_THRESHOLD = 5.5;
const STRING_ENTROPY_MEDIUM = 5.5;
const STRING_ENTROPY_HIGH = 6.5;

/**
 * Calculate Shannon entropy of a string.
 * Returns a value between 0 (completely uniform) and log2(alphabet_size).
 * For byte data, max is 8 bits.
 * @param {string} str - Input string
 * @returns {number} Entropy in bits (0-8)
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const freq = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }

  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Extract string literals from JS source code via regex.
 * Matches single-quoted, double-quoted, and backtick strings.
 * @param {string} content - JS source code
 * @returns {string[]} Array of string contents (without quotes)
 */
function extractStringLiterals(content) {
  const strings = [];
  // Match "...", '...', `...` — non-greedy, no newlines for single/double
  const regex = /(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`)/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const str = match[1] || match[2] || match[3];
    if (str) strings.push(str);
  }
  return strings;
}

/**
 * Scan JavaScript files for high-entropy content (base64, hex, encrypted payloads).
 * Follows the same pattern as detectObfuscation().
 * @param {string} targetPath - Directory to scan
 * @returns {Array} threats
 */
function scanEntropy(targetPath) {
  const threats = [];
  const files = findFiles(targetPath, { extensions: ['.js'], excludedDirs: ENTROPY_EXCLUDED_DIRS });

  for (const file of files) {
    // Size guard
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) continue;
    } catch {
      continue;
    }

    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }

    const relativePath = path.relative(targetPath, file);

    // File-level entropy check
    const fileEntropy = calculateShannonEntropy(content);
    if (fileEntropy > FILE_ENTROPY_THRESHOLD) {
      threats.push({
        type: 'high_entropy_file',
        severity: 'MEDIUM',
        message: `High entropy file (${fileEntropy.toFixed(2)} bits) — possibly obfuscated or encoded content`,
        file: relativePath
      });
    }

    // String-level entropy check
    const strings = extractStringLiterals(content);
    for (const str of strings) {
      if (str.length < MIN_STRING_LENGTH) continue;
      const strEntropy = calculateShannonEntropy(str);
      if (strEntropy > STRING_ENTROPY_MEDIUM) {
        const severity = strEntropy > STRING_ENTROPY_HIGH ? 'HIGH' : 'MEDIUM';
        threats.push({
          type: 'high_entropy_string',
          severity,
          message: `High entropy string (${strEntropy.toFixed(2)} bits, ${str.length} chars) — possible base64/hex/encrypted payload`,
          file: relativePath
        });
      }
    }
  }

  return threats;
}

module.exports = { scanEntropy, calculateShannonEntropy };
