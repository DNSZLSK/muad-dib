const fs = require('fs');
const path = require('path');
const { findFiles, forEachSafeFile } = require('../utils.js');

const ENTROPY_EXCLUDED_DIRS = ['.git', '.muaddib-cache', '__compiled__', '__tests__', '__test__', 'dist', 'build'];

// File patterns to skip (compiled/minified/bundled)
const SKIP_FILE_PATTERNS = ['.min.js', '.bundle.js', '.prod.js'];

// Files containing encoding/character tables have legitimately high entropy
const ENCODING_TABLE_RE = /(?:encoding|tables|unicode|charmap|codepage)/i;

// Minimum string length to analyze (short strings naturally have low entropy)
const MIN_STRING_LENGTH = 50;

// Maximum string length to analyze — strings >1000 chars are data blobs
// (certificates, unicode tables, embedded binary), not malware payloads.
// Real malware uses 50-500 char encoded payloads; making payloads longer
// defeats the purpose of obfuscation.
const MAX_STRING_LENGTH = 1000;

// Thresholds (string-level only — file-level entropy removed, see design notes)
const STRING_ENTROPY_MEDIUM = 5.5;
const STRING_ENTROPY_HIGH = 6.5;

// Long base64 threshold (chars) — base64 payloads >200 chars outside source maps are suspicious
const LONG_BASE64_THRESHOLD = 200;

// Whitelist patterns for non-malicious high-entropy strings
const SOURCE_MAP_REGEX = /^data:application\/json;base64,/;
const SHA256_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
const MD5_HEX_REGEX = /^[0-9a-fA-F]{32}$/;
const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const JWT_REGEX = /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

// Obfuscation pattern detection
const HEX_VAR_REGEX = /_0x[a-f0-9]{4,6}/g;
const BASE64_CHARS_REGEX = /^[A-Za-z0-9+/=]+$/;

/**
 * Check if a string matches a known non-malicious pattern.
 * @param {string} str - The string to check
 * @param {string} filePath - The file path (for context-dependent checks)
 * @returns {boolean} true if the string is whitelisted
 */
function isWhitelistedString(str, filePath) {
  if (SOURCE_MAP_REGEX.test(str)) return true;
  if (SHA256_HEX_REGEX.test(str)) return true;
  if (MD5_HEX_REGEX.test(str)) return true;
  if (UUID_REGEX.test(str)) return true;

  // JWT tokens in test files
  if (JWT_REGEX.test(str)) {
    const lowerPath = filePath.toLowerCase();
    if (lowerPath.includes('test') || lowerPath.includes('spec') || lowerPath.includes('mock') || lowerPath.includes('fixture')) {
      return true;
    }
  }

  return false;
}

/**
 * Calculate Shannon entropy of a string.
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
 * @param {string} content - JS source code
 * @returns {string[]} Array of string contents (without quotes)
 */
function extractStringLiterals(content) {
  const strings = [];
  const regex = /(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`)/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const str = match[1] || match[2] || match[3];
    if (str) strings.push(str);
  }
  return strings;
}

/**
 * Check if a file should be skipped based on path patterns.
 * @param {string} filePath - Absolute file path
 * @returns {boolean} true if the file should be skipped
 */
function shouldSkipFile(filePath) {
  const basename = path.basename(filePath);
  for (const pattern of SKIP_FILE_PATTERNS) {
    if (basename.endsWith(pattern)) return true;
  }
  return false;
}

/**
 * Check if file content contains a source map reference.
 * @param {string} content - File content
 * @returns {boolean}
 */
function hasSourceMap(content) {
  return content.includes('//# sourceMappingURL=') || content.includes('//@ sourceMappingURL=');
}

/**
 * Detect JS obfuscation patterns that are signatures of real malware.
 * Returns an array of threats for patterns found in the file content.
 * @param {string} content - File content
 * @param {string} relativePath - Relative file path for threat reporting
 * @returns {Array} threats
 */
function detectObfuscationPatterns(content, relativePath) {
  const threats = [];

  // 1. Hex variable names: _0x[a-f0-9]{4,6} — classic JS obfuscator signature
  const hexVarMatches = content.match(HEX_VAR_REGEX);
  if (hexVarMatches && hexVarMatches.length >= 3) {
    const uniqueVars = new Set(hexVarMatches);
    if (uniqueVars.size >= 3) {
      threats.push({
        type: 'js_obfuscation_pattern',
        severity: 'HIGH',
        message: `JS obfuscator hex variables detected (${uniqueVars.size} unique _0x* vars) — signature of javascript-obfuscator/obfuscator.io`,
        file: relativePath
      });
    }
  }

  // 2. Encoded string arrays: arrays of 20+ string literals that look like base64/hex
  const strings = extractStringLiterals(content);
  const encodedStrings = strings.filter(s => {
    if (s.length < 8) return false;
    return BASE64_CHARS_REGEX.test(s) && calculateShannonEntropy(s) > 4.5;
  });
  if (encodedStrings.length >= 20) {
    threats.push({
      type: 'js_obfuscation_pattern',
      severity: 'HIGH',
      message: `Encoded string array detected (${encodedStrings.length} base64/hex strings) — typical of string array rotation obfuscation`,
      file: relativePath
    });
  }

  // 3. eval() or Function() called with high-entropy content
  //    Match: eval("...high entropy...") or Function("...high entropy...")
  const evalFuncRegex = /(?:eval|Function)\s*\(\s*(?:"([^"]{50,})"|'([^']{50,})'|`([^`]{50,})`)/g;
  let evalMatch;
  while ((evalMatch = evalFuncRegex.exec(content)) !== null) {
    const arg = evalMatch[1] || evalMatch[2] || evalMatch[3];
    if (arg) {
      const argEntropy = calculateShannonEntropy(arg);
      if (argEntropy > STRING_ENTROPY_MEDIUM) {
        threats.push({
          type: 'js_obfuscation_pattern',
          severity: 'HIGH',
          message: `eval/Function called with high-entropy argument (${argEntropy.toFixed(2)} bits, ${arg.length} chars) — likely executing obfuscated payload`,
          file: relativePath
        });
        break; // One finding per file is enough
      }
    }
  }

  // 4. Long base64 strings (>200 chars) outside source maps
  for (const str of strings) {
    if (str.length > LONG_BASE64_THRESHOLD && BASE64_CHARS_REGEX.test(str)) {
      // Skip source map data URLs
      if (SOURCE_MAP_REGEX.test(str)) continue;
      threats.push({
        type: 'js_obfuscation_pattern',
        severity: 'HIGH',
        message: `Long base64 payload detected (${str.length} chars) — possible encoded malicious code`,
        file: relativePath
      });
      break; // One finding per file is enough
    }
  }

  return threats;
}

/**
 * Scan JavaScript files for high-entropy strings and JS obfuscation patterns.
 * @param {string} targetPath - Directory to scan
 * @param {object} [options] - Options
 * @param {number} [options.entropyThreshold] - Custom string-level entropy threshold (default: 5.5)
 * @returns {Array} threats
 */
function scanEntropy(targetPath, options = {}) {
  const threats = [];
  const stringThreshold = options.entropyThreshold || STRING_ENTROPY_MEDIUM;
  const files = findFiles(targetPath, { extensions: ['.js', '.mjs', '.cjs'], excludedDirs: ENTROPY_EXCLUDED_DIRS });

  const safeFiles = files.filter(f => !shouldSkipFile(f));
  forEachSafeFile(safeFiles, (file, content) => {
    // Skip files containing source maps (legitimate compiled output)
    if (hasSourceMap(content)) return;

    const relativePath = path.relative(targetPath, file);

    // Obfuscation pattern detection (MUADDIB-ENTROPY-003)
    const obfuscationThreats = detectObfuscationPatterns(content, relativePath);
    threats.push(...obfuscationThreats);

    // String-level entropy check (MUADDIB-ENTROPY-001)
    const strings = extractStringLiterals(content);
    for (const str of strings) {
      if (str.length < MIN_STRING_LENGTH) continue;

      // B12: Windowed analysis for strings > MAX_STRING_LENGTH
      if (str.length > MAX_STRING_LENGTH) {
        if (SOURCE_MAP_REGEX.test(str) || SHA256_HEX_REGEX.test(str)) continue;
        const WINDOW = 500, WIN_THRESHOLD = 6.0;
        for (let i = 0; i < str.length; i += WINDOW) {
          const w = str.slice(i, i + WINDOW);
          if (w.length < 20) continue;
          if (calculateShannonEntropy(w) > WIN_THRESHOLD) {
            threats.push({
              type: 'high_entropy_string',
              severity: ENCODING_TABLE_RE.test(relativePath) ? 'LOW' : 'MEDIUM',
              message: `High entropy window in long string (${str.length} chars, offset ${i}) — possible padded payload`,
              file: relativePath
            });
            break;
          }
        }
        continue;
      }

      // Skip whitelisted patterns
      if (isWhitelistedString(str, relativePath)) continue;

      const strEntropy = calculateShannonEntropy(str);
      if (strEntropy > stringThreshold) {
        const isEncodingTable = ENCODING_TABLE_RE.test(relativePath);
        const severity = isEncodingTable ? 'LOW' : (strEntropy > STRING_ENTROPY_HIGH ? 'HIGH' : 'MEDIUM');
        threats.push({
          type: 'high_entropy_string',
          severity,
          message: `High entropy string (${strEntropy.toFixed(2)} bits, ${str.length} chars) — possible base64/hex/encrypted payload`,
          file: relativePath
        });
      }
    }

    // B11: Fragment cluster — many short high-entropy strings = payload fragmentation
    const FRAG_MIN = 8, FRAG_MAX = 49, FRAG_COUNT = 10, FRAG_ENTROPY = 5.0;
    const frags = strings.filter(s =>
      s.length >= FRAG_MIN && s.length <= FRAG_MAX &&
      !SOURCE_MAP_REGEX.test(s) && !SHA256_HEX_REGEX.test(s) && !MD5_HEX_REGEX.test(s) &&
      !UUID_REGEX.test(s) && !JWT_REGEX.test(s) &&
      calculateShannonEntropy(s) > FRAG_ENTROPY
    );
    if (frags.length >= FRAG_COUNT) {
      threats.push({
        type: 'fragmented_high_entropy_cluster',
        severity: ENCODING_TABLE_RE.test(relativePath) ? 'LOW' : 'MEDIUM',
        message: `Fragment cluster: ${frags.length} short high-entropy strings (8-49 chars) — possible payload fragmentation.`,
        file: relativePath
      });
    }
  });

  return threats;
}

module.exports = { scanEntropy, calculateShannonEntropy };
