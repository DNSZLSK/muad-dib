const fs = require('fs');
const path = require('path');

/**
 * Directories excluded from scanning (tests, build, etc.)
 */
const EXCLUDED_DIRS = [
  'test', 'tests', 'node_modules', '.git', 'src', 'vscode-extension',
  'scripts', 'bin', 'tools', 'build', 'dist', 'fixtures', 'examples',
  '__tests__', '__mocks__', 'benchmark', 'benchmarks', 'docs', 'doc'
];

/**
 * Patterns to identify dev/test files
 */
const DEV_PATTERNS = [
  /^scripts\//,
  /^bin\//,
  /^tools\//,
  /^build\//,
  /^fixtures\//,
  /^examples\//,
  /^__tests__\//,
  /^__mocks__\//,
  /^benchmark/,
  /^docs?\//,
  /^compiler\//,
  /^packages\/.*\/scripts\//,
  /\.test\.js$/,
  /\.spec\.js$/,
  /test\.js$/,
  /spec\.js$/
];

/**
 * Checks if a path corresponds to a dev/test file
 * @param {string} relativePath - Relative path of the file
 * @returns {boolean}
 */
function isDevFile(relativePath) {
  return DEV_PATTERNS.some(pattern => pattern.test(relativePath));
}

/**
 * Recursively searches for JavaScript files
 * @param {string} dir - Starting directory
 * @param {string[]} [results=[]] - Accumulator array (internal use)
 * @returns {string[]} List of .js file paths
 */
function findJsFiles(dir, results = []) {
  if (!fs.existsSync(dir)) return results;

  const items = fs.readdirSync(dir);

  for (const item of items) {
    if (EXCLUDED_DIRS.includes(item)) continue;

    const fullPath = path.join(dir, item);

    try {
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        findJsFiles(fullPath, results);
      } else if (item.endsWith('.js')) {
        results.push(fullPath);
      }
    } catch {
      // Ignore permission errors
    }
  }

  return results;
}

/**
 * Escapes HTML characters to prevent XSS
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

module.exports = {
  EXCLUDED_DIRS,
  DEV_PATTERNS,
  isDevFile,
  findJsFiles,
  escapeHtml
};
