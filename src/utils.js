const fs = require('fs');
const path = require('path');

/**
 * Directories excluded from scanning.
 * Only skip dependency/VCS/cache dirs - never skip user source code.
 */
const EXCLUDED_DIRS = ['node_modules', '.git', '.muaddib-cache'];

/**
 * Extra directories to exclude (set at runtime via --exclude flag).
 * Merged into every findFiles() call on top of the caller's excludedDirs.
 */
let _extraExcludedDirs = [];

function setExtraExcludes(dirs) {
  _extraExcludedDirs = Array.isArray(dirs) ? dirs : [];
}

function getExtraExcludes() {
  return _extraExcludedDirs;
}

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
 * Generic recursive file finder with symlink protection and depth limit.
 * @param {string} dir - Starting directory
 * @param {object} [options] - Options
 * @param {string[]} [options.extensions=['.js']] - File extensions to match
 * @param {string[]} [options.excludedDirs=EXCLUDED_DIRS] - Dirs to skip
 * @param {number} [options.maxDepth=100] - Max recursion depth
 * @param {string[]} [options.results=[]] - Accumulator (internal)
 * @param {Set} [options.visitedInodes=new Set()] - Symlink loop detection (note: inode tracking
 *   is unreliable on Windows where stat.ino may be 0; maxDepth serves as fallback protection)
 * @param {number} [options.depth=0] - Current depth (internal)
 * @returns {string[]} List of matching file paths
 */
function findFiles(dir, options = {}) {
  const {
    extensions = ['.js'],
    excludedDirs = EXCLUDED_DIRS,
    maxDepth = 100,
    results = [],
    visitedInodes = new Set(),
    depth = 0
  } = options;

  if (depth > maxDepth) return results;
  if (!fs.existsSync(dir)) return results;

  // Merge runtime --exclude dirs so every scanner respects them
  const allExcludedDirs = _extraExcludedDirs.length > 0
    ? [...new Set([...excludedDirs, ..._extraExcludedDirs])]
    : excludedDirs;

  let items;
  try {
    items = fs.readdirSync(dir);
  } catch {
    return results;
  }

  for (const item of items) {
    if (allExcludedDirs.includes(item)) continue;

    const fullPath = path.join(dir, item);

    try {
      const lstat = fs.lstatSync(fullPath);

      // Symlink protection
      if (lstat.isSymbolicLink()) {
        try {
          const realPath = fs.realpathSync(fullPath);
          const realStat = fs.statSync(realPath);
          if (realStat.ino !== 0 && visitedInodes.has(realStat.ino)) continue;
          if (realStat.ino !== 0) visitedInodes.add(realStat.ino);
          if (realStat.isDirectory()) {
            findFiles(realPath, { extensions, excludedDirs, maxDepth, results, visitedInodes, depth: depth + 1 });
          } else if (extensions.some(ext => item.endsWith(ext))) {
            results.push(realPath);
          }
        } catch {
          // Broken symlink, skip
        }
        continue;
      }

      if (lstat.ino !== 0) visitedInodes.add(lstat.ino);

      if (lstat.isDirectory()) {
        findFiles(fullPath, { extensions, excludedDirs, maxDepth, results, visitedInodes, depth: depth + 1 });
      } else if (extensions.some(ext => item.endsWith(ext))) {
        results.push(fullPath);
      }
    } catch {
      // Ignore permission errors
    }
  }

  return results;
}

/**
 * Recursively searches for JavaScript files (convenience wrapper)
 * @param {string} dir - Starting directory
 * @param {string[]} [results=[]] - Accumulator array (internal use)
 * @returns {string[]} List of .js file paths
 */
function findJsFiles(dir, results = []) {
  return findFiles(dir, { extensions: ['.js'], results });
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

/**
 * Extracts the function/method name from a CallExpression AST node
 * @param {object} node - AST CallExpression node
 * @returns {string} Function name or empty string
 */
function getCallName(node) {
  if (node.callee.type === 'Identifier') {
    return node.callee.name;
  }
  if (node.callee.type === 'MemberExpression' && node.callee.property) {
    return node.callee.property.name;
  }
  return '';
}

/**
 * Minimal CLI spinner (npm/ora style, no external deps).
 * Frames rotate every 100ms via setInterval.
 * Uses ANSI escapes to clear/rewrite the current line.
 */
class Spinner {
  constructor() {
    this._frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    this._index = 0;
    this._interval = null;
    this._text = '';
  }

  start(text) {
    this._text = text;
    this._index = 0;
    if (this._interval) clearInterval(this._interval);
    this._render();
    this._interval = setInterval(() => this._render(), 100);
    return this;
  }

  update(text) {
    this._text = text;
  }

  succeed(text) {
    this._stop();
    process.stdout.write('\r\x1b[K\x1b[32m\u2713\x1b[0m ' + text + '\n');
  }

  fail(text) {
    this._stop();
    process.stdout.write('\r\x1b[K\x1b[31m\u2717\x1b[0m ' + text + '\n');
  }

  _render() {
    const frame = this._frames[this._index % this._frames.length];
    process.stdout.write('\r\x1b[K' + frame + ' ' + this._text);
    this._index++;
  }

  _stop() {
    if (this._interval) {
      clearInterval(this._interval);
      this._interval = null;
    }
  }
}

module.exports = {
  EXCLUDED_DIRS,
  DEV_PATTERNS,
  isDevFile,
  findFiles,
  findJsFiles,
  escapeHtml,
  getCallName,
  Spinner,
  setExtraExcludes,
  getExtraExcludes
};
