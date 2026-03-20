const fs = require('fs');
const path = require('path');
const { MAX_FILE_SIZE } = require('./shared/constants.js');

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
let _scanRoot = '';

/**
 * Memoization cache for findFiles(). Key = dir|extensions|excludedDirs.
 * Cleared between scans via clearFileListCache().
 */
const _fileListCache = new Map();

function setExtraExcludes(dirs, scanRoot) {
  _extraExcludedDirs = Array.isArray(dirs) ? dirs : [];
  _scanRoot = scanRoot || '';
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
    visitedPaths = new Set(),
    depth = 0
  } = options;

  // Top-level memoization: identical (dir, extensions, excludedDirs) → cached result
  if (depth === 0) {
    const cacheKey = dir + '|' + extensions.slice().sort().join(',') + '|' +
      [...excludedDirs, ..._extraExcludedDirs].sort().join(',');
    const cached = _fileListCache.get(cacheKey);
    if (cached) return [...cached]; // return copy to prevent mutation
    const result = _findFilesImpl(dir, { extensions, excludedDirs, maxDepth, results, visitedInodes, visitedPaths, depth });
    _fileListCache.set(cacheKey, [...result]);
    return result;
  }

  return _findFilesImpl(dir, { extensions, excludedDirs, maxDepth, results, visitedInodes, visitedPaths, depth });
}

function _findFilesImpl(dir, { extensions, excludedDirs, maxDepth, results, visitedInodes, visitedPaths, depth }) {
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
    const fullPath = path.join(dir, item);

    // Check both bare name ("tests") and relative path ("src/scanner")
    if (allExcludedDirs.includes(item)) continue;
    if (_extraExcludedDirs.length > 0 && _scanRoot) {
      const rel = path.relative(_scanRoot, fullPath).replace(/\\/g, '/');
      if (_extraExcludedDirs.some(ex => rel === ex || rel.startsWith(ex + '/'))) continue;
    }

    try {
      const lstat = fs.lstatSync(fullPath);

      // Symlink protection
      if (lstat.isSymbolicLink()) {
        try {
          const realPath = fs.realpathSync(fullPath);
          const realStat = fs.statSync(realPath);
          if (realStat.ino !== 0) {
            if (visitedInodes.has(realStat.ino)) continue;
            visitedInodes.add(realStat.ino);
          } else {
            // Windows ino=0 fallback: use resolved path for cycle detection
            if (visitedPaths.has(realPath)) continue;
            visitedPaths.add(realPath);
          }
          if (realStat.isDirectory()) {
            _findFilesImpl(realPath, { extensions, excludedDirs, maxDepth, results, visitedInodes, visitedPaths, depth: depth + 1 });
          } else if (extensions.some(ext => item.endsWith(ext))) {
            results.push(realPath);
          }
        } catch {
          // Broken symlink, skip
        }
        continue;
      }

      if (lstat.ino !== 0) {
        visitedInodes.add(lstat.ino);
      } else {
        // Windows ino=0 fallback: use resolved path for cycle detection
        const resolvedPath = path.resolve(fullPath);
        if (lstat.isDirectory()) {
          if (visitedPaths.has(resolvedPath)) continue;
          visitedPaths.add(resolvedPath);
        }
      }

      if (lstat.isDirectory()) {
        _findFilesImpl(fullPath, { extensions, excludedDirs, maxDepth, results, visitedInodes, visitedPaths, depth: depth + 1 });
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
  // .d.ts included: legitimate .d.ts files never contain require/exec/network calls,
  // so any executable code in .d.ts is a high-confidence malicious payload hiding technique.
  return findFiles(dir, { extensions: ['.js', '.mjs', '.cjs', '.d.ts'], results });
}

function clearFileListCache() {
  _fileListCache.clear();
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
    // Batch 2: handle bracket notation cp['exec']('cmd') — computed property with string literal
    if (node.callee.computed && node.callee.property.type === 'Literal'
        && typeof node.callee.property.value === 'string') {
      return node.callee.property.value;
    }
    return node.callee.property.name || '';
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

/**
 * Iterates files with size guard and error handling.
 * Calls callback(file, content) for each readable file under MAX_FILE_SIZE.
 */
function forEachSafeFile(files, callback) {
  for (const file of files) {
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) continue;
    } catch { continue; }
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch { continue; }
    callback(file, content);
  }
}

/**
 * Lists installed packages in node_modules (handles scoped packages).
 * @param {string} targetPath - Root of the project
 * @returns {string[]} Package names (e.g. ['express', '@babel/core'])
 */
function listInstalledPackages(targetPath) {
  const nm = path.join(targetPath, 'node_modules');
  if (!fs.existsSync(nm)) return [];
  const names = [];
  try {
    for (const item of fs.readdirSync(nm)) {
      if (item.startsWith('.')) continue;
      const itemPath = path.join(nm, item);
      try {
        const stat = fs.lstatSync(itemPath);
        if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
        if (item.startsWith('@')) {
          for (const si of fs.readdirSync(itemPath)) {
            const ss = fs.lstatSync(path.join(itemPath, si));
            if (!ss.isSymbolicLink() && ss.isDirectory()) names.push(`${item}/${si}`);
          }
        } else {
          names.push(item);
        }
      } catch { /* skip unreadable */ }
    }
  } catch { /* no node_modules readable */ }
  return names;
}

/**
 * Logs to stderr when MUADDIB_DEBUG is set. No-op otherwise.
 */
function debugLog(...args) {
  if (process.env.MUADDIB_DEBUG) console.error('[DEBUG]', ...args);
}

module.exports = {
  EXCLUDED_DIRS,
  DEV_PATTERNS,
  isDevFile,
  findFiles,
  findJsFiles,
  clearFileListCache,
  escapeHtml,
  getCallName,
  Spinner,
  setExtraExcludes,
  getExtraExcludes,
  forEachSafeFile,
  listInstalledPackages,
  debugLog
};
