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
 * Generic recursive file finder with symlink protection and depth limit.
 * @param {string} dir - Starting directory
 * @param {object} [options] - Options
 * @param {string[]} [options.extensions=['.js']] - File extensions to match
 * @param {string[]} [options.excludedDirs=EXCLUDED_DIRS] - Dirs to skip
 * @param {number} [options.maxDepth=100] - Max recursion depth
 * @param {string[]} [options.results=[]] - Accumulator (internal)
 * @param {Set} [options.visitedInodes=new Set()] - Symlink loop detection
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

  let items;
  try {
    items = fs.readdirSync(dir);
  } catch {
    return results;
  }

  for (const item of items) {
    if (excludedDirs.includes(item)) continue;

    const fullPath = path.join(dir, item);

    try {
      const lstat = fs.lstatSync(fullPath);

      // Symlink protection
      if (lstat.isSymbolicLink()) {
        try {
          const realPath = fs.realpathSync(fullPath);
          const realStat = fs.statSync(realPath);
          if (visitedInodes.has(realStat.ino)) continue;
          visitedInodes.add(realStat.ino);
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

      visitedInodes.add(lstat.ino);

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

module.exports = {
  EXCLUDED_DIRS,
  DEV_PATTERNS,
  isDevFile,
  findFiles,
  findJsFiles,
  escapeHtml,
  getCallName
};
