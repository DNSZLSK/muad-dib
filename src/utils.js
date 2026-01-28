const fs = require('fs');
const path = require('path');

/**
 * Repertoires exclus du scan (tests, build, etc.)
 */
const EXCLUDED_DIRS = [
  'test', 'tests', 'node_modules', '.git', 'src', 'vscode-extension',
  'scripts', 'bin', 'tools', 'build', 'dist', 'fixtures', 'examples',
  '__tests__', '__mocks__', 'benchmark', 'benchmarks', 'docs', 'doc'
];

/**
 * Patterns pour identifier les fichiers de dev/test
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
 * Verifie si un chemin correspond a un fichier de dev/test
 * @param {string} relativePath - Chemin relatif du fichier
 * @returns {boolean}
 */
function isDevFile(relativePath) {
  return DEV_PATTERNS.some(pattern => pattern.test(relativePath));
}

/**
 * Recherche recursive des fichiers JavaScript
 * @param {string} dir - Repertoire de depart
 * @param {string[]} [results=[]] - Tableau accumulateur (usage interne)
 * @returns {string[]} Liste des chemins de fichiers .js
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
      // Ignore les erreurs de permission
    }
  }

  return results;
}

/**
 * Echappe les caracteres HTML pour prevenir les XSS
 * @param {string} str - Chaine a echapper
 * @returns {string} Chaine echappee
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
