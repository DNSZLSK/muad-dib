const path = require('path');
const { isDevFile, findJsFiles, forEachSafeFile } = require('../utils.js');

/**
 * Shared scanner wrapper: iterates JS files, runs analyzeFileFn on original + deobfuscated code,
 * deduplicates findings by type::message key.
 * @param {string} targetPath - Root directory to scan
 * @param {Function} analyzeFileFn - (content, filePath, basePath) => threats[]
 * @param {object} [options]
 * @param {Function} [options.deobfuscate] - Deobfuscation function
 * @param {string[]} [options.excludedFiles] - Relative paths to skip
 * @param {boolean} [options.skipDevFiles=true] - Whether to skip dev/test files
 * @returns {Array} Combined threats
 */
function analyzeWithDeobfuscation(targetPath, analyzeFileFn, options = {}) {
  const threats = [];
  const files = findJsFiles(targetPath);

  forEachSafeFile(files, (file, content) => {
    const relativePath = path.relative(targetPath, file).replace(/\\/g, '/');

    if (options.excludedFiles && options.excludedFiles.includes(relativePath)) return;
    if (options.skipDevFiles !== false && isDevFile(relativePath)) return;

    // .d.ts files: strip TypeScript declaration syntax before JS parsing.
    // Legitimate .d.ts files contain only type declarations (no executable code).
    // Any require/exec/network calls in a .d.ts are high-confidence malicious payload hiding.
    let effectiveContent = content;
    if (file.endsWith('.d.ts')) {
      effectiveContent = content.split('\n').map(line => {
        const trimmed = line.trim();
        // Strip lines that are pure TypeScript declarations (Acorn can't parse these)
        if (/^export\s+declare\s+/.test(trimmed)) return '// [ts-stripped]';
        if (/^declare\s+(function|class|const|let|var|type|interface|enum|namespace|module|global)\s/.test(trimmed)) return '// [ts-stripped]';
        if (/^(export\s+)?(type|interface)\s/.test(trimmed)) return '// [ts-stripped]';
        return line;
      }).join('\n');
    }

    // Analyze original code first (preserves obfuscation-detection rules)
    const fileThreats = analyzeFileFn(effectiveContent, file, targetPath);
    threats.push(...fileThreats);

    // Also analyze deobfuscated code for additional findings hidden by obfuscation
    if (typeof options.deobfuscate === 'function') {
      try {
        const result = options.deobfuscate(effectiveContent);
        if (result.transforms.length > 0) {
          const deobThreats = analyzeFileFn(result.code, file, targetPath);
          const existingKeys = new Set(fileThreats.map(t => `${t.type}::${t.message}`));
          for (const dt of deobThreats) {
            if (!existingKeys.has(`${dt.type}::${dt.message}`)) {
              threats.push(dt);
            }
          }
        }
      } catch { /* deobfuscation failed — skip */ }
    }
  });

  return threats;
}

module.exports = { analyzeWithDeobfuscation };
