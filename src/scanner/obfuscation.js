const fs = require('fs');
const path = require('path');
const { findFiles, forEachSafeFile } = require('../utils.js');

// node_modules NOT excluded: detect obfuscated code in dependencies.
// dist/build/out/output excluded: bundled output is always flagged as isPackageOutput (LOW)
// and costs significant processing time on large SDKs.
const OBF_EXCLUDED_DIRS = ['.git', '.muaddib-cache', 'dist', 'build', 'out', 'output'];

function detectObfuscation(targetPath) {
  const threats = [];
  const files = findFiles(targetPath, { extensions: ['.js', '.mjs', '.cjs'], excludedDirs: OBF_EXCLUDED_DIRS });

  forEachSafeFile(files, (file, content) => {
    const relativePath = path.relative(targetPath, file);

    const signals = [];
    let score = 0;
    const basename = path.basename(file);
    const isMinified = basename.endsWith('.min.js');
    const isBundled = basename.endsWith('.bundle.js');
    const pathParts = relativePath.split(path.sep);
    const isInDistOrBuild = pathParts.some(p => p === 'dist' || p === 'build');
    const isLargeCjsMjs = (basename.endsWith('.cjs') || basename.endsWith('.mjs')) && content.length > 100 * 1024;
    // P6: Any JS file > 100KB is overwhelmingly bundled output regardless of directory name.
    // Real obfuscated malware is typically small (<50KB). Catches prettier plugins/, svelte compiler/, etc.
    const isLargeJs = basename.endsWith('.js') && content.length > 100 * 1024;
    // Locale/i18n files legitimately contain invisible Unicode (e.g. Persian ZWNJ U+200C)
    const isLocaleFile = /(?:^|[/\\])(?:locale|locales|i18n|intl|lang|languages|translations)[/\\]/i.test(relativePath);
    const isPackageOutput = isMinified || isBundled || isInDistOrBuild || isLargeCjsMjs || isLargeJs || isLocaleFile;

    // 1. Ratio code sur une seule ligne (skip .min.js — minification, not obfuscation)
    if (!isMinified) {
      const lines = content.split(/\r?\n/).filter(l => l.trim());
      const longLines = lines.filter(l => l.length > 500);
      if (lines.length > 0 && longLines.length / lines.length > 0.3) {
        score += 25;
        signals.push('long_single_lines');
      }
    }

    // 2. Hex escapes massifs (tracked but only scored with corroborating signals)
    let hexScore = 0;
    const hexCount = countMatches(content, /\\x[0-9a-fA-F]{2}/g);
    if (hexCount > 20) {
      hexScore = 25;
      signals.push('hex_escapes');
    }

    // 3. Unicode escapes massifs (tracked but only scored with corroborating signals)
    let unicodeScore = 0;
    const unicodeCount = countMatches(content, /\\u[0-9a-fA-F]{4}/g);
    if (unicodeCount > 20) {
      unicodeScore = 20;
      signals.push('unicode_escapes');
    }

    // 4. Variables style obfuscateur (_0x, _0xabc)
    const obfVarCount = countMatches(content, /\b_0x[a-f0-9]+\b/gi);
    if (obfVarCount > 5) {
      score += 30;
      signals.push('obfuscated_variables');
    }

    // 5. String arrays suspects (programmatic check to avoid ReDoS)
    if (hasLargeStringArray(content)) {
      score += 25;
      signals.push('string_array');
    }

    // 6. atob/btoa avec eval
    if (/atob\s*\(/.test(content) && /(eval|Function)\s*\(/.test(content)) {
      score += 30;
      signals.push('base64_eval');
    }

    // 7. Unicode invisible character injection (GlassWorm — mars 2026)
    // Detects zero-width chars, variation selectors, tag characters embedded in source
    const invisibleCount = countInvisibleUnicode(content);
    if (invisibleCount >= 10) {
      threats.push({
        type: 'unicode_invisible_injection',
        severity: isPackageOutput ? 'LOW' : 'CRITICAL',
        message: `${invisibleCount} invisible Unicode characters detected (zero-width, variation selectors, tag chars). Possible hidden payload encoded via invisible codepoints.`,
        file: relativePath
      });
    }

    // Hex/unicode escapes alone are not obfuscation (e.g. lodash Unicode char tables).
    // Only count them when combined with strong obfuscation signals.
    const hasStrongSignals = signals.some(s => s !== 'hex_escapes' && s !== 'unicode_escapes');
    if (hasStrongSignals) {
      score += hexScore + unicodeScore;
    }

    if (score >= 40) {
      threats.push({
        type: 'obfuscation_detected',
        severity: isPackageOutput ? 'LOW' : (score >= 70 ? 'CRITICAL' : 'HIGH'),
        message: `Code obfusque (score: ${score}). Signaux: ${signals.join(', ')}`,
        file: relativePath
      });
    }
  });

  return threats;
}

/**
 * Count regex matches without creating a full match array (avoids memory spikes on large files).
 */
function countMatches(str, regex) {
  let count = 0;
  while (regex.exec(str) !== null) count++;
  return count;
}

/**
 * Programmatic check for large string arrays (avoids ReDoS from nested regex quantifiers).
 * Detects patterns like: var x = ["a", "b", "c", ...] with 10+ quoted items.
 */
function hasLargeStringArray(content) {
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const varIdx = line.indexOf('var ');
    if (varIdx === -1) continue;
    const bracketIdx = line.indexOf('[', varIdx);
    if (bracketIdx === -1) continue;
    const closeBracketIdx = line.indexOf(']', bracketIdx);
    if (closeBracketIdx === -1) continue;
    const segment = line.slice(bracketIdx, closeBracketIdx + 1);
    // Count quoted strings in the segment
    let count = 0;
    for (let i = 0; i < segment.length; i++) {
      if (segment[i] === '"' || segment[i] === "'") {
        const quote = segment[i];
        const end = segment.indexOf(quote, i + 1);
        if (end !== -1 && end - i - 1 <= 50) {
          count++;
          i = end;
        }
      }
    }
    if (count >= 10) return true;
  }
  return false;
}

/**
 * Count invisible Unicode codepoints in content (GlassWorm detection).
 * Covers BMP zero-width chars, variation selectors, and supplementary plane
 * tag characters / variation selectors supplement via codePointAt iteration.
 *
 * Codepoints detected:
 * - U+200B, U+200C, U+200D (zero-width space/joiner/non-joiner)
 * - U+FEFF (BOM — only if position > 0; pos 0 is legitimate BOM)
 * - U+2060 (word joiner), U+180E (Mongolian vowel separator)
 * - U+FE00-U+FE0E (variation selectors — excludes U+FE0F emoji presentation selector)
 * - U+E0100-U+E01EF (variation selectors supplement)
 * - U+E0001-U+E007F (tag characters)
 */
function countInvisibleUnicode(content) {
  let count = 0;
  for (let i = 0; i < content.length; i++) {
    const cp = content.codePointAt(i);
    // BMP invisible chars
    if (cp === 0x200B || cp === 0x200C || cp === 0x200D ||
        cp === 0x2060 || cp === 0x180E) {
      count++;
    }
    // BOM only suspicious after position 0
    else if (cp === 0xFEFF && i > 0) {
      count++;
    }
    // BMP variation selectors (U+FE00-U+FE0E) — excludes U+FE0F (emoji presentation selector)
    else if (cp >= 0xFE00 && cp <= 0xFE0E) {
      count++;
    }
    // Supplementary plane: variation selectors supplement (U+E0100-U+E01EF)
    else if (cp >= 0xE0100 && cp <= 0xE01EF) {
      count++;
      i++; // skip surrogate pair low half
    }
    // Supplementary plane: tag characters (U+E0001-U+E007F)
    else if (cp >= 0xE0001 && cp <= 0xE007F) {
      count++;
      i++; // skip surrogate pair low half
    }
    // Skip surrogate pair low half for other supplementary chars
    else if (cp > 0xFFFF) {
      i++;
    }
  }
  return count;
}

module.exports = { detectObfuscation };