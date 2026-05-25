const fs = require('fs');
const path = require('path');
const { findFiles, forEachSafeFile, debugLog } = require('../utils.js');
const { countInvisibleUnicode } = require('../shared/unicode-invisibles.js');

// node_modules NOT excluded: detect obfuscated code in dependencies.
// dist/build/out/output excluded: bundled output is always flagged as isPackageOutput (LOW)
// and costs significant processing time on large SDKs.
const OBF_EXCLUDED_DIRS = ['.git', '.muaddib-cache', 'dist', 'build', 'out', 'output'];

// v2.10.73 P4: WASM/Emscripten artifact detection
// These files are high-entropy by construction (compiled WebAssembly, asm.js bytecode
// tables, Emscripten output). They produced 52+ ENTROPY/obfuscation FP fires in the
// v2.10.72 audit (e.g. node_modules/mpg123-decoder/src/EmscriptenWasm.js inside
// @leoqlin/openclaw-qqbot's bundled deps). Skipped from obfuscation detection only —
// other scanners (AST, dataflow, hash, IOC) still analyze them, so actual malware
// hidden in a WASM file can still be caught through those channels.
const WASM_BASENAME_RE = /(?:wasm|emscripten|dcmtk|ffmpeg-wasm|opus-decoder|mpg123-decoder|wasm-audio-decoders)/i;
const WASM_CONTENT_MARKERS = [
  'Module["asm"]',
  'Module.asm',
  'WebAssembly.instantiate',
  'WebAssembly.compile',
  '_emscripten_',
  'asmLibraryArg',
  'wasmMemory',
  'wasmTable',
  'HEAPU8',
  'HEAP32',
  'AGFzbQ' // base64 of WASM magic bytes \x00asm — TRES specific marker
];

function isWasmEmscriptenArtifact(filePath, content) {
  const basename = path.basename(filePath);
  if (WASM_BASENAME_RE.test(basename)) return true;
  // Sample first 64KB to avoid scanning huge files fully (WASM blobs are often >1MB)
  const sample = content.length > 65536 ? content.slice(0, 65536) : content;
  for (const marker of WASM_CONTENT_MARKERS) {
    if (sample.indexOf(marker) !== -1) return true;
  }
  return false;
}

function detectObfuscation(targetPath) {
  const threats = [];
  let wasmSkipped = 0;
  const files = findFiles(targetPath, { extensions: ['.js', '.mjs', '.cjs'], excludedDirs: OBF_EXCLUDED_DIRS });

  forEachSafeFile(files, (file, content) => {
    const relativePath = path.relative(targetPath, file);

    // v2.10.73 P4: Skip WASM/Emscripten artifacts — high-entropy by construction,
    // produced 52+ FP fires in v2.10.72 audit (mpg123-decoder in @leoqlin/openclaw-qqbot).
    // Other scanners still analyze these files — this only filters obfuscation heuristics.
    if (isWasmEmscriptenArtifact(file, content)) {
      wasmSkipped++;
      return;
    }

    const signals = [];
    let score = 0;
    const basename = path.basename(file);
    const isMinified = basename.endsWith('.min.js');
    const isBundled = basename.endsWith('.bundle.js');
    const pathParts = relativePath.split(path.sep);
    const isInDistOrBuild = pathParts.some(p => p === 'dist' || p === 'build');
    const isLargeCjsMjs = (basename.endsWith('.cjs') || basename.endsWith('.mjs')) && content.length > 100 * 1024;
    // P6: Any JS file > 100KB is overwhelmingly bundled output regardless of directory name,
    // UNLESS it contains javascript-obfuscator markers (_0x hex variables). Bundlers
    // (webpack/rollup/esbuild) never produce _0x vars — this is a discriminant unique to
    // javascript-obfuscator, which is only used to hide malicious intent.
    // Mini Shai-Hulud campaign (2026-05): 2.3MB payload exploited the original blanket
    // exemption to evade detection on @tanstack/react-router (12M weekly downloads).
    const isLargeJsCandidate = basename.endsWith('.js') && content.length > 100 * 1024;
    const hasObfuscatorMarkers = isLargeJsCandidate && /\b_0x[a-f0-9]{4,}\b/.test(content.slice(0, 8192));
    const isLargeJs = isLargeJsCandidate && !hasObfuscatorMarkers;
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

  if (wasmSkipped > 0) {
    debugLog(`[obfuscation] skipped ${wasmSkipped} WASM/Emscripten artifact(s) — high-entropy by construction`);
  }

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

module.exports = { detectObfuscation };