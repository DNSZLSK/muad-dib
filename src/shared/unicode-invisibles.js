'use strict';

/**
 * Unicode invisible character helpers — shared by obfuscation.js and ai-config.js.
 *
 * Extracted v2.11.25 (TrapDoor campaign, mai 2026) : la fonction locale dans
 * obfuscation.js couvrait `.js/.cjs/.mjs/.ts/.tsx/.py` mais pas les configs IA
 * (.cursorrules, CLAUDE.md). En la partageant, ai-config.js peut normaliser le
 * contenu avant ses regex et bloquer le vecteur "cu<U+200B>rl|sh" avec ZW
 * interspersés dans le mot-clé.
 *
 * Codepoints détectés (superset du scope original obfuscation.js, qui n'incluait
 * pas LRM/RLM ni les directional override) :
 *
 *   Zero-width:
 *     U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ
 *     U+2060 word joiner
 *     U+180E Mongolian vowel separator
 *
 *   Directional (bidi spoofing — Trojan Source CVE-2021-42574) :
 *     U+200E LRM, U+200F RLM
 *     U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO
 *
 *   Invisible math operators (peuvent casser un parser sans être vus) :
 *     U+2061 function application, U+2062 invisible times,
 *     U+2063 invisible separator, U+2064 invisible plus
 *
 *   BOM (mid-text only; position 0 est légitime UTF-8 BOM) :
 *     U+FEFF
 *
 *   Variation selectors :
 *     U+FE00-FE0E (excludes U+FE0F emoji presentation selector — légitime)
 *     U+E0100-E01EF supplementary plane variation selectors
 *
 *   Tag characters (utilisés par GlassWorm pour encoder du payload) :
 *     U+E0001, U+E0020-E007F
 *
 * CJK, accents, emoji standards (avec U+FE0F) sont volontairement EXCLUS — pas
 * de FP attendu sur du contenu international légitime.
 *
 * Références :
 *  - https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode
 *  - https://trojansource.codes/ (Trojan Source, CVE-2021-42574)
 *  - https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates (mai 2026)
 */

/**
 * Returns true if the codepoint at position `i` is considered invisible.
 * Sets `skipNext` true on the result if the codepoint is supplementary
 * (caller must `i++` to skip the low surrogate half).
 *
 * @param {string} content
 * @param {number} i
 * @returns {{ invisible: boolean, supplementary: boolean }}
 */
function inspectCodepoint(content, i) {
  const cp = content.codePointAt(i);

  // BMP zero-width
  if (cp === 0x200B || cp === 0x200C || cp === 0x200D) {
    return { invisible: true, supplementary: false };
  }

  // BMP directional (Trojan Source)
  if (cp === 0x200E || cp === 0x200F ||
      (cp >= 0x202A && cp <= 0x202E)) {
    return { invisible: true, supplementary: false };
  }

  // BMP word joiner & friends
  if (cp === 0x2060 || cp === 0x180E) {
    return { invisible: true, supplementary: false };
  }

  // BMP invisible math operators (U+2061-2064)
  if (cp >= 0x2061 && cp <= 0x2064) {
    return { invisible: true, supplementary: false };
  }

  // BOM only suspicious after position 0
  if (cp === 0xFEFF && i > 0) {
    return { invisible: true, supplementary: false };
  }

  // BMP variation selectors (U+FE00-U+FE0E) — excludes U+FE0F emoji presentation
  if (cp >= 0xFE00 && cp <= 0xFE0E) {
    return { invisible: true, supplementary: false };
  }

  // Supplementary plane: variation selectors supplement (U+E0100-U+E01EF)
  if (cp >= 0xE0100 && cp <= 0xE01EF) {
    return { invisible: true, supplementary: true };
  }

  // Supplementary plane: tag characters (U+E0001 + U+E0020-U+E007F)
  if (cp === 0xE0001 || (cp >= 0xE0020 && cp <= 0xE007F)) {
    return { invisible: true, supplementary: true };
  }

  // Other supplementary chars (non-invisible) — need to skip low surrogate
  if (cp > 0xFFFF) {
    return { invisible: false, supplementary: true };
  }

  return { invisible: false, supplementary: false };
}

/**
 * Count invisible Unicode codepoints in `content`.
 *
 * @param {string} content
 * @returns {number}
 */
function countInvisibleUnicode(content) {
  let count = 0;
  for (let i = 0; i < content.length; i++) {
    const { invisible, supplementary } = inspectCodepoint(content, i);
    if (invisible) count++;
    if (supplementary) i++; // skip low surrogate half
  }
  return count;
}

/**
 * Return a copy of `content` with all invisible codepoints removed.
 *
 * Used to normalize text before pattern matching: prevents an attacker
 * from splitting a keyword (`cu<U+200B>rl`) with zero-width chars to evade
 * regex like /curl\s+/i.
 *
 * @param {string} content
 * @returns {string}
 */
function stripInvisibleUnicode(content) {
  // Fast path: if no codepoint > 0x7F, content is pure ASCII — nothing to strip.
  let hasHighChar = false;
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) > 0x7F) { hasHighChar = true; break; }
  }
  if (!hasHighChar) return content;

  let out = '';
  for (let i = 0; i < content.length; i++) {
    const { invisible, supplementary } = inspectCodepoint(content, i);
    if (!invisible) {
      // Preserve original char(s). For supplementary, copy both surrogate halves.
      if (supplementary) {
        out += content[i] + content[i + 1];
        i++;
      } else {
        out += content[i];
      }
    } else if (supplementary) {
      // Skip both surrogate halves
      i++;
    }
  }
  return out;
}

module.exports = {
  countInvisibleUnicode,
  stripInvisibleUnicode
};
