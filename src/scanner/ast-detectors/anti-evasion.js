'use strict';

/**
 * Anti-analysis / sandbox-evasion detection (2026, born from the @longzy "Contagious
 * Interview" DPRK npm campaign — whose payload charcode-encodes a `MUADDIB_GVISOR` check to
 * refuse detonation inside our sandbox).
 *
 * Design stance: we do NOT try to HIDE the sandbox. That is an unwinnable arms race — gVisor
 * is detectable via /proc, syscall quirks and timing, and an attacker re-reads our public
 * repo. Instead we detect the EVASION ITSELF, statically. That is durable and lose-lose for
 * the attacker: evade → this convicts them (immune to any env-hiding, because it reads code);
 * don't evade → the dynamic sandbox detonates them.
 *
 * Two complementary, marker-AGNOSTIC-first signals (emitted in handlePostWalk):
 *
 *   1. analyzer_honeytoken_reference (CRITICAL, FP~0) — the file hides, behind charcode
 *      encoding, a reference to a known analysis-environment tripwire (our own
 *      `MUADDIB_GVISOR`, a peer analyzer's marker, a poison-token name). We match ONLY the
 *      obfuscated form: legitimate security tooling (incl. MUAD'DIB's own sandbox code)
 *      references these markers in the clear, but no benign package charcode-encodes a check
 *      for one. This deliberately weaponises our sandbox marker as a HONEYTOKEN — we keep
 *      `MUADDIB_GVISOR` public and STABLE precisely so any package that checks for it
 *      self-incriminates. Hiding/rotating it would throw the honeytoken away for nothing.
 *
 *   2. the structural "detonation-gate wall" (see countExitGuards / hasHostRecon, combined
 *      with env-read + obfuscation in handlePostWalk) — a stack of silent process.exit()
 *      guards that read the environment. Keys on the SHAPE, so it catches NOVEL markers a
 *      signature list never would. FP-safe by coupling, not breadth.
 *
 * Both are static → immune to sandbox-hiding, and both fire regardless of whether the
 * (secondary, LOG-ONLY) dynamic sandbox ever runs.
 */

// Analysis-environment tripwire markers with ZERO legitimate reason to be *charcode-hidden*
// inside a package. Curated for near-zero FP: excludes AWS doc example keys
// (AKIAIOSFODNN7EXAMPLE) which legitimately appear in tutorials/tests. Keep this list stable
// and public — every entry is a planted honeytoken.
const ANALYZER_MARKERS = [
  'MUADDIB_GVISOR',        // our own sandbox marker — the primary honeytoken
  'DetonationLogFilePath',
  'THREAT_ANALYZER_MODEL',
  'ASPECT_TLOG',
  'PYPI_POISON',
  'SANDYCLAW_',
  'OPENCLAW_',
  'PERMISO_',
  'CHAINRADAR_'
];

// Bound the charcode-array decode so a pathological file can't blow the CPU budget.
const MAX_DECODE_ARRAYS = 300;
// A char-code array literal: >=6 small integers, e.g. [77,85,65,68,68,73,66,...].
const CHARCODE_ARRAY_RE = /\[\s*(\d{1,3}(?:\s*,\s*\d{1,3}){5,})\s*\]/g;

/**
 * Return the first analyzer marker that appears CHARCODE-ENCODED in `content` (i.e. hidden
 * inside a numeric array literal that decodes to a string containing the marker), or null.
 * Plaintext references are intentionally ignored (see module doc). Bounded, side-effect-free.
 */
function detectAnalyzerHoneytoken(content) {
  if (!content || content.indexOf('[') === -1) return null;
  CHARCODE_ARRAY_RE.lastIndex = 0;
  let match, seen = 0;
  while ((match = CHARCODE_ARRAY_RE.exec(content)) !== null) {
    if (++seen > MAX_DECODE_ARRAYS) break;
    const nums = match[1].split(',').map(n => parseInt(n, 10));
    // Only decode arrays that are entirely printable ASCII codes (a real hidden string).
    if (nums.some(n => !(n >= 9 && n <= 126))) continue;
    let decoded;
    try { decoded = String.fromCharCode.apply(null, nums); } catch { continue; }
    for (const m of ANALYZER_MARKERS) {
      if (decoded.indexOf(m) !== -1) return m;
    }
  }
  return null;
}

/** Count silent `process.exit(` guards — the magnitude of the "detonation-gate wall". */
function countExitGuards(content) {
  if (!content) return 0;
  const m = content.match(/process\s*\.\s*exit\s*\(/g);
  return m ? m.length : 0;
}

/** Host/environment reconnaissance calls (note: `os` is often aliased, e.g. `_os.hostname()`). */
function hasHostRecon(content) {
  return !!content && /\.\s*(?:hostname|userInfo|networkInterfaces)\s*\(/.test(content);
}

module.exports = { ANALYZER_MARKERS, detectAnalyzerHoneytoken, countExitGuards, hasHostRecon };
