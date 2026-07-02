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

// Bound the number of decode attempts so a pathological file can't blow the CPU budget.
const MAX_DECODE = 300;
// A char-code array literal: >=6 small integers, e.g. [77,85,65,68,68,73,66,...].
const CHARCODE_ARRAY_RE = /\[\s*(\d{1,3}(?:\s*,\s*\d{1,3}){5,})\s*\]/g;
// A base64 blob big enough to hide a marker (>=12 chars ~ a 9+ byte string).
const BASE64_RE = /['"`]([A-Za-z0-9+/]{12,}={0,2})['"`]/g;
// Hex-encoded string: a run of \xHH escapes, or a contiguous even-length hex literal.
const HEX_ESCAPE_RE = /((?:\\x[0-9a-fA-F]{2}){8,})/g;
const HEX_LITERAL_RE = /['"`]([0-9a-fA-F]{16,})['"`]/g;

// Return the first planted analyzer marker contained in `decoded`, or null.
function markerIn(decoded) {
  if (!decoded) return null;
  for (const m of ANALYZER_MARKERS) {
    if (decoded.indexOf(m) !== -1) return m;
  }
  return null;
}

/**
 * Return the first analyzer marker that appears OBFUSCATED in `content` — hidden inside a
 * charcode array, a base64 blob, or a hex string that decodes to text containing the marker —
 * or null. Plaintext references are intentionally ignored (see module doc): MUAD'DIB's own
 * sandbox code and legit security tooling reference these markers in the clear, but no benign
 * package *encodes* a check for one. Bounded (MAX_DECODE total decodes), side-effect-free.
 */
function detectAnalyzerHoneytoken(content) {
  if (!content) return null;
  let seen = 0;

  // (1) charcode array: e.g. [77,85,65,68,...] whose codes decode to a marker string
  if (content.indexOf('[') !== -1) {
    CHARCODE_ARRAY_RE.lastIndex = 0;
    let match;
    while ((match = CHARCODE_ARRAY_RE.exec(content)) !== null) {
      if (++seen > MAX_DECODE) return null;
      const nums = match[1].split(',').map(n => parseInt(n, 10));
      if (nums.some(n => !(n >= 9 && n <= 126))) continue; // printable ASCII only
      let decoded; try { decoded = String.fromCharCode.apply(null, nums); } catch { continue; }
      const m = markerIn(decoded); if (m) return m;
    }
  }

  // (2) base64 blob: e.g. Buffer.from(b64, 'base64') where b64 decodes to a marker
  BASE64_RE.lastIndex = 0;
  let b;
  while ((b = BASE64_RE.exec(content)) !== null) {
    if (++seen > MAX_DECODE) return null;
    let decoded; try { decoded = Buffer.from(b[1], 'base64').toString('latin1'); } catch { continue; }
    const m = markerIn(decoded); if (m) return m;
  }

  // (3) hex string: '\x4d\x55...' escapes or a contiguous '4d5541...' literal
  for (const re of [HEX_ESCAPE_RE, HEX_LITERAL_RE]) {
    re.lastIndex = 0;
    let h;
    while ((h = re.exec(content)) !== null) {
      if (++seen > MAX_DECODE) return null;
      const pairs = h[1].match(/[0-9a-fA-F]{2}/g);
      if (!pairs) continue;
      let decoded; try { decoded = pairs.map(x => String.fromCharCode(parseInt(x, 16))).join(''); } catch { continue; }
      const m = markerIn(decoded); if (m) return m;
    }
  }

  return null;
}

// process.env KEY-ENUMERATION coupled with a test against an analysis-marker prefix
//   (enumerate the env keys, then test each against the distinctive MUADDIB prefix — our own
//   tool name, FP-safe; bare 'GVISOR' is a real runtime and is deliberately NOT matched).
// Marker-AGNOSTIC re: the exact var name (matches any MUADDIB_* var), unlike the
// exact-name form `process.env.MUADDIB_GVISOR`. FP-safe by coupling: a scanned package has no
// legitimate reason to enumerate the environment looking for OUR sandbox-marker prefix
// (verified: MUAD'DIB reads its own MUADDIB_* vars directly, never via enumerate+startsWith).
const ENV_ENUM_RE = /Object\s*\.\s*(?:keys|entries|getOwnPropertyNames)\s*\(\s*process\s*\.\s*env|for\b[^;{}]*\bin\b\s*process\s*\.\s*env/;
const ENV_KEY_MARKER_TEST_RE = /\.\s*(?:startsWith|includes|indexOf|search|match)\s*\(\s*['"`][^'"`]*MUADDIB|['"`][^'"`]*MUADDIB[^'"`]*['"`]\s*(?:===?|!==?)|(?:===?|!==?)\s*['"`][^'"`]*MUADDIB/;

/**
 * Detect generic `process.env` enumeration whose keys are tested for the distinctive MUADDIB
 * prefix (case-sensitive; bare 'GVISOR' is a real runtime, deliberately not matched). Returns the matched marker family (string) or null. Marker-agnostic, FP-safe
 * by coupling (env enumeration + our own tripwire prefix).
 */
function detectEnvMarkerEnumeration(content) {
  if (!content || content.indexOf('process') === -1) return null;
  if (!ENV_ENUM_RE.test(content)) return null;
  return ENV_KEY_MARKER_TEST_RE.test(content) ? 'MUADDIB' : null;
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

module.exports = { ANALYZER_MARKERS, detectAnalyzerHoneytoken, detectEnvMarkerEnumeration, countExitGuards, hasHostRecon };
