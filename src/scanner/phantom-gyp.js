/**
 * Phantom-Gyp compound correlator (Phase 1b — the real fix).
 *
 * The line-by-line `gyp_command_exec` detector (src/scanner/package.js, MUADDIB-PKG-023)
 * is an FP-first SPEED-BUMP: it flags a binding.gyp command-substitution `<!(...)` only
 * when the command line itself carries a malice marker (curl, pipe-to-shell, inline
 * network payload…). The dominant Phantom-Gyp shape — a bare `<!(node setup.js)` whose
 * payload lives in setup.js — is statically INDISTINGUISHABLE from a legit build helper
 * (`<!(node ./util/has_lib.js)`), so the speed-bump deliberately lets it pass to honor
 * "FPR must never increase".
 *
 * This post-processor closes that gap WITHOUT any FP cost by compounding two signals:
 *   (sink)    a `<!(node x.js)` / `<!(python y.py)` command-substitution in binding.gyp,
 *             which node-gyp runs at *configure* time on install — no lifecycle script
 *             needed; and
 *   (verdict) the invoked file (x.js) being INDEPENDENTLY judged malicious by the proven
 *             AST / dataflow / module-graph scanners (a CRITICAL finding, or a non-LOW
 *             HIGH_CONFIDENCE_MALICE_TYPES finding) on that exact file.
 * Only when BOTH hold do we emit `gyp_phantom_exec` (CRITICAL). The verdict comes from
 * the existing scanners, so the false-positive rate is bounded by theirs → FP≈0 by
 * construction. A benign build helper invoked the same way produces no malice verdict, so
 * nothing fires and the package gains zero new findings.
 *
 * Runs as a post-processor (it needs the full, post-scan threats array) — it re-reads
 * binding.gyp directly rather than threading a marker threat through FP reductions, so a
 * benign package never carries any intermediate Phantom-Gyp signal.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { HIGH_CONFIDENCE_MALICE_TYPES } = require('../monitor/classify.js');

// Command-substitution capture: the required `!` gates command execution. Plain
// `<(...)` / `<@(...)` (variable expansion, benign) is intentionally NOT matched —
// flagging it would be a hard false positive. We capture only up to the FIRST closing
// `)` so each command-sub body is isolated (unlike package.js's danger-marker scan, the
// script-file extraction needs the exact command, not a 400-char window).
const GYP_CMDSUB_RE = /<!@?\(([^)\n]{0,400})\)/g;
// Interpreter at the start of the command body that runs a SCRIPT FILE argument.
const SCRIPT_INTERP_RE = /^\s*(node|nodejs|python[0-9.]*|ruby|perl)\b(.*)$/i;
// Recognized script-file extensions (kept tight — a bare token without one is not
// assumed to be a script, to avoid matching subcommands like "rebuild").
const SCRIPT_FILE_RE = /\.(?:js|cjs|mjs|py|rb|pl)$/i;
// Inline-eval flags mean the payload is INLINE (no script file) — that case belongs to
// the gyp_command_exec speed-bump, not here, so we skip the command-sub entirely.
const INLINE_EVAL_FLAG_RE = /^--?(?:e|p|c|eval|print)$/i;

/** Normalize a relative path for comparison: backslashes→/, strip leading ./ and /. */
function _normRel(f) {
  return String(f || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

/**
 * Extract the script files invoked by `<!(interpreter file …)` command-substitutions in
 * a binding.gyp. Inline-eval forms (`node -e …`) and non-script interpreter queries
 * (`node -p "require('node-addon-api').include"`) yield no file and are skipped.
 *
 * @param {string} gypContent - raw binding.gyp text
 * @returns {Array<{interpreter:string, file:string}>}
 */
function extractGypInvokedScripts(gypContent) {
  const out = [];
  if (!gypContent || typeof gypContent !== 'string') return out;
  GYP_CMDSUB_RE.lastIndex = 0;
  let m;
  while ((m = GYP_CMDSUB_RE.exec(gypContent)) !== null) {
    const body = m[1];
    const im = SCRIPT_INTERP_RE.exec(body);
    if (!im) continue;
    const interpreter = im[1].toLowerCase();
    const tokens = (im[2] || '').trim().split(/\s+/).filter(Boolean);
    let scriptFile = null;
    for (const tok of tokens) {
      if (tok.startsWith('-')) {
        // An inline-eval flag means there is no script file in this command-sub.
        if (INLINE_EVAL_FLAG_RE.test(tok)) { scriptFile = null; break; }
        continue; // some other flag — keep scanning for the script argument
      }
      const clean = tok.replace(/^['"]+|['"]+$/g, '');
      if (SCRIPT_FILE_RE.test(clean)) { scriptFile = clean; break; }
    }
    if (scriptFile) out.push({ interpreter, file: scriptFile });
  }
  return out;
}

/**
 * True when a threat is a high-confidence malice verdict on its file: a CRITICAL of any
 * type, or a non-LOW finding of a HIGH_CONFIDENCE_MALICE_TYPES type. This reuses the
 * established "quasi-never legit" judgment rather than inventing a new bar.
 */
function _isMaliceVerdict(t) {
  if (!t || !t.type) return false;
  if (t.type === 'gyp_phantom_exec') return false; // never self-reference
  if (t.severity === 'CRITICAL') return true;
  if (t.severity !== 'LOW' && HIGH_CONFIDENCE_MALICE_TYPES.has(t.type)) return true;
  return false;
}

/**
 * Phantom-Gyp compound: for each `<!(node x.js)` in binding.gyp, if x.js is independently
 * judged malicious in the same scan, push one CRITICAL `gyp_phantom_exec` threat. Mutates
 * `threats` in place. Best-effort and side-effect-free on benign packages (no malice
 * verdict on the invoked file ⇒ no push, no marker).
 *
 * @param {Array<object>} threats - the deduplicated, post-scan threats array
 * @param {string} targetPath - scan target directory (where binding.gyp lives)
 * @returns {object|null} the pushed compound threat, or null if nothing fired
 */
function correlatePhantomGyp(threats, targetPath) {
  if (!Array.isArray(threats) || !targetPath) return null;
  if (threats.some(t => t && t.type === 'gyp_phantom_exec')) return null; // idempotent

  let gypContent;
  try {
    const gypPath = path.join(targetPath, 'binding.gyp');
    if (!fs.existsSync(gypPath)) return null;
    gypContent = fs.readFileSync(gypPath, 'utf8');
  } catch { return null; }

  const scripts = extractGypInvokedScripts(gypContent);
  if (scripts.length === 0) return null;

  for (const { interpreter, file } of scripts) {
    const norm = _normRel(file);
    const base = norm.split('/').pop();
    const hasDir = norm.includes('/');
    const malice = threats.find(t => {
      if (!t || !t.file || !_isMaliceVerdict(t)) return false;
      const tf = _normRel(t.file);
      if (tf === norm) return true;
      // A bare `<!(node loader.js)` ref (no directory) matches the invoked file by
      // basename — binding.gyp refs resolve relative to the package root, the same
      // base the scanners use for threat.file (path.relative(targetPath, …)).
      if (!hasDir && tf.split('/').pop() === base) return true;
      return false;
    });
    if (malice) {
      const compound = {
        type: 'gyp_phantom_exec',
        severity: 'CRITICAL',
        message: `binding.gyp runs <!(${interpreter} ${file}) at configure-time via node-gyp (no lifecycle script required) and ${file} is independently judged malicious (${malice.type}/${malice.severity}) — Phantom Gyp install-time payload (compound).`,
        file: 'binding.gyp',
        compound: true,
        count: 1
      };
      threats.push(compound);
      return compound; // one compound per package is enough
    }
  }
  return null;
}

module.exports = { extractGypInvokedScripts, correlatePhantomGyp, _normRel, _isMaliceVerdict };
