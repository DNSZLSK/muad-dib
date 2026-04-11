'use strict';

/**
 * Bundle file detection helpers — v2.10.73 P1 (FP cluster fix).
 *
 * Audit forensique v2.10.72 (2026-04-11, 78 packages deep-reviewed) a révélé
 * que les 14 packages babylonjs/electron/@kitware/vtk.js/@stencil/core/playwright/
 * @testim/testim-cli/@vanwei-wcs/video-player-v2/@bookolosystem/engine/@epie/bi-crud/etc.
 * scoraient ≥50 parce que les rules AST/dataflow/obfuscation tiraient sur des
 * helpers bundler standards (__webpack_require__, Function("return this")(),
 * var __copyProps, .replace chains, prototype pollution for framework reactivity).
 *
 * Fix :
 * 1. Regex étendue `BUNDLE_PATH_RE` couvrant les patterns manquants :
 *    .umd.js, .esm.js, .es.js, .common.js, .max.js, hash-suffixed chunks,
 *    fesm*, browser/, assets/, chunks/.
 * 2. Liste de veto `VETO_TYPES` — types qui indiquent une injection malveillante
 *    dans un bundle (staged_binary_payload, fetch_decrypt_exec, etc.). Si un
 *    threat veto est présent dans le même fichier, le bundle downgrade est
 *    annulé — bundle suspecté d'injection (event-stream style).
 * 3. Liste `SENSITIVE_ENV_RE` — noms d'env vars sensibles. Un env_access sur
 *    un de ces noms dans un bundle annule aussi le downgrade (credential theft).
 *
 * Architecture : pas de lecture de contenu fichier ni de cache — la détection
 * se fait purement sur le path et sur les types de threats co-occurring dans le
 * même fichier. Pour la v2.10.74, un `isStructuralBundle()` avec lecture de
 * signatures (`__webpack_require__`, `sourceMappingURL=`) pourrait être ajouté
 * si les tests FPR montrent qu'il reste des FPs sur des bundles non-nommés.
 */

// Extended bundle path/basename regex (replaces the narrow DIST_FILE_RE).
// Covers the audit findings: babylonjs, electron, @kitware/vtk.js, dprint,
// @jetbrains/junie, @zuplo/core, @stencil/core, playwright, @equinor/*,
// @alipay/*, @testim/testim-cli, @vanwei-wcs/video-player-v2, @bookolosystem/engine,
// @epie/bi-crud, @fairyhunter13/opentui-core, rsshub.
//
// Pattern groups:
//  - Directory prefixes (dist/, build/, out/, output/, lib/bundled/, browser/,
//    fesm*/, esm/, esm5/, esm2015/, esm2020/, bundles/, assets/, chunks/, _app/)
//  - Basename suffixes (.min.js, .bundle.js, .umd.js, .esm.js, .es.js,
//    .common.js, .max.js, .prod.js, .production.js, + .cjs / .mjs variants)
//  - Hash-suffixed chunks (esbuild/vite/rollup/webpack convention):
//    `basename-[a-f0-9]{6,16}.js|mjs|cjs`
const BUNDLE_PATH_RE = new RegExp(
  // Path prefix group
  '(?:^|[/\\\\])' +
  '(?:dist|build|out|output|browser|bundles|assets|chunks|_app|' +
  'lib[/\\\\]bundled|fesm\\d*|esm|esm5|esm2015|esm2020)' +
  '[/\\\\]' +
  // OR basename suffix group
  '|\\.(?:min|bundle|umd|esm|es|common|max|prod|production)\\.(?:m?js|cjs)$' +
  // OR hash-suffixed chunk
  '|(?:^|[/\\\\])[\\w-]+[-.][a-f0-9]{6,16}\\.(?:m?js|cjs)$',
  'i'
);

// Threat types that, when present on the same file as a bundle downgrade
// candidate, VETO the downgrade entirely — the bundle is suspected of
// malicious injection or active C2/persistence.
//
// IMPORTANT: types that feed existing compound rules are INTENTIONALLY NOT listed
// here. The scoring pipeline already has a mechanism to recover downgraded signals
// via `applyCompoundBoosts` + `originalSeverity` gates (see src/scoring.js:462 and
// compound gate at line 410). Types like `staged_binary_payload`, `crypto_decipher`,
// `fetch_decrypt_exec`, `zlib_inflate_eval` ARE downgraded in bundles but their
// `originalSeverity` is preserved so compound rules (crypto_staged_payload, etc.)
// can still fire. Adding them to VETO_TYPES would break the existing v2.9.6 test
// suite (compound-scoring.test.js:305 and similar) without adding value.
//
// This VETO list is limited to patterns that :
//  1. Have no compound fallback (rare patterns not yet wired into a compound)
//  2. Indicate active C2, persistence, or worm propagation (structurally unique to
//     malware — a legit bundler never produces `reverse_shell` or `node_modules_write`)
//  3. Are IOC hits (highest confidence, never downgraded regardless of context)
const VETO_TYPES = new Set([
  // Active C2 / backdoor — structurally unique to malware, no legit bundler path
  'reverse_shell',
  'node_modules_write',        // worm propagation (Shai-Hulud style)
  'npm_publish_worm',
  'npm_token_steal',
  'systemd_persistence',
  // Unicode steganography (GlassWorm) — bundlers never produce invisible unicode
  'unicode_invisible_injection',
  // IOC hits (never downgraded regardless of context)
  'ioc_match',
  'known_malicious_package',
  'shai_hulud_marker'
]);

// Sensitive environment variable patterns. An `env_access` threat whose
// `message` contains any of these, present on the same file as a bundle
// downgrade candidate, VETOs the downgrade — the bundle reads credentials.
// NODE_ENV, NODE_OPTIONS, PATH, HOME, SHELL, CI, DEBUG etc. are NOT included
// (they are read by bundler output for legit reasons like runtime detection).
const SENSITIVE_ENV_RE = new RegExp(
  '\\b(' +
    'NPM_TOKEN|NPM_CONFIG_AUTHTOKEN|NPMRC|' +
    'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|' +
    'SSH_PRIVATE_KEY|SSH_KEY|SSH_AUTH_SOCK|' +
    'GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|' +
    'GCP_[A-Z_]+|GOOGLE_APPLICATION_CREDENTIALS|' +
    'AZURE_[A-Z_]+|AZURE_CLIENT_SECRET|' +
    'STRIPE_SECRET_KEY|STRIPE_LIVE|' +
    // Catch-all suffix patterns
    '[A-Z][A-Z0-9_]*_SECRET|[A-Z][A-Z0-9_]*_PRIVATE_KEY|' +
    '[A-Z][A-Z0-9_]*_API_KEY|[A-Z][A-Z0-9_]*_AUTH_TOKEN' +
  ')\\b'
);

/**
 * Check if a file path matches bundle heuristics.
 * @param {string} filePath - relative or absolute file path
 * @returns {boolean}
 */
function isBundlePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return false;
  return BUNDLE_PATH_RE.test(filePath);
}

/**
 * Check if any threat in `threats` on the same file as `targetFile` is a
 * veto signal (VETO_TYPES OR env_access on sensitive env var). If so, the
 * bundle-downgrade gate should NOT downgrade — the bundle is suspected of
 * malicious injection (event-stream / flatmap-stream style) or credential theft.
 *
 * @param {Array} threats - full threats array (all scanners combined)
 * @param {string} targetFile - the file path being evaluated for downgrade
 * @returns {boolean} - true if a veto signal is found
 */
function hasBundleVetoSignal(threats, targetFile) {
  if (!Array.isArray(threats) || !targetFile) return false;
  for (const t of threats) {
    if (t.file !== targetFile) continue;
    if (VETO_TYPES.has(t.type)) return true;
    if (t.type === 'env_access' && t.message && SENSITIVE_ENV_RE.test(t.message)) {
      return true;
    }
  }
  return false;
}

module.exports = {
  BUNDLE_PATH_RE,
  VETO_TYPES,
  SENSITIVE_ENV_RE,
  isBundlePath,
  hasBundleVetoSignal
};
