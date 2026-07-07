/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

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
//  - Double-extension bundler outputs (index.cjs.js, index.esm.js, index.umd.js
//    at package root — common pattern for @equinor/*, tsdx/rollup bundled libs)
//  - Hash-suffixed chunks (esbuild/vite/rollup/webpack convention):
//    `basename-[a-f0-9]{6,16}.js|mjs|cjs`
//  - Tool-specific subdirectories that contain vendored bundles (v2.10.75):
//    * `lib/[name]Bundle*/` — Playwright-style `lib/utilsBundleImpl/`
//    * `.yarn/releases/` — vendored yarn/pnpm releases shipped in template packages
//    * `sys/(node|browser|deno)/` — Stencil-style platform-specific bundle
//    * `compiled/` — SWC/Stencil compiled output
//    * `typings/` — only if matches a .d.ts file (defensive)
const BUNDLE_PATH_RE = new RegExp(
  // Path prefix group (directories that almost always contain bundled output)
  '(?:^|[/\\\\])' +
  '(?:dist|build|out|output|browser|bundles|assets|chunks|_app|compiled|' +
  'lib[/\\\\]bundled|fesm\\d*|esm|esm5|esm2015|esm2020)' +
  '[/\\\\]' +
  // OR Playwright-style lib/xxxBundle*/ (e.g. lib/utilsBundleImpl/, lib/mcpBundleImpl/,
  // lib/transform/babelBundleImpl.js) — matches the directory form
  // `lib/.../xxxBundleImpl/index.js` and the flat form `lib/.../xxxBundleImpl.js`
  // at any depth under lib/.
  '|(?:^|[/\\\\])lib[/\\\\][^\\n]*[Bb]undle[\\w-]*(?:[/\\\\]|\\.(?:m?js|cjs)$)' +
  // OR vendored yarn/pnpm releases (@backstage/create-app templates etc.)
  '|(?:^|[/\\\\])\\.yarn[/\\\\]releases[/\\\\]' +
  '|(?:^|[/\\\\])\\.pnpm[/\\\\](?:releases|dist)[/\\\\]' +
  // OR Stencil-style sys/(node|browser|deno) containing compiled platform bundles
  '|(?:^|[/\\\\])sys[/\\\\](?:node|browser|deno)[/\\\\]' +
  // OR basename suffix group (single extension)
  '|\\.(?:min|bundle|umd|esm|es|cjs|common|max|prod|production|iife)\\.(?:m?js|cjs)$' +
  // OR double-extension bundler outputs at root: index.cjs.js, index.esm.js, etc.
  // Anchored by `^` or path separator + basename with exactly the double extension.
  '|(?:^|[/\\\\])[\\w-]+\\.(?:cjs|esm|umd|es|iife|min)\\.js$' +
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
  'shai_hulud_marker',
  // Mini Shai-Hulud campaign (2026-05): detached process + credential harvest + network
  // is the DPRK/Lazarus evasion pattern. Writing to .claude/settings.json or
  // .vscode/tasks.json is developer tooling persistence — never produced by a bundler.
  'detached_credential_exfil',   // AST-047 — spawn detached + env + network
  'ai_config_injection',         // AST-027 — writes to .claude/ MCP config
  'ide_task_persistence'         // AST-035 — writes to .vscode/tasks.json
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
    // v2.10.75 fix: a LOW severity threat should never block the bundle downgrade
    // of unrelated co-occurring threats. Typical regression case: a locale file
    // (locales/fa-IR/*.js) contains `unicode_invisible_injection` at LOW (already
    // downgraded by `isLocaleFile` in obfuscation.js) but also contains bundler
    // helpers. Before this fix, the LOW unicode signal vetoed the bundle downgrade
    // of the other threats, so the package scored higher than pre-v2.10.74.
    if (t.severity === 'LOW') continue;
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
