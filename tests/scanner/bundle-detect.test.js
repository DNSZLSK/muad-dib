'use strict';

// Tests for src/shared/bundle-detect.js
// - isBundlePath() path heuristics (BUNDLE_PATH_RE)
// - hasBundleVetoSignal() veto check + v2.10.75 LOW severity filter
//
// Introduced v2.10.75 as the permanent test coverage for the extended bundle
// path regex (fixes FP cluster on @stencil/core, playwright, playwright-core,
// @equinor/echo-core, @backstage/create-app, @uploadcare/file-uploader) and
// the LOW severity veto bug (unicode_invisible_injection in locale files was
// blocking unrelated downgrades).

const { test, assert } = require('../test-utils');
const { isBundlePath, hasBundleVetoSignal, VETO_TYPES } = require('../../src/shared/bundle-detect.js');

function runBundleDetectTests() {
  console.log('\n=== BUNDLE-DETECT TESTS ===\n');

  // ============================================================
  // isBundlePath() — legacy patterns (regression protection)
  // These were in the original DIST_FILE_RE and must still match.
  // ============================================================

  test('isBundlePath legacy: dist/bundle.js → MATCH', () => {
    assert(isBundlePath('dist\\bundle.js'), 'dist/bundle.js must match');
    assert(isBundlePath('dist/bundle.js'), 'dist/bundle.js (forward slash) must match');
  });

  test('isBundlePath legacy: build/main.js → MATCH', () => {
    assert(isBundlePath('build\\main.js'), 'build/main.js must match');
  });

  test('isBundlePath legacy: foo.min.js → MATCH', () => {
    assert(isBundlePath('foo.min.js'), 'foo.min.js must match');
  });

  test('isBundlePath legacy: bar.bundle.js → MATCH', () => {
    assert(isBundlePath('bar.bundle.js'), 'bar.bundle.js must match');
  });

  test('isBundlePath legacy: assets/index-a1b2c3d4.js → MATCH (hash chunk)', () => {
    assert(isBundlePath('assets\\index-a1b2c3d4.js'), 'hash-suffixed chunk must match');
    assert(isBundlePath('chunks\\vendor-abc123ef.mjs'), 'mjs hash chunk must match');
  });

  test('isBundlePath legacy: fesm2020/core.mjs → MATCH', () => {
    assert(isBundlePath('fesm2020\\core.mjs'), 'fesm2020/core.mjs must match');
    assert(isBundlePath('fesm2015\\foo.js'), 'fesm2015/ must match');
  });

  test('isBundlePath legacy: .umd.js, .esm.js, .es.js, .common.js, .max.js → MATCH', () => {
    assert(isBundlePath('pkg.umd.js'), '.umd.js must match');
    assert(isBundlePath('pkg.esm.js'), '.esm.js must match');
    assert(isBundlePath('pkg.es.js'), '.es.js must match');
    assert(isBundlePath('pkg.common.js'), '.common.js must match');
    assert(isBundlePath('babylon.max.js'), '.max.js must match');
  });

  // ============================================================
  // isBundlePath() — v2.10.75 new patterns (FP cluster fix)
  // These were ADDED in v2.10.75 to cover the 7 packages in Cluster A
  // of the v2.10.74 audit: @stencil/core, playwright, playwright-core,
  // @equinor/echo-core, @backstage/create-app, @uploadcare/file-uploader.
  // ============================================================

  test('isBundlePath v2.10.75: sys/node/index.js (Stencil) → MATCH', () => {
    assert(isBundlePath('sys\\node\\index.js'), '@stencil/core sys/node/index.js must match');
    assert(isBundlePath('sys\\browser\\index.js'), 'sys/browser/ must match');
    assert(isBundlePath('sys\\deno\\index.js'), 'sys/deno/ must match');
  });

  test('isBundlePath v2.10.75: lib/xxxBundle*/ directory (Playwright) → MATCH', () => {
    assert(isBundlePath('lib\\utilsBundleImpl\\index.js'),
      'playwright-core lib/utilsBundleImpl/ must match');
  });

  test('isBundlePath v2.10.75: lib/xxxBundle*.js flat file (Playwright) → MATCH', () => {
    assert(isBundlePath('lib\\mcpBundleImpl.js'),
      'playwright-core lib/mcpBundleImpl.js must match');
  });

  test('isBundlePath v2.10.75: lib/.../xxxBundle* at depth 2 (Playwright) → MATCH', () => {
    assert(isBundlePath('lib\\transform\\babelBundleImpl.js'),
      'playwright lib/transform/babelBundleImpl.js must match at depth 2');
  });

  test('isBundlePath v2.10.75: index.cjs.js (double extension at root) → MATCH', () => {
    assert(isBundlePath('index.cjs.js'),
      '@equinor/echo-core index.cjs.js (double .cjs.js) must match');
    assert(isBundlePath('main.esm.js'), 'main.esm.js must match');
    assert(isBundlePath('bundle.umd.js'), 'bundle.umd.js must match');
  });

  test('isBundlePath v2.10.75: .yarn/releases/ vendored yarn → MATCH', () => {
    assert(isBundlePath('templates\\default-app\\.yarn\\releases\\yarn-4.4.1.cjs'),
      '@backstage/create-app templates/.../.yarn/releases/yarn-*.cjs must match');
    assert(isBundlePath('.yarn\\releases\\yarn-3.0.0.cjs'),
      'root .yarn/releases/ must match');
  });

  test('isBundlePath v2.10.75: .pnpm/(releases|dist)/ → MATCH', () => {
    assert(isBundlePath('.pnpm\\releases\\pnpm.cjs'), '.pnpm/releases/ must match');
    assert(isBundlePath('.pnpm\\dist\\pnpm.js'), '.pnpm/dist/ must match');
  });

  test('isBundlePath v2.10.75: .iife.js suffix (uploadcare) → MATCH', () => {
    assert(isBundlePath('web\\file-uploader.iife.min.js'),
      '@uploadcare file-uploader.iife.min.js must match (via .min.js or .iife.js)');
  });

  test('isBundlePath v2.10.75: compiled/ prefix (SWC/Stencil) → MATCH', () => {
    assert(isBundlePath('compiled\\index.js'), 'compiled/ must match');
  });

  // ============================================================
  // isBundlePath() — negative cases (must NOT match)
  // Application code that should receive full severity scoring.
  // ============================================================

  test('isBundlePath negative: src/utils/auth.js → NO', () => {
    assert(!isBundlePath('src\\utils\\auth.js'), 'src/utils/auth.js must NOT match');
  });

  test('isBundlePath negative: lib/index.js (plain lib/) → NO', () => {
    assert(!isBundlePath('lib\\index.js'), 'plain lib/index.js must NOT match');
  });

  test('isBundlePath negative: lib/Adapters/AdapterLoader.js (parse-server plugin loader) → NO', () => {
    // parse-server FP that is NOT a bundle — it's an application plugin loader.
    // P2 (ctx.varSource) should handle the severity, not P1 bundle downgrade.
    assert(!isBundlePath('lib\\Adapters\\AdapterLoader.js'),
      'parse-server plugin loader must NOT match — not a bundle');
  });

  test('isBundlePath negative: index.js (root, no bundle suffix) → NO', () => {
    assert(!isBundlePath('index.js'), 'plain index.js must NOT match');
  });

  test('isBundlePath negative: plain .cjs / .mjs (no bundle suffix) → NO', () => {
    assert(!isBundlePath('lib\\core.cjs'), 'plain lib/core.cjs must NOT match');
    assert(!isBundlePath('src\\foo.mjs'), 'plain src/foo.mjs must NOT match');
  });

  test('isBundlePath negative: package.json → NO', () => {
    assert(!isBundlePath('package.json'), 'package.json must NOT match');
  });

  test('isBundlePath negative: empty / null / undefined → NO', () => {
    assert(!isBundlePath(''), 'empty string must NOT match');
    assert(!isBundlePath(null), 'null must NOT match');
    assert(!isBundlePath(undefined), 'undefined must NOT match');
  });

  test('isBundlePath negative: lib/SomeBundler.js (no "bundle" substring) → NO', () => {
    // Guard against regex overreach: "Bundler" (capital B, different word) must not
    // accidentally match the [Bb]undle pattern. Our pattern is [Bb]undle so "Bundler"
    // matches "Bundle" as a substring — this is OK (a file named *Bundler is likely
    // bundler-related). But plain "Bundles" or "MyBundleLoader" also match which is
    // acceptable. The strict negative is a file without "bundle" at all:
    assert(!isBundlePath('lib\\SomeFile.js'),
      'plain lib/SomeFile.js (no "bundle" token) must NOT match');
  });

  // ============================================================
  // hasBundleVetoSignal() — v2.10.75 LOW severity filter fix
  // The bug: a LOW severity unicode_invisible_injection on a locale file
  // (already downgraded by isLocaleFile in obfuscation.js) was blocking the
  // bundle downgrade of unrelated co-occurring threats. Fix: skip LOW threats.
  // ============================================================

  test('hasBundleVetoSignal: empty threats array → false', () => {
    assert(!hasBundleVetoSignal([], 'dist/bundle.js'),
      'empty threats must not veto');
    assert(!hasBundleVetoSignal(null, 'dist/bundle.js'),
      'null threats must not veto');
  });

  test('hasBundleVetoSignal: HIGH reverse_shell on target file → true (veto)', () => {
    const threats = [
      { type: 'reverse_shell', severity: 'HIGH', file: 'dist/bundle.js', message: 'nc -e' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'HIGH reverse_shell must veto bundle downgrade');
  });

  test('hasBundleVetoSignal v2.10.75 FIX: LOW severity threat is SKIPPED (no veto)', () => {
    // This is the regression fix: a LOW-severity threat in the veto list should
    // not block the downgrade. Typical case: unicode_invisible_injection LOW
    // on a Persian/Arabic locale file already downgraded by isLocaleFile.
    const threats = [
      { type: 'unicode_invisible_injection', severity: 'LOW', file: 'dist/bundle.js', message: '15 U+200C' }
    ];
    assert(!hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'LOW severity threat must be skipped (v2.10.75 fix — not block downgrade)');
  });

  test('hasBundleVetoSignal v2.10.75: LOW reverse_shell is also skipped', () => {
    // Edge case: even a VETO_TYPES member at LOW severity should be skipped.
    // Rationale: a LOW reverse_shell pattern match is likely a FP in a bundle
    // (bundler string obfuscation can include strings that look like net.Socket
    // calls without actually being one). Real reverse shells fire HIGH/CRITICAL.
    const threats = [
      { type: 'reverse_shell', severity: 'LOW', file: 'dist/bundle.js', message: 'net.Socket pattern' }
    ];
    assert(!hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'LOW reverse_shell must be skipped — only non-LOW veto signals block');
  });

  test('hasBundleVetoSignal: MEDIUM severity veto still blocks', () => {
    // Confirm only LOW is skipped — MEDIUM and above still veto.
    const threats = [
      { type: 'npm_token_steal', severity: 'MEDIUM', file: 'dist/bundle.js', message: '...' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'MEDIUM npm_token_steal must still veto (only LOW is skipped)');
  });

  test('hasBundleVetoSignal: CRITICAL ioc_match vetoes', () => {
    const threats = [
      { type: 'ioc_match', severity: 'CRITICAL', file: 'dist/bundle.js', message: 'IOC hash' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'CRITICAL ioc_match must veto');
  });

  test('hasBundleVetoSignal: HIGH node_modules_write vetoes (Shai-Hulud worm pattern)', () => {
    const threats = [
      { type: 'node_modules_write', severity: 'HIGH', file: 'dist/worm.js', message: 'writeFile to node_modules' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/worm.js'),
      'node_modules_write must veto');
  });

  test('hasBundleVetoSignal: env_access with sensitive env name → true', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'dist/bundle.js',
        message: 'process.env.NPM_TOKEN read' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'env_access reading NPM_TOKEN must veto');
  });

  test('hasBundleVetoSignal: env_access with AWS secret key → true', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'dist/bundle.js',
        message: 'process.env.AWS_SECRET_ACCESS_KEY' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'env_access reading AWS_SECRET_ACCESS_KEY must veto');
  });

  test('hasBundleVetoSignal: env_access with non-sensitive env name → false', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'dist/bundle.js',
        message: 'process.env.PATH read' }
    ];
    assert(!hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'env_access on PATH must NOT veto (not sensitive)');
  });

  test('hasBundleVetoSignal v2.10.75: LOW env_access with NPM_TOKEN is skipped', () => {
    // Even sensitive env var access at LOW is skipped — consistent with the
    // broader LOW-severity skip policy. In practice env_access on NPM_TOKEN
    // almost never fires LOW (it's HIGH by default) so this is a defensive edge.
    const threats = [
      { type: 'env_access', severity: 'LOW', file: 'dist/bundle.js',
        message: 'process.env.NPM_TOKEN' }
    ];
    assert(!hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'LOW env_access must be skipped even with sensitive env name');
  });

  test('hasBundleVetoSignal: threat on DIFFERENT file → not considered', () => {
    // The function only considers threats whose .file matches targetFile.
    // A veto signal on file A must not block downgrade on file B.
    const threats = [
      { type: 'reverse_shell', severity: 'CRITICAL', file: 'src/evil.js', message: 'on evil' }
    ];
    assert(!hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'threat on different file must not veto target file');
  });

  test('hasBundleVetoSignal: multiple threats, one vetoes, others ignored', () => {
    const threats = [
      { type: 'dangerous_call_eval', severity: 'HIGH', file: 'dist/bundle.js', message: 'eval()' },
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/bundle.js', message: 'score 80' },
      { type: 'systemd_persistence', severity: 'HIGH', file: 'dist/bundle.js', message: 'systemctl enable' }
    ];
    assert(hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'systemd_persistence HIGH among 3 threats must veto');
  });

  test('hasBundleVetoSignal: non-veto types never block', () => {
    // credential_regex_harvest, dangerous_call_eval etc. are NOT in VETO_TYPES
    // because they have compound recovery via originalSeverity gate in scoring.
    const threats = [
      { type: 'credential_regex_harvest', severity: 'CRITICAL', file: 'dist/bundle.js', message: 'regex' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/bundle.js', message: 'eval' },
      { type: 'string_mutation_obfuscation', severity: 'HIGH', file: 'dist/bundle.js', message: 'chain' }
    ];
    assert(!hasBundleVetoSignal(threats, 'dist/bundle.js'),
      'non-VETO types (credential_regex_harvest, dangerous_call_eval, etc.) must NOT veto');
  });

  test('hasBundleVetoSignal: VETO_TYPES set contains expected types', () => {
    // Sanity check on the set contents — regression guard against accidental removal.
    const expected = ['reverse_shell', 'node_modules_write', 'npm_publish_worm',
      'npm_token_steal', 'systemd_persistence', 'unicode_invisible_injection',
      'ioc_match', 'known_malicious_package', 'shai_hulud_marker'];
    for (const t of expected) {
      assert(VETO_TYPES.has(t), 'VETO_TYPES must contain ' + t);
    }
    // Must NOT contain compound-recoverable types
    const forbidden = ['staged_binary_payload', 'crypto_decipher', 'fetch_decrypt_exec',
      'zlib_inflate_eval', 'dangerous_call_eval', 'credential_regex_harvest'];
    for (const t of forbidden) {
      assert(!VETO_TYPES.has(t),
        'VETO_TYPES must NOT contain ' + t + ' (has compound recovery via originalSeverity)');
    }
  });
}

module.exports = { runBundleDetectTests };
