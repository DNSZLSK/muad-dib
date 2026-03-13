'use strict';

const { test, assert } = require('../test-utils');
const { applyFPReductions, calculateRiskScore, computeGroupScore } = require('../../src/scoring.js');

async function runScoringHardeningTests() {
  console.log('\n=== SCORING HARDENING TESTS (v2.5.13) ===\n');

  // ===================================================================
  // H1: Per-file plugin loader — file with 5 dynamic_require → downgrade
  // ===================================================================
  test('H1: Per-file plugin loader — file with 5+ in same file → downgrade', () => {
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr1' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr2' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr3' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr4' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr5' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW', `File with 5+ should be LOW, got ${threats[0].severity}`);
    assert(threats[4].severity === 'LOW', `File with 5+ should be LOW, got ${threats[4].severity}`);
  });

  test('H1: Per-file plugin loader — file with 1 stays HIGH', () => {
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'a.js', message: 'dr1' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'b.js', message: 'dr2' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'c.js', message: 'dr3' },
      { type: 'dynamic_import', severity: 'HIGH', file: 'd.js', message: 'di1' },
      { type: 'dynamic_import', severity: 'HIGH', file: 'e.js', message: 'di2' }
    ];
    applyFPReductions(threats, null, null);
    // No individual file exceeds 4, so none should be downgraded
    assert(threats[0].severity === 'HIGH', `File with 1 should stay HIGH, got ${threats[0].severity}`);
    assert(threats[3].severity === 'HIGH', `File with 1 should stay HIGH, got ${threats[3].severity}`);
  });

  // ===================================================================
  // H2: Global >4 but no file >4 → no downgrade
  // ===================================================================
  test('H2: Global >4 but no file individually >4 → no downgrade', () => {
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'a.js', message: 'dr1' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'a.js', message: 'dr2' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'b.js', message: 'dr3' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'b.js', message: 'dr4' },
      { type: 'dynamic_import', severity: 'HIGH', file: 'c.js', message: 'di1' }
    ];
    applyFPReductions(threats, null, null);
    // Global count is 5, but a.js=2, b.js=2, c.js=1 — all under 4
    assert(threats[0].severity === 'HIGH', `a.js should stay HIGH, got ${threats[0].severity}`);
    assert(threats[2].severity === 'HIGH', `b.js should stay HIGH, got ${threats[2].severity}`);
  });

  // ===================================================================
  // H3: Lifecycle CRITICAL floor → packageScore >= 50
  // ===================================================================
  test('H3: Lifecycle CRITICAL floor → packageScore >= 50', () => {
    const threats = [
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json', message: 'curl|sh' }
    ];
    const result = calculateRiskScore(threats);
    assert(result.packageScore >= 50,
      `CRITICAL lifecycle should get floor 50, got ${result.packageScore}`);
    assert(result.riskLevel === 'HIGH' || result.riskLevel === 'CRITICAL',
      `Risk level should be HIGH+, got ${result.riskLevel}`);
  });

  // ===================================================================
  // H4: Lifecycle HIGH alone → no floor (stays at 10)
  // ===================================================================
  test('H4: Lifecycle HIGH alone → no floor', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'HIGH', file: 'package.json', message: 'preinstall' }
    ];
    const result = calculateRiskScore(threats);
    assert(result.packageScore === 10,
      `HIGH lifecycle should score 10 (no floor), got ${result.packageScore}`);
  });

  // ===================================================================
  // H5: Percentage guard 40% — type at 45% → NOT downgraded
  // ===================================================================
  test('H5: Percentage guard 40% — type at 45% → NOT downgraded', () => {
    // 5 dynamic_require out of 11 total = 45.5% — above 40% threshold
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr1' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr2' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr3' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr4' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr5' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr6' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr7' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr8' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr9' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr10' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: 'dr11' },
      // 11 dynamic_require only — ratio is 100%/24 — need other threats to set ratio
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'a.js', message: 'flow1' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'b.js', message: 'flow2' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'c.js', message: 'flow3' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'd.js', message: 'flow4' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'e.js', message: 'flow5' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'f.js', message: 'flow6' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'g.js', message: 'flow7' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'h.js', message: 'flow8' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'i.js', message: 'flow9' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'j.js', message: 'flow10' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'k.js', message: 'flow11' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'l.js', message: 'flow12' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'm.js', message: 'flow13' }
    ];
    // 11 dynamic_require / 24 total = 45.8% > 40%, so count threshold NOT applied
    // But per-file loader check: loader.js has 11 > 4, so those get LOW from plugin loader rule
    // The FP_COUNT_THRESHOLDS for dynamic_require (>10) won't fire because ratio > 40%
    applyFPReductions(threats, null, null);
    // They get LOW from the plugin loader per-file rule, not from count threshold
    assert(threats[0].severity === 'LOW', `Per-file should still downgrade, got ${threats[0].severity}`);
  });

  // ===================================================================
  // H6: Percentage guard 40% — type at 35% → downgraded if count > threshold
  // ===================================================================
  test('H6: Percentage guard 40% — type at 35% → downgraded via count threshold', () => {
    // 11 dynamic_require in same file, many other threats to bring ratio below 40%
    const threats = [];
    for (let i = 0; i < 11; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: `dr${i}` });
    }
    // Add 21 other threats to bring dynamic_require ratio to 11/32 = 34.4%
    for (let i = 0; i < 21; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: `f${i}.js`, message: `o${i}` });
    }
    applyFPReductions(threats, null, null);
    // Per-file: loader.js has 11 > 4 → LOW from plugin loader
    // Also FP_COUNT_THRESHOLDS: dynamic_require > 10 and ratio < 40% → LOW
    assert(threats[0].severity === 'LOW', `Should be LOW, got ${threats[0].severity}`);
  });

  // ===================================================================
  // H7: suspicious_dataflow 80% exception still works
  // ===================================================================
  test('H7: suspicious_dataflow at 75% IS downgraded (under 80% guard)', () => {
    const threats = [];
    // 6 dataflow + 2 other = 75%
    for (let i = 0; i < 6; i++) {
      threats.push({ type: 'suspicious_dataflow', severity: 'CRITICAL', file: `f${i}.js`, message: `flow${i}` });
    }
    threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: 'a.js', message: 'obf' });
    threats.push({ type: 'dangerous_call_function', severity: 'MEDIUM', file: 'b.js', message: 'call' });
    applyFPReductions(threats, null, null);
    // 6/8 = 75% < 80% and count > 3 → should be downgraded to LOW
    assert(threats[0].severity === 'LOW',
      `suspicious_dataflow at 75% should be LOW, got ${threats[0].severity}`);
  });

  // P7: suspicious_dataflow now has full bypass (like vm_code_execution).
  // The 80% ratio guard was removed — packages with >3 suspicious_dataflow are always SDKs.
  test('H7-P7: suspicious_dataflow at 90% IS downgraded (full bypass, no 80% guard)', () => {
    const threats = [];
    // 9 dataflow + 1 other = 90%
    for (let i = 0; i < 9; i++) {
      threats.push({ type: 'suspicious_dataflow', severity: 'CRITICAL', file: `f${i}.js`, message: `flow${i}` });
    }
    threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: 'a.js', message: 'obf' });
    applyFPReductions(threats, null, null);
    // P7: full bypass → downgraded regardless of ratio
    assert(threats[0].severity === 'LOW',
      `suspicious_dataflow at 90% should be LOW (P7 full bypass), got ${threats[0].severity}`);
  });

  // ===================================================================
  // Mixed per-file: one file > 4, another < 4
  // ===================================================================
  test('H-mixed: Only file exceeding threshold gets downgraded', () => {
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'plugins.js', message: 'dr1' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'plugins.js', message: 'dr2' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'plugins.js', message: 'dr3' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'plugins.js', message: 'dr4' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'plugins.js', message: 'dr5' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'index.js', message: 'dr-index' }
    ];
    applyFPReductions(threats, null, null);
    // plugins.js has 5 > 4 → LOW
    assert(threats[0].severity === 'LOW', `plugins.js should be LOW, got ${threats[0].severity}`);
    // index.js has 1 → stays HIGH
    assert(threats[5].severity === 'HIGH', `index.js should stay HIGH, got ${threats[5].severity}`);
  });

  // ===================================================================
  // CRITICAL package + file-level threats combined
  // ===================================================================
  test('H-lifecycle: CRITICAL lifecycle + file threats scores correctly', () => {
    const threats = [
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json', message: 'curl|sh' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'index.js', message: 'flow' }
    ];
    const result = calculateRiskScore(threats);
    // Package: 25 → floor 50, file: 10, total: 60
    assert(result.riskScore >= 60,
      `Should be at least 60 (floor 50 + file 10), got ${result.riskScore}`);
  });

  // ==========================================================================
  // FP-P5 Fix 5: Dist two-notch downgrade for bundler artifact types
  // ==========================================================================
  test('FP-P5 Fix5: bundler artifact eval in dist/ gets two-notch downgrade', () => {
    const threats = [
      { type: 'dangerous_call_eval', severity: 'HIGH', file: 'dist/bundle.js', message: 'eval()' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'dist/bundle.js', message: 'require(x)' },
      { type: 'obfuscation_detected', severity: 'MEDIUM', file: 'dist/bundle.js', message: 'obfusc' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW', `eval HIGH in dist/ should be LOW (two-notch), got ${threats[0].severity}`);
    assert(threats[1].severity === 'LOW', `dynamic_require HIGH in dist/ should be LOW (two-notch), got ${threats[1].severity}`);
    assert(threats[2].severity === 'LOW', `obfuscation MEDIUM in dist/ should be LOW (two-notch), got ${threats[2].severity}`);
  });

  // P7: env_access is now a DIST_BUNDLER_ARTIFACT_TYPE → two-notch downgrade in dist/
  test('FP-P5/P7: env_access in dist/ gets two-notch downgrade (now bundler artifact)', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'dist/index.js', message: 'env' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'build/main.js', message: 'flow' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW', `env_access HIGH in dist/ should be LOW (P7 two-notch), got ${threats[0].severity}`);
    assert(threats[1].severity === 'MEDIUM', `suspicious_dataflow HIGH in build/ should be MEDIUM (one-notch), got ${threats[1].severity}`);
  });

  test('FP-P5 Fix5: compound detection exempt from dist/ downgrade', () => {
    const threats = [
      { type: 'fetch_decrypt_exec', severity: 'CRITICAL', file: 'dist/payload.js', message: 'fetch+decrypt+eval' },
      { type: 'download_exec_binary', severity: 'CRITICAL', file: 'build/dropper.js', message: 'download+chmod+exec' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL', `fetch_decrypt_exec should stay CRITICAL in dist/, got ${threats[0].severity}`);
    assert(threats[1].severity === 'CRITICAL', `download_exec_binary should stay CRITICAL in build/, got ${threats[1].severity}`);
  });

  test('FP-P5 Fix5: CRITICAL bundler artifact in dist/ → MEDIUM (two-notch)', () => {
    const threats = [
      { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/vendor.min.js', message: 'eval' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'MEDIUM', `eval CRITICAL in dist/ should be MEDIUM (two-notch), got ${threats[0].severity}`);
  });

  // ==========================================================================
  // FP-P6 Fix 1: credential_regex_harvest count-based downgrade
  // ==========================================================================
  // P7: credential_regex_harvest threshold lowered from >4 to >2
  test('FP-P7: credential_regex_harvest >2 hits → LOW', () => {
    const threats = [];
    for (let i = 0; i < 4; i++) {
      threats.push({ type: 'credential_regex_harvest', severity: 'HIGH', file: 'lib/http.js', message: `regex${i}` });
    }
    // Add other threats to keep ratio below 40%
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `f${i}.js`, message: `env${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `credential_regex_harvest with 4 hits should be LOW (P7 threshold >2), got ${threats[0].severity}`);
  });

  test('FP-P7: credential_regex_harvest <=2 hits stays HIGH', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'steal.js', message: 'regex1' },
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'steal.js', message: 'regex2' },
      { type: 'env_access', severity: 'MEDIUM', file: 'a.js', message: 'env' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'HIGH',
      `credential_regex_harvest with 2 hits should stay HIGH, got ${threats[0].severity}`);
  });

  // ==========================================================================
  // FP-P6 Fix 2: remote_code_load + proxy_data_intercept NOT exempt from dist/
  // ==========================================================================
  test('FP-P6 Fix2: remote_code_load in dist/ gets downgrade (no longer exempt)', () => {
    const threats = [
      { type: 'remote_code_load', severity: 'CRITICAL', file: 'dist/bundle.js', message: 'fetch+eval' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'HIGH',
      `remote_code_load in dist/ should be HIGH (1-notch), got ${threats[0].severity}`);
  });

  test('FP-P6 Fix2: proxy_data_intercept in dist/ gets downgrade (no longer exempt)', () => {
    const threats = [
      { type: 'proxy_data_intercept', severity: 'CRITICAL', file: 'dist/vendor.js', message: 'proxy+net' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'HIGH',
      `proxy_data_intercept in dist/ should be HIGH (1-notch), got ${threats[0].severity}`);
  });

  test('FP-P6 Fix2: remote_code_load in source file stays CRITICAL', () => {
    const threats = [
      { type: 'remote_code_load', severity: 'CRITICAL', file: 'src/loader.js', message: 'fetch+eval' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `remote_code_load in src/ should stay CRITICAL, got ${threats[0].severity}`);
  });

  test('FP-P6 Fix2: fetch_decrypt_exec still exempt from dist/ downgrade', () => {
    const threats = [
      { type: 'fetch_decrypt_exec', severity: 'CRITICAL', file: 'dist/payload.js', message: 'fetch+decrypt+eval' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `fetch_decrypt_exec should stay CRITICAL in dist/ (still exempt), got ${threats[0].severity}`);
  });

  // ==========================================================================
  // FP-P7: env_access count-based downgrade (>10 → LOW)
  // ==========================================================================
  test('FP-P7: env_access >10 hits → LOW (config loader pattern)', () => {
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `config${i}.js`, message: `env${i}` });
    }
    // Add other threats to keep ratio below 40%
    for (let i = 0; i < 20; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: `f${i}.js`, message: `o${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `env_access with 12 hits should be LOW, got ${threats[0].severity}`);
  });

  test('FP-P7: env_access <=10 hits stays HIGH', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `config${i}.js`, message: `env${i}` });
    }
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: `f${i}.js`, message: `o${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'HIGH',
      `env_access with 5 hits should stay HIGH, got ${threats[0].severity}`);
  });

  // ==========================================================================
  // FP-P7: high_entropy_string count-based downgrade (>5 → LOW)
  // ==========================================================================
  test('FP-P7: high_entropy_string >5 hits → LOW (bundled data pattern)', () => {
    const threats = [];
    for (let i = 0; i < 8; i++) {
      threats.push({ type: 'high_entropy_string', severity: 'MEDIUM', file: `data${i}.js`, message: `entropy${i}` });
    }
    // Add other threats to keep ratio below 40%
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `f${i}.js`, message: `env${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `high_entropy_string with 8 hits should be LOW, got ${threats[0].severity}`);
  });

  test('FP-P7: high_entropy_string <=5 hits stays MEDIUM', () => {
    const threats = [];
    for (let i = 0; i < 3; i++) {
      threats.push({ type: 'high_entropy_string', severity: 'MEDIUM', file: `data${i}.js`, message: `entropy${i}` });
    }
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `f${i}.js`, message: `env${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'MEDIUM',
      `high_entropy_string with 3 hits should stay MEDIUM, got ${threats[0].severity}`);
  });

  // ==========================================================================
  // FP-P7: Extended DIST_FILE_RE — out/ and output/ directories
  // ==========================================================================
  test('FP-P7: bundler artifacts in out/ get two-notch downgrade', () => {
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'out/index.js', message: 'require(x)' },
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'output/bundle.js', message: 'obfusc' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW', `dynamic_require in out/ should be LOW (two-notch), got ${threats[0].severity}`);
    assert(threats[1].severity === 'LOW', `obfuscation in output/ should be LOW (two-notch), got ${threats[1].severity}`);
  });

  test('FP-P7: credential_regex_harvest in dist/ gets one-notch downgrade (not bundler artifact)', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'dist/http-client.js', message: 'Bearer regex' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'MEDIUM',
      `credential_regex_harvest in dist/ should be MEDIUM (1-notch, not bundler artifact), got ${threats[0].severity}`);
  });

  // ==========================================================================
  // FP-P7: suspicious_dataflow full bypass — 100% ratio still downgrades
  // ==========================================================================
  test('FP-P7: suspicious_dataflow at 100% IS downgraded (full bypass)', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'suspicious_dataflow', severity: 'CRITICAL', file: `f${i}.js`, message: `flow${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `suspicious_dataflow at 100% should be LOW (full bypass), got ${threats[0].severity}`);
  });

  test('FP-P7: suspicious_dataflow <=3 stays CRITICAL (below count threshold)', () => {
    const threats = [
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'a.js', message: 'flow1' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'b.js', message: 'flow2' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `suspicious_dataflow with 2 hits should stay CRITICAL, got ${threats[0].severity}`);
  });
}

module.exports = { runScoringHardeningTests };
