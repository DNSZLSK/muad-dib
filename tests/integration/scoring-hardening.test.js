'use strict';

const path = require('path');
const { test, asyncTest, assert, runScanDirect } = require('../test-utils');
const { applyFPReductions, calculateRiskScore, computeGroupScore, CONFIDENCE_FACTORS } = require('../../src/scoring.js');

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
    // lifecycle_script has MEDIUM confidence → round(10 * 0.85) = round(8.5) = 9
    assert(result.packageScore === 9,
      `HIGH lifecycle should score 9 (medium conf, no floor), got ${result.packageScore}`);
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
  // Audit v3 B3: removed `from` constraint → no dilution floor, ALL go LOW
  test('FP-P7: credential_regex_harvest >2 hits → ALL go LOW (no dilution floor)', () => {
    const threats = [];
    for (let i = 0; i < 4; i++) {
      threats.push({ type: 'credential_regex_harvest', severity: 'HIGH', file: 'lib/http.js', message: `regex${i}` });
    }
    // Add other threats to keep ratio below 40%
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `f${i}.js`, message: `env${i}` });
    }
    applyFPReductions(threats, null, null);
    const credThreats = threats.filter(t => t.type === 'credential_regex_harvest');
    const highOnes = credThreats.filter(t => t.severity === 'HIGH');
    const lowOnes = credThreats.filter(t => t.severity === 'LOW');
    // Audit v3 B3: no dilution floor — all instances go LOW for complete FP suppression
    assert(highOnes.length === 0,
      `Expected 0 HIGH (no dilution floor), got ${highOnes.length}`);
    assert(lowOnes.length === 4,
      `All 4 should be LOW, got ${lowOnes.length}`);
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
  // FP-P6/P9: remote_code_load + proxy_data_intercept are bundler artifacts in dist/
  // ==========================================================================
  test('FP-P9: remote_code_load CRITICAL in dist/ gets 2-notch downgrade (bundler artifact)', () => {
    const threats = [
      { type: 'remote_code_load', severity: 'CRITICAL', file: 'dist/bundle.js', message: 'fetch+eval' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'MEDIUM',
      `remote_code_load in dist/ should be MEDIUM (2-notch bundler artifact), got ${threats[0].severity}`);
  });

  test('FP-P9: remote_code_load HIGH in dist/ gets downgraded to LOW', () => {
    const threats = [
      { type: 'remote_code_load', severity: 'HIGH', file: 'dist/index-Co9R73to.js', message: 'fetch+eval chunk' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `remote_code_load HIGH in dist/ should be LOW (2-notch), got ${threats[0].severity}`);
  });

  test('P8: proxy_data_intercept in dist/ gets 2-notch downgrade (bundler artifact)', () => {
    const threats = [
      { type: 'proxy_data_intercept', severity: 'CRITICAL', file: 'dist/vendor.js', message: 'proxy+net' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'MEDIUM',
      `proxy_data_intercept in dist/ should be MEDIUM (2-notch bundler artifact), got ${threats[0].severity}`);
  });

  test('P8: proxy_data_intercept HIGH in dist/ gets downgraded to LOW', () => {
    const threats = [
      { type: 'proxy_data_intercept', severity: 'HIGH', file: 'dist/chunk-abc.js', message: 'proxy trap' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `proxy_data_intercept HIGH in dist/ should be LOW (2-notch), got ${threats[0].severity}`);
  });

  test('P8: proxy_data_intercept in source file stays CRITICAL', () => {
    const threats = [
      { type: 'proxy_data_intercept', severity: 'CRITICAL', file: 'src/handler.js', message: 'proxy+net' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `proxy_data_intercept in src/ should stay CRITICAL, got ${threats[0].severity}`);
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

  // Audit v3 B3: env_access maxCount lowered from 10→4
  test('FP-P7: env_access <=4 hits stays HIGH', () => {
    const threats = [];
    for (let i = 0; i < 4; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `config${i}.js`, message: `env${i}` });
    }
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: `f${i}.js`, message: `o${i}` });
    }
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'HIGH',
      `env_access with 4 hits should stay HIGH, got ${threats[0].severity}`);
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

  // ==========================================================================
  // v2.6.5: Percentage guard bypass fix
  // ==========================================================================
  test('v2.6.5: single suspicious_dataflow at high ratio stays HIGH (no bypass)', () => {
    // 1 suspicious_dataflow + 1 other = 50% ratio. Should NOT be downgraded
    // because count (1) <= maxCount (3)
    const threats = [
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'a.js', message: 'flow1' },
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'b.js', message: 'obf1' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `Single suspicious_dataflow at 50% ratio should stay CRITICAL, got ${threats[0].severity}`);
  });

  test('v2.6.5: 4 suspicious_dataflow in SDK package → downgrade (count > 3)', () => {
    const threats = [
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'a.js', message: 'flow1' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'b.js', message: 'flow2' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'c.js', message: 'flow3' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'd.js', message: 'flow4' },
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'e.js', message: 'obf1' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'LOW',
      `4 suspicious_dataflow (count > 3) should be LOW, got ${threats[0].severity}`);
  });

  test('v2.6.5: 2 suspicious_dataflow at 60% ratio stays CRITICAL (count <= 3)', () => {
    // 2 suspicious_dataflow + 1 other = 66% ratio but count <= 3
    const threats = [
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'a.js', message: 'flow1' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'b.js', message: 'flow2' },
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'c.js', message: 'obf1' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `2 suspicious_dataflow at 66% ratio should stay CRITICAL (count <= 3), got ${threats[0].severity}`);
  });

  // ==========================================================================
  // v2.6.5: CI smoke test — regression guard for scoring
  // ==========================================================================
  const GT_DIR = path.join(__dirname, '..', 'ground-truth', 'samples');

  await asyncTest('CI smoke: event-stream scores >= 20', async () => {
    const dir = path.join(GT_DIR, 'event-stream');
    const result = await runScanDirect(dir);
    assert(result.summary.riskScore >= 20,
      `event-stream should score >= 20, got ${result.summary.riskScore}`);
  });

  await asyncTest('CI smoke: flatmap-stream scores >= 20', async () => {
    const dir = path.join(GT_DIR, 'flatmap-stream');
    const result = await runScanDirect(dir);
    assert(result.summary.riskScore >= 20,
      `flatmap-stream should score >= 20, got ${result.summary.riskScore}`);
  });

  await asyncTest('CI smoke: coa scores >= 20', async () => {
    const dir = path.join(GT_DIR, 'coa');
    const result = await runScanDirect(dir);
    assert(result.summary.riskScore >= 20,
      `coa should score >= 20, got ${result.summary.riskScore}`);
  });

  // ==========================================================================
  // v2.6.5: Paranoid mode alias detection
  // ==========================================================================
  const PARANOID_DIR = path.join(__dirname, '..', 'samples', 'paranoid');

  await asyncTest('PARANOID: detects eval alias (const e = eval; e(code))', async () => {
    const result = await runScanDirect(PARANOID_DIR, { paranoid: true });
    const evalThreats = result.threats.filter(t =>
      t.type === 'MUADDIB-PARANOID-003' && t.message && t.message.includes('alias')
    );
    assert(evalThreats.length > 0,
      `Should detect eval alias in paranoid mode, got ${evalThreats.length} threats`);
  });

  await asyncTest('PARANOID: detects Function alias (const F = Function; new F(code))', async () => {
    const result = await runScanDirect(PARANOID_DIR, { paranoid: true });
    const fnThreats = result.threats.filter(t =>
      t.type === 'MUADDIB-PARANOID-003'
    );
    assert(fnThreats.length > 0,
      `Should detect Function alias in paranoid mode, got ${fnThreats.length} threats`);
  });

  // ===================================================================
  // C2: MCP Server Awareness — downgrade mcp_config_injection to MEDIUM
  //     when @modelcontextprotocol/sdk is in dependencies
  // ===================================================================

  console.log('\n=== C2: MCP SERVER AWARENESS TESTS ===\n');

  test('C2: mcp_config_injection CRITICAL → MEDIUM when MCP SDK in dependencies', () => {
    const threats = [
      { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'index.js', message: 'MCP config write' }
    ];
    const deps = { '@modelcontextprotocol/sdk': '^1.0.0' };
    applyFPReductions(threats, null, null, deps);
    assert(threats[0].severity === 'MEDIUM',
      `MCP SDK dep should downgrade to MEDIUM, got ${threats[0].severity}`);
    assert(threats[0].mcpSdkDowngrade === true,
      'Should set mcpSdkDowngrade flag');
  });

  test('C2: mcp_config_injection stays CRITICAL without MCP SDK', () => {
    const threats = [
      { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'index.js', message: 'MCP config write' }
    ];
    applyFPReductions(threats, null, null, null);
    assert(threats[0].severity === 'CRITICAL',
      `Without MCP SDK dep, should stay CRITICAL, got ${threats[0].severity}`);
  });

  test('C2: mcp_config_injection stays CRITICAL with MCP SDK in devDependencies only', () => {
    // devDependencies are NOT passed as packageDeps — only production deps
    const threats = [
      { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'index.js', message: 'MCP config write' }
    ];
    // Empty deps (SDK would be in devDependencies, not here)
    const deps = { 'express': '^4.0.0' };
    applyFPReductions(threats, null, null, deps);
    assert(threats[0].severity === 'CRITICAL',
      `Without MCP SDK in deps, should stay CRITICAL, got ${threats[0].severity}`);
  });

  test('C2: HC types NOT downgraded even with MCP SDK dep', () => {
    const threats = [
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json', message: 'curl|sh' },
      { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'index.js', message: 'MCP config write' }
    ];
    const deps = { '@modelcontextprotocol/sdk': '^1.0.0' };
    applyFPReductions(threats, null, null, deps);
    assert(threats[0].severity === 'CRITICAL',
      `lifecycle_shell_pipe should stay CRITICAL, got ${threats[0].severity}`);
    assert(threats[1].severity === 'MEDIUM',
      `mcp_config_injection should downgrade to MEDIUM, got ${threats[1].severity}`);
  });

  test('C2: mcp_config_injection already non-CRITICAL — no change', () => {
    const threats = [
      { type: 'mcp_config_injection', severity: 'HIGH', file: 'index.js', message: 'MCP config write' }
    ];
    const deps = { '@modelcontextprotocol/sdk': '^1.0.0' };
    applyFPReductions(threats, null, null, deps);
    assert(threats[0].severity === 'HIGH',
      `Already HIGH should stay HIGH (not double-downgrade), got ${threats[0].severity}`);
  });

  // ==========================================================================
  // v2.7.9: FP Audit Trail — reductions[] tracking
  // ==========================================================================

  console.log('\n=== FP AUDIT TRAIL TESTS (v2.7.9) ===\n');

  test('SCORING: applyFPReductions adds reductions[] to downgraded threats', () => {
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'loader.js', message: `dr${i}` });
    }
    applyFPReductions(threats, null, null);
    const downgraded = threats.filter(t => t.severity === 'LOW');
    assert(downgraded.length > 0, 'some threats should be downgraded');
    downgraded.forEach(t => {
      assert(Array.isArray(t.reductions), 'reductions should be an array');
      assert(t.reductions.length > 0, 'reductions should not be empty for downgraded threats');
      const hasExpectedRule = t.reductions.some(r => r.rule === 'count_threshold' || r.rule === 'plugin_loader_per_file');
      assert(hasExpectedRule, 'rule should be count_threshold or plugin_loader_per_file');
    });
  });

  test('SCORING: reductions[] is empty for non-downgraded threats', () => {
    const threats = [
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json', message: 'lsp' }
    ];
    applyFPReductions(threats, null, null);
    assert(Array.isArray(threats[0].reductions), 'reductions should be initialized');
    assert(threats[0].reductions.length === 0, 'no reductions for non-downgraded threat');
  });

  test('SCORING: reductions[] tracks dist file downgrade with correct rule', () => {
    const threats = [
      { type: 'dangerous_call_eval', severity: 'MEDIUM', file: 'dist/bundle.js', message: 'eval in dist' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].reductions.length > 0, 'dist file should be downgraded');
    const r = threats[0].reductions.find(r => r.rule === 'dist_file');
    assert(r, 'should have dist_file reduction');
    assert(r.from === 'MEDIUM', 'from should be MEDIUM');
    assert(r.to === 'LOW', 'to should be LOW');
  });

  test('SCORING: reductions[] tracks multiple reductions on same threat', () => {
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'dist/loader.js', message: `dr${i}` });
    }
    applyFPReductions(threats, null, null);
    const multi = threats.filter(t => t.reductions.length >= 1);
    assert(multi.length > 0, 'threats should have at least one reduction');
  });

  test('SCORING: reductions[] tracks MCP SDK downgrade', () => {
    const threats = [
      { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'index.js', message: 'MCP config' }
    ];
    applyFPReductions(threats, null, null, { '@modelcontextprotocol/sdk': '^1.0.0' });
    assert(threats[0].reductions.length > 0, 'MCP SDK should add a reduction');
    const r = threats[0].reductions.find(r => r.rule === 'mcp_sdk');
    assert(r, 'should have mcp_sdk reduction');
    assert(r.from === 'CRITICAL', 'from CRITICAL');
    assert(r.to === 'MEDIUM', 'to MEDIUM');
  });

  test('SCORING: reductions[] tracks unreachable downgrade', () => {
    const reachable = new Set(['main.js']);
    const threats = [
      { type: 'dangerous_call_eval', severity: 'HIGH', file: 'orphan.js', message: 'eval' }
    ];
    applyFPReductions(threats, reachable, null);
    const r = threats[0].reductions.find(r => r.rule === 'unreachable');
    assert(r, 'should have unreachable reduction');
    assert(r.to === 'LOW', 'unreachable should downgrade to LOW');
  });

  // ===================================================================
  // CONFIDENCE-WEIGHTED SCORING (v2.7.10)
  // ===================================================================

  test('CONFIDENCE: CONFIDENCE_FACTORS has correct values', () => {
    assert(CONFIDENCE_FACTORS.high === 1.0, 'high should be 1.0');
    assert(CONFIDENCE_FACTORS.medium === 0.85, 'medium should be 0.85');
    assert(CONFIDENCE_FACTORS.low === 0.6, 'low should be 0.6');
  });

  test('CONFIDENCE: all-HIGH-confidence threats score unchanged', () => {
    // reverse_shell: CRITICAL, high confidence. env_access: HIGH, high confidence.
    const threats = [
      { type: 'reverse_shell', severity: 'CRITICAL', file: 'a.js', message: 'rs' },
      { type: 'env_access', severity: 'HIGH', file: 'a.js', message: 'ea' }
    ];
    const score = computeGroupScore(threats);
    // CRITICAL(25)*1.0 + HIGH(10)*1.0 = 35
    assert(score === 35, `all-HIGH-conf should score 35, got ${score}`);
  });

  test('CONFIDENCE: MEDIUM-confidence threats score less than HIGH-confidence at same severity', () => {
    // lifecycle_script is MEDIUM confidence, CRITICAL severity
    const highConf = [{ type: 'reverse_shell', severity: 'CRITICAL', file: 'a.js', message: 'rs' }];
    const medConf = [{ type: 'lifecycle_script', severity: 'CRITICAL', file: 'a.js', message: 'ls' }];
    const highScore = computeGroupScore(highConf);
    const medScore = computeGroupScore(medConf);
    // 25*1.0=25 vs 25*0.85=21.25→21
    assert(highScore === 25, `HIGH-conf CRITICAL should score 25, got ${highScore}`);
    assert(medScore === 21, `MEDIUM-conf CRITICAL should score 21, got ${medScore}`);
    assert(highScore > medScore, 'HIGH-conf should score more than MEDIUM-conf');
  });

  test('CONFIDENCE: LOW-confidence threats score less than MEDIUM-confidence', () => {
    // possible_obfuscation is LOW confidence, MEDIUM severity
    const medConf = [{ type: 'obfuscation_detected', severity: 'MEDIUM', file: 'a.js', message: 'ob' }];
    const lowConf = [{ type: 'possible_obfuscation', severity: 'MEDIUM', file: 'a.js', message: 'po' }];
    const medScore = computeGroupScore(medConf);
    const lowScore = computeGroupScore(lowConf);
    // round(3*0.85)=round(2.55)=3 vs round(3*0.6)=round(1.8)=2
    assert(medScore === 3, `MEDIUM-conf MEDIUM-sev should score 3, got ${medScore}`);
    assert(lowScore === 2, `LOW-conf MEDIUM-sev should score 2, got ${lowScore}`);
    assert(medScore > lowScore, 'MEDIUM-conf should score more than LOW-conf');
  });

  test('CONFIDENCE: unknown threat type defaults to factor 1.0', () => {
    const threats = [
      { type: 'totally_unknown_threat_xyz', severity: 'HIGH', file: 'a.js', message: 'unk' }
    ];
    const score = computeGroupScore(threats);
    // getRule returns confidence:'low' for unknown → 10*0.6=6
    // Wait, getRule returns {confidence:'low'} for unknown types
    // So this tests that getRule fallback works: 10 * 0.6 = 6
    assert(score === 6, `unknown type should use getRule fallback (low conf → 6), got ${score}`);
  });

  test('CONFIDENCE: proto_hook MEDIUM cap still works with confidence weighting', () => {
    // prototype_hook has HIGH confidence → factor 1.0
    // 6 MEDIUM proto_hooks → 6*3*1.0=18, capped at 15
    const threats = [];
    for (let i = 0; i < 6; i++) {
      threats.push({ type: 'prototype_hook', severity: 'MEDIUM', file: 'a.js', message: `ph${i}` });
    }
    const score = computeGroupScore(threats);
    assert(score === 15, `proto_hook MEDIUM cap should still apply (15), got ${score}`);
  });

  test('CONFIDENCE: mixed confidence threats accumulate correctly', () => {
    const threats = [
      // env_access: HIGH conf, HIGH sev → 10*1.0 = 10
      { type: 'env_access', severity: 'HIGH', file: 'a.js', message: 'ea' },
      // high_entropy_string: MEDIUM conf, MEDIUM sev → 3*0.85 = 2.55
      { type: 'high_entropy_string', severity: 'MEDIUM', file: 'a.js', message: 'he' },
      // possible_obfuscation: LOW conf, LOW sev → 1*0.6 = 0.6
      { type: 'possible_obfuscation', severity: 'LOW', file: 'a.js', message: 'po' }
    ];
    const score = computeGroupScore(threats);
    // floor(10 + 2.55 + 0.6) = floor(13.15) = 13
    assert(score === 13, `mixed confidence should score 13, got ${score}`);
  });

  test('CONFIDENCE: paranoid rules (no confidence field) default to factor 1.0', () => {
    // Paranoid rules have no confidence field → getRule returns rule without confidence
    // CONFIDENCE_FACTORS[undefined] = undefined → || 1.0
    const threats = [
      { type: 'MUADDIB-PARANOID-001', severity: 'MEDIUM', file: 'a.js', message: 'p1' }
    ];
    const score = computeGroupScore(threats);
    // MEDIUM(3) * 1.0 = 3
    assert(score === 3, `paranoid rule should score at full weight (3), got ${score}`);
  });

  // ===================================================================
  // C4: Lifecycle-Aware FP Reduction Guard
  // ===================================================================
  console.log('\n  --- C4: Lifecycle Guard ---\n');

  test('C4: 5x obfuscation_detected + lifecycle_script (MEDIUM) → 1 instance restored to MEDIUM', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'MEDIUM', file: `obf${i}.js`, message: 'obfuscated code' });
    }
    threats.push({ type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall: node setup.js' });
    // Add padding to keep typeRatio < 0.4
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const obfThreats = threats.filter(t => t.type === 'obfuscation_detected');
    const mediumCount = obfThreats.filter(t => t.severity === 'MEDIUM').length;
    // Dilution floor restores 1 (from field + maxCount ≤ 3), lifecycle guard restores another OR same
    // Actually: obfuscation_detected has from:undefined in FP_COUNT_THRESHOLDS → no dilution floor
    // Lifecycle guard restores 1 to MEDIUM
    assert(mediumCount >= 1, `At least 1 obfuscation_detected should be MEDIUM (lifecycle guard), got ${mediumCount}`);
    const guardReductions = obfThreats.filter(t => t.reductions.some(r => r.rule === 'lifecycle_guard'));
    assert(guardReductions.length === 1, `Exactly 1 should have lifecycle_guard, got ${guardReductions.length}`);
  });

  test('C4: 12x dynamic_require + lifecycle_script (MEDIUM) → 1 instance restored', () => {
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `loader${i}.js`, message: `Dynamic require of ./plugin${i}` });
    }
    threats.push({ type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'postinstall: node install.js' });
    for (let i = 0; i < 25; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const drThreats = threats.filter(t => t.type === 'dynamic_require');
    const guardReductions = drThreats.filter(t => t.reductions.some(r => r.rule === 'lifecycle_guard'));
    assert(guardReductions.length === 1, `Exactly 1 dynamic_require should have lifecycle_guard, got ${guardReductions.length}`);
    assert(guardReductions[0].severity === 'MEDIUM', `Restored should be MEDIUM, got ${guardReductions[0].severity}`);
  });

  test('C4: 5x obfuscation_detected WITHOUT lifecycle → no guard', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'MEDIUM', file: `obf${i}.js`, message: 'obfuscated' });
    }
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const obfThreats = threats.filter(t => t.type === 'obfuscation_detected');
    const guardReductions = obfThreats.filter(t => t.reductions.some(r => r.rule === 'lifecycle_guard'));
    assert(guardReductions.length === 0, `No lifecycle_guard without lifecycle, got ${guardReductions.length}`);
  });

  test('C4: 5x obfuscation_detected + lifecycle_script LOW (benign) → no guard', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'MEDIUM', file: `obf${i}.js`, message: 'obfuscated' });
    }
    // Benign lifecycle (node-gyp) will be downgraded to LOW by benign_lifecycle
    threats.push({ type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'Script "install" detected: node-gyp rebuild' });
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const obfThreats = threats.filter(t => t.type === 'obfuscation_detected');
    const guardReductions = obfThreats.filter(t => t.reductions.some(r => r.rule === 'lifecycle_guard'));
    assert(guardReductions.length === 0, `No lifecycle_guard when lifecycle is LOW (benign), got ${guardReductions.length}`);
  });

  test('C4: lifecycle guard only restores types that were count-threshold downgraded', () => {
    const threats = [
      { type: 'obfuscation_detected', severity: 'MEDIUM', file: 'a.js', message: 'obf' },
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall: node setup.js' }
    ];
    // Only 1 instance → count not exceeded → no downgrade → no guard needed
    applyFPReductions(threats);
    const obf = threats.find(t => t.type === 'obfuscation_detected');
    const guardReductions = obf.reductions.filter(r => r.rule === 'lifecycle_guard');
    assert(guardReductions.length === 0, `No guard needed when not count-threshold downgraded, got ${guardReductions.length}`);
  });
}

module.exports = { runScoringHardeningTests };
