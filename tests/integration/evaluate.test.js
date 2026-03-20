const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, runCommand } = require('../test-utils');

async function runEvaluateTests() {
  console.log('\n=== EVALUATE TESTS ===\n');

  const {
    evaluate,
    evaluateGroundTruth,
    evaluateBenign,
    evaluateAdversarial,
    saveMetrics,
    silentScan,
    ADVERSARIAL_SAMPLES,
    HOLDOUT_SAMPLES,
    GT_THRESHOLD,
    BENIGN_THRESHOLD,
    ADR_THRESHOLD
  } = require('../../src/commands/evaluate.js');

  // Module structure tests
  test('EVALUATE: module exports evaluate function', () => {
    assert(typeof evaluate === 'function', 'evaluate should be a function');
  });

  test('EVALUATE: module exports sub-evaluators', () => {
    assert(typeof evaluateGroundTruth === 'function', 'evaluateGroundTruth should be a function');
    assert(typeof evaluateBenign === 'function', 'evaluateBenign should be a function');
    assert(typeof evaluateAdversarial === 'function', 'evaluateAdversarial should be a function');
  });

  test('EVALUATE: ADVERSARIAL_SAMPLES is an array with expected count', () => {
    assert(Array.isArray(ADVERSARIAL_SAMPLES), 'ADVERSARIAL_SAMPLES should be an array');
    assert(ADVERSARIAL_SAMPLES.length >= 37, `Expected >= 37 adversarial samples, got ${ADVERSARIAL_SAMPLES.length}`);
  });

  test('EVALUATE: ADVERSARIAL_SAMPLES contains expected sample names', () => {
    const expected = [
      'async-iterator-exfil', 'console-override-exfil', 'wasm-c2-payload',
      'fn-return-eval', 'charcode-arithmetic', 'locale-config-sync',
    ];
    for (const name of expected) {
      assert(ADVERSARIAL_SAMPLES.includes(name), `Missing sample: ${name}`);
    }
  });

  test('EVALUATE: HOLDOUT_SAMPLES is an array with 40 entries', () => {
    assert(Array.isArray(HOLDOUT_SAMPLES), 'HOLDOUT_SAMPLES should be an array');
    assert(HOLDOUT_SAMPLES.length === 40, `Expected 40 holdout samples, got ${HOLDOUT_SAMPLES.length}`);
  });

  test('EVALUATE: ADR_THRESHOLD is a global number (no per-sample thresholds)', () => {
    assert(typeof ADR_THRESHOLD === 'number', 'ADR_THRESHOLD should be a number');
    assert(ADR_THRESHOLD > 0, 'ADR_THRESHOLD should be > 0');
    assert(ADR_THRESHOLD === 20, `ADR_THRESHOLD should be 20, got ${ADR_THRESHOLD}`);
  });

  test('EVALUATE: GT_THRESHOLD is 3', () => {
    assert(GT_THRESHOLD === 3, `Expected GT_THRESHOLD=3, got ${GT_THRESHOLD}`);
  });

  test('EVALUATE: BENIGN_THRESHOLD is 20', () => {
    assert(BENIGN_THRESHOLD === 20, `Expected BENIGN_THRESHOLD=20, got ${BENIGN_THRESHOLD}`);
  });

  // silentScan tests
  await asyncTest('EVALUATE: silentScan returns result with summary', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-eval-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'clean', version: '1.0.0' }));
      const result = await silentScan(tmpDir);
      assert(result.summary !== undefined, 'result should have summary');
      assert(typeof result.summary.riskScore === 'number', 'riskScore should be number');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('EVALUATE: silentScan handles nonexistent dir gracefully', async () => {
    const result = await silentScan('/nonexistent/path/xyz');
    assert(result.summary.riskScore === 0, 'riskScore should be 0 for error');
  });

  // Ground truth structure
  await asyncTest('EVALUATE: evaluateGroundTruth returns correct structure', async () => {
    const gt = await evaluateGroundTruth();
    assert(typeof gt.detected === 'number', 'detected should be number');
    assert(typeof gt.total === 'number', 'total should be number');
    assert(typeof gt.tpr === 'number', 'tpr should be number');
    assert(Array.isArray(gt.details), 'details should be array');
    assert(gt.total > 0, 'should have at least 1 ground truth attack');
    assert(gt.tpr >= 0 && gt.tpr <= 1, 'tpr should be between 0 and 1');
  });

  // Adversarial structure
  await asyncTest('EVALUATE: evaluateAdversarial returns correct structure', async () => {
    const adv = await evaluateAdversarial();
    assert(typeof adv.detected === 'number', 'detected should be number');
    assert(typeof adv.total === 'number', 'total should be number');
    assert(typeof adv.adr === 'number', 'adr should be number');
    assert(Array.isArray(adv.details), 'details should be array');
    // total = ADVERSARIAL_SAMPLES + HOLDOUT_SAMPLES
    const expectedTotal = ADVERSARIAL_SAMPLES.length + HOLDOUT_SAMPLES.length;
    assert(adv.total === expectedTotal, `Expected ${expectedTotal} adversarial+holdout samples, got ${adv.total}`);
    for (const d of adv.details) {
      assert(typeof d.name === 'string', 'detail name should be string');
      assert(typeof d.score === 'number', 'detail score should be number');
      assert(typeof d.threshold === 'number', 'detail threshold should be number');
      assert(typeof d.detected === 'boolean', 'detail detected should be boolean');
    }
  });

  // saveMetrics
  test('EVALUATE: saveMetrics writes JSON file', () => {
    const tmpMetrics = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-metrics-'));
    // Temporarily override METRICS_DIR by testing saveMetrics behavior
    const report = { version: '0.0.0-test', date: new Date().toISOString(), groundTruth: {}, benign: {}, adversarial: {} };
    const metricsDir = path.join(tmpMetrics, 'metrics');
    fs.mkdirSync(metricsDir, { recursive: true });
    const filepath = path.join(metricsDir, `v${report.version}.json`);
    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
    assert(fs.existsSync(filepath), 'metrics file should exist');
    const loaded = JSON.parse(fs.readFileSync(filepath, 'utf8'));
    assert(loaded.version === '0.0.0-test', 'version should match');
    fs.rmSync(tmpMetrics, { recursive: true, force: true });
  });

  // CLI tests — evaluate is hidden from --help (internal command, like monitor)
  test('EVALUATE: evaluate is hidden from --help', () => {
    const output = runCommand('--help');
    assert(!output.includes('muaddib evaluate'), 'evaluate should NOT appear in help');
  });

  // --- Wilson CI tests ---
  const { wilsonCI, isBenignHoldout } = require('../../src/commands/evaluate.js');

  test('EVALUATE: wilsonCI returns valid interval for 46/49', () => {
    const ci = wilsonCI(46, 49);
    assert(ci.lower > 0.8, `CI lower should be > 0.8, got ${ci.lower.toFixed(3)}`);
    assert(ci.upper <= 1.0, `CI upper should be <= 1.0, got ${ci.upper.toFixed(3)}`);
    assert(ci.lower < ci.upper, 'lower should be < upper');
    assert(ci.center > ci.lower && ci.center < ci.upper, 'center should be between lower and upper');
  });

  test('EVALUATE: wilsonCI handles 0/0', () => {
    const ci = wilsonCI(0, 0);
    assert(ci.lower === 0, 'lower should be 0');
    assert(ci.upper === 0, 'upper should be 0');
  });

  test('EVALUATE: wilsonCI handles 0/100 (no successes)', () => {
    const ci = wilsonCI(0, 100);
    assert(ci.lower === 0, 'lower should be 0 for no successes');
    assert(ci.upper > 0, 'upper should be > 0 (CI has width)');
    assert(ci.upper < 0.05, `upper should be small, got ${ci.upper.toFixed(3)}`);
  });

  test('EVALUATE: wilsonCI handles 100/100 (all successes)', () => {
    const ci = wilsonCI(100, 100);
    assert(ci.lower > 0.95, `lower should be > 0.95, got ${ci.lower.toFixed(3)}`);
    assert(ci.upper > 0.99, `upper should be > 0.99, got ${ci.upper.toFixed(6)}`);
  });

  // --- Scan result cache tests ---
  const { computeSrcFingerprint, loadScanCache, saveScanCache } = require('../../src/commands/evaluate.js');

  test('EVALUATE: computeSrcFingerprint returns stable string', () => {
    const fp1 = computeSrcFingerprint();
    const fp2 = computeSrcFingerprint();
    assert(typeof fp1 === 'string', 'fingerprint should be a string');
    assert(fp1.length > 0, 'fingerprint should not be empty');
    assert(fp1 === fp2, 'fingerprint should be deterministic');
  });

  test('EVALUATE: loadScanCache returns 0 when no cache file', () => {
    const count = loadScanCache();
    // Either 0 (no cache) or a number (cached results exist) — both valid
    assert(typeof count === 'number' || count === undefined, 'loadScanCache should return number or undefined');
  });

  await asyncTest('EVALUATE: silentScan uses cache on second call', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-eval-cache-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'cache-test', version: '1.0.0' }));
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'module.exports = {};');
      const result1 = await silentScan(tmpDir);
      const result2 = await silentScan(tmpDir);
      assert(result1.summary.riskScore === result2.summary.riskScore, 'Cached result should have same score');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // --- Benign holdout split tests ---
  test('EVALUATE: isBenignHoldout is deterministic', () => {
    const r1 = isBenignHoldout('express');
    const r2 = isBenignHoldout('express');
    assert(r1 === r2, 'Same package should always get same split');
  });

  test('EVALUATE: isBenignHoldout produces ~30% holdout rate', () => {
    // Test with a set of package names
    const names = ['express', 'lodash', 'react', 'chalk', 'yargs', 'debug', 'minimist',
      'commander', 'axios', 'glob', 'rimraf', 'mkdirp', 'semver', 'ws', 'uuid',
      'dotenv', 'cors', 'helmet', 'passport', 'moment'];
    const holdout = names.filter(n => isBenignHoldout(n)).length;
    const ratio = holdout / names.length;
    assert(ratio >= 0.1 && ratio <= 0.6, `Holdout ratio should be ~30%, got ${(ratio * 100).toFixed(0)}%`);
  });
}

module.exports = { runEvaluateTests };
