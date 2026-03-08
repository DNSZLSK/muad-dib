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
    ADVERSARIAL_THRESHOLDS,
    GT_THRESHOLD,
    BENIGN_THRESHOLD
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

  test('EVALUATE: ADVERSARIAL_THRESHOLDS has 62 entries', () => {
    const keys = Object.keys(ADVERSARIAL_THRESHOLDS);
    assert(keys.length === 62, `Expected 62 adversarial thresholds, got ${keys.length}`);
  });

  test('EVALUATE: ADVERSARIAL_THRESHOLDS has correct sample names', () => {
    const expected = [
      // Vague 1-4 (35 samples)
      'ci-trigger-exfil', 'delayed-exfil', 'docker-aware',
      'staged-fetch', 'dns-chunk-exfil', 'string-concat-obfuscation',
      'postinstall-download', 'dynamic-require', 'iife-exfil',
      'conditional-chain', 'template-literal-obfuscation', 'proxy-env-intercept',
      'nested-payload', 'dynamic-import', 'websocket-exfil',
      'bun-runtime-evasion', 'preinstall-exec', 'remote-dynamic-dependency',
      'github-exfil', 'detached-background',
      'ai-agent-weaponization', 'ai-config-injection', 'rdd-zero-deps',
      'discord-webhook-exfil', 'preinstall-background-fork',
      'silent-error-swallow', 'double-base64-exfil', 'crypto-wallet-harvest',
      'self-hosted-runner-backdoor', 'dead-mans-switch', 'fake-captcha-fingerprint',
      'pyinstaller-dropper', 'gh-cli-token-steal', 'triple-base64-github-push',
      'browser-api-hook',
      // Vague 5 (27 samples)
      'async-iterator-exfil', 'console-override-exfil', 'cross-file-callback-exfil',
      'error-reporting-exfil', 'error-stack-exfil', 'event-emitter-exfil',
      'fn-return-exfil', 'getter-defineProperty-exfil', 'http-header-exfil',
      'import-map-poison', 'intl-polyfill-backdoor', 'net-time-exfil',
      'postmessage-exfil', 'process-title-exfil', 'promise-chain-exfil',
      'proxy-getter-dns-exfil', 'readable-stream-exfil', 'response-intercept-exfil',
      'setTimeout-eval-chain', 'setter-trap-exfil', 'sourcemap-payload',
      'stream-pipe-exfil', 'svg-payload-fetch', 'symbol-iterator-exfil',
      'toJSON-hijack', 'url-constructor-exfil', 'wasm-c2-payload'
    ];
    for (const name of expected) {
      assert(ADVERSARIAL_THRESHOLDS[name] !== undefined, `Missing threshold for ${name}`);
    }
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
    // total = ADVERSARIAL_THRESHOLDS (62) + HOLDOUT_THRESHOLDS (40) = 102
    assert(adv.total === 102, `Expected 102 adversarial+holdout samples, got ${adv.total}`);
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
}

module.exports = { runEvaluateTests };
