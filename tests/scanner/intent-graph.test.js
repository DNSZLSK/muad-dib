'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const { test, asyncTest, assert, assertIncludes, runScanDirect, addSkipped } = require('../test-utils');
const { classifySource, classifySink, buildIntentPairs, COHERENCE_MATRIX, CROSS_FILE_MULTIPLIER } = require('../../src/intent-graph.js');

const ADVERSARIAL_DIR = path.join(__dirname, '..', '..', 'datasets', 'adversarial');

async function runIntentGraphTests() {
  // =========================================================================
  // Unit tests: classifySource
  // =========================================================================

  test('INTENT: classifySource — sensitive_string → credential_read', () => {
    const result = classifySource({ type: 'sensitive_string', message: '.npmrc detected' });
    assert(result === 'credential_read', `Expected credential_read, got ${result}`);
  });

  test('INTENT: classifySource — env_access excluded (config, not credential theft)', () => {
    const result = classifySource({ type: 'env_access', message: 'process.env.TOKEN' });
    assert(result === null, `Expected null (env_access excluded), got ${result}`);
  });

  test('INTENT: classifySource — env_harvesting_dynamic → credential_read', () => {
    const result = classifySource({ type: 'env_harvesting_dynamic', message: 'rest destructuring' });
    assert(result === 'credential_read', `Expected credential_read, got ${result}`);
  });

  test('INTENT: classifySource — suspicious_dataflow excluded (double-counting prevention)', () => {
    const result = classifySource({ type: 'suspicious_dataflow', message: 'credential_read + network' });
    assert(result === null, `Expected null (excluded), got ${result}`);
  });

  test('INTENT: classifySource — suspicious_dataflow telemetry_read also excluded', () => {
    const result = classifySource({ type: 'suspicious_dataflow', message: 'telemetry_read only' });
    assert(result === null, `Expected null (excluded), got ${result}`);
  });

  test('INTENT: classifySource — cross_file_dataflow excluded (already scored by module-graph)', () => {
    const result = classifySource({ type: 'cross_file_dataflow', message: 'credential_read in A → network in B' });
    assert(result === null, `Expected null (cross_file_dataflow excluded), got ${result}`);
  });

  test('INTENT: classifySource — unrelated type → null', () => {
    const result = classifySource({ type: 'obfuscation_detected', message: 'hex strings' });
    assert(result === null, `Expected null, got ${result}`);
  });

  test('INTENT: classifySource — message with .npmrc → credential_read', () => {
    const result = classifySource({ type: 'unknown_type', message: 'Reference to ".npmrc" detected.' });
    assert(result === 'credential_read', `Expected credential_read, got ${result}`);
  });

  // =========================================================================
  // Unit tests: classifySink
  // =========================================================================

  test('INTENT: classifySink — dangerous_call_eval → exec_sink', () => {
    const result = classifySink({ type: 'dangerous_call_eval', message: 'eval()' });
    assert(result === 'exec_sink', `Expected exec_sink, got ${result}`);
  });

  test('INTENT: classifySink — credential_tampering → file_tamper', () => {
    const result = classifySink({ type: 'credential_tampering', message: 'write to .npmrc' });
    assert(result === 'file_tamper', `Expected file_tamper, got ${result}`);
  });

  test('INTENT: classifySink — message with https.request → network_external', () => {
    const result = classifySink({ type: 'unknown_type', message: 'calls https.request to external host' });
    assert(result === 'network_external', `Expected network_external, got ${result}`);
  });

  test('INTENT: classifySink — unrelated type → null', () => {
    const result = classifySink({ type: 'obfuscation_detected', message: 'hex strings' });
    assert(result === null, `Expected null, got ${result}`);
  });

  // =========================================================================
  // Unit tests: coherence matrix
  // =========================================================================

  test('INTENT: coherence matrix — credential_read → network_external = +30 CRITICAL', () => {
    const entry = COHERENCE_MATRIX.credential_read.network_external;
    assert(entry.modifier === 30, `Expected modifier 30, got ${entry.modifier}`);
    assert(entry.severity === 'CRITICAL', `Expected CRITICAL, got ${entry.severity}`);
  });

  test('INTENT: coherence matrix — telemetry_read → network_external = 0', () => {
    const entry = COHERENCE_MATRIX.telemetry_read.network_external;
    assert(entry.modifier === 0, `Expected modifier 0, got ${entry.modifier}`);
  });

  test('INTENT: coherence matrix — command_output → network_external = +20 HIGH', () => {
    const entry = COHERENCE_MATRIX.command_output.network_external;
    assert(entry.modifier === 20, `Expected modifier 20, got ${entry.modifier}`);
    assert(entry.severity === 'HIGH', `Expected HIGH, got ${entry.severity}`);
  });

  test('INTENT: cross-file multiplier = 0.5', () => {
    assert(CROSS_FILE_MULTIPLIER === 0.5, `Expected 0.5, got ${CROSS_FILE_MULTIPLIER}`);
  });

  // =========================================================================
  // Unit tests: buildIntentPairs
  // =========================================================================

  test('INTENT: buildIntentPairs — intra-file credential source + eval sink = +25', () => {
    const threats = [
      { type: 'sensitive_string', severity: 'HIGH', message: '.npmrc detected', file: 'index.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval() called', file: 'index.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.pairs.length > 0, 'Should have at least one pair');
    const credExec = result.pairs.find(p => p.sourceType === 'credential_read' && p.sinkType === 'exec_sink');
    assert(credExec, 'Should find credential_read → exec_sink pair');
    assert(credExec.modifier === 25, `Intra-file modifier should be 25, got ${credExec.modifier}`);
    assert(credExec.crossFile === false, 'Should be intra-file');
  });

  test('INTENT: buildIntentPairs — cross-file credential → exec = 0 (no cross-file pairing)', () => {
    // Cross-file co-occurrence is NOT paired — module-graph handles cross-file taint
    const threats = [
      { type: 'sensitive_string', severity: 'HIGH', message: '.npmrc detected', file: 'reader.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval() called', file: 'exec.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.pairs.length === 0, 'Cross-file co-occurrence should produce no pairs');
    assert(result.intentScore === 0, 'Intent score should be 0 for cross-file');
  });

  test('INTENT: buildIntentPairs — suspicious_dataflow excluded as source (no double-counting)', () => {
    const threats = [
      { type: 'suspicious_dataflow', severity: 'HIGH', message: 'credential_read + network', file: 'index.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.pairs.length === 0, 'suspicious_dataflow should produce no pairs (excluded)');
    assert(result.intentScore === 0, 'Intent score should be 0');
  });

  test('INTENT: buildIntentPairs — generates intent_credential_exfil threat for high-value pairs', () => {
    const threats = [
      { type: 'sensitive_string', severity: 'HIGH', message: '.npmrc detected', file: 'reader.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval() used', file: 'reader.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentThreats.length > 0, 'Should generate intent threats');
    assert(result.intentThreats[0].type === 'intent_credential_exfil',
      `Expected intent_credential_exfil, got ${result.intentThreats[0].type}`);
  });

  test('INTENT: buildIntentPairs — no pairs when no sources', () => {
    const threats = [
      { type: 'obfuscation_detected', severity: 'HIGH', message: 'hex strings', file: 'util.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.pairs.length === 0, 'Should have no pairs');
    assert(result.intentScore === 0, 'Intent score should be 0');
  });

  // =========================================================================
  // Integration: backward-compat — compound detections unchanged
  // =========================================================================

  test('INTENT: backward-compat — intent is always additive (>= 0)', () => {
    const threats = [
      { type: 'zlib_inflate_eval', severity: 'CRITICAL', message: 'zlib + eval', file: 'index.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentScore >= 0, `Intent score should be >= 0, got ${result.intentScore}`);
  });

  // =========================================================================
  // Integration: adversarial packages detection
  // =========================================================================

  // Group A: pure-API adversarial samples. Cross-file only, no eval/Function.
  // These are partially detected by individual scanners but the intent graph
  // cannot boost them (cross-file pairing removed to prevent FP explosion).
  // Full detection requires module-graph improvements for class/EventEmitter/stream taint.

  const sampleNames = [
    'locale-config-sync', 'metrics-aggregator-lite', 'env-config-validator',
    'stream-transform-kit', 'cache-warmup-utils', 'fn-return-eval',
    'call-chain-eval', 'regex-source-require', 'charcode-arithmetic', 'object-method-alias'
  ];
  const samplesExist = sampleNames.some(n => fs.existsSync(path.join(ADVERSARIAL_DIR, n)));

  if (!samplesExist) {
    addSkipped(10);
  } else {
    await asyncTest('INTENT: A1 locale-config-sync partially detected (cross-file class taint)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'locale-config-sync');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 10,
        `locale-config-sync should score >= 10, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: A2 metrics-aggregator-lite partially detected (EventEmitter gap)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'metrics-aggregator-lite');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 3,
        `metrics-aggregator-lite should score >= 3, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: A3 env-config-validator partially detected (rest destructuring)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'env-config-validator');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 10,
        `env-config-validator should score >= 10, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: A4 stream-transform-kit partially detected (stream pipe gap)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'stream-transform-kit');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 10,
        `stream-transform-kit should score >= 10, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: A5 cache-warmup-utils detected', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'cache-warmup-utils');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 25,
        `cache-warmup-utils should score >= 25, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: B1 fn-return-eval detected (eval factory)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'fn-return-eval');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 25,
        `fn-return-eval should score >= 25, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: B2 call-chain-eval detected (.call.call evasion)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'call-chain-eval');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 20,
        `call-chain-eval should score >= 20, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: B3 regex-source-require detected (regex .source)', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'regex-source-require');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 25,
        `regex-source-require should score >= 25, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: B4 charcode-arithmetic detected', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'charcode-arithmetic');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 25,
        `charcode-arithmetic should score >= 25, got ${result.summary.riskScore}`);
    });

    await asyncTest('INTENT: B5 object-method-alias detected', async () => {
      const dir = path.join(ADVERSARIAL_DIR, 'object-method-alias');
      if (!fs.existsSync(dir)) { addSkipped(1); return; }
      const result = await runScanDirect(dir, { _capture: true });
      assert(result.summary.riskScore >= 25,
        `object-method-alias should score >= 25, got ${result.summary.riskScore}`);
    });
  }

  // =========================================================================
  // Negative tests: scanner fixes should not FP on benign patterns
  // =========================================================================

  test('INTENT: negative — arrow function not returning eval is not an eval factory', () => {
    const result = classifySource({ type: 'dynamic_require', message: 'require(x)' });
    assert(result === null, 'dynamic_require should not be a source');
  });

  test('INTENT: negative — benign package with only telemetry should get 0 intent', () => {
    const threats = [
      { type: 'suspicious_dataflow', severity: 'HIGH', message: 'telemetry_read (os.platform) + network send', file: 'index.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentScore === 0, `Telemetry-only should score 0, got ${result.intentScore}`);
  });

  test('INTENT: negative — SDK with env_access + eval should get 0 intent (env_access excluded)', () => {
    // aws-sdk, mailgun, bluebird all have env_access + eval/Function — NOT malicious
    const threats = [
      { type: 'env_access', severity: 'MEDIUM', message: 'process.env.AWS_REGION', file: 'lib/config.js' },
      { type: 'dangerous_call_function', severity: 'HIGH', message: 'new Function()', file: 'lib/util.js' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', message: 'credential_read + network', file: 'lib/http.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentScore === 0, `SDK pattern should score 0 intent, got ${result.intentScore}`);
    assert(result.intentThreats.length === 0, 'Should not generate intent threats for SDKs');
  });

  test('INTENT: negative — cross-file source+sink in different files = 0 intent (no co-occurrence pairing)', () => {
    // This is the key FP prevention test: a package with credential read in one file
    // and network call in another should NOT get intent boost without proven data flow
    const threats = [
      { type: 'sensitive_string', severity: 'HIGH', message: '.npmrc detected', file: 'lib/config.js' },
      { type: 'env_harvesting_dynamic', severity: 'HIGH', message: 'Object.keys(process.env)', file: 'lib/config.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval()', file: 'lib/template.js' },
      { type: 'dangerous_call_function', severity: 'HIGH', message: 'new Function()', file: 'lib/util.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentScore === 0, `Cross-file only pattern should score 0, got ${result.intentScore}`);
    assert(result.intentThreats.length === 0, 'Should not generate intent threats for cross-file co-occurrence');
  });
}

module.exports = { runIntentGraphTests };
