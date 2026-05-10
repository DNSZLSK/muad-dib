'use strict';

const { test, assert } = require('../test-utils');
const {
  evaluateSandboxTrigger,
  TRIGGERS,
  SANDBOX_TRIGGER_MIN_SCORE,
  SANDBOX_TRIGGER_MAX_SCORE
} = require('../../src/sandbox/compound-triggers.js');

function runSandboxCompoundTriggersTests() {
  console.log('\n=== SANDBOX COMPOUND TRIGGERS TESTS ===\n');

  test('SANDBOX-COMPOUND: exports 6 triggers and bounds', () => {
    assert(Array.isArray(TRIGGERS), 'TRIGGERS must be an array');
    assert(TRIGGERS.length === 6, 'Expected 6 triggers, got ' + TRIGGERS.length);
    const names = TRIGGERS.map(t => t.name);
    for (const expected of [
      'lifecycle_install_chain',
      'stub_with_external_dep',
      'decrypt_then_execute',
      'invisible_blockchain',
      'npm_token_self_use',
      'obfuscated_oversize'
    ]) {
      assert(names.includes(expected), 'Missing compound: ' + expected);
    }
    assert(SANDBOX_TRIGGER_MIN_SCORE === 15, 'Min score must be 15');
    assert(SANDBOX_TRIGGER_MAX_SCORE === 35, 'Max score must be 35');
  });

  test('SANDBOX-COMPOUND: invalid input returns shouldRun=false', () => {
    assert(evaluateSandboxTrigger(null, 25).shouldRun === false, 'null threats');
    assert(evaluateSandboxTrigger([], NaN).shouldRun === false, 'NaN score');
    assert(evaluateSandboxTrigger('not array', 25).shouldRun === false, 'non-array threats');
  });

  test('SANDBOX-COMPOUND: score < 15 never triggers (Shai-Hulud pattern, low score)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM' },
      { type: 'credential_regex_harvest', severity: 'HIGH' }
    ];
    const r = evaluateSandboxTrigger(threats, 14);
    assert(r.shouldRun === false, 'Score 14 must not trigger');
    assert(r.compound === null, 'No compound at score 14');
  });

  test('SANDBOX-COMPOUND: score > 35 never triggers (already definitive)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'CRITICAL' },
      { type: 'credential_regex_harvest', severity: 'CRITICAL' }
    ];
    const r = evaluateSandboxTrigger(threats, 80);
    assert(r.shouldRun === false, 'Score 80 must not trigger');
    assert(r.reason === 'score above window', 'Reason should be above window');
  });

  test('SANDBOX-COMPOUND: lifecycle_install_chain matches Shai-Hulud (positif)', () => {
    const threats = [
      { type: 'lifecycle_added_critical', severity: 'CRITICAL', file: 'package.json' },
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'index.js' }
    ];
    const r = evaluateSandboxTrigger(threats, 25);
    assert(r.shouldRun === true, 'Should trigger');
    assert(r.compound === 'lifecycle_install_chain', 'Expected lifecycle_install_chain, got ' + r.compound);
    assert(r.watchpoints.length > 0, 'Should have watchpoints');
  });

  test('SANDBOX-COMPOUND: popular package with no compound match (negatif)', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'lib/index.js' },
      { type: 'github_api_call', severity: 'HIGH', file: 'lib/utils.js' }
    ];
    const r = evaluateSandboxTrigger(threats, 25);
    assert(r.shouldRun === false, 'Must not trigger on benign HIGH-only signals');
    assert(r.compound === null, 'No compound matched');
  });

  test('SANDBOX-COMPOUND: stub_with_external_dep matches ltidi chain', () => {
    const threats = [
      { type: 'stub_package_external_payload', severity: 'CRITICAL', file: 'package.json' },
      { type: 'external_tarball_dep', severity: 'CRITICAL', file: 'package.json' }
    ];
    const r = evaluateSandboxTrigger(threats, 28);
    assert(r.shouldRun === true, 'Should trigger');
    assert(r.compound === 'stub_with_external_dep', 'Expected stub_with_external_dep, got ' + r.compound);
  });

  test('SANDBOX-COMPOUND: decrypt_then_execute matches Axios 2026 OrDeR_7077', () => {
    const threats = [
      { type: 'anti_forensic_xor_autodelete', severity: 'CRITICAL', file: 'setup.js' },
      { type: 'dangerous_call_function', severity: 'HIGH', file: 'setup.js' }
    ];
    const r = evaluateSandboxTrigger(threats, 30);
    assert(r.shouldRun === true, 'Should trigger');
    assert(r.compound === 'decrypt_then_execute', 'Expected decrypt_then_execute, got ' + r.compound);
  });

  test('SANDBOX-COMPOUND: invisible_blockchain matches GlassWorm', () => {
    const threats = [
      { type: 'unicode_variation_decoder', severity: 'CRITICAL', file: 'extension.js' },
      { type: 'blockchain_rpc_endpoint', severity: 'MEDIUM', file: 'extension.js' }
    ];
    const r = evaluateSandboxTrigger(threats, 22);
    assert(r.shouldRun === true, 'Should trigger');
    assert(r.compound === 'invisible_blockchain', 'Expected invisible_blockchain, got ' + r.compound);
  });

  test('SANDBOX-COMPOUND: npm_token_self_use matches CanisterWorm', () => {
    const threats = [
      { type: 'npm_token_steal', severity: 'CRITICAL', file: 'index.js' },
      { type: 'remote_code_load', severity: 'HIGH', file: 'index.js' }
    ];
    const r = evaluateSandboxTrigger(threats, 30);
    assert(r.shouldRun === true, 'Should trigger');
    assert(r.compound === 'npm_token_self_use', 'Expected npm_token_self_use, got ' + r.compound);
  });

  test('SANDBOX-COMPOUND: obfuscated_oversize matches Shai-Hulud bun_environment.js (with size)', () => {
    const threats = [
      { type: 'js_obfuscation_pattern', severity: 'HIGH', file: 'bun_environment.js' },
      { type: 'staged_payload', severity: 'CRITICAL', file: 'bun_environment.js' }
    ];
    const fileSizes = { 'bun_environment.js': 10 * 1024 * 1024 };
    const r = evaluateSandboxTrigger(threats, 28, fileSizes);
    assert(r.shouldRun === true, 'Should trigger with 10MB obfuscated file');
    assert(r.compound === 'obfuscated_oversize', 'Expected obfuscated_oversize, got ' + r.compound);
  });

  test('SANDBOX-COMPOUND: obfuscated_oversize negatif when small obf file', () => {
    const threats = [
      { type: 'js_obfuscation_pattern', severity: 'HIGH', file: 'small.js' },
      { type: 'staged_payload', severity: 'CRITICAL', file: 'small.js' }
    ];
    const fileSizes = { 'small.js': 4096 };
    const r = evaluateSandboxTrigger(threats, 28, fileSizes);
    assert(r.compound !== 'obfuscated_oversize', 'Must not trigger oversize for tiny obf file');
  });

  test('SANDBOX-COMPOUND: trigger.matches errors are isolated (defensive)', () => {
    const brokenThreat = Object.create(null);
    Object.defineProperty(brokenThreat, 'type', {
      get() { throw new Error('boom'); }
    });
    const r = evaluateSandboxTrigger([brokenThreat], 25);
    assert(r.shouldRun === false, 'Defensive: errors must not throw');
  });
}

module.exports = { runSandboxCompoundTriggersTests };
