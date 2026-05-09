'use strict';

const { test, assert } = require('../test-utils');
const { applyCompoundBoosts, applyFPReductions } = require('../../src/scoring.js');

function _seedReductions(threats) {
  // applyCompoundBoosts expects originalSeverity ; applyFPReductions sets it.
  // Use a no-op applyFPReductions call (no reachableFiles, packageDeps) to
  // populate the field without changing severities.
  applyFPReductions(threats, null, null, null);
}

function runCompoundTighteningTests() {
  console.log('\n=== COMPOUND TIGHTENING TESTS (Chantier 7) ===\n');

  // ---------------------------------------------------------------------------
  // excludeIfBundled gate on lifecycle_dataflow
  // ---------------------------------------------------------------------------

  test('lifecycle_dataflow: fires when dataflow is in src/', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'lib/exfil.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_dataflow');
    assert(compound !== undefined, 'compound should fire');
    assert(compound.severity === 'HIGH');
  });

  test('lifecycle_dataflow: SKIPS when dataflow is only in dist/', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'dist/main.bundle.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_dataflow');
    assert(compound === undefined,
      'compound must not fire when dataflow lives only in dist/, got ' + JSON.stringify(compound));
  });

  test('lifecycle_dataflow: fires when ANY dataflow is outside dist/', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'dist/main.bundle.js' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'src/runtime.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_dataflow');
    assert(compound !== undefined, 'should fire when at least one dataflow is in src/');
  });

  test('lifecycle_dataflow: skipped when only dist/, even with build/ alt name', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json' },
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'build/index.min.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_dataflow');
    assert(compound === undefined, 'build/ paths also bundled');
  });

  // ---------------------------------------------------------------------------
  // requireOriginalSeverityHigh on obfuscated_lifecycle_env
  // ---------------------------------------------------------------------------

  test('obfuscated_lifecycle_env: fires when env_access HIGH original', () => {
    const threats = [
      { type: 'obfuscation_detected', severity: 'MEDIUM', file: 'lib/loader.js' },
      { type: 'env_access', severity: 'HIGH', file: 'lib/loader.js' },
      { type: 'lifecycle_script', severity: 'CRITICAL', file: 'package.json' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'obfuscated_lifecycle_env');
    assert(compound !== undefined, 'should fire with HIGH env_access');
  });

  test('obfuscated_lifecycle_env: SKIPS when all components only MEDIUM', () => {
    const threats = [
      { type: 'obfuscation_detected', severity: 'MEDIUM', file: 'lib/loader.js' },
      { type: 'env_access', severity: 'MEDIUM', file: 'lib/loader.js' },
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'obfuscated_lifecycle_env');
    assert(compound === undefined, 'must not fire on all-MEDIUM components');
  });

  test('obfuscated_lifecycle_env: SKIPS when fully bundled', () => {
    // All components in dist/, even with HIGH severity
    const threats = [
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/main.min.js' },
      { type: 'env_access', severity: 'HIGH', file: 'dist/main.min.js' },
      { type: 'lifecycle_script', severity: 'CRITICAL', file: 'package.json' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'obfuscated_lifecycle_env');
    assert(compound === undefined, 'all bundled => skip');
  });

  // ---------------------------------------------------------------------------
  // Other compounds remain unaffected (regression guard)
  // ---------------------------------------------------------------------------

  test('lifecycle_typosquat: still fires with new gates (no excludeIfBundled)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'CRITICAL', file: 'package.json' },
      { type: 'typosquat_detected', severity: 'CRITICAL', file: 'package.json' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_typosquat');
    assert(compound !== undefined, 'lifecycle_typosquat unchanged');
  });

  test('crypto_staged_payload: still fires (sameFile already gates it)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'lib/loader.js' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'lib/loader.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound !== undefined, 'crypto_staged_payload unchanged');
  });

  test('lifecycle_dangerous_exec: NOT bundled-excluded (dangerous_exec is HC)', () => {
    // dangerous_exec is in DIST_EXEMPT_TYPES, so even when in dist/ the compound
    // should still consider firing. We did not add excludeIfBundled to
    // lifecycle_dangerous_exec - this test guards against accidental change.
    const threats = [
      { type: 'lifecycle_script', severity: 'CRITICAL', file: 'package.json' },
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'dist/main.min.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_dangerous_exec');
    assert(compound !== undefined, 'lifecycle_dangerous_exec must still fire even in dist/');
  });
}

module.exports = { runCompoundTighteningTests };

if (require.main === module) {
  runCompoundTighteningTests();
  const { getCounters } = require('../test-utils');
  console.log(JSON.stringify(getCounters()));
}
