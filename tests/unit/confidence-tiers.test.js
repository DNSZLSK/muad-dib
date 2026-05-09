'use strict';

const { test, assert } = require('../test-utils');
const {
  getConfidenceTier,
  annotateConfidenceTiers,
  tierAtLeast,
  VERIFIED_TYPES,
  HIGH_TIER_EXTRA,
  LOW_TIER_TYPES,
  TIER_ORDER
} = require('../../src/rules/confidence-tiers.js');

function runConfidenceTiersTests() {
  console.log('\n=== CONFIDENCE TIERS TESTS (Chantier 6) ===\n');

  // ---------------------------------------------------------------------------
  // getConfidenceTier - mapping
  // ---------------------------------------------------------------------------

  test('getConfidenceTier: ioc_match => verified', () => {
    assert(getConfidenceTier('ioc_match', 'CRITICAL') === 'verified');
  });

  test('getConfidenceTier: known_malicious_hash => verified', () => {
    assert(getConfidenceTier('known_malicious_hash', 'CRITICAL') === 'verified');
  });

  test('getConfidenceTier: shai_hulud_marker => verified', () => {
    assert(getConfidenceTier('shai_hulud_marker', 'CRITICAL') === 'verified');
  });

  test('getConfidenceTier: cross_file_dataflow => high', () => {
    assert(getConfidenceTier('cross_file_dataflow', 'CRITICAL') === 'high');
  });

  test('getConfidenceTier: lifecycle_shell_pipe => high (HC type)', () => {
    assert(getConfidenceTier('lifecycle_shell_pipe', 'CRITICAL') === 'high');
  });

  test('getConfidenceTier: intent_credential_exfil => high', () => {
    assert(getConfidenceTier('intent_credential_exfil', 'CRITICAL') === 'high');
  });

  test('getConfidenceTier: crypto_staged_payload (compound) => high', () => {
    assert(getConfidenceTier('crypto_staged_payload', 'CRITICAL') === 'high');
  });

  test('getConfidenceTier: possible_obfuscation => low', () => {
    assert(getConfidenceTier('possible_obfuscation', 'HIGH') === 'low',
      'heuristic types are low regardless of severity');
  });

  test('getConfidenceTier: high_entropy_string => low', () => {
    assert(getConfidenceTier('high_entropy_string', 'HIGH') === 'low');
  });

  test('getConfidenceTier: dangerous_call_eval (single-rule) HIGH severity => medium', () => {
    assert(getConfidenceTier('dangerous_call_eval', 'HIGH') === 'medium');
  });

  test('getConfidenceTier: env_access HIGH => medium', () => {
    // env_access is not in VERIFIED nor HIGH_TIER_EXTRA so falls back by severity
    assert(getConfidenceTier('env_access', 'HIGH') === 'medium');
  });

  test('getConfidenceTier: env_access MEDIUM => low', () => {
    assert(getConfidenceTier('env_access', 'MEDIUM') === 'low',
      'medium severity heuristic falls to low tier');
  });

  test('getConfidenceTier: count downgrade flag forces low', () => {
    assert(getConfidenceTier('env_access', 'HIGH', { isCountDowngrade: true }) === 'low');
  });

  test('getConfidenceTier: unreachable flag forces low', () => {
    assert(getConfidenceTier('env_access', 'HIGH', { isUnreachable: true }) === 'low');
  });

  test('getConfidenceTier: VERIFIED beats unreachable flag', () => {
    assert(getConfidenceTier('ioc_match', 'CRITICAL', { isUnreachable: true }) === 'verified',
      'a verified IOC stays verified even if technically unreachable');
  });

  test('getConfidenceTier: missing/empty type returns low', () => {
    assert(getConfidenceTier('', 'HIGH') === 'low');
    assert(getConfidenceTier(null, 'HIGH') === 'low');
    assert(getConfidenceTier(undefined, 'HIGH') === 'low');
  });

  // ---------------------------------------------------------------------------
  // annotateConfidenceTiers - mutation
  // ---------------------------------------------------------------------------

  test('annotateConfidenceTiers: tags every threat in place', () => {
    const threats = [
      { type: 'ioc_match', severity: 'CRITICAL' },
      { type: 'env_access', severity: 'HIGH' },
      { type: 'possible_obfuscation', severity: 'MEDIUM' }
    ];
    const annotated = annotateConfidenceTiers(threats);
    assert(annotated === 3, 'all 3 annotated');
    assert(threats[0].confidenceTier === 'verified');
    assert(threats[1].confidenceTier === 'medium');
    assert(threats[2].confidenceTier === 'low');
  });

  test('annotateConfidenceTiers: respects existing tier (idempotent)', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', confidenceTier: 'high' }
    ];
    annotateConfidenceTiers(threats);
    assert(threats[0].confidenceTier === 'high', 'existing tier preserved');
  });

  test('annotateConfidenceTiers: derives flags from reductions trail', () => {
    const threats = [
      {
        type: 'env_access', severity: 'LOW',
        reductions: [{ rule: 'count_threshold', from: 'HIGH', to: 'LOW' }]
      }
    ];
    annotateConfidenceTiers(threats);
    assert(threats[0].confidenceTier === 'low',
      'count threshold reduction => low tier');
  });

  test('annotateConfidenceTiers: derives flag from unreachable bool', () => {
    const threats = [
      { type: 'env_access', severity: 'LOW', unreachable: true }
    ];
    annotateConfidenceTiers(threats);
    assert(threats[0].confidenceTier === 'low');
  });

  test('annotateConfidenceTiers: handles non-array gracefully', () => {
    assert(annotateConfidenceTiers(null) === 0);
    assert(annotateConfidenceTiers(undefined) === 0);
    assert(annotateConfidenceTiers('not array') === 0);
  });

  test('annotateConfidenceTiers: skips invalid threat objects', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH' },
      null,
      undefined,
      { type: 'ioc_match', severity: 'CRITICAL' }
    ];
    const annotated = annotateConfidenceTiers(threats);
    assert(annotated === 2, '2 valid threats annotated');
  });

  // ---------------------------------------------------------------------------
  // tierAtLeast comparison
  // ---------------------------------------------------------------------------

  test('tierAtLeast: high meets the high threshold', () => {
    assert(tierAtLeast('high', 'high') === true);
  });

  test('tierAtLeast: verified meets the high threshold', () => {
    assert(tierAtLeast('verified', 'high') === true);
  });

  test('tierAtLeast: medium does NOT meet high', () => {
    assert(tierAtLeast('medium', 'high') === false);
  });

  test('tierAtLeast: invalid tier returns false', () => {
    assert(tierAtLeast('garbage', 'high') === false);
  });

  test('TIER_ORDER: verified > high > medium > low', () => {
    assert(TIER_ORDER.verified > TIER_ORDER.high);
    assert(TIER_ORDER.high > TIER_ORDER.medium);
    assert(TIER_ORDER.medium > TIER_ORDER.low);
  });

  // ---------------------------------------------------------------------------
  // Set semantics: a type appears in at most one of VERIFIED/HIGH/LOW
  // ---------------------------------------------------------------------------

  test('Set partition: VERIFIED & HIGH_TIER_EXTRA disjoint', () => {
    for (const t of VERIFIED_TYPES) {
      assert(!HIGH_TIER_EXTRA.has(t), 'overlap on ' + t);
    }
  });

  test('Set partition: VERIFIED & LOW_TIER disjoint', () => {
    for (const t of VERIFIED_TYPES) {
      assert(!LOW_TIER_TYPES.has(t), 'overlap on ' + t);
    }
  });

  test('Set partition: HIGH_TIER_EXTRA & LOW_TIER disjoint', () => {
    for (const t of HIGH_TIER_EXTRA) {
      assert(!LOW_TIER_TYPES.has(t), 'overlap on ' + t);
    }
  });
}

module.exports = { runConfidenceTiersTests };

if (require.main === module) {
  runConfidenceTiersTests();
  const { getCounters } = require('../test-utils');
  console.log(JSON.stringify(getCounters()));
}
