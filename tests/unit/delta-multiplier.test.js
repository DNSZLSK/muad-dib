'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { test, assert } = require('../test-utils');
const dm = require('../../src/scoring/delta-multiplier.js');
const {
  applyDeltaMultiplier,
  buildThreatSignature,
  computeSignatures,
  loadCachedSignatures,
  saveCachedSignatures,
  selectPriorVersions,
  loadPriorVersionSignatures,
  MIN_PRIOR_VERSIONS_FOR_DECAY
} = dm;

function _withTempCacheDir(fn) {
  // Tests use the same cache as production but with synthetic package names
  // so collisions are impossible. The cache is a key/value store on disk.
  return fn();
}

function _uniquePackage() {
  return 'muaddib-test-' + Math.random().toString(36).slice(2, 10);
}

function runDeltaMultiplierTests() {
  console.log('\n=== DELTA MULTIPLIER TESTS (Chantier 3) ===\n');

  // ---------------------------------------------------------------------------
  // buildThreatSignature
  // ---------------------------------------------------------------------------

  test('buildThreatSignature: type + normalized file', () => {
    const sig = buildThreatSignature({
      type: 'suspicious_dataflow',
      severity: 'HIGH',
      file: 'lib/utils.js'
    });
    assert(sig === 'suspicious_dataflow:lib/utils.js', 'got: ' + sig);
  });

  test('buildThreatSignature: collapses hex hashes', () => {
    const sig = buildThreatSignature({
      type: 'env_access',
      file: 'dist/main.a3f2b1c4d5.js'
    });
    assert(sig === 'env_access:dist/main.HEX.js', 'got: ' + sig);
  });

  test('buildThreatSignature: collapses semver triplets', () => {
    const sig = buildThreatSignature({
      type: 'env_access',
      file: 'vendor/library@1.2.3/index.js'
    });
    assert(sig === 'env_access:vendor/library@VER/index.js', 'got: ' + sig);
  });

  test('buildThreatSignature: collapses long numbers', () => {
    const sig = buildThreatSignature({
      type: 'env_access',
      file: 'chunks/12345.js'
    });
    assert(sig === 'env_access:chunks/N.js', 'got: ' + sig);
  });

  test('buildThreatSignature: returns null on missing type', () => {
    assert(buildThreatSignature({ file: 'a.js' }) === null);
    assert(buildThreatSignature(null) === null);
    assert(buildThreatSignature(undefined) === null);
  });

  test('buildThreatSignature: forward-slash normalizes Windows paths', () => {
    const sig = buildThreatSignature({
      type: 'env_access',
      file: 'lib\\sub\\index.js'
    });
    assert(sig === 'env_access:lib/sub/index.js', 'got: ' + sig);
  });

  // ---------------------------------------------------------------------------
  // computeSignatures
  // ---------------------------------------------------------------------------

  test('computeSignatures: returns a Set sized to unique signatures', () => {
    const sigs = computeSignatures([
      { type: 'env_access', file: 'a.js' },
      { type: 'env_access', file: 'a.js' }, // dedup
      { type: 'env_access', file: 'b.js' }
    ]);
    assert(sigs instanceof Set, 'should be a Set');
    assert(sigs.size === 2, 'expected 2 unique sigs, got ' + sigs.size);
  });

  test('computeSignatures: empty array returns empty set', () => {
    const sigs = computeSignatures([]);
    assert(sigs instanceof Set && sigs.size === 0);
  });

  test('computeSignatures: skips invalid threats', () => {
    const sigs = computeSignatures([
      { type: 'env_access', file: 'a.js' },
      null,
      { file: 'no-type.js' },
      { type: 'env_access', file: 'b.js' }
    ]);
    assert(sigs.size === 2, 'expected 2, got ' + sigs.size);
  });

  // ---------------------------------------------------------------------------
  // Cache roundtrip
  // ---------------------------------------------------------------------------

  test('saveCachedSignatures + loadCachedSignatures: roundtrip', () => {
    const pkg = _uniquePackage();
    const sigs = new Set(['env_access:a.js', 'suspicious_dataflow:b.js']);
    const ok = saveCachedSignatures(pkg, '1.0.0', sigs);
    assert(ok === true, 'save should succeed');
    const loaded = loadCachedSignatures(pkg, '1.0.0');
    assert(loaded instanceof Set, 'load should return a Set');
    assert(loaded.size === 2, 'should have 2 sigs');
    assert(loaded.has('env_access:a.js'), 'sig 1 present');
    assert(loaded.has('suspicious_dataflow:b.js'), 'sig 2 present');
  });

  test('loadCachedSignatures: missing package returns null', () => {
    const loaded = loadCachedSignatures(_uniquePackage(), '0.0.1');
    assert(loaded === null, 'expected null');
  });

  test('loadCachedSignatures: handles array form (legacy)', () => {
    const pkg = _uniquePackage();
    const ok = saveCachedSignatures(pkg, '2.0.0', ['type1:a.js', 'type2:b.js']);
    assert(ok === true);
    const loaded = loadCachedSignatures(pkg, '2.0.0');
    assert(loaded.size === 2, 'array input should round-trip as Set');
  });

  // ---------------------------------------------------------------------------
  // selectPriorVersions
  // ---------------------------------------------------------------------------

  test('selectPriorVersions: returns 3 most recent prior versions', () => {
    const packument = {
      time: {
        created: '2024-01-01T00:00:00Z',
        modified: '2026-05-01T00:00:00Z',
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.1.0': '2024-06-01T00:00:00Z',
        '1.2.0': '2024-12-01T00:00:00Z',
        '1.3.0': '2025-06-01T00:00:00Z',
        '2.0.0': '2026-05-01T00:00:00Z'
      }
    };
    const out = selectPriorVersions(packument, '2.0.0');
    assert(out.length === 3, 'expected 3, got ' + out.length);
    assert(out[0] === '1.3.0', 'most recent prior should be 1.3.0, got ' + out[0]);
    assert(out[1] === '1.2.0');
    assert(out[2] === '1.1.0');
  });

  test('selectPriorVersions: excludes the current version', () => {
    const packument = {
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '2.0.0': '2026-05-01T00:00:00Z'
      }
    };
    const out = selectPriorVersions(packument, '2.0.0');
    assert(out.includes('1.0.0'), 'should include 1.0.0');
    assert(!out.includes('2.0.0'), 'should NOT include 2.0.0');
  });

  test('selectPriorVersions: skips meta keys created/modified', () => {
    const packument = {
      time: {
        created: '2024-01-01T00:00:00Z',
        modified: '2026-05-01T00:00:00Z',
        '1.0.0': '2024-01-01T00:00:00Z'
      }
    };
    const out = selectPriorVersions(packument, '2.0.0');
    assert(!out.includes('created'), 'no meta keys');
    assert(!out.includes('modified'), 'no meta keys');
  });

  test('selectPriorVersions: empty packument returns []', () => {
    assert(selectPriorVersions(null, '1.0.0').length === 0);
    assert(selectPriorVersions({}, '1.0.0').length === 0);
    assert(selectPriorVersions({ time: {} }, '1.0.0').length === 0);
  });

  // ---------------------------------------------------------------------------
  // applyDeltaMultiplier — core decay logic
  // ---------------------------------------------------------------------------

  test('applyDeltaMultiplier: stable threat in 3+ priors decays to LOW', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'lib/a.js' }
    ];
    const priors = new Map([
      ['2.0.9', new Set(['env_access:lib/a.js', 'other:b.js'])],
      ['2.0.8', new Set(['env_access:lib/a.js'])],
      ['2.0.7', new Set(['env_access:lib/a.js'])]
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(r.downgraded === 1, 'expected 1 downgraded, got ' + r.downgraded);
    assert(threats[0].severity === 'LOW', 'severity should be LOW, got ' + threats[0].severity);
    assert(threats[0].deltaStable === true, 'deltaStable flag set');
    assert(threats[0].deltaPresentInPrior === 3, 'deltaPresentInPrior=3');
    const reasons = (threats[0].reductions || []).map(rr => rr.rule);
    assert(reasons.includes('delta_stable'), 'reductions trail records delta_stable');
  });

  test('applyDeltaMultiplier: threat in only 2 priors does NOT decay', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'lib/a.js' }
    ];
    const priors = new Map([
      ['2.0.9', new Set(['env_access:lib/a.js'])],
      ['2.0.8', new Set(['env_access:lib/a.js'])],
      ['2.0.7', new Set(['unrelated:b.js'])]
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(r.downgraded === 0, 'should not downgrade');
    assert(threats[0].severity === 'HIGH', 'severity unchanged');
    assert(threats[0].deltaPresentInPrior === 2);
  });

  test('applyDeltaMultiplier: bypasses HC types', () => {
    const threats = [
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json' }
    ];
    const priors = new Map([
      ['2.0.9', new Set(['lifecycle_shell_pipe:package.json'])],
      ['2.0.8', new Set(['lifecycle_shell_pipe:package.json'])],
      ['2.0.7', new Set(['lifecycle_shell_pipe:package.json'])]
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(r.downgraded === 0, 'HC bypassed');
    assert(threats[0].severity === 'CRITICAL', 'HC stays CRITICAL');
  });

  test('applyDeltaMultiplier: bypasses IOC types', () => {
    const threats = [
      { type: 'ioc_match', severity: 'CRITICAL', file: 'index.js' }
    ];
    const priors = new Map([
      ['2.0.9', new Set(['ioc_match:index.js'])],
      ['2.0.8', new Set(['ioc_match:index.js'])],
      ['2.0.7', new Set(['ioc_match:index.js'])]
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(r.downgraded === 0, 'IOC bypassed');
    assert(threats[0].severity === 'CRITICAL', 'IOC stays CRITICAL');
  });

  test('applyDeltaMultiplier: marks deltaNew when missing from N-1', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'lib/new.js' }
    ];
    // N-1 (2.0.9) does NOT have this threat
    const priors = new Map([
      ['2.0.9', new Set(['unrelated:b.js'])],
      ['2.0.8', new Set([])],
      ['2.0.7', new Set([])]
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(threats[0].deltaNew === true, 'deltaNew flag set');
    assert(r.newThreats === 1, 'newThreats count');
  });

  test('applyDeltaMultiplier: insufficient baseline (<3) is no-op', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'lib/a.js' }
    ];
    const priors = new Map([
      ['2.0.9', new Set(['env_access:lib/a.js'])],
      ['2.0.8', new Set(['env_access:lib/a.js'])]
      // Only 2 priors - not enough
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(r.downgraded === 0, 'should not downgrade');
    assert(r.baselineSize === 2);
    assert(threats[0].severity === 'HIGH', 'unchanged');
  });

  test('applyDeltaMultiplier: empty/null inputs do not throw', () => {
    assert(applyDeltaMultiplier(null, new Map()) === null);
    assert(applyDeltaMultiplier([], null) === null);
    const r = applyDeltaMultiplier([], new Map());
    assert(r && r.downgraded === 0);
  });

  test('applyDeltaMultiplier: already-LOW threats stay LOW (no double reduction)', () => {
    const threats = [
      { type: 'env_access', severity: 'LOW', file: 'lib/a.js', reductions: [] }
    ];
    const priors = new Map([
      ['2.0.9', new Set(['env_access:lib/a.js'])],
      ['2.0.8', new Set(['env_access:lib/a.js'])],
      ['2.0.7', new Set(['env_access:lib/a.js'])]
    ]);
    const r = applyDeltaMultiplier(threats, priors);
    assert(r.downgraded === 0, 'already LOW, not counted');
    assert(threats[0].severity === 'LOW');
    // deltaStable should not be set since we did not downgrade
    assert(!threats[0].deltaStable, 'no deltaStable flag for already-LOW');
  });

  test('MIN_PRIOR_VERSIONS_FOR_DECAY constant is sane', () => {
    assert(MIN_PRIOR_VERSIONS_FOR_DECAY === 3, 'should be 3 per plan');
  });

  // ---------------------------------------------------------------------------
  // loadPriorVersionSignatures - integration of select + load
  // ---------------------------------------------------------------------------

  test('loadPriorVersionSignatures: returns map from cache', () => {
    const pkg = _uniquePackage();
    saveCachedSignatures(pkg, '1.0.0', ['env_access:a.js']);
    saveCachedSignatures(pkg, '1.1.0', ['env_access:a.js', 'env_access:b.js']);
    saveCachedSignatures(pkg, '1.2.0', ['env_access:c.js']);

    const packument = {
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.1.0': '2024-06-01T00:00:00Z',
        '1.2.0': '2024-12-01T00:00:00Z',
        '2.0.0': '2025-06-01T00:00:00Z'
      }
    };
    const out = loadPriorVersionSignatures(pkg, '2.0.0', packument);
    assert(out.size === 3, 'should load all 3 prior versions, got ' + out.size);
    assert(out.has('1.2.0'), 'should include 1.2.0');
    assert(out.get('1.2.0').has('env_access:c.js'));
  });

  test('loadPriorVersionSignatures: cache miss => no entry but no throw', () => {
    const pkg = _uniquePackage();
    const packument = {
      time: {
        '0.9.0': '2024-01-01T00:00:00Z',
        '1.0.0': '2024-06-01T00:00:00Z'
      }
    };
    const out = loadPriorVersionSignatures(pkg, '1.0.0', packument);
    assert(out instanceof Map, 'returns a Map');
    assert(out.size === 0, 'no cache entries to load');
  });
}

module.exports = { runDeltaMultiplierTests };

if (require.main === module) {
  runDeltaMultiplierTests();
  const { getCounters } = require('../test-utils');
  console.log(JSON.stringify(getCounters()));
}
