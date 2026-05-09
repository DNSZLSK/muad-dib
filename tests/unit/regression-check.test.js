'use strict';

const { test, assert } = require('../test-utils');

function runRegressionCheckTests() {
  console.log('\n=== REGRESSION CHECK TESTS (Chantier 8) ===\n');

  const { checkMetric, findNewClusters } = require('../../scripts/regression-check.js');

  // --- checkMetric : FPR direction (lower-is-better) ---

  test('checkMetric: FPR going up beyond tolerance is a regression', () => {
    const cur = { flagged: 30, scanned: 200, fpr: 0.15 };
    const base = { flagged: 14, scanned: 200, fpr: 0.07 };
    const r = checkMetric('FPR random', cur, base, 0.005, 'lower-is-better');
    assert(r.regressed === true, 'should be regressed');
    assert(r.delta > 0, 'delta should be positive');
    assert(r.status === 'compared', 'status should be compared');
  });

  test('checkMetric: FPR going down (improvement) is not a regression', () => {
    const cur = { flagged: 7, scanned: 200, fpr: 0.035 };
    const base = { flagged: 14, scanned: 200, fpr: 0.07 };
    const r = checkMetric('FPR random', cur, base, 0.005, 'lower-is-better');
    assert(r.regressed === false, 'improvement is not regression');
  });

  test('checkMetric: FPR change within tolerance is not a regression', () => {
    const cur = { flagged: 14, scanned: 200, fpr: 0.0725 };
    const base = { flagged: 14, scanned: 200, fpr: 0.07 };
    const r = checkMetric('FPR random', cur, base, 0.005, 'lower-is-better');
    assert(r.regressed === false, 'within tolerance');
  });

  // --- checkMetric : TPR / ADR direction (higher-is-better) ---

  test('checkMetric: TPR going down beyond tolerance is a regression', () => {
    const cur = { detected: 55, total: 65, tpr: 0.846 };
    const base = { detected: 61, total: 65, tpr: 0.9385 };
    const r = checkMetric('TPR ground truth', cur, base, 0.005, 'higher-is-better');
    assert(r.regressed === true, 'TPR drop is regression');
    assert(r.delta < 0, 'delta should be negative');
  });

  test('checkMetric: TPR going up is not a regression', () => {
    const cur = { detected: 64, total: 65, tpr: 0.984 };
    const base = { detected: 61, total: 65, tpr: 0.9385 };
    const r = checkMetric('TPR ground truth', cur, base, 0.005, 'higher-is-better');
    assert(r.regressed === false, 'improvement is not regression');
  });

  test('checkMetric: ADR direction higher-is-better with adr field', () => {
    const cur = { detected: 100, available: 107, adr: 0.935 };
    const base = { detected: 103, available: 107, adr: 0.963 };
    const r = checkMetric('ADR', cur, base, 0.005, 'higher-is-better');
    assert(r.regressed === true, 'ADR drop > 0.5pt is regression');
  });

  // --- checkMetric : missing data ---

  test('checkMetric: missing baseline returns status=missing', () => {
    const r = checkMetric('FPR random', { fpr: 0.07, flagged: 14, scanned: 200 }, null, 0.005, 'lower-is-better');
    assert(r.status === 'missing', 'should be missing');
    assert(r.regressed === false, 'missing != regression');
  });

  test('checkMetric: missing current returns status=missing', () => {
    const r = checkMetric('FPR random', null, { fpr: 0.07, flagged: 14, scanned: 200 }, 0.005, 'lower-is-better');
    assert(r.status === 'missing', 'should be missing');
  });

  // --- findNewClusters ---

  test('findNewClusters: returns clusters not present in baseline', () => {
    const current = {
      fpClusters: { topClusters: [
        { key: 'a|x|src', count: 5, rule_type: 'a', file_pattern: 'x', is_bundle: false, distinct_packages: 5 },
        { key: 'b|y|bundle', count: 3, rule_type: 'b', file_pattern: 'y', is_bundle: true, distinct_packages: 3 },
        { key: 'c|z|src', count: 1, rule_type: 'c', file_pattern: 'z', is_bundle: false, distinct_packages: 1 }
      ]}
    };
    const baseline = {
      fpClusters: { topClusters: [
        { key: 'a|x|src', count: 5, rule_type: 'a', file_pattern: 'x', is_bundle: false, distinct_packages: 5 }
      ]}
    };
    const fresh = findNewClusters(current, baseline, 5);
    assert(fresh.length === 2, `expected 2 new clusters, got ${fresh.length}`);
    assert(fresh[0].rule_type === 'b', 'most frequent new cluster first');
    assert(fresh[1].rule_type === 'c', 'second new cluster');
  });

  test('findNewClusters: returns empty when no fpClusters in current', () => {
    const fresh = findNewClusters({}, { fpClusters: { topClusters: [] } }, 5);
    assert(fresh.length === 0, 'no current = no new');
  });

  test('findNewClusters: caps at topN', () => {
    const current = { fpClusters: { topClusters: [] } };
    for (let i = 0; i < 10; i++) {
      current.fpClusters.topClusters.push({ key: `k${i}`, count: 10 - i, rule_type: 't', file_pattern: 'p', is_bundle: false, distinct_packages: 1 });
    }
    const baseline = { fpClusters: { topClusters: [] } };
    const fresh = findNewClusters(current, baseline, 3);
    assert(fresh.length === 3, 'capped at 3');
    assert(fresh[0].count === 10, 'highest count first');
  });
}

module.exports = { runRegressionCheckTests };
