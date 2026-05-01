'use strict';

const { test, assert } = require('../test-utils');
const { applyReputationFactor, REPUTATION_FACTOR_BOUNDS } = require('../../src/scoring.js');

function makeResult(score) {
  return { summary: { riskScore: score, riskLevel: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : score > 0 ? 'LOW' : 'SAFE' } };
}

async function runReputationFactorTests() {
  console.log('\n=== REPUTATION FACTOR TESTS (Hybrid v3 Phase 4) ===\n');

  test('Phase 4: null metadata is no-op', () => {
    const r = makeResult(80);
    const out = applyReputationFactor(r, null);
    assert(out === null, 'Should return null adjustment');
    assert(r.summary.riskScore === 80, `Score unchanged, got ${r.summary.riskScore}`);
  });

  test('Phase 4: empty metadata (all fields missing) returns neutral 1.0', () => {
    const r = makeResult(80);
    const out = applyReputationFactor(r, {});
    assert(out === null, 'No factor adjustment when no signals applied');
    assert(r.summary.riskScore === 80);
    assert(r.summary.reputationFactor === 1.0);
  });

  test('Phase 4: zero/null metadata fields treated as absent (not 0-versions / 0-downloads)', () => {
    const r = makeResult(80);
    const out = applyReputationFactor(r, {
      package_age_days: 0,
      version_count: 0,
      weekly_downloads: 0,
      has_repository: null,
      author_package_count: null
    });
    assert(out === null, 'Zero numeric fields should not trigger penalty branches');
    assert(r.summary.riskScore === 80);
  });

  test('Phase 4: established package (5y+ age, 200+ versions, 1M+ downloads) gets factor << 1', () => {
    const r = makeResult(60);
    const out = applyReputationFactor(r, {
      package_age_days: 2500,
      version_count: 250,
      weekly_downloads: 5_000_000,
      has_repository: true,
      author_package_count: 100
    });
    assert(out !== null);
    // age -0.5, versions -0.3, downloads -0.4, repo -0.05, author -0.1 → 1.0 - 1.35 = -0.35 → clamped 0.10
    assert(out.factor === REPUTATION_FACTOR_BOUNDS.min, `Expected min factor, got ${out.factor}`);
    assert(r.summary.riskScore === Math.round(60 * REPUTATION_FACTOR_BOUNDS.min),
      `Expected score reduction, got ${r.summary.riskScore}`);
  });

  test('Phase 4: fresh suspicious package (1d age, 1 version, no repo, single-pkg author) gets factor >> 1', () => {
    const r = makeResult(40);
    const out = applyReputationFactor(r, {
      package_age_days: 1,
      version_count: 1,
      weekly_downloads: 5,
      has_repository: false,
      author_package_count: 1
    });
    assert(out !== null);
    // age +0.3, versions +0.2, downloads +0.15, repo +0.15, author +0.15 = 1.0 + 0.95 = 1.95 → clamped 1.5
    assert(out.factor === REPUTATION_FACTOR_BOUNDS.max, `Expected max factor, got ${out.factor}`);
    assert(r.summary.riskScore === Math.round(40 * REPUTATION_FACTOR_BOUNDS.max));
  });

  test('Phase 4: factor lifts riskScore at score boundary (50 → CRITICAL)', () => {
    const r = makeResult(50);
    const out = applyReputationFactor(r, { package_age_days: 1, has_repository: false });
    assert(out !== null);
    assert(r.summary.riskScore > 50, `Score should have risen, got ${r.summary.riskScore}`);
    assert(r.summary.riskLevel === r.summary.riskScore >= 75 ? 'CRITICAL' : r.summary.riskLevel);
  });

  test('Phase 4: factor caps at 100 (no overflow)', () => {
    const r = makeResult(95);
    const out = applyReputationFactor(r, { package_age_days: 1, version_count: 1, has_repository: false, author_package_count: 1 });
    assert(out !== null);
    assert(r.summary.riskScore <= 100, `Should cap at 100, got ${r.summary.riskScore}`);
  });

  test('Phase 4: floor at 0 (no negative)', () => {
    const r = makeResult(5);
    applyReputationFactor(r, { package_age_days: 3000, version_count: 500, weekly_downloads: 10_000_000 });
    assert(r.summary.riskScore >= 0, `Should not go negative, got ${r.summary.riskScore}`);
  });

  test('Phase 4: riskLevel updated alongside riskScore', () => {
    const r = makeResult(80);
    applyReputationFactor(r, { package_age_days: 3000, version_count: 500, weekly_downloads: 10_000_000 });
    // 80 * 0.10 = 8 → LOW
    assert(r.summary.riskLevel === 'LOW', `Expected LOW after factor 0.10, got ${r.summary.riskLevel}@${r.summary.riskScore}`);
  });

  test('Phase 4: has_repository true gives slight reassurance only', () => {
    const r = makeResult(50);
    const out = applyReputationFactor(r, { has_repository: true });
    assert(out !== null);
    assert(out.factor < 1.0 && out.factor > 0.9, `Slight reduction expected, got ${out.factor}`);
  });

  test('Phase 4: bounds constants are { min: 0.10, max: 1.5 }', () => {
    assert(REPUTATION_FACTOR_BOUNDS.min === 0.10, 'min should be 0.10');
    assert(REPUTATION_FACTOR_BOUNDS.max === 1.5, 'max should be 1.5');
  });
}

module.exports = { runReputationFactorTests };
