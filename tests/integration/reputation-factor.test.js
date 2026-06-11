'use strict';

const { test, assert } = require('../test-utils');
const { applyReputationFactor, REPUTATION_FACTOR_BOUNDS, REPUTATION_MALICE_FLOOR } = require('../../src/scoring.js');
const { HIGH_CONFIDENCE_MALICE_TYPES } = require('../../src/monitor/classify.js');

function makeResult(score) {
  return { summary: { riskScore: score, riskLevel: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : score > 0 ? 'LOW' : 'SAFE' } };
}

function makeResultWithThreats(score, threats) {
  const r = makeResult(score);
  r.threats = threats;
  return r;
}

// Reputation metadata that drives the factor to its floor (0.10): a mature, very
// popular package — exactly the profile an account-takeover hides behind.
const ESTABLISHED_META = {
  package_age_days: 2500, version_count: 250, weekly_downloads: 5_000_000,
  has_repository: true, author_package_count: 100
};

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

  // ── Track R: malice-aware floor on the reputation multiplier ──────────────
  // The ×0.10 suppression must not bury a confirmed-malice detection (account
  // takeover of a popular package) below the alert threshold, while leaving the
  // suppression of benign popular packages fully intact (zero FP cost).

  test('Track R: HC-type detection is floored at the alert threshold despite ×0.10', () => {
    const hcType = [...HIGH_CONFIDENCE_MALICE_TYPES][0];
    const r = makeResultWithThreats(80, [{ type: hcType, severity: 'CRITICAL' }]);
    const out = applyReputationFactor(r, ESTABLISHED_META);
    assert(out !== null);
    assert(out.factor === REPUTATION_FACTOR_BOUNDS.min, `expected min factor, got ${out.factor}`);
    // 80 * 0.10 = 8 → would be a FN; floor lifts it to REPUTATION_MALICE_FLOOR.
    assert(r.summary.riskScore === REPUTATION_MALICE_FLOOR,
      `confirmed malice must not fall below ${REPUTATION_MALICE_FLOOR}, got ${r.summary.riskScore}`);
  });

  test('Track R: compound detection (compound:true) also triggers the floor', () => {
    const r = makeResultWithThreats(90, [{ type: 'lifecycle_dataflow', severity: 'CRITICAL', compound: true }]);
    applyReputationFactor(r, ESTABLISHED_META);
    assert(r.summary.riskScore === REPUTATION_MALICE_FLOOR,
      `compound must be floored, got ${r.summary.riskScore}`);
  });

  test('Track R: staged_payload + suspicious_domain(HIGH) triggers the floor', () => {
    const r = makeResultWithThreats(70, [
      { type: 'staged_payload', severity: 'HIGH' },
      { type: 'suspicious_domain', severity: 'HIGH' }
    ]);
    applyReputationFactor(r, ESTABLISHED_META);
    assert(r.summary.riskScore === REPUTATION_MALICE_FLOOR,
      `staged-C2 must be floored, got ${r.summary.riskScore}`);
  });

  test('Track R (FP guard): benign popular package WITHOUT confirmed malice keeps full ×0.10', () => {
    // env_access is not a HIGH_CONFIDENCE_MALICE_TYPE → no floor → suppression preserved.
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('env_access'), 'precondition: env_access not HC');
    const r = makeResultWithThreats(80, [{ type: 'env_access', severity: 'LOW' }]);
    applyReputationFactor(r, ESTABLISHED_META);
    assert(r.summary.riskScore === 8, `benign suppression must be preserved (80×0.10=8), got ${r.summary.riskScore}`);
  });

  test('Track R: floor only raises — never lowers a score already above threshold', () => {
    const hcType = [...HIGH_CONFIDENCE_MALICE_TYPES][0];
    const r = makeResultWithThreats(80, [{ type: hcType, severity: 'CRITICAL' }]);
    // has_repository alone → mild factor (~0.95): 80×0.95=76, already >20, untouched.
    applyReputationFactor(r, { has_repository: true });
    assert(r.summary.riskScore > REPUTATION_MALICE_FLOOR && r.summary.riskScore < 80,
      `mild factor with malice should stay between floor and original, got ${r.summary.riskScore}`);
  });

  test('Track R: result without a threats array is unaffected by the floor', () => {
    const r = makeResult(80); // no .threats field
    applyReputationFactor(r, ESTABLISHED_META);
    assert(r.summary.riskScore === 8, `no threats → plain ×0.10 (=8), got ${r.summary.riskScore}`);
  });

  test('Track R: floor constant is the alert threshold (20)', () => {
    assert(REPUTATION_MALICE_FLOOR === 20, `expected 20, got ${REPUTATION_MALICE_FLOOR}`);
  });

  // ── P3: provenance signals feed the reputation factor ──────────────────────

  test('P3: has_provenance true → mild downweight (fewer FP on attested packages)', () => {
    const r = makeResult(60);
    const out = applyReputationFactor(r, { has_provenance: true });
    assert(out !== null, 'provenance presence is a signal → factor applied');
    assert(out.factor < 1.0 && out.factor >= 0.85, `expected ~0.90 downweight, got ${out.factor}`);
    assert(r.summary.riskScore < 60, `attested package should be downweighted, got ${r.summary.riskScore}`);
  });

  test('P3: provenance_regressed true → upweight (Ultralytics build-divergence suspicion)', () => {
    const r = makeResult(40);
    const out = applyReputationFactor(r, { provenance_regressed: true });
    assert(out !== null);
    assert(out.factor > 1.0, `regression must raise the factor, got ${out.factor}`);
    assert(r.summary.riskScore > 40, `lost-provenance package should be upweighted, got ${r.summary.riskScore}`);
  });

  test('P3: regression dominates presence (mutually exclusive branch)', () => {
    // provenance_regressed implies the latest lacks provenance, so has_provenance is
    // false in practice; assert the suspicion branch wins regardless.
    const r = makeResult(50);
    const out = applyReputationFactor(r, { has_provenance: false, provenance_regressed: true });
    assert(out.factor > 1.0, `regression branch must dominate, got ${out.factor}`);
  });

  test('P3 (FP guard): a young unattested package is NOT penalised for missing provenance', () => {
    // has_provenance:false alone (no regression) applies no provenance signal — new
    // legitimate packages without CI attestation must not be upweighted.
    const r = makeResult(50);
    const out = applyReputationFactor(r, { has_provenance: false });
    assert(out === null, 'absence-without-regression is not a signal → no factor change');
    assert(r.summary.riskScore === 50, `score must be unchanged, got ${r.summary.riskScore}`);
  });

  // ── P3 hardening (TeamPCP / Mini Shai-Hulud): a VALID attestation must never earn
  // a trust bonus on a package that also shows malice. The May-2026 campaign shipped
  // 84 malicious TanStack versions with valid SLSA L3 Sigstore attestations by
  // hijacking the legitimate runner's OIDC identity — provenance proved the pipeline,
  // not the code. The presence bonus is withheld whenever a malice signal is present.

  test('P3 (TeamPCP guard): attested + confirmed-malice (HC type) → provenance bonus withheld', () => {
    const hcType = [...HIGH_CONFIDENCE_MALICE_TYPES][0];
    const r = makeResultWithThreats(60, [{ type: hcType, severity: 'CRITICAL' }]);
    const out = applyReputationFactor(r, { has_provenance: true });
    assert(out === null, 'attested-but-malicious → no provenance downweight applied');
    assert(r.summary.riskScore === 60, `provenance must not reduce a malware score, got ${r.summary.riskScore}`);
  });

  test('P3 (TeamPCP guard): any HIGH/CRITICAL signal (not just HC) withholds the bonus', () => {
    const r = makeResultWithThreats(60, [{ type: 'some_high_finding', severity: 'HIGH' }]);
    const out = applyReputationFactor(r, { has_provenance: true });
    assert(out === null, 'a HIGH severity signal alone suppresses the provenance trust bonus');
    assert(r.summary.riskScore === 60, `score must be unchanged, got ${r.summary.riskScore}`);
  });

  test('P3 (TeamPCP guard): clean attested package STILL gets the downweight (no malice)', () => {
    // Only LOW/MEDIUM noise present → not a malice signal → bonus still applies (FP win kept).
    const r = makeResultWithThreats(60, [{ type: 'env_access', severity: 'LOW' }]);
    const out = applyReputationFactor(r, { has_provenance: true });
    assert(out !== null && out.factor < 1.0, `clean attested package keeps the downweight, got ${out && out.factor}`);
  });

  // ── P4: pre-release channel versions inherit (partial) reputation ──────────────
  const ESTABLISHED = { package_age_days: 2500, version_count: 250, weekly_downloads: 5_000_000, has_repository: true, author_package_count: 100 };

  test('P4: canary on a non-latest pre-release dist-tag → partial reputation (not skipped)', () => {
    const r = makeResult(60);
    const out = applyReputationFactor(r, { ...ESTABLISHED, latest_version: '3.19.1', scan_version: '3.19.0-nightly-x', dist_tags: { latest: '3.19.1', next: '3.19.0-nightly-x' } });
    assert(out !== null, 'a canary on a maintainer pre-release tag must NOT be skipped');
    // attenuated: between the full min factor (0.10) and neutral (1.0).
    assert(out.factor > REPUTATION_FACTOR_BOUNDS.min && out.factor < 1.0, `expected attenuated factor, got ${out.factor}`);
    assert(r.summary.riskScore < 60, `score should be suppressed, got ${r.summary.riskScore}`);
  });

  test('P4 (anti-ATO guard): a historical non-latest version (no pre-release tag) is still SKIPPED', () => {
    const r = makeResult(60);
    const out = applyReputationFactor(r, { ...ESTABLISHED, latest_version: '3.19.1', scan_version: '3.10.0', dist_tags: { latest: '3.19.1' } });
    assert(out === null, 'historical/pinned-old versions must not inherit reputation');
    assert(r.summary.riskScore === 60, `score must be unchanged, got ${r.summary.riskScore}`);
  });

  test('P4: the latest version still gets the FULL reputation (unchanged)', () => {
    const r = makeResult(60);
    const out = applyReputationFactor(r, { ...ESTABLISHED, latest_version: '3.19.1', scan_version: '3.19.1', dist_tags: { latest: '3.19.1' } });
    assert(out !== null && out.factor === REPUTATION_FACTOR_BOUNDS.min, `latest gets full min factor, got ${out && out.factor}`);
  });

  test('P4: a malicious canary is still floored by Track R (reputation cannot bury it)', () => {
    const hcType = [...HIGH_CONFIDENCE_MALICE_TYPES][0];
    const r = makeResultWithThreats(80, [{ type: hcType, severity: 'CRITICAL' }]);
    applyReputationFactor(r, { ...ESTABLISHED, latest_version: '3.19.1', scan_version: '3.19.0-nightly-x', dist_tags: { latest: '3.19.1', next: '3.19.0-nightly-x' } });
    assert(r.summary.riskScore >= REPUTATION_MALICE_FLOOR, `confirmed malice on a canary must stay >= ${REPUTATION_MALICE_FLOOR}, got ${r.summary.riskScore}`);
  });
}

module.exports = { runReputationFactorTests };
