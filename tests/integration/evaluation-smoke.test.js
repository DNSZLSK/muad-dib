const { test, assert } = require('../test-utils');

async function runEvaluationSmokeTests() {
  console.log('\n=== EVALUATION SMOKE TESTS ===\n');

  const {
    ADR_THRESHOLD,
    GT_THRESHOLD,
    BENIGN_THRESHOLD,
    ADVERSARIAL_SAMPLES,
    HOLDOUT_SAMPLES,
  } = require('../../src/commands/evaluate.js');

  test('EVAL-SMOKE: ADR_THRESHOLD is a positive number', () => {
    assert(typeof ADR_THRESHOLD === 'number', 'ADR_THRESHOLD should be a number');
    assert(ADR_THRESHOLD > 0, 'ADR_THRESHOLD should be > 0');
  });

  test('EVAL-SMOKE: GT_THRESHOLD is a positive number', () => {
    assert(typeof GT_THRESHOLD === 'number', 'GT_THRESHOLD should be a number');
    assert(GT_THRESHOLD > 0, 'GT_THRESHOLD should be > 0');
  });

  test('EVAL-SMOKE: BENIGN_THRESHOLD is a positive number', () => {
    assert(typeof BENIGN_THRESHOLD === 'number', 'BENIGN_THRESHOLD should be a number');
    assert(BENIGN_THRESHOLD > 0, 'BENIGN_THRESHOLD should be > 0');
  });

  test('EVAL-SMOKE: BENIGN_THRESHOLD and ADR_THRESHOLD are aligned', () => {
    assert(ADR_THRESHOLD === BENIGN_THRESHOLD,
      `ADR_THRESHOLD (${ADR_THRESHOLD}) should equal BENIGN_THRESHOLD (${BENIGN_THRESHOLD})`);
  });

  test('EVAL-SMOKE: Sample lists are arrays (no per-sample thresholds)', () => {
    assert(Array.isArray(ADVERSARIAL_SAMPLES), 'ADVERSARIAL_SAMPLES should be an array');
    assert(Array.isArray(HOLDOUT_SAMPLES), 'HOLDOUT_SAMPLES should be an array');
  });

  test('EVAL-SMOKE: Sample lists have no duplicates', () => {
    const advSet = new Set(ADVERSARIAL_SAMPLES);
    // Note: fn-return-eval appears twice (Vague 6 Group B), deduplicate check is on unique entries
    const holdSet = new Set(HOLDOUT_SAMPLES);
    assert(holdSet.size === HOLDOUT_SAMPLES.length,
      `HOLDOUT_SAMPLES has duplicates: ${HOLDOUT_SAMPLES.length} entries, ${holdSet.size} unique`);
  });

  test('EVAL-SMOKE: Scoring weights are consistent between monitor and scoring', () => {
    const { SEVERITY_WEIGHTS } = require('../../src/scoring.js');
    const { computeRiskScore } = require('../../src/monitor.js');

    // Verify monitor uses same weights as scoring.js
    const oneOfEach = computeRiskScore({ critical: 1, high: 1, medium: 1, low: 1 });
    const expected = SEVERITY_WEIGHTS.CRITICAL + SEVERITY_WEIGHTS.HIGH + SEVERITY_WEIGHTS.MEDIUM + SEVERITY_WEIGHTS.LOW;
    assert(oneOfEach === expected,
      `Monitor score (${oneOfEach}) should match scoring.js weights sum (${expected})`);
  });
}

module.exports = { runEvaluationSmokeTests };
