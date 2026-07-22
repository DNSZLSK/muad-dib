'use strict';

const { test, assert } = require('../test-utils');

async function runSandboxGateTests() {
  console.log('\n=== SANDBOX GATE TESTS ===\n');

  // SANDBOX_SCORE_THRESHOLD is captured at module-load time from
  // process.env.MUADDIB_SANDBOX_SCORE_THRESHOLD. Tests rely on the exported
  // pure helper `computeSandboxScoreThreshold` to verify the parsing /
  // clamping logic without monkey-patching the constant or re-requiring the
  // module.
  const {
    SANDBOX_SCORE_THRESHOLD,
    computeSandboxScoreThreshold,
    computeSandboxGate,
  } = require('../../src/monitor/queue.js');

  // ── Default & clamping ───────────────────────────────────────────────────

  test('SANDBOX-GATE: SANDBOX_SCORE_THRESHOLD is exported as a finite number in [0, 100]', () => {
    assert(typeof SANDBOX_SCORE_THRESHOLD === 'number', `expected number, got ${typeof SANDBOX_SCORE_THRESHOLD}`);
    assert(Number.isFinite(SANDBOX_SCORE_THRESHOLD), 'must be finite');
    assert(SANDBOX_SCORE_THRESHOLD >= 0 && SANDBOX_SCORE_THRESHOLD <= 100,
      `must be in [0, 100], got ${SANDBOX_SCORE_THRESHOLD}`);
  });

  test('SANDBOX-GATE: default threshold is 40 when env var is unset/empty', () => {
    assert(computeSandboxScoreThreshold(undefined) === 40,
      `unset → 40, got ${computeSandboxScoreThreshold(undefined)}`);
    assert(computeSandboxScoreThreshold('') === 40,
      `empty → 40, got ${computeSandboxScoreThreshold('')}`);
    assert(computeSandboxScoreThreshold(null) === 40,
      `null → 40, got ${computeSandboxScoreThreshold(null)}`);
  });

  test('SANDBOX-GATE: numeric strings parse correctly', () => {
    assert(computeSandboxScoreThreshold('25') === 25, `"25" → 25, got ${computeSandboxScoreThreshold('25')}`);
    assert(computeSandboxScoreThreshold('40') === 40, `"40" → 40, got ${computeSandboxScoreThreshold('40')}`);
    assert(computeSandboxScoreThreshold('80') === 80, `"80" → 80, got ${computeSandboxScoreThreshold('80')}`);
    assert(computeSandboxScoreThreshold('0') === 0,
      `"0" → 0 (must NOT fall through to default), got ${computeSandboxScoreThreshold('0')}`);
  });

  test('SANDBOX-GATE: out-of-range values are clamped to [0, 100]', () => {
    assert(computeSandboxScoreThreshold('-50') === 0,
      `negative → 0, got ${computeSandboxScoreThreshold('-50')}`);
    assert(computeSandboxScoreThreshold('999') === 100,
      `> 100 → 100, got ${computeSandboxScoreThreshold('999')}`);
    assert(computeSandboxScoreThreshold('150') === 100,
      `150 → 100, got ${computeSandboxScoreThreshold('150')}`);
  });

  test('SANDBOX-GATE: non-numeric strings fall through to default 40', () => {
    assert(computeSandboxScoreThreshold('abc') === 40,
      `"abc" → 40, got ${computeSandboxScoreThreshold('abc')}`);
    assert(computeSandboxScoreThreshold('NaN') === 40,
      `"NaN" → 40, got ${computeSandboxScoreThreshold('NaN')}`);
  });

  // ── Behaviour: gate semantics (real exported gate, exercised offline) ────
  //
  // computeSandboxGate IS the tier gate used by scanPackage (queue.js) — no
  // replica to keep in lockstep. The environment preconditions
  // (isSandboxEnabled, sandboxAvailable, large-package skip) stay at the call
  // site; this covers the tier/score/queue policy itself.

  test('SANDBOX-GATE: T1a always sandboxes regardless of score (HC malice mandatory)', () => {
    assert(computeSandboxGate('1a', 0, 100, 40) === true, 'T1a score=0 → true');
    assert(computeSandboxGate('1a', 5, 5_000, 40) === true, 'T1a score=5 with huge queue → true');
    assert(computeSandboxGate('1a', 99, 0, 80) === true, 'T1a score=99 high threshold → true');
  });

  test('SANDBOX-GATE: T1b score < threshold → NO sandbox (gates out the 25-39 noise band)', () => {
    assert(computeSandboxGate('1b', 24, 0, 40) === false, 'T1b score=24 < 40 → false');
    assert(computeSandboxGate('1b', 39, 0, 40) === false, 'T1b score=39 < 40 → false');
    assert(computeSandboxGate('1b', 25, 0, 40) === false,
      'T1b score=25 (old threshold) now gated out → false');
  });

  test('SANDBOX-GATE: T1b score >= threshold → sandbox eligible', () => {
    assert(computeSandboxGate('1b', 40, 5_000, 40) === true,
      'T1b score=40 (axon-enterprise was 52) → true regardless of queue depth');
    assert(computeSandboxGate('1b', 100, 0, 40) === true, 'T1b score=100 → true');
  });

  test('SANDBOX-GATE: T2 requires BOTH score gate AND queue < 50', () => {
    assert(computeSandboxGate(2, 40, 49, 40) === true,  'T2 score=40 + queue=49 → true');
    assert(computeSandboxGate(2, 40, 50, 40) === false, 'T2 score=40 + queue=50 → false (queue cap)');
    assert(computeSandboxGate(2, 30, 0, 40) === false,  'T2 score=30 + queue=0 → false (score gate)');
  });

  test('SANDBOX-GATE: unknown tier never sandboxes (no accidental default-true)', () => {
    assert(computeSandboxGate(3, 100, 0, 40) === false, 'tier 3 → false even at score 100');
    assert(computeSandboxGate(undefined, 100, 0, 40) === false, 'undefined tier → false');
    assert(computeSandboxGate('2', 100, 0, 40) === false,
      'string "2" is not tier 2 — the gate compares strictly (T1 tiers are strings, T2 is a number)');
  });

  test('SANDBOX-GATE: env var override widens or tightens the gate', () => {
    // Operators can lower the threshold during a rollback if Stage 3 turns out
    // to drop a real signal somewhere — e.g. set MUADDIB_SANDBOX_SCORE_THRESHOLD=25.
    const widened = computeSandboxScoreThreshold('25');
    assert(computeSandboxGate('1b', 25, 0, widened) === true,
      'T1b score=25 with threshold=25 → true (operator lowered the gate)');
    const tightened = computeSandboxScoreThreshold('60');
    assert(computeSandboxGate('1b', 52, 0, tightened) === false,
      'T1b score=52 with threshold=60 → false (axon-enterprise would now miss — illustrates the 40 default is the right floor)');
  });
}

module.exports = { runSandboxGateTests };
