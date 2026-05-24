const { test, assert } = require('../test-utils');
const { checkReleaseZero } = require('../../src/scanner/release-zero.js');

async function runReleaseZeroTests() {
  console.log('\n=== RELEASE_ZERO TESTS ===\n');

  // ── Positive cases (conjunction met) ──
  test('RELEASE_ZERO: 0.0.0 + postinstall triggers MEDIUM', () => {
    const t = checkReleaseZero('0.0.0', { postinstall: 'node setup.js' }, null);
    assert(t !== null, 'expected threat');
    assert(t.type === 'release_zero_package', 'wrong type: ' + t.type);
    assert(t.severity === 'MEDIUM', 'expected MEDIUM, got ' + t.severity);
    assert(t.reason === 'install_scripts');
    assert(t.file === 'package.json');
  });

  test('RELEASE_ZERO: 0.0 + install script triggers', () => {
    const t = checkReleaseZero('0.0', { install: './evil.sh' }, null);
    assert(t !== null);
    assert(t.severity === 'MEDIUM');
  });

  test('RELEASE_ZERO: 0 + preinstall triggers', () => {
    const t = checkReleaseZero('0', { preinstall: 'node a.js' }, null);
    assert(t !== null);
  });

  test('RELEASE_ZERO: 0.0.0 + recent publish (5d) triggers', () => {
    const t = checkReleaseZero('0.0.0', {}, { age_days: 5 });
    assert(t !== null);
    assert(t.reason === 'recent_publish');
  });

  test('RELEASE_ZERO: 0.0.0 + recent (0d, just published) triggers', () => {
    const t = checkReleaseZero('0.0.0', {}, { age_days: 0 });
    assert(t !== null);
  });

  test('RELEASE_ZERO: both install_scripts AND recent → reason=install_scripts (prioritised)', () => {
    const t = checkReleaseZero('0.0.0', { postinstall: 'a' }, { age_days: 5 });
    assert(t !== null);
    assert(t.reason === 'install_scripts', 'install_scripts must be reported when both present');
  });

  // ── Negative cases (no FP) ──
  test('RELEASE_ZERO: 1.0.0 with install script does NOT trigger', () => {
    assert(checkReleaseZero('1.0.0', { postinstall: 'node a.js' }, null) === null);
  });

  test('RELEASE_ZERO: 0.0.0 with no scripts + old (1000d) does NOT trigger (abandonned placeholder)', () => {
    assert(checkReleaseZero('0.0.0', {}, { age_days: 1000 }) === null);
  });

  test('RELEASE_ZERO: 0.0.0 with no scripts and no metadata does NOT trigger', () => {
    assert(checkReleaseZero('0.0.0', {}, null) === null);
  });

  test('RELEASE_ZERO: 0.0.0-beta does NOT trigger (semver pre-release legitimate)', () => {
    assert(checkReleaseZero('0.0.0-beta', { postinstall: 'a' }, null) === null);
  });

  test('RELEASE_ZERO: v0.0.0 does NOT trigger (leading v non-standard)', () => {
    assert(checkReleaseZero('v0.0.0', { postinstall: 'a' }, null) === null);
  });

  test('RELEASE_ZERO: null/empty/undefined version does NOT trigger', () => {
    assert(checkReleaseZero(null, { postinstall: 'a' }, null) === null);
    assert(checkReleaseZero('', { postinstall: 'a' }, null) === null);
    assert(checkReleaseZero(undefined, { postinstall: 'a' }, null) === null);
  });

  test('RELEASE_ZERO: age_days = 30 (boundary) does NOT trigger (strict <30)', () => {
    assert(checkReleaseZero('0.0.0', {}, { age_days: 30 }) === null);
  });

  test('RELEASE_ZERO: age_days = -1 (data error) does NOT trigger', () => {
    assert(checkReleaseZero('0.0.0', {}, { age_days: -1 }) === null);
  });

  test('RELEASE_ZERO: 0.0.0.0 (4 segments) does NOT trigger (only 0/0.0/0.0.0 forms)', () => {
    assert(checkReleaseZero('0.0.0.0', { postinstall: 'a' }, null) === null);
  });

  test('RELEASE_ZERO: 0.1.0 does NOT trigger (non-zero minor)', () => {
    assert(checkReleaseZero('0.1.0', { postinstall: 'a' }, null) === null);
  });

  // ── Isolated-signal safety (feedback_weak_signals_composite_scoring) ──
  // MEDIUM (3) × confidence_high (1.0) = 3 points. Well below T1 (20) and the
  // alert threshold (35). A single release_zero signal cannot trigger a HIGH
  // alert on its own — it only contributes to composite scoring.
  test('RELEASE_ZERO: MEDIUM severity ensures signal stays below T1 in isolation', () => {
    const t = checkReleaseZero('0.0.0', { postinstall: 'node a.js' }, null);
    assert(t !== null);
    // MEDIUM weight is 3, confidence high (1.0) → 3 points isolated. Safe.
    assert(t.severity === 'MEDIUM', 'severity must stay MEDIUM to keep isolated score <20');
  });
}

module.exports = { runReleaseZeroTests };
