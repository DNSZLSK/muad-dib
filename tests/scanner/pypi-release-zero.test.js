'use strict';

const { test, assert } = require('../test-utils');

function runPyPIReleaseZeroTests() {
  console.log('\n=== PYPI RELEASE-ZERO TESTS ===\n');

  const { checkPyPIReleaseZero, _internal } = require('../../src/scanner/pypi-release-zero.js');
  const { PYPI_RELEASE_ZERO_RE } = _internal;

  test('PYPI-RZ: regex matches PEP 440 zero-versions', () => {
    const positives = ['0', '0.0', '0.0.0', '0.0.0.0', '0.0.0a1', '0.0.0b2', '0.0.0rc3', '0.0.0.dev1', '0.0.0.post1', '0!0.0'];
    for (const v of positives) {
      assert(PYPI_RELEASE_ZERO_RE.test(v), `expected match for "${v}"`);
    }
  });

  test('PYPI-RZ: regex rejects non-zero versions', () => {
    const negatives = ['0.1.0', '0.0.1', '1.0.0', '', 'abc', '0..0'];
    for (const v of negatives) {
      assert(!PYPI_RELEASE_ZERO_RE.test(v), `expected no match for "${v}"`);
    }
  });

  test('PYPI-RZ: fires on v0.0.0 + recent publish (<30d)', () => {
    const t = checkPyPIReleaseZero('0.0.0', { age_days: 5 });
    assert(t !== null);
    assert(t.type === 'pypi_release_zero');
    assert(t.severity === 'MEDIUM');
    assert(t.version === '0.0.0');
    assert(t.age_days === 5);
    assert(t.file === 'pyproject.toml');
  });

  test('PYPI-RZ: no fire on v0.0.0 + old publish (>30d)', () => {
    assert(checkPyPIReleaseZero('0.0.0', { age_days: 31 }) === null);
    assert(checkPyPIReleaseZero('0.0.0', { age_days: 365 }) === null);
  });

  test('PYPI-RZ: no fire on real v1.0.0 even if recent', () => {
    assert(checkPyPIReleaseZero('1.0.0', { age_days: 1 }) === null);
  });

  test('PYPI-RZ: no fire on missing meta or missing age_days', () => {
    assert(checkPyPIReleaseZero('0.0.0', null) === null);
    assert(checkPyPIReleaseZero('0.0.0', {}) === null);
    assert(checkPyPIReleaseZero('0.0.0', { age_days: null }) === null);
  });

  test('PYPI-RZ: fires on PEP 440 pre-release v0.0.0a1 + recent', () => {
    const t = checkPyPIReleaseZero('0.0.0a1', { age_days: 10 });
    assert(t !== null && t.severity === 'MEDIUM');
  });

  test('PYPI-RZ: no fire on empty / non-string version', () => {
    assert(checkPyPIReleaseZero('', { age_days: 1 }) === null);
    assert(checkPyPIReleaseZero(null, { age_days: 1 }) === null);
    assert(checkPyPIReleaseZero(undefined, { age_days: 1 }) === null);
  });
}

module.exports = { runPyPIReleaseZeroTests };
