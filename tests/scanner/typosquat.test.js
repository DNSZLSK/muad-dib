const path = require('path');
const { test, assert, assertIncludes, runScan, TESTS_DIR } = require('../test-utils');

async function runTyposquatTests() {
  console.log('\n=== TYPOSQUATTING TESTS ===\n');

  test('TYPOSQUAT: Detects lodahs (lodash)', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'lodahs', 'Should detect lodahs');
  });

  test('TYPOSQUAT: Detects axois (axios)', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'axois', 'Should detect axois');
  });

  test('TYPOSQUAT: Detects expres (express)', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'expres', 'Should detect expres');
  });

  test('TYPOSQUAT: Severity HIGH', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'HIGH', 'Should be HIGH');
  });
}

module.exports = { runTyposquatTests };
