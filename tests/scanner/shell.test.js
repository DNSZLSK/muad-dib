const path = require('path');
const { test, assertIncludes, runScan, TESTS_DIR } = require('../test-utils');

async function runShellTests() {
  console.log('\n=== SHELL TESTS ===\n');

  test('SHELL: Detects curl | sh', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'curl', 'Should detect curl | sh');
  });

  test('SHELL: Detects wget && chmod +x', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'wget', 'Should detect wget');
  });

  test('SHELL: Detects reverse shell', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'reverse', 'Should detect reverse shell');
  });

  test('SHELL: Detects rm -rf $HOME', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'home', 'Should detect home deletion');
  });
}

module.exports = { runShellTests };
