const path = require('path');
const { test, assertIncludes, runScan, TESTS_DIR } = require('../test-utils');

async function runObfuscationTests() {
  console.log('\n=== OBFUSCATION TESTS ===\n');

  test('OBFUSCATION: Detects massive hex escapes', () => {
    const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
    assertIncludes(output, 'obfusc', 'Should detect obfuscation');
  });

  test('OBFUSCATION: Detects _0x variables', () => {
    const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
    assertIncludes(output, 'obfusc', 'Should detect _0x variables');
  });
}

module.exports = { runObfuscationTests };
