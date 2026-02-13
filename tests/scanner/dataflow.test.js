const path = require('path');
const { test, assertIncludes, runScan, TESTS_DIR } = require('../test-utils');

async function runDataflowTests() {
  console.log('\n=== DATAFLOW TESTS ===\n');

  test('DATAFLOW: Detects credential read + network send', () => {
    const output = runScan(path.join(TESTS_DIR, 'dataflow'));
    assertIncludes(output, 'Suspicious flow', 'Should detect suspicious flow');
  });

  test('DATAFLOW: Detects env read + fetch', () => {
    const output = runScan(path.join(TESTS_DIR, 'dataflow'));
    assertIncludes(output, 'CRITICAL', 'Should be CRITICAL');
  });
}

module.exports = { runDataflowTests };
