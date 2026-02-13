const path = require('path');
const { test, assertIncludes, runScan, TESTS_DIR } = require('../test-utils');

async function runPackageTests() {
  console.log('\n=== PACKAGE.JSON TESTS ===\n');

  test('PACKAGE: Detects suspicious preinstall', () => {
    const output = runScan(path.join(TESTS_DIR, 'package'));
    assertIncludes(output, 'preinstall', 'Should detect preinstall');
  });

  test('PACKAGE: Detects suspicious postinstall', () => {
    const output = runScan(path.join(TESTS_DIR, 'package'));
    assertIncludes(output, 'postinstall', 'Should detect postinstall');
  });

  // Marker tests (grouped under package scanner)
  console.log('\n=== MARKER TESTS ===\n');

  test('MARKERS: Detects Shai-Hulud', () => {
    const output = runScan(path.join(TESTS_DIR, 'markers'));
    assertIncludes(output, 'Shai-Hulud', 'Should detect Shai-Hulud marker');
  });

  test('MARKERS: Detects The Second Coming', () => {
    const output = runScan(path.join(TESTS_DIR, 'markers'));
    assertIncludes(output, 'Second Coming', 'Should detect The Second Coming marker');
  });
}

module.exports = { runPackageTests };
