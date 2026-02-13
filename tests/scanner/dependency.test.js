const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, createTempPkg, cleanupTemp } = require('../test-utils');
const {
  scanDependencies,
  checkRehabilitatedPackage
} = require('../../src/scanner/dependencies.js');
const { safeInstall } = require('../../src/safe-install.js');

async function runDependencyTests() {
  console.log('\n=== DEPENDENCIES TESTS ===\n');

  // --- checkRehabilitatedPackage ---

  test('DEPS: checkRehabilitatedPackage null for unknown', () => {
    assert(checkRehabilitatedPackage('unknown-xyz', '1.0.0') === null, 'Should return null');
  });

  test('DEPS: checkRehabilitatedPackage true for safe=true', () => {
    assert(checkRehabilitatedPackage('chalk', '5.0.0') === true, 'chalk should be true');
  });

  test('DEPS: checkRehabilitatedPackage false for compromised version', () => {
    assert(checkRehabilitatedPackage('ua-parser-js', '0.7.29') === false, 'Should be false');
  });

  test('DEPS: checkRehabilitatedPackage true for safe version of partial', () => {
    assert(checkRehabilitatedPackage('ua-parser-js', '2.0.0') === true, 'Should be true');
  });

  // --- scanDependencies async tests ---

  await asyncTest('DEPS: scanDependencies empty without node_modules', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats) && threats.length === 0, 'Should be empty array');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies skips rehabilitated safe pkg', async () => {
    const tmpDir = createTempPkg([{ name: 'chalk', version: '5.4.0' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.file && x.file.includes('chalk'));
      assert(t.length === 0, 'chalk should not generate threats');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects rehabilitated compromised version', async () => {
    const tmpDir = createTempPkg([{ name: 'coa', version: '2.0.3' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.message && x.message.includes('coa'));
      assert(t.length > 0, 'Should detect coa@2.0.3');
      assert(t[0].severity === 'CRITICAL', 'Should be CRITICAL');
      assert(t[0].type === 'known_malicious_package', 'Should be known_malicious_package');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects wildcard malicious pkg', async () => {
    const tmpDir = createTempPkg([{ name: 'lodahs', version: '1.0.0' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.message && x.message.includes('lodahs'));
      assert(t.length > 0, 'Should detect lodahs');
      assert(t[0].severity === 'CRITICAL', 'Should be CRITICAL');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects specific version malicious pkg', async () => {
    const tmpDir = createTempPkg([{ name: 'event-stream', version: '3.3.6' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.message && x.message.includes('event-stream'));
      assert(t.length > 0, 'Should detect event-stream@3.3.6');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies skips trusted pkg for file checks', async () => {
    const tmpDir = createTempPkg([
      { name: 'esbuild', version: '0.19.0', files: [{ name: 'setup_bun.js' }] }
    ]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.type === 'suspicious_file' && x.file.includes('esbuild'));
      assert(t.length === 0, 'esbuild should not trigger suspicious file');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects suspicious file', async () => {
    const tmpDir = createTempPkg([
      { name: 'random-pkg-abc', version: '1.0.0', files: [{ name: 'setup_bun.js' }] }
    ]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.type === 'suspicious_file');
      assert(t.length > 0, 'Should detect suspicious file');
      assert(t[0].severity === 'HIGH', 'Should be HIGH');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects Shai-Hulud marker', async () => {
    const tmpDir = createTempPkg([{
      name: 'evil-pkg-test',
      version: '1.0.0',
      rawPkgJson: JSON.stringify({ name: 'evil-pkg-test', version: '1.0.0', description: 'Shai-Hulud was here' })
    }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.type === 'shai_hulud_marker');
      assert(t.length > 0, 'Should detect Shai-Hulud marker');
      assert(t[0].severity === 'CRITICAL', 'Should be CRITICAL');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: listPackages handles scoped packages', async () => {
    const tmpDir = createTempPkg([{ name: '@test-scope/test-pkg', version: '1.0.0' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should handle scoped packages');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: listPackages skips hidden directories', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    fs.mkdirSync(path.join(tmpDir, 'node_modules', '.cache'), { recursive: true });
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should skip hidden dirs');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: listPackages skips non-directory items', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(path.join(nmDir, 'README.md'), 'hello');
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should skip files');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: getPackageVersion returns * without package.json', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    fs.mkdirSync(path.join(tmpDir, 'node_modules', 'no-pkg-json'), { recursive: true });
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should not crash');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: getPackageVersion returns * for missing version field', async () => {
    const tmpDir = createTempPkg([
      { name: 'no-version-pkg', rawPkgJson: JSON.stringify({ name: 'no-version-pkg' }) }
    ]);
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should handle missing version');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  // --- Safe install tests ---

  console.log('\n=== SAFE INSTALL TESTS ===\n');

  async function quietSafeInstall(packages, options) {
    const origLog = console.log;
    console.log = () => {};
    try {
      return await safeInstall(packages, options);
    } finally {
      console.log = origLog;
    }
  }

  await asyncTest('SAFE-INSTALL: blocks known malicious wildcard package', async () => {
    const result = await quietSafeInstall(['lodahs']);
    assert(result.blocked === true, 'Should be blocked');
    assert(result.package === 'lodahs', 'Should identify lodahs');
  });

  await asyncTest('SAFE-INSTALL: blocks rehabilitated compromised version', async () => {
    const result = await quietSafeInstall(['coa@2.0.3']);
    assert(result.blocked === true, 'Should be blocked');
    assert(result.package === 'coa', 'Should identify coa');
  });

  await asyncTest('SAFE-INSTALL: cache prevents rescan, IOC catches malicious', async () => {
    const result = await quietSafeInstall(['lodahs']);
    assert(result.blocked === true, 'Should be blocked by lodahs');
    assert(result.package === 'lodahs', 'Should identify lodahs');
  });

  await asyncTest('SAFE-INSTALL: scoped package version parsing + invalid name', async () => {
    const result = await quietSafeInstall(['@evil/foo;bar@1.0.0']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: force mode continues then name validation blocks', async () => {
    const result = await quietSafeInstall(['lodahs', 'foo;rm'], { force: true });
    assert(result.blocked === true, 'Should be blocked by name validation');
  });

  await asyncTest('SAFE-INSTALL: rehabilitated safe package passes checkIOCs', async () => {
    const result = await quietSafeInstall(['chalk', 'lodahs']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: non-scoped package with version parsing', async () => {
    const result = await quietSafeInstall(['event-stream@3.3.6']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: depth=0 unknown pkg blocked by npm view fail', async () => {
    const result = await quietSafeInstall(['zzz-nonexistent-pkg-99999', 'lodahs']);
    assert(result.blocked === true, 'Should be blocked');
  });
}

module.exports = { runDependencyTests };
