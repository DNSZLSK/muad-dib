const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, createTempPkg, cleanupTemp } = require('../test-utils');
const {
  scanDependencies,
  checkRehabilitatedPackage,
  listPackages,
  getPackageVersion
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

  test('DEPS: listPackages resolves scoped packages to "@scope/name" with version', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    const scopedDir = path.join(nmDir, '@test-scope', 'test-pkg');
    fs.mkdirSync(scopedDir, { recursive: true });
    fs.writeFileSync(path.join(scopedDir, 'package.json'), JSON.stringify({ name: '@test-scope/test-pkg', version: '2.1.0' }));
    try {
      const pkgs = listPackages(nmDir);
      const scoped = pkgs.find(p => p.name === '@test-scope/test-pkg');
      assert(scoped, 'Scoped package must be listed under its full @scope/name');
      assert(scoped.version === '2.1.0', `Should read the scoped version, got ${scoped.version}`);
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  test('DEPS: listPackages skips hidden directories (.cache is not a package)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(path.join(nmDir, '.cache'), { recursive: true });
    fs.mkdirSync(path.join(nmDir, 'real-pkg'), { recursive: true });
    try {
      const pkgs = listPackages(nmDir);
      assert(!pkgs.some(p => p.name === '.cache'), 'Hidden .cache dir must be skipped');
      assert(pkgs.some(p => p.name === 'real-pkg'), 'Non-hidden package must still be listed');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  test('DEPS: listPackages skips non-directory items (a stray file is not a package)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(path.join(nmDir, 'README.md'), 'hello');
    fs.mkdirSync(path.join(nmDir, 'real-pkg'), { recursive: true });
    try {
      const pkgs = listPackages(nmDir);
      assert(!pkgs.some(p => p.name === 'README.md'), 'A plain file must not be listed as a package');
      assert(pkgs.some(p => p.name === 'real-pkg'), 'The real package dir must still be listed');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  test('DEPS: getPackageVersion returns "*" when package.json is absent', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const pkgDir = path.join(tmpDir, 'no-pkg-json');
    fs.mkdirSync(pkgDir, { recursive: true });
    try {
      assert(getPackageVersion(pkgDir) === '*', 'Missing package.json → version "*"');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  test('DEPS: getPackageVersion returns "*" when the version field is missing, else the version', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const noVer = path.join(tmpDir, 'no-version');
    const withVer = path.join(tmpDir, 'with-version');
    fs.mkdirSync(noVer, { recursive: true });
    fs.mkdirSync(withVer, { recursive: true });
    fs.writeFileSync(path.join(noVer, 'package.json'), JSON.stringify({ name: 'no-version' }));
    fs.writeFileSync(path.join(withVer, 'package.json'), JSON.stringify({ name: 'with-version', version: '3.4.5' }));
    try {
      assert(getPackageVersion(noVer) === '*', 'Missing version field → "*"');
      assert(getPackageVersion(withVer) === '3.4.5', 'Present version field → its value');
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

  await asyncTest('SAFE-INSTALL: scoped package version parsing + invalid name', async () => {
    const result = await quietSafeInstall(['@evil/foo;bar@1.0.0']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: force mode bypasses IOC block, name validation still blocks the bad name', async () => {
    // With force:true the lodahs IOC block is bypassed (install continues), so
    // the block must come from the invalid name 'foo;rm' — not from lodahs.
    const result = await quietSafeInstall(['lodahs', 'foo;rm'], { force: true });
    assert(result.blocked === true, 'Should be blocked by name validation');
    assert(result.package === 'foo;rm', `The blocker must be the invalid name, not lodahs — got ${result.package}`);
  });

  await asyncTest('SAFE-INSTALL: a non-IOC package passes the IOC check; the real IOC (lodahs) is the blocker', async () => {
    // Mock `npm view` to succeed so chalk clears the registry check offline —
    // otherwise fail-closed blocks chalk first and we never reach lodahs. This
    // isolates the IOC-check discrimination: chalk (not in IOC) must pass, and
    // lodahs (wildcard IOC, caught before npm view) must be the blocker.
    const cp = require('child_process');
    const origSpawn = cp.spawnSync;
    cp.spawnSync = (cmd, args, opts) => {
      if (Array.isArray(args) && args[0] === 'view') {
        return { status: 0, stdout: JSON.stringify({ name: args[1], version: '5.0.0' }), stderr: '', error: null };
      }
      return origSpawn(cmd, args, opts);
    };
    try {
      const result = await quietSafeInstall(['chalk', 'lodahs']);
      assert(result.blocked === true, 'Should be blocked');
      assert(result.package === 'lodahs', `chalk must pass the IOC check — the blocker is lodahs, got ${result.package}`);
    } finally {
      cp.spawnSync = origSpawn;
    }
  });

  await asyncTest('SAFE-INSTALL: non-scoped package with version parsing', async () => {
    const result = await quietSafeInstall(['event-stream@3.3.6']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: an unknown package is blocked when npm view fails (fail-closed)', async () => {
    // Mock `npm view` to fail deterministically (offline-hermetic). safe-install
    // keeps cp.spawnSync mockable on purpose (see its module header comment).
    const cp = require('child_process');
    const origSpawn = cp.spawnSync;
    cp.spawnSync = (cmd, args, opts) => {
      if (Array.isArray(args) && args[0] === 'view') {
        return { status: 1, stdout: '', stderr: 'npm ERR! 404 Not found', error: null };
      }
      return origSpawn(cmd, args, opts);
    };
    try {
      const result = await quietSafeInstall(['zzz-nonexistent-pkg-99999']);
      assert(result.blocked === true, 'Unknown package with a failing npm view must be blocked (fail-closed)');
      assert(result.package === 'zzz-nonexistent-pkg-99999',
        `The blocked package must be the unknown one, got ${result.package}`);
    } finally {
      cp.spawnSync = origSpawn;
    }
  });
}

module.exports = { runDependencyTests };
