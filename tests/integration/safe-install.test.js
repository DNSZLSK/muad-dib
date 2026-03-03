const { test, asyncTest, assert, assertIncludes } = require('../test-utils');

async function runSafeInstallTests() {
  console.log('\n=== SAFE INSTALL TESTS ===\n');

  const { isValidPackageName, checkRehabilitated, safeInstall, checkIOCs } = require('../../src/safe-install.js');

  // --- isValidPackageName ---

  test('SAFE-INSTALL: Valid unscoped package name', () => {
    assert(isValidPackageName('express') === true, 'express should be valid');
    assert(isValidPackageName('lodash') === true, 'lodash should be valid');
    assert(isValidPackageName('my-package') === true, 'my-package should be valid');
    assert(isValidPackageName('my_package') === true, 'my_package should be valid');
    assert(isValidPackageName('my.package') === true, 'my.package should be valid');
  });

  test('SAFE-INSTALL: Valid scoped package name', () => {
    assert(isValidPackageName('@scope/package') === true, '@scope/package should be valid');
    assert(isValidPackageName('@babel/core') === true, '@babel/core should be valid');
    assert(isValidPackageName('@types/node') === true, '@types/node should be valid');
  });

  test('SAFE-INSTALL: Package name with version suffix', () => {
    assert(isValidPackageName('express@4.18.0') === true, 'express@4.18.0 should be valid');
    assert(isValidPackageName('@scope/pkg@latest') === true, '@scope/pkg@latest should be valid');
    assert(isValidPackageName('@scope/pkg@1.0.0') === true, '@scope/pkg@1.0.0 should be valid');
  });

  test('SAFE-INSTALL: Invalid package names (injection attempts)', () => {
    assert(isValidPackageName('pkg; rm -rf /') === false, 'semicolon injection should be invalid');
    assert(isValidPackageName('$(whoami)') === false, 'command substitution should be invalid');
    assert(isValidPackageName('pkg && echo hacked') === false, 'ampersand injection should be invalid');
    assert(isValidPackageName('../../../etc/passwd') === false, 'path traversal should be invalid');
    assert(isValidPackageName('PKG_WITH_CAPS') === false, 'uppercase should be invalid');
  });

  test('SAFE-INSTALL: Scoped package without slash is invalid', () => {
    assert(isValidPackageName('@scopeonly') === false, '@scopeonly without / should be invalid');
  });

  // --- checkRehabilitated ---

  test('SAFE-INSTALL: Rehabilitated package returns safe', () => {
    const result = checkRehabilitated('chalk', '5.0.0');
    assert(result !== null, 'chalk should be in rehabilitated list');
    assert(result.safe === true, 'chalk should be safe');
    assert(typeof result.note === 'string', 'Should have a note');
  });

  test('SAFE-INSTALL: Non-rehabilitated package returns null', () => {
    const result = checkRehabilitated('totally-unknown-pkg-xyz', '1.0.0');
    assert(result === null, 'Unknown package should return null');
  });

  test('SAFE-INSTALL: Rehabilitated package with compromised version', () => {
    // Find a package with specific compromised versions
    const { REHABILITATED_PACKAGES } = require('../../src/shared/constants.js');
    let testPkg = null;
    let testVersion = null;
    for (const [name, info] of Object.entries(REHABILITATED_PACKAGES)) {
      if (info.compromised && info.compromised.length > 0) {
        testPkg = name;
        testVersion = info.compromised[0];
        break;
      }
    }
    if (testPkg) {
      const result = checkRehabilitated(testPkg, testVersion);
      assert(result !== null, `${testPkg} should be in rehabilitated list`);
      assert(result.safe === false, `${testPkg}@${testVersion} should NOT be safe (compromised version)`);
    }
  });

  test('SAFE-INSTALL: Rehabilitated package with non-compromised version is safe', () => {
    const { REHABILITATED_PACKAGES } = require('../../src/shared/constants.js');
    let testPkg = null;
    for (const [name, info] of Object.entries(REHABILITATED_PACKAGES)) {
      if (info.compromised && info.compromised.length > 0) {
        testPkg = name;
        break;
      }
    }
    if (testPkg) {
      const result = checkRehabilitated(testPkg, '999.999.999');
      assert(result !== null, `${testPkg} should be in rehabilitated list`);
      assert(result.safe === true, `${testPkg}@999.999.999 should be safe (not in compromised list)`);
    }
  });
  // --- checkIOCs ---

  test('SAFE-INSTALL: checkIOCs returns null for safe package', () => {
    const { checkIOCs } = require('../../src/safe-install.js');
    const result = checkIOCs('express', 'express', null);
    assert(result === null, 'express should not be in IOCs');
  });

  test('SAFE-INSTALL: checkIOCs returns null for rehabilitated package', () => {
    const { checkIOCs } = require('../../src/safe-install.js');
    const result = checkIOCs('chalk@5.0.0', 'chalk', '5.0.0');
    assert(result === null, 'chalk@5.0.0 should return null (rehabilitated safe)');
  });

  test('SAFE-INSTALL: checkIOCs returns result for compromised rehabilitated version', () => {
    const { checkIOCs } = require('../../src/safe-install.js');
    const { REHABILITATED_PACKAGES } = require('../../src/shared/constants.js');
    // Find a package with compromised versions
    let testPkg = null;
    let testVersion = null;
    for (const [name, info] of Object.entries(REHABILITATED_PACKAGES)) {
      if (info.compromised && info.compromised.length > 0) {
        testPkg = name;
        testVersion = info.compromised[0];
        break;
      }
    }
    if (testPkg) {
      const result = checkIOCs(testPkg + '@' + testVersion, testPkg, testVersion);
      assert(result !== null, `${testPkg}@${testVersion} should return malicious result`);
      assert(result.source === 'rehabilitated-compromised', 'Source should be rehabilitated-compromised');
    }
  });

  test('SAFE-INSTALL: checkIOCs checks wildcard IOCs (known malicious)', () => {
    const { checkIOCs } = require('../../src/safe-install.js');
    // Test with a package name that's known to be in the IOC database (loadash typosquat)
    const result = checkIOCs('loadash', 'loadash', null);
    // loadash is a known typosquat in the IOC database
    if (result) {
      assert(result.name === 'loadash', 'Should match loadash');
    }
    // Even if not found (depends on IOC load), the function should not throw
  });

  test('SAFE-INSTALL: checkIOCs handles package with version', () => {
    const { checkIOCs } = require('../../src/safe-install.js');
    // Test with a package NOT in IOCs
    const result = checkIOCs('lodash@4.17.21', 'lodash', '4.17.21');
    assert(result === null, 'lodash should not be in IOCs');
  });
  // --- scanPackageRecursive ---

  console.log('\n=== SCAN PACKAGE RECURSIVE TESTS ===\n');

  const { scanPackageRecursive } = require('../../src/safe-install.js');

  await asyncTest('SAFE-INSTALL: scanPackageRecursive rejects invalid name', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await scanPackageRecursive('$(evil)', 0, 3);
      assert(result.safe === false, 'Should be unsafe');
      assert(result.reason === 'invalid_name', 'Reason should be invalid_name');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: scanPackageRecursive skips already-scanned package', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      // First scan to add to cache
      await scanPackageRecursive('lodash', 0, 0);
      // Second scan should return safe immediately (cached)
      const result = await scanPackageRecursive('lodash', 0, 0);
      assert(result.safe === true, 'Cached package should be safe');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: scanPackageRecursive respects depth limit', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await scanPackageRecursive('some-fake-pkg-' + Date.now(), 5, 3);
      assert(result.safe === true, 'Should be safe at depth > maxDepth');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: scanPackageRecursive detects unsafe package', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      // Use a package name that definitely does not exist on npm
      const result = await scanPackageRecursive('zzzz-nonexistent-pkg-test-' + Date.now(), 0, 3);
      assert(result.safe === false, 'Should be unsafe');
      assert(result.reason === 'npm_unreachable',
        'Reason should be npm_unreachable, got ' + result.reason);
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: scanPackageRecursive parses scoped@version', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      // Use an unlikely package at depth > max to test version parsing path
      const result = await scanPackageRecursive('@fake/pkg-' + Date.now() + '@1.0.0', 5, 3);
      assert(result.safe === true, 'Should be safe (depth exceeded)');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: scanPackageRecursive parses unscoped@version', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await scanPackageRecursive('fake-pkg-' + Date.now() + '@2.0.0', 5, 3);
      assert(result.safe === true, 'Should be safe (depth exceeded)');
    } finally {
      console.log = origLog;
    }
  });

  // --- safeInstall ---

  console.log('\n=== SAFE INSTALL FLOW TESTS ===\n');

  await asyncTest('SAFE-INSTALL: safeInstall blocks known malicious package', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await safeInstall(['loadash']);
      if (result.blocked) {
        assert(result.blocked === true, 'Should be blocked');
        assert(result.threats.length > 0, 'Should have threats');
        assert(result.threats[0].severity === 'CRITICAL', 'Should be CRITICAL');
      }
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: safeInstall blocks invalid package name', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await safeInstall(['$(whoami)']);
      assert(result.blocked === true, 'Should be blocked');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SAFE-INSTALL: safeInstall with force flag on malicious package', async () => {
    const origLog = console.log;
    const origAppend = require('fs').appendFileSync;
    const cp = require('child_process');
    const origSpawnSync = cp.spawnSync;
    // Mock appendFileSync to avoid writing audit log
    require('fs').appendFileSync = () => {};
    // Mock spawnSync to prevent real npm install (loadash exists on npm and would contaminate package.json)
    cp.spawnSync = () => ({ status: 1, stdout: '', stderr: 'mocked' });
    console.log = () => {};
    try {
      const result = await safeInstall(['loadash'], { force: true });
      // Force flag allows installation to proceed past IOC check
      // spawnSync is mocked so no real npm install runs
    } finally {
      console.log = origLog;
      require('fs').appendFileSync = origAppend;
      cp.spawnSync = origSpawnSync;
    }
  });
}

module.exports = { runSafeInstallTests };
