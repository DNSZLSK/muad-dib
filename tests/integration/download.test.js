const { test, assert } = require('../test-utils');

async function runDownloadTests() {
  console.log('\n=== DOWNLOAD TESTS ===\n');

  const { isAllowedDownloadRedirect, sanitizePackageName } = require('../../src/shared/download.js');

  // --- isAllowedDownloadRedirect ---

  test('DOWNLOAD: Allows HTTPS to registry.npmjs.org', () => {
    const result = isAllowedDownloadRedirect('https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz');
    assert(result.allowed === true, 'Should allow registry.npmjs.org');
  });

  test('DOWNLOAD: Allows HTTPS to files.pythonhosted.org', () => {
    const result = isAllowedDownloadRedirect('https://files.pythonhosted.org/packages/pkg.tar.gz');
    assert(result.allowed === true, 'Should allow files.pythonhosted.org');
  });

  test('DOWNLOAD: Allows HTTPS to registry.yarnpkg.com', () => {
    const result = isAllowedDownloadRedirect('https://registry.yarnpkg.com/pkg/-/pkg-1.0.0.tgz');
    assert(result.allowed === true, 'Should allow registry.yarnpkg.com');
  });

  test('DOWNLOAD: Blocks HTTP (non-HTTPS)', () => {
    const result = isAllowedDownloadRedirect('http://registry.npmjs.org/pkg');
    assert(result.allowed === false, 'Should block HTTP');
    assert(result.error.includes('non-HTTPS'), 'Error should mention non-HTTPS');
  });

  test('DOWNLOAD: Blocks private IP 127.0.0.1', () => {
    const result = isAllowedDownloadRedirect('https://127.0.0.1/payload');
    assert(result.allowed === false, 'Should block 127.0.0.1');
    assert(result.error.includes('private IP'), 'Error should mention private IP');
  });

  test('DOWNLOAD: Blocks private IP 10.x.x.x', () => {
    const result = isAllowedDownloadRedirect('https://10.0.0.1/payload');
    assert(result.allowed === false, 'Should block 10.x.x.x');
  });

  test('DOWNLOAD: Blocks private IP 192.168.x.x', () => {
    const result = isAllowedDownloadRedirect('https://192.168.1.1/payload');
    assert(result.allowed === false, 'Should block 192.168.x.x');
  });

  test('DOWNLOAD: Blocks non-allowlisted domain', () => {
    const result = isAllowedDownloadRedirect('https://evil.com/payload');
    assert(result.allowed === false, 'Should block evil.com');
    assert(result.error.includes('not in allowlist'), 'Error should mention allowlist');
  });

  test('DOWNLOAD: Blocks invalid URL', () => {
    const result = isAllowedDownloadRedirect('not-a-url');
    assert(result.allowed === false, 'Should block invalid URL');
    assert(result.error.includes('invalid URL'), 'Error should mention invalid URL');
  });

  // --- sanitizePackageName ---

  test('DOWNLOAD: Sanitizes path traversal from package name', () => {
    const result = sanitizePackageName('../../../etc/passwd');
    assert(!result.includes('..'), 'Should remove .. sequences');
    assert(!result.includes('/'), 'Should replace / with _');
    assert(result.includes('etc'), 'Should preserve etc');
    assert(result.includes('passwd'), 'Should preserve passwd');
  });

  test('DOWNLOAD: Sanitizes scoped package name', () => {
    assert(sanitizePackageName('@scope/package') === 'scope_package', 'Should replace @ and /');
  });

  test('DOWNLOAD: Leaves simple name unchanged', () => {
    assert(sanitizePackageName('express') === 'express', 'Simple name should be unchanged');
  });

  test('DOWNLOAD: Handles multiple path traversal sequences', () => {
    const result = sanitizePackageName('../../pkg/../evil');
    assert(!result.includes('..'), 'Should remove all .. sequences');
    assert(!result.includes('/'), 'Should replace all /');
    assert(result.includes('pkg'), 'Should preserve pkg');
    assert(result.includes('evil'), 'Should preserve evil');
  });
}

module.exports = { runDownloadTests };
