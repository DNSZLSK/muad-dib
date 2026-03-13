const { test, assert } = require('../test-utils');

async function runDownloadTests() {
  console.log('\n=== DOWNLOAD TESTS ===\n');

  const { isAllowedDownloadRedirect, sanitizePackageName, MAX_REDIRECTS } = require('../../src/shared/download.js');

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

  // --- MAX_REDIRECTS (v2.6.5) ---

  test('DOWNLOAD: MAX_REDIRECTS is exported and equals 5', () => {
    assert(MAX_REDIRECTS === 5, `MAX_REDIRECTS should be 5, got ${MAX_REDIRECTS}`);
  });

  // --- normalizeHostname (SSRF octal/hex bypass protection) ---

  const { normalizeHostname, isPrivateIP } = require('../../src/shared/download.js');

  test('DOWNLOAD: normalizeHostname converts decimal IP', () => {
    assert(normalizeHostname('2130706433') === '127.0.0.1', 'Decimal 2130706433 should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts hex integer IP', () => {
    assert(normalizeHostname('0x7f000001') === '127.0.0.1', 'Hex 0x7f000001 should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts octal dotted IP', () => {
    assert(normalizeHostname('0177.0.0.01') === '127.0.0.1', 'Octal 0177.0.0.01 should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts hex dotted IP', () => {
    assert(normalizeHostname('0x7f.0x0.0x0.0x1') === '127.0.0.1', 'Hex dotted should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts mixed octal/decimal', () => {
    assert(normalizeHostname('0xA.0.0.01') === '10.0.0.1', 'Mixed hex+octal should be 10.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname preserves normal hostnames', () => {
    assert(normalizeHostname('registry.npmjs.org') === 'registry.npmjs.org', 'Should preserve normal hostname');
  });

  test('DOWNLOAD: normalizeHostname handles IPv6-mapped IPv4', () => {
    assert(normalizeHostname('::ffff:127.0.0.1') === '127.0.0.1', 'Should unwrap IPv6-mapped IPv4');
  });

  test('DOWNLOAD: isPrivateIP blocks octal loopback', () => {
    assert(isPrivateIP('0177.0.0.01') === true, 'Octal 127.0.0.1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks hex integer loopback', () => {
    assert(isPrivateIP('0x7f000001') === true, 'Hex integer 127.0.0.1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks hex dotted 10.x', () => {
    assert(isPrivateIP('0xA.0.0.1') === true, 'Hex dotted 10.0.0.1 should be private');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks octal loopback', () => {
    const result = isAllowedDownloadRedirect('https://0177.0.0.01/payload');
    assert(result.allowed === false, 'Should block octal loopback');
  });
}

module.exports = { runDownloadTests };
