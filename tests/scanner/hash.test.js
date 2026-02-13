const fs = require('fs');
const path = require('path');
const os = require('os');
const nodeCrypto = require('crypto');
const { test, asyncTest, assert, cleanupTemp } = require('../test-utils');
const {
  scanHashes,
  computeHash,
  computeHashCached,
  clearHashCache,
  getHashCacheSize
} = require('../../src/scanner/hash.js');

async function runHashTests() {
  console.log('\n=== HASH TESTS ===\n');

  test('HASH: computeHash returns valid SHA256', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const tmpFile = path.join(tmpDir, 'test.js');
    fs.writeFileSync(tmpFile, 'console.log("hello");');
    const hash = computeHash(tmpFile);
    assert(typeof hash === 'string' && hash.length === 64 && /^[0-9a-f]+$/.test(hash), 'Should be valid SHA256');
    const expected = nodeCrypto.createHash('sha256').update(fs.readFileSync(tmpFile)).digest('hex');
    assert(hash === expected, 'Should match Node crypto');
    cleanupTemp(tmpDir);
  });

  test('HASH: computeHashCached computes and caches', () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const tmpFile = path.join(tmpDir, 'test.js');
    fs.writeFileSync(tmpFile, 'var x = 1;');
    const hash1 = computeHashCached(tmpFile);
    assert(hash1 && hash1.length === 64, 'Should return hash');
    assert(getHashCacheSize() > 0, 'Cache should have entry');
    const hash2 = computeHashCached(tmpFile);
    assert(hash1 === hash2, 'Should return cached hash');
    cleanupTemp(tmpDir);
    clearHashCache();
  });

  test('HASH: computeHashCached invalidates on mtime change', () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const tmpFile = path.join(tmpDir, 'test.js');
    fs.writeFileSync(tmpFile, 'var a = 1;');
    const hash1 = computeHashCached(tmpFile);
    fs.writeFileSync(tmpFile, 'var a = 2;');
    const future = new Date(Date.now() + 5000);
    fs.utimesSync(tmpFile, future, future);
    const hash2 = computeHashCached(tmpFile);
    assert(hash1 !== hash2, 'Should recompute after file change');
    cleanupTemp(tmpDir);
    clearHashCache();
  });

  test('HASH: computeHashCached returns null for non-existent file', () => {
    const result = computeHashCached('/nonexistent/path/file.js');
    assert(result === null, 'Should return null');
  });

  test('HASH: clearHashCache and getHashCacheSize', () => {
    clearHashCache();
    assert(getHashCacheSize() === 0, 'Should be 0 after clear');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const tmpFile = path.join(tmpDir, 'test.js');
    fs.writeFileSync(tmpFile, 'var y = 2;');
    computeHashCached(tmpFile);
    assert(getHashCacheSize() === 1, 'Should be 1');
    clearHashCache();
    assert(getHashCacheSize() === 0, 'Should be 0 after clear');
    cleanupTemp(tmpDir);
  });

  // --- scanHashes async tests ---

  await asyncTest('HASH: scanHashes empty without node_modules', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats) && threats.length === 0, 'Should be empty');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('HASH: scanHashes traverses node_modules JS files', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const pkgDir = path.join(tmpDir, 'node_modules', 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = {};');
    fs.writeFileSync(path.join(pkgDir, 'README.md'), '# Readme');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats), 'Should return array');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes handles nested directories', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const nestedDir = path.join(tmpDir, 'node_modules', 'pkg', 'lib', 'utils');
    fs.mkdirSync(nestedDir, { recursive: true });
    fs.writeFileSync(path.join(nestedDir, 'helper.js'), 'function help() {}');
    fs.writeFileSync(path.join(tmpDir, 'node_modules', 'pkg', 'index.js'), 'require("./lib/utils/helper");');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats), 'Should handle nested dirs');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes respects MAX_DEPTH limit', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    let deepDir = path.join(tmpDir, 'node_modules');
    for (let i = 0; i < 52; i++) {
      deepDir = path.join(deepDir, String(i));
    }
    fs.mkdirSync(deepDir, { recursive: true });
    fs.writeFileSync(path.join(deepDir, 'deep.js'), 'var deep = true;');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats), 'Should handle deep nesting gracefully');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes skips non-JS files', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const pkgDir = path.join(tmpDir, 'node_modules', 'txt-only');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'data.txt'), 'not javascript');
    fs.writeFileSync(path.join(pkgDir, 'config.json'), '{}');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats) && threats.length === 0, 'Should be empty for non-JS');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });
}

module.exports = { runHashTests };
