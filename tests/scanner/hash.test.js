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
const { loadCachedIOCs } = require('../../src/ioc/updater.js');

// scanHashes only fires when the file's SHA-256 is in the known-malicious set.
// In CI the scraped IOC files are absent, so without injection the traversal /
// extension / depth tests were vacuous (empty set → early return, only
// Array.isArray asserted). We inject a real hash into the live IOC singleton
// (returned by reference and stable within the source-check window), so the
// scanner actually has something to match — then restore it.
function withInjectedHash(hash, fn) {
  const iocs = loadCachedIOCs();
  const origHashesSet = iocs.hashesSet;
  const workingSet = origHashesSet instanceof Set ? origHashesSet : new Set(iocs.hashes || []);
  const alreadyPresent = workingSet.has(hash);
  workingSet.add(hash);
  iocs.hashesSet = workingSet;
  try {
    return fn();
  } finally {
    if (!alreadyPresent) workingSet.delete(hash);
    iocs.hashesSet = origHashesSet;
  }
}

const EVIL_CONTENT = 'var __malicious_payload__ = require("child_process").exec("id");';
const EVIL_HASH = nodeCrypto.createHash('sha256').update(EVIL_CONTENT).digest('hex');

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

  await asyncTest('HASH: scanHashes detects a known-malicious hash in node_modules and ignores clean files', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const pkgDir = path.join(tmpDir, 'node_modules', 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'evil.js'), EVIL_CONTENT);      // known hash → must fire
    fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = {};'); // clean → must not
    fs.writeFileSync(path.join(pkgDir, 'README.md'), '# Readme');
    try {
      const threats = await withInjectedHash(EVIL_HASH, () => scanHashes(tmpDir));
      const hit = threats.find(t => t.type === 'known_malicious_hash');
      assert(hit, 'Should flag the file whose hash is in the known-malicious set');
      assert(hit.severity === 'CRITICAL', 'known_malicious_hash is CRITICAL');
      assert(hit.file.replace(/\\/g, '/').endsWith('test-pkg/evil.js'), `Should point at evil.js, got ${hit.file}`);
      assert(threats.length === 1, 'The clean index.js must NOT be flagged (only the malicious hash)');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes traverses into nested node_modules directories', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const nestedDir = path.join(tmpDir, 'node_modules', 'pkg', 'lib', 'utils');
    fs.mkdirSync(nestedDir, { recursive: true });
    fs.writeFileSync(path.join(nestedDir, 'helper.js'), EVIL_CONTENT); // planted deep
    try {
      const threats = await withInjectedHash(EVIL_HASH, () => scanHashes(tmpDir));
      const hit = threats.find(t => t.type === 'known_malicious_hash');
      assert(hit, 'Should recurse into node_modules/pkg/lib/utils and match the nested file');
      assert(hit.file.replace(/\\/g, '/').endsWith('lib/utils/helper.js'), `Should point at the nested file, got ${hit.file}`);
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes skips non-JS files even when their content matches a known hash', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const pkgDir = path.join(tmpDir, 'node_modules', 'txt-only');
    fs.mkdirSync(pkgDir, { recursive: true });
    // Same malicious content, but as .txt/.json — the extension filter must
    // prevent a match (only .js is hashed).
    fs.writeFileSync(path.join(pkgDir, 'data.txt'), EVIL_CONTENT);
    fs.writeFileSync(path.join(pkgDir, 'config.json'), EVIL_CONTENT);
    try {
      const threats = await withInjectedHash(EVIL_HASH, () => scanHashes(tmpDir));
      assert(threats.length === 0, 'Non-JS files must not be hashed/flagged even with a known-malicious content hash');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });
}

module.exports = { runHashTests };
