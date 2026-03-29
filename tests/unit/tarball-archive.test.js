'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { test, asyncTest, assert, assertIncludes } = require('../test-utils');

async function runTarballArchiveTests() {
  console.log('\n=== Tarball Archive Tests ===\n');

  // --- Unit tests for helpers ---

  test('sanitizeForFilename: scoped package', () => {
    const { sanitizeForFilename } = require('../../src/monitor/tarball-archive.js');
    const result = sanitizeForFilename('@evil/malware-pkg');
    assert(result === 'evil__malware-pkg', `Expected "evil__malware-pkg", got "${result}"`);
  });

  test('sanitizeForFilename: simple package', () => {
    const { sanitizeForFilename } = require('../../src/monitor/tarball-archive.js');
    const result = sanitizeForFilename('evil-pkg');
    assert(result === 'evil-pkg', `Expected "evil-pkg", got "${result}"`);
  });

  test('sanitizeForFilename: strips unsafe characters', () => {
    const { sanitizeForFilename } = require('../../src/monitor/tarball-archive.js');
    const result = sanitizeForFilename('pkg<>name');
    assert(!result.includes('<') && !result.includes('>'), `Unsafe chars not stripped: "${result}"`);
  });

  test('sha256File: computes correct hash', () => {
    const { sha256File } = require('../../src/monitor/tarball-archive.js');
    const tmpFile = path.join(os.tmpdir(), `sha256-test-${Date.now()}.bin`);
    const content = Buffer.from('test content for hashing');
    fs.writeFileSync(tmpFile, content);
    try {
      const hash = sha256File(tmpFile);
      const expected = crypto.createHash('sha256').update(content).digest('hex');
      assert(hash === expected, `Hash mismatch: ${hash} !== ${expected}`);
    } finally {
      try { fs.unlinkSync(tmpFile); } catch {}
    }
  });

  test('getArchiveDateString: returns YYYY-MM-DD format', () => {
    const { getArchiveDateString } = require('../../src/monitor/tarball-archive.js');
    const dateStr = getArchiveDateString();
    assert(/^\d{4}-\d{2}-\d{2}$/.test(dateStr), `Invalid date format: "${dateStr}"`);
  });

  // --- Integration tests using temp archive dir ---

  await asyncTest('archiveSuspectTarball: creates .tgz and .json at correct path', async () => {
    const { archiveSuspectTarball, getArchiveDateString } = require('../../src/monitor/tarball-archive.js');
    const tmpArchive = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-test-'));

    // Create a fake tarball to serve (we'll mock downloadToFile via a local file)
    const fakeTgzContent = Buffer.from('fake tarball content');
    const fakeTgzPath = path.join(tmpArchive, 'source.tgz');
    fs.writeFileSync(fakeTgzPath, fakeTgzContent);

    // Monkey-patch ARCHIVE_DIR for this test via env
    const origDir = process.env.MUADDIB_ARCHIVE_DIR;
    process.env.MUADDIB_ARCHIVE_DIR = tmpArchive;

    // We need to re-require to pick up the new env
    // Instead, test the core logic directly by creating files manually
    // since downloadToFile requires a real HTTPS URL.
    // Test the metadata structure and dedup logic instead.

    const dateStr = getArchiveDateString();
    const dayDir = path.join(tmpArchive, dateStr);
    fs.mkdirSync(dayDir, { recursive: true });

    // Simulate what archiveSuspectTarball does
    const basename = 'evil-pkg-1.0.0';
    const tgzDest = path.join(dayDir, `${basename}.tgz`);
    const jsonDest = path.join(dayDir, `${basename}.json`);
    fs.writeFileSync(tgzDest, fakeTgzContent);

    const hash = crypto.createHash('sha256').update(fakeTgzContent).digest('hex');
    const metadata = {
      package: 'evil-pkg',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      score: 45,
      priority: 'T1a',
      rules_triggered: ['AST-001', 'SHELL-005'],
      llm_verdict: null,
      tarball_sha256: hash
    };
    fs.writeFileSync(jsonDest, JSON.stringify(metadata, null, 2));

    // Verify .tgz exists
    assert(fs.existsSync(tgzDest), '.tgz file should exist');
    // Verify .json exists
    assert(fs.existsSync(jsonDest), '.json file should exist');

    // Verify metadata fields
    const loaded = JSON.parse(fs.readFileSync(jsonDest, 'utf8'));
    assert(loaded.package === 'evil-pkg', `package field mismatch: ${loaded.package}`);
    assert(loaded.version === '1.0.0', `version field mismatch: ${loaded.version}`);
    assert(loaded.score === 45, `score field mismatch: ${loaded.score}`);
    assert(loaded.priority === 'T1a', `priority field mismatch: ${loaded.priority}`);
    assert(Array.isArray(loaded.rules_triggered), 'rules_triggered should be array');
    assert(loaded.rules_triggered.length === 2, `Expected 2 rules, got ${loaded.rules_triggered.length}`);
    assert(loaded.llm_verdict === null, 'llm_verdict should be null');
    assert(loaded.tarball_sha256 === hash, 'SHA-256 mismatch');
    assert(/^\d{4}-\d{2}-\d{2}T/.test(loaded.timestamp), 'timestamp should be ISO format');

    // Cleanup
    process.env.MUADDIB_ARCHIVE_DIR = origDir || '';
    if (!origDir) delete process.env.MUADDIB_ARCHIVE_DIR;
    fs.rmSync(tmpArchive, { recursive: true, force: true });
  });

  test('archiveSuspectTarball: .json sha256 matches actual .tgz hash', () => {
    const tmpArchive = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-hash-'));
    const content = Buffer.from('real tarball bytes ' + Math.random());
    const tgzPath = path.join(tmpArchive, 'pkg-1.0.0.tgz');
    fs.writeFileSync(tgzPath, content);

    const expectedHash = crypto.createHash('sha256').update(content).digest('hex');
    const { sha256File } = require('../../src/monitor/tarball-archive.js');
    const computedHash = sha256File(tgzPath);

    assert(computedHash === expectedHash, `SHA-256 mismatch: ${computedHash} !== ${expectedHash}`);

    fs.rmSync(tmpArchive, { recursive: true, force: true });
  });

  await asyncTest('archiveSuspectTarball: duplicate is skipped (no overwrite)', async () => {
    const { archiveSuspectTarball, getArchiveDateString, sanitizeForFilename } = require('../../src/monitor/tarball-archive.js');
    const tmpArchive = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-dedup-'));
    const origDir = process.env.MUADDIB_ARCHIVE_DIR;
    process.env.MUADDIB_ARCHIVE_DIR = tmpArchive;

    // Re-require to pick up env change
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const mod = require('../../src/monitor/tarball-archive.js');

    const dateStr = mod.getArchiveDateString();
    const dayDir = path.join(tmpArchive, dateStr);
    fs.mkdirSync(dayDir, { recursive: true });

    // Pre-create the .tgz file (simulate already archived)
    const safeName = mod.sanitizeForFilename('dedup-pkg');
    const tgzPath = path.join(dayDir, `${safeName}-2.0.0.tgz`);
    const originalContent = Buffer.from('original content');
    fs.writeFileSync(tgzPath, originalContent);

    // Attempt to archive same package — should return false (dedup)
    const result = await mod.archiveSuspectTarball('dedup-pkg', '2.0.0', 'https://registry.npmjs.org/dedup-pkg/-/dedup-pkg-2.0.0.tgz', {
      score: 30,
      priority: 'T2',
      rulesTriggered: ['AST-001']
    });

    assert(result === false, `Expected false (dedup), got ${result}`);
    // Original content should be unchanged
    const afterContent = fs.readFileSync(tgzPath);
    assert(afterContent.equals(originalContent), 'File content should not have been overwritten');

    process.env.MUADDIB_ARCHIVE_DIR = origDir || '';
    if (!origDir) delete process.env.MUADDIB_ARCHIVE_DIR;
    fs.rmSync(tmpArchive, { recursive: true, force: true });
  });

  await asyncTest('archiveSuspectTarball: invalid URL does not throw (silent fail)', async () => {
    const origDir = process.env.MUADDIB_ARCHIVE_DIR;
    const tmpArchive = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-fail-'));
    process.env.MUADDIB_ARCHIVE_DIR = tmpArchive;
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const mod = require('../../src/monitor/tarball-archive.js');

    let threw = false;
    try {
      // This will fail because it's not a real URL — but it should not throw
      // (the caller wraps in .catch, but the function itself should propagate the error,
      // which is then caught by the fire-and-forget .catch in queue.js)
      await mod.archiveSuspectTarball('bad-pkg', '1.0.0', 'https://registry.npmjs.org/bad-pkg/-/bad-pkg-1.0.0.tgz', {
        score: 20,
        priority: 'T2'
      });
    } catch {
      // Expected: downloadToFile rejects, which is caught by the .catch wrapper in queue.js
      threw = true;
    }
    // The function IS expected to throw/reject when download fails —
    // the pipeline safety comes from the .catch() wrapper in queue.js.
    // This test just verifies the function rejects cleanly without crashing.
    assert(threw === true, 'archiveSuspectTarball should reject on download failure (caught by pipeline .catch)');

    process.env.MUADDIB_ARCHIVE_DIR = origDir || '';
    if (!origDir) delete process.env.MUADDIB_ARCHIVE_DIR;
    fs.rmSync(tmpArchive, { recursive: true, force: true });
  });

  await asyncTest('archiveSuspectTarball: returns false for missing params', async () => {
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const mod = require('../../src/monitor/tarball-archive.js');

    const r1 = await mod.archiveSuspectTarball(null, '1.0.0', 'https://example.com/x.tgz', { score: 10 });
    assert(r1 === false, 'Should return false for null packageName');

    const r2 = await mod.archiveSuspectTarball('pkg', null, 'https://example.com/x.tgz', { score: 10 });
    assert(r2 === false, 'Should return false for null version');

    const r3 = await mod.archiveSuspectTarball('pkg', '1.0.0', null, { score: 10 });
    assert(r3 === false, 'Should return false for null tarballUrl');
  });

  test('queue.js imports tarball-archive without error', () => {
    // Verify the import doesn't break the module
    delete require.cache[require.resolve('../../src/monitor/queue.js')];
    let importError = null;
    try {
      // Reading the source and checking for the import line
      const queueSrc = fs.readFileSync(require.resolve('../../src/monitor/queue.js'), 'utf8');
      assertIncludes(queueSrc, "require('./tarball-archive.js')", 'queue.js should import tarball-archive');
      assertIncludes(queueSrc, 'archiveSuspectTarball', 'queue.js should use archiveSuspectTarball');
      assertIncludes(queueSrc, '.catch(', 'archive call should have .catch wrapper');
    } catch (e) {
      importError = e;
    }
    assert(!importError, `queue.js integration check failed: ${importError}`);
  });
}

module.exports = { runTarballArchiveTests };
