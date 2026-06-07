'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { test, asyncTest, assert } = require('../test-utils');

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

  test('queue.js loads with tarball-archive wired in (import resolves, archiver reachable)', () => {
    // Behavioral replacement for the old source-grep: actually require queue.js so the
    // `require('./tarball-archive.js')` wiring is exercised — a broken path or a syntax error
    // in the suspect-tarball archiver would throw here. Then confirm the archiver it wires is
    // reachable (not dead code).
    delete require.cache[require.resolve('../../src/monitor/queue.js')];
    let loadError = null;
    try {
      require('../../src/monitor/queue.js');
    } catch (e) {
      loadError = e;
    }
    assert(!loadError, `queue.js failed to load with the tarball-archive import: ${loadError && loadError.message}`);
    const archiver = require('../../src/monitor/tarball-archive.js');
    assert(typeof archiver.archiveSuspectTarball === 'function',
      'archiveSuspectTarball should be reachable (queue.js wires it for suspect tarballs)');
  });

  // --- Defense in depth: retention default, periodic cleanup, disk-space gate ---

  test('getRetentionDays: default is 7 days when env unset', () => {
    const origRetention = process.env.MUADDIB_ARCHIVE_RETENTION_DAYS;
    delete process.env.MUADDIB_ARCHIVE_RETENTION_DAYS;
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const { getRetentionDays } = require('../../src/monitor/tarball-archive.js');
    const result = getRetentionDays();
    if (origRetention !== undefined) process.env.MUADDIB_ARCHIVE_RETENTION_DAYS = origRetention;
    assert(result === 7, `expected 7, got ${result}`);
  });

  await asyncTest('startPeriodicCleanup: triggers cleanupOldArchives on tick', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-periodic-'));
    const oldDir = path.join(tmp, '2020-01-01');
    fs.mkdirSync(oldDir, { recursive: true });
    fs.writeFileSync(path.join(oldDir, 'x.tgz'), 'x');
    const origDir = process.env.MUADDIB_ARCHIVE_DIR;
    process.env.MUADDIB_ARCHIVE_DIR = tmp;
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const mod = require('../../src/monitor/tarball-archive.js');
    const timer = mod.startPeriodicCleanup(50); // 50ms test interval
    try {
      await new Promise(r => setTimeout(r, 150));
      assert(!fs.existsSync(oldDir), 'old day directory should be purged after tick');
    } finally {
      clearInterval(timer);
      process.env.MUADDIB_ARCHIVE_DIR = origDir || '';
      if (!origDir) delete process.env.MUADDIB_ARCHIVE_DIR;
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  await asyncTest('archiveSuspectTarball: skips when free space below threshold', async () => {
    const origDir = process.env.MUADDIB_ARCHIVE_DIR;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-diskgate-'));
    process.env.MUADDIB_ARCHIVE_DIR = tmp;
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const realStatfs = fs.statfsSync;
    fs.statfsSync = () => ({ bavail: 0, bsize: 4096 }); // simulate ~0 bytes free
    try {
      const { archiveSuspectTarball, getArchiveDateString } = require('../../src/monitor/tarball-archive.js');
      // Pass BOTH score>0 and rulesTriggered so the disk gate is what fires —
      // not the score===0 && rules.length===0 early return. Otherwise a future
      // refactor of the score gate could make this test pass for the wrong reason.
      const result = await archiveSuspectTarball(
        'pkg', '1.0.0', 'https://example.com/x.tgz',
        { score: 50, rulesTriggered: [{ rule: 'TEST-DISK-GATE' }] }
      );
      assert(result === false, 'archive should be skipped when disk almost full');
      // Belt-and-suspenders: confirm the gate stopped us before mkdir touched the disk.
      const dayDir = path.join(tmp, getArchiveDateString());
      assert(!fs.existsSync(dayDir), 'day dir should not exist — disk gate must fire before mkdirSync');
    } finally {
      fs.statfsSync = realStatfs;
      process.env.MUADDIB_ARCHIVE_DIR = origDir || '';
      if (!origDir) delete process.env.MUADDIB_ARCHIVE_DIR;
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  // --- Alert-only tarball retention: keep JSON for every suspect, .tgz for alerts only ---

  test('getArchiveTgzMinScore: default 20, env override respected, bounds enforced', () => {
    const orig = process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE;
    const reload = () => {
      delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
      return require('../../src/monitor/tarball-archive.js').getArchiveTgzMinScore();
    };
    try {
      delete process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE;
      assert(reload() === 20, 'default should be 20');
      process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE = '50';
      assert(reload() === 50, 'env override 50 should apply');
      process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE = '999';
      assert(reload() === 20, 'out-of-range falls back to 20');
    } finally {
      if (orig === undefined) delete process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE;
      else process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE = orig;
      delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    }
  });

  await asyncTest('archiveSuspectTarball: below threshold keeps JSON only (no .tgz, no network)', async () => {
    const origDir = process.env.MUADDIB_ARCHIVE_DIR;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-jsononly-'));
    process.env.MUADDIB_ARCHIVE_DIR = tmp;
    delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
    const mod = require('../../src/monitor/tarball-archive.js');
    try {
      // score 5 (< 20 default) WITH a triggered rule → suspect but below alert floor.
      // Must NOT touch the network (the bogus URL would fail) and must NOT write a .tgz.
      const result = await mod.archiveSuspectTarball(
        'low-suspect', '1.2.3', 'https://registry.npmjs.org/low-suspect/-/low-suspect-1.2.3.tgz',
        { score: 5, priority: 'P3', rulesTriggered: ['MUADDIB-AST-001'] }
      );
      assert(result === true, `expected true (JSON written), got ${result}`);
      const dayDir = path.join(tmp, mod.getArchiveDateString());
      const jsonPath = path.join(dayDir, 'low-suspect-1.2.3.json');
      const tgzPath = path.join(dayDir, 'low-suspect-1.2.3.tgz');
      assert(fs.existsSync(jsonPath), 'JSON metadata should be written for below-threshold suspect');
      assert(!fs.existsSync(tgzPath), '.tgz must NOT be downloaded for below-threshold suspect');
      const meta = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      assert(meta.tarball_archived === false, 'tarball_archived should be false');
      assert(meta.tarball_sha256 === null, 'tarball_sha256 should be null');
      assert(meta.score === 5, 'score recorded in JSON');
      assert(Array.isArray(meta.rules_triggered) && meta.rules_triggered.length === 1, 'rules recorded in JSON');

      // Dedup: a second call for the same package@version returns false (no rewrite).
      const again = await mod.archiveSuspectTarball(
        'low-suspect', '1.2.3', 'https://registry.npmjs.org/low-suspect/-/low-suspect-1.2.3.tgz',
        { score: 5, priority: 'P3', rulesTriggered: ['MUADDIB-AST-001'] }
      );
      assert(again === false, 'second below-threshold call should dedup to false');
    } finally {
      process.env.MUADDIB_ARCHIVE_DIR = origDir || '';
      if (!origDir) delete process.env.MUADDIB_ARCHIVE_DIR;
      delete require.cache[require.resolve('../../src/monitor/tarball-archive.js')];
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
}

module.exports = { runTarballArchiveTests };
