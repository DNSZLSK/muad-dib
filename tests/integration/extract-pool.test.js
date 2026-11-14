'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { test, asyncTest, assert } = require('../test-utils');

// Build a real npm-style .tgz fixture (files under package/) and return its path.
function makeTgz(dir, files) {
  const pkgDir = path.join(dir, 'package');
  fs.mkdirSync(pkgDir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(pkgDir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  const tgz = path.join(dir, 'fixture.tgz');
  execFileSync('tar', ['czf', tgz, '-C', dir, 'package']);
  return tgz;
}

async function runExtractPoolTests() {
  const { extractInPool, destroyExtractPool, getPoolStats } = require('../../src/shared/extract-pool.js');

  await asyncTest('EXTRACT-POOL: extracts a tgz off-thread and returns the package root', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xpool-'));
    try {
      const tgz = makeTgz(tmp, { 'index.js': 'module.exports = 1;\n', 'package.json': '{"name":"x"}' });
      const dest = path.join(tmp, 'out');
      fs.mkdirSync(dest);
      const root = await extractInPool(tgz, dest);
      assert(fs.existsSync(path.join(root, 'index.js')), 'index.js should be extracted');
      assert(
        fs.readFileSync(path.join(root, 'package.json'), 'utf8').includes('"name":"x"'),
        'package.json content present'
      );
    } finally {
      await destroyExtractPool();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  await asyncTest('EXTRACT-POOL: handles many concurrent jobs (worker reuse + FIFO queueing)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xpool-'));
    try {
      const jobs = [];
      for (let i = 0; i < 12; i++) {
        const sub = path.join(tmp, 'j' + i);
        fs.mkdirSync(sub, { recursive: true });
        const tgz = makeTgz(sub, { 'v.txt': 'job-' + i });
        const dest = path.join(sub, 'out');
        fs.mkdirSync(dest);
        jobs.push(extractInPool(tgz, dest).then((root) => fs.readFileSync(path.join(root, 'v.txt'), 'utf8')));
      }
      const results = await Promise.all(jobs);
      for (let i = 0; i < 12; i++) assert(results[i] === 'job-' + i, `job ${i} content matches`);
      // More jobs than POOL_SIZE proves reuse: the pool never exceeds its cap.
      const stats = getPoolStats();
      assert(stats.size <= stats.max, 'live workers never exceed the bounded cap');
    } finally {
      await destroyExtractPool();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  await asyncTest('EXTRACT-POOL: a failing extraction rejects without killing the pool', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xpool-'));
    try {
      const dest = path.join(tmp, 'out');
      fs.mkdirSync(dest);
      // Non-existent archive → extractArchive throws in the worker → job rejects.
      let rejected = false;
      try {
        await extractInPool(path.join(tmp, 'does-not-exist.tgz'), dest);
      } catch {
        rejected = true;
      }
      assert(rejected, 'missing archive should reject');

      // The pool must still serve a subsequent valid job (it survived the error).
      const tgz = makeTgz(tmp, { 'ok.txt': 'recovered' });
      const dest2 = path.join(tmp, 'out2');
      fs.mkdirSync(dest2);
      const root = await extractInPool(tgz, dest2);
      assert(fs.readFileSync(path.join(root, 'ok.txt'), 'utf8') === 'recovered', 'pool recovered after a failure');
    } finally {
      await destroyExtractPool();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  // Partial-extraction evasion (2026-11-14): the monitor extracts through this pool. A tarball
  // with a member tar refuses must come back as a partial report, not a rejection, and the
  // findings must survive the scan-worker hop into the score.
  await asyncTest('EXTRACT-POOL: detailed mode returns a partial report for a hostile tarball, and the monitor scan worker scores it', async () => {
    const zlib = require('zlib');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xpool-'));
    const member = (name, body, type = '0', linkname = '') => {
      const h = Buffer.alloc(512);
      h.write(name, 0, 100, 'utf8');
      h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
      h.write(body.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
      h.write('        ', 148); h.write(type, 156); h.write(linkname, 157, 100, 'utf8');
      h.write('ustar\0', 257); h.write('00', 263);
      let sum = 0; for (const b of h) sum += b;
      h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
      return Buffer.concat([h, body, Buffer.alloc((512 - (body.length % 512)) % 512)]);
    };
    try {
      const tgz = path.join(tmp, 'evil.tgz');
      fs.writeFileSync(tgz, zlib.gzipSync(Buffer.concat([
        member('package/package.json', Buffer.from('{"name":"evasion-fixture","version":"1.0.0"}')),
        member('package/link', Buffer.alloc(0), '2', '../../outside'),
        member('package/link/x.txt', Buffer.from('x')),
        member('package/index.js', Buffer.from('module.exports = 1;')),
        Buffer.alloc(1024)])));
      const dest = path.join(tmp, 'out');
      fs.mkdirSync(dest);
      const report = await extractInPool(tgz, dest, { detailed: true });
      assert(report && report.partial === true, 'pool must resolve a partial report, got ' + JSON.stringify(report));
      assert(fs.existsSync(path.join(report.dir, 'index.js')), 'the accepted members are on disk');
      assert(report.hostileMembers.some(m => m.reason === 'write-through-symlink'), 'hostile member reported: ' + JSON.stringify(report.hostileMembers));

      const { extractionFindings } = require('../../src/shared/download.js');
      const { runScanInWorker } = require('../../src/monitor/queue.js');
      // No monitorMode: it enables trusted-dep-diff, a registry fetch; only the worker hop matters here.
      const ctx = { name: 'evasion-fixture', version: '1.0.0', ecosystem: 'npm', extractionFindings: extractionFindings(report) };
      const result = await runScanInWorker(report.dir, 60000, ctx, null);
      const types = result.threats.map(t => t.type);
      assert(types.includes('archive_hostile_member') && types.includes('archive_partial_extraction'), 'findings must reach the worker result: ' + types.join(','));
      assert(result.summary.riskScore >= 10, 'the HIGH hostile-member finding must count in the score, got ' + result.summary.riskScore);
      assert(result.analysis && result.analysis.status === 'INCONCLUSIVE', 'a partial extraction makes the analysis INCONCLUSIVE (lot 1 contract), got ' + JSON.stringify(result.analysis));
      assert(result.analysis.incomplete.some(e => e.component === 'extraction' && e.reason === 'partial-archive'), 'the incompleteness entry names the extraction: ' + JSON.stringify(result.analysis.incomplete));

      // Negative: without findings in the context, the same clean files score nothing archive-related,
      // and an unknown injected type is dropped by the executor.
      const plain = await runScanInWorker(report.dir, 60000, { ...ctx, extractionFindings: [{ type: 'known_malicious_package', severity: 'CRITICAL', message: 'x', file: 'package.json' }] }, null);
      assert(!plain.threats.some(t => t.type.startsWith('archive_') || t.type === 'known_malicious_package'), 'only the two archive types are accepted: ' + plain.threats.map(t => t.type).join(','));
    } finally {
      await destroyExtractPool();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EXTRACT-POOL: getPoolStats reports a bounded, idle pool after teardown', () => {
    const stats = getPoolStats();
    assert(typeof stats.max === 'number' && stats.max >= 1, 'pool has a bounded max size');
    assert(stats.size <= stats.max, 'live workers never exceed the cap');
    assert(stats.pending === 0, 'no pending jobs leak after teardown');
  });
}

module.exports = { runExtractPoolTests };
