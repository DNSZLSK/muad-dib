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

  test('EXTRACT-POOL: getPoolStats reports a bounded, idle pool after teardown', () => {
    const stats = getPoolStats();
    assert(typeof stats.max === 'number' && stats.max >= 1, 'pool has a bounded max size');
    assert(stats.size <= stats.max, 'live workers never exceed the cap');
    assert(stats.pending === 0, 'no pending jobs leak after teardown');
  });
}

module.exports = { runExtractPoolTests };
