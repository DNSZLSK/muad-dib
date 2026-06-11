'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert } = require('../test-utils');
const {
  acquireHeavySlot, releaseHeavySlot, isHeavyScan, getHeavyLaneState,
  resetHeavyLane, heavyScanBytesThreshold, HEAVY_REQUEUE_MAX
} = require('../../src/monitor/heavy-lane.js');
const { measureJsWeight, computeHeavyRequeue } = require('../../src/monitor/queue.js');

const LANE_ENV_KEYS = ['MUADDIB_HEAVY_SCAN_MAX', 'MUADDIB_HEAVY_SCAN_BYTES', 'MUADDIB_HEAVY_WAIT_MAX_MS'];

function setLaneEnv(vars) {
  const save = {};
  for (const k of LANE_ENV_KEYS) save[k] = process.env[k];
  for (const k of LANE_ENV_KEYS) {
    if (vars[k] !== undefined) process.env[k] = String(vars[k]);
    else delete process.env[k];
  }
  resetHeavyLane();
  return () => {
    for (const k of LANE_ENV_KEYS) {
      if (save[k] !== undefined) process.env[k] = save[k]; else delete process.env[k];
    }
    resetHeavyLane();
  };
}

function withLaneEnv(vars, fn) {
  const restore = setLaneEnv(vars);
  try { return fn(); }
  finally { restore(); }
}

// The sync variant restores env on fn's synchronous RETURN — for an async fn
// that means before its awaits run (and the embedded resetHeavyLane wipes the
// slots mid-test). Async bodies must use this awaited variant.
async function withLaneEnvAsync(vars, fn) {
  const restore = setLaneEnv(vars);
  try { return await fn(); }
  finally { restore(); }
}

const tick = () => new Promise(r => setTimeout(r, 10));

async function runHeavyLaneTests() {
  console.log('\n=== HEAVY-LANE (C2 memory-bounded scans) TESTS ===\n');

  test('HEAVY-LANE: isHeavyScan — default threshold, env override, truncated walk → heavy', () => {
    withLaneEnv({}, () => {
      assert(heavyScanBytesThreshold() === 3 * 1024 * 1024, 'default threshold is 3 MiB');
      assert(isHeavyScan({ totalJsBytes: 12 * 1024, truncated: false }) === false, '12KB JS is light');
      assert(isHeavyScan({ totalJsBytes: 8 * 1024 * 1024, truncated: false }) === true, '8MB JS is heavy');
      assert(isHeavyScan({ totalJsBytes: 0, truncated: true }) === true, 'truncated measurement defaults to heavy');
      assert(isHeavyScan(null) === false, 'null weight is light (defensive)');
    });
    withLaneEnv({ MUADDIB_HEAVY_SCAN_BYTES: 1024 }, () => {
      assert(isHeavyScan({ totalJsBytes: 2048, truncated: false }) === true, 'env threshold override respected');
    });
  });

  test('HEAVY-LANE: measureJsWeight — sums parsable JS, excludes node_modules, skips oversize files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-weight-'));
    try {
      fs.writeFileSync(path.join(dir, 'index.js'), 'x'.repeat(1000));
      fs.writeFileSync(path.join(dir, 'lib.mjs'), 'y'.repeat(500));
      fs.writeFileSync(path.join(dir, 'README.md'), 'z'.repeat(9000)); // not JS — ignored
      fs.mkdirSync(path.join(dir, 'node_modules', 'dep'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'node_modules', 'dep', 'big.js'), 'w'.repeat(50000)); // excluded dir
      fs.mkdirSync(path.join(dir, 'src'));
      fs.writeFileSync(path.join(dir, 'src', 'app.tsx'), 't'.repeat(300));
      const w = measureJsWeight(dir);
      assert(w.totalJsBytes === 1800, `total = 1000+500+300 = 1800, got ${w.totalJsBytes}`);
      assert(w.maxJsFileBytes === 1000, `max file = 1000, got ${w.maxJsFileBytes}`);
      assert(w.truncated === false, 'small tree is not truncated');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('HEAVY-LANE: measureJsWeight — depth overflow flags truncated (→ heavy by default)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-deep-'));
    try {
      let p = dir;
      for (let i = 0; i < 10; i++) { p = path.join(p, `d${i}`); fs.mkdirSync(p); }
      fs.writeFileSync(path.join(p, 'deep.js'), 'x');
      const w = measureJsWeight(dir);
      assert(w.truncated === true, 'walk past maxDepth must flag truncated');
      assert(isHeavyScan(w) === true, 'truncated classifies heavy');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await asyncTest('HEAVY-LANE: semaphore bounds concurrency at MAX, FIFO transfer on release', async () => {
    await withLaneEnvAsync({ MUADDIB_HEAVY_SCAN_MAX: 2 }, async () => {
      const a = await acquireHeavySlot();
      const b = await acquireHeavySlot();
      assert(a === true && b === true, 'first two acquires are immediate');
      assert(getHeavyLaneState().active === 2, 'two slots active');

      const order = [];
      const c = acquireHeavySlot().then(() => order.push('c'));
      const d = acquireHeavySlot().then(() => order.push('d'));
      await tick();
      assert(order.length === 0, 'third and fourth acquires pend while saturated');
      assert(getHeavyLaneState().waiting === 2, 'two waiters queued');

      releaseHeavySlot();
      await c;
      assert(order.join(',') === 'c', 'release wakes the FIRST waiter (FIFO)');
      assert(getHeavyLaneState().active === 2, 'slot transferred, active unchanged');

      releaseHeavySlot();
      await d;
      releaseHeavySlot();
      releaseHeavySlot();
      assert(getHeavyLaneState().active === 0 && getHeavyLaneState().waiting === 0, 'lane drains to idle');
    });
  });

  await asyncTest('HEAVY-LANE: wait-timeout rejects HEAVY_LANE_WAIT_TIMEOUT and removes the waiter (no phantom slot)', async () => {
    await withLaneEnvAsync({ MUADDIB_HEAVY_SCAN_MAX: 1 }, async () => {
      await acquireHeavySlot();
      let err = null;
      try { await acquireHeavySlot({ maxWaitMs: 30 }); } catch (e) { err = e; }
      assert(err && err.code === 'HEAVY_LANE_WAIT_TIMEOUT', `expected HEAVY_LANE_WAIT_TIMEOUT, got ${err && err.code}`);
      assert(getHeavyLaneState().waiting === 0, 'timed-out waiter removed from the queue');
      // The release after a timed-out wait must NOT wake a dead waiter:
      releaseHeavySlot();
      assert(getHeavyLaneState().active === 0, 'slot fully returned — no phantom holder');
      const again = await acquireHeavySlot();
      assert(again === true, 'lane still serves new acquires after a timeout');
    });
  });

  await asyncTest('HEAVY-LANE: abort signal rejects ABORT_ERR and removes the waiter', async () => {
    await withLaneEnvAsync({ MUADDIB_HEAVY_SCAN_MAX: 1 }, async () => {
      await acquireHeavySlot();
      const controller = new AbortController();
      const pending = acquireHeavySlot({ signal: controller.signal });
      await tick();
      controller.abort();
      let err = null;
      try { await pending; } catch (e) { err = e; }
      assert(err && err.code === 'ABORT_ERR', `expected ABORT_ERR, got ${err && err.code}`);
      assert(getHeavyLaneState().waiting === 0, 'aborted waiter removed from the queue');
      // Already-aborted signal rejects immediately:
      let err2 = null;
      try { await acquireHeavySlot({ signal: controller.signal }); } catch (e) { err2 = e; }
      assert(err2 && err2.code === 'ABORT_ERR', 'pre-aborted signal rejects without queueing');
      assert(getHeavyLaneState().waiting === 0, 'no waiter leaked by the pre-aborted path');
    });
  });

  await asyncTest('HEAVY-LANE: MUADDIB_HEAVY_SCAN_MAX=0 disables the lane (immediate, nothing held)', async () => {
    await withLaneEnvAsync({ MUADDIB_HEAVY_SCAN_MAX: 0 }, async () => {
      const held = await acquireHeavySlot({ maxWaitMs: 5 });
      assert(held === false, 'disabled lane resolves false (no slot to release)');
      assert(getHeavyLaneState().active === 0, 'nothing accounted as active');
    });
  });

  await asyncTest('HEAVY-LANE: slot released on scan failure (try/finally contract)', async () => {
    await withLaneEnvAsync({ MUADDIB_HEAVY_SCAN_MAX: 1 }, async () => {
      const held = await acquireHeavySlot();
      try {
        assert(held === true, 'slot held');
        throw new Error('simulated scan failure');
      } catch { /* the scanPackage finally runs the release below */ }
      finally { if (held) releaseHeavySlot(); }
      assert(getHeavyLaneState().active === 0, 'slot returned after failure');
    });
  });

  test('HEAVY-LANE: computeHeavyRequeue — bounded passes, then no more requeues', () => {
    const item = { name: 'big-pkg', version: '1.0.0' };
    for (let pass = 1; pass <= HEAVY_REQUEUE_MAX; pass++) {
      const d = computeHeavyRequeue(item);
      assert(d.requeue === true && d.retries === pass, `pass ${pass} requeues (got requeue=${d.requeue}, retries=${d.retries})`);
    }
    const final = computeHeavyRequeue(item);
    assert(final.requeue === false, `pass ${HEAVY_REQUEUE_MAX + 1} must NOT requeue`);
    assert(item._heavyRetries === HEAVY_REQUEUE_MAX + 1, 'retry counter persisted on the item');
  });
}

module.exports = { runHeavyLaneTests };
