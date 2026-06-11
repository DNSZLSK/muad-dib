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

  // Plain-source fixture content: short lines (~25 chars) like real code —
  // single-line repeat() strings would trip the minification probe.
  const plainJs = bytes => 'const someVariable = 12;\n'.repeat(Math.ceil(bytes / 25)).slice(0, bytes);

  test('HEAVY-LANE: measureJsWeight — sums parsable JS, excludes node_modules, skips oversize files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-weight-'));
    try {
      fs.writeFileSync(path.join(dir, 'index.js'), plainJs(1000));
      fs.writeFileSync(path.join(dir, 'lib.mjs'), plainJs(500));
      fs.writeFileSync(path.join(dir, 'README.md'), 'z'.repeat(9000)); // not JS — ignored
      fs.mkdirSync(path.join(dir, 'node_modules', 'dep'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'node_modules', 'dep', 'big.js'), plainJs(50000)); // excluded dir
      fs.mkdirSync(path.join(dir, 'src'));
      fs.writeFileSync(path.join(dir, 'src', 'app.tsx'), plainJs(300));
      const w = measureJsWeight(dir);
      assert(w.totalJsBytes === 1800, `total = 1000+500+300 = 1800, got ${w.totalJsBytes}`);
      assert(w.maxJsFileBytes === 1000, `max file = 1000, got ${w.maxJsFileBytes}`);
      assert(w.minifiedJsBytes === 0, `plain source carries no minified bytes, got ${w.minifiedJsBytes}`);
      assert(w.weightedJsBytes === 1800, `weighted = total when nothing is minified, got ${w.weightedJsBytes}`);
      assert(w.truncated === false, 'small tree is not truncated');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('HEAVY-LANE: minified JS weighs ×12 — a small minified bundle classifies heavy (powerlines/sshift regression)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-min-'));
    try {
      // 400KB single-line bundle (like powerlines: 449KB minified → 1151MB heap
      // while a raw-bytes threshold called it light) + a little plain source.
      fs.writeFileSync(path.join(dir, 'bundle.min.js'), 'var a=1;'.repeat(50000));
      fs.writeFileSync(path.join(dir, 'index.js'), plainJs(2000));
      const w = measureJsWeight(dir);
      assert(w.minifiedJsBytes === 400000, `minified bytes detected, got ${w.minifiedJsBytes}`);
      assert(w.weightedJsBytes === 2000 + 12 * 400000, `weighted = plain + 12×minified, got ${w.weightedJsBytes}`);
      assert(isHeavyScan(w) === true, '400KB minified must classify heavy at the 3MiB default');
      // Same raw volume as plain source stays light:
      const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-min2-'));
      try {
        fs.writeFileSync(path.join(dir2, 'big-source.js'), plainJs(402000));
        const w2 = measureJsWeight(dir2);
        assert(w2.minifiedJsBytes === 0, 'multi-line source is not minified');
        assert(isHeavyScan(w2) === false, '400KB of PLAIN source stays light');
      } finally { fs.rmSync(dir2, { recursive: true, force: true }); }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('HEAVY-LANE: an oversize JS file (>10MB) forces heavy even with tiny total JS (omnius regression)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-oversize-'));
    try {
      // omnius: a 30MB dist/index.js + 39KB of other JS → classified light →
      // 1347MB heap (content scanners load the 30MB file whole). The big file
      // is skipped for the AST but must still flip the package to heavy.
      fs.writeFileSync(path.join(dir, 'index.js'), plainJs(2000));
      fs.writeFileSync(path.join(dir, 'dist.js'), plainJs(11 * 1024 * 1024)); // > 10MB cap
      const w = measureJsWeight(dir);
      assert(w.oversize === true, 'a >10MB JS file must set oversize');
      assert(w.totalJsBytes < 1024 * 1024, `oversize file is excluded from totalJsBytes (got ${w.totalJsBytes})`);
      assert(isHeavyScan(w) === true, 'oversize forces heavy regardless of total/weighted bytes');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('HEAVY-LANE: minification probe skips a banner header — minified body after the offset is detected', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-banner-'));
    try {
      // A license banner can pad the first 4KB (plain, multi-line) so the old
      // 4KB probe called a minified bundle light. The 64KB offset probe reads
      // past the banner. (Distinct from bike4mind, which turned out to be
      // genuinely non-minified — see the prediction-limit note in the PR.)
      const banner = '// SPDX-License-Identifier: MIT\n'.repeat(120); // ~3.8KB multi-line
      const minBody = 'function x(a,b){return a+b;};'.repeat(40000); // ~1.1MB single line
      fs.writeFileSync(path.join(dir, 'bundle.mjs'), banner + minBody);
      const w = measureJsWeight(dir);
      assert(w.minifiedJsBytes > 0, 'minified body past the banner must be detected by the 64KB offset probe');
      assert(isHeavyScan(w) === true, 'banner-prefixed minified bundle classifies heavy');
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
