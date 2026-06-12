const { test, asyncTest, assert } = require('../test-utils');
const path = require('path');

/**
 * Phase A (governors program): process-wide network brain.
 *
 * Regression context (2026-06-12): per-thread limiter instances meant the
 * aggregate registry rate was (1 + N workers) × RATE — npm penalized the IP
 * for ~5h — and the backoff state was split-brain (main at level 19 while
 * workers kept poking at level 3). Recovery was also binary: a single 429 per
 * probe re-armed a 60s pause forever (no de-escalation).
 *
 * Pure AIMD core tests need no timers; the harness tests spawn REAL workers
 * through runScanInWorker (MUADDIB_SCAN_WORKER_PATH seam) so the production
 * plumbing — workerData.rateBrain, proxy messages, queue.js handlers — is the
 * thing under test.
 */

const BRAIN_STUB = path.join(__dirname, '..', 'fixtures', 'brain-stub-worker.js');
const limiter = require('../../src/shared/http-limiter.js');
const queue = require('../../src/monitor/queue.js');

const C = { base: 1000, max: 60000, windowMs: 30000, minGrants: 10 };
const freshBo = () => ({ level: 0, pauseUntil: 0, lastPauseMs: 0, last429At: 0, windowStart: 0, grantsInWindow: 0, saw429InWindow: false });

async function withStubWorker(fn) {
  const saved = process.env.MUADDIB_SCAN_WORKER_PATH;
  process.env.MUADDIB_SCAN_WORKER_PATH = BRAIN_STUB;
  try { return await fn(); } finally {
    if (saved === undefined) delete process.env.MUADDIB_SCAN_WORKER_PATH;
    else process.env.MUADDIB_SCAN_WORKER_PATH = saved;
  }
}

async function runNetworkBrainTests() {
  console.log('\n=== NETWORK BRAIN TESTS (phase A) ===\n');

  // ─── Pure AIMD core (computeBackoffTransition) ───

  test('BRAIN: escalation doubles per expired pause window and caps at max', () => {
    // Each 429 lands just AFTER the previous pause expires (the sustained-storm
    // shape): inside the quiet window, so it escalates instead of resetting.
    let st = freshBo();
    let now = 10_000;
    const pauses = [];
    for (let i = 0; i < 9; i++) {
      const r = limiter.computeBackoffTransition(st, { type: '429', now }, C);
      assert(r.escalated, `storm 429 #${i + 1} must escalate`);
      pauses.push(r.pauseMs);
      st = r.state;
      now = st.pauseUntil + 10;
    }
    assert(pauses[0] === 1000 && pauses[1] === 2000 && pauses[2] === 4000,
      `pause doubles per window (got ${pauses.slice(0, 3)})`);
    assert(st.lastPauseMs === C.max && pauses[pauses.length - 1] === C.max,
      `pause caps at max (got ${st.lastPauseMs})`);
  });

  test('BRAIN: 429s inside an active pause never re-escalate', () => {
    let s = freshBo();
    let r = limiter.computeBackoffTransition(s, { type: '429', now: 10_000 }, C);
    const level = r.state.level;
    r = limiter.computeBackoffTransition(r.state, { type: '429', now: 10_500 }, C); // pause active until 11_000
    assert(!r.escalated && r.state.level === level, 'in-pause 429 must not escalate');
    assert(r.state.saw429InWindow === true, 'in-pause 429 marks the window dirty');
  });

  test('BRAIN: a clean window (≥minGrants, zero 429) de-escalates one level', () => {
    let s = { ...freshBo(), level: 3, lastPauseMs: 4000, last429At: 9_000 };
    let now = 20_000;
    let st = s;
    for (let i = 0; i < C.minGrants; i++) {
      st = limiter.computeBackoffTransition(st, { type: 'grant', now: now + i * 100 }, C).state;
    }
    const r = limiter.computeBackoffTransition(st, { type: 'grant', now: now + C.windowMs + 1 }, C);
    assert(r.deescalated && r.state.level === 2, `clean window must de-escalate 3→2 (got ${r.state.level})`);
  });

  test('BRAIN: a window that saw a 429 does NOT de-escalate; level floors at 0', () => {
    // Dirty window: enough grants but saw429InWindow set.
    let st = { ...freshBo(), level: 2, saw429InWindow: true, windowStart: 10_000, grantsInWindow: C.minGrants + 5 };
    let r = limiter.computeBackoffTransition(st, { type: 'grant', now: 10_000 + C.windowMs + 1 }, C);
    assert(!r.deescalated && r.state.level === 2, 'dirty window must hold the level');
    // Floor: level 0 never goes negative.
    st = { ...freshBo(), level: 0, windowStart: 50_000, grantsInWindow: C.minGrants + 5 };
    r = limiter.computeBackoffTransition(st, { type: 'grant', now: 50_000 + C.windowMs + 1 }, C);
    assert(!r.deescalated && r.state.level === 0, 'level must floor at 0');
  });

  test('BRAIN: full quiet resets the escalation to base', () => {
    let s = { ...freshBo(), level: 5, lastPauseMs: 16_000, last429At: 100_000 };
    const quiet = 16_000 * 2 + C.base * 5 + 1;
    const r = limiter.computeBackoffTransition(s, { type: '429', now: 100_000 + quiet }, C);
    assert(r.state.level === 1 && r.pauseMs === C.base, `quiet period restarts at base (level ${r.state.level}, pause ${r.pauseMs})`);
  });

  // ─── Per-host isolation (main-thread, no workers needed) ───

  await asyncTest('BRAIN: a npm 429 does not freeze the pypi bucket', async () => {
    limiter.resetLimiter();
    limiter.signal429('registry.npmjs.org');
    const npmState = limiter.getRateLimiterState('registry.npmjs.org');
    assert(npmState.pauseRemainingMs > 0, 'npm bucket must be paused after its 429');
    const t0 = Date.now();
    const { granted } = await limiter.awaitRateToken('pypi.org', { maxWaitMs: 2000 });
    assert(granted && Date.now() - t0 < 500, 'pypi token must grant immediately while npm pauses');
    limiter.resetLimiter();
  });

  // ─── Worker harness: the production plumbing end-to-end ───

  await asyncTest('BRAIN: aggregate grant rate across 4 workers respects the single budget', async () => {
    await withStubWorker(async () => {
      limiter.resetLimiter();
      const runs = [];
      for (let i = 0; i < 4; i++) {
        runs.push(queue.runScanInWorker('/tmp/x', 30000,
          { name: `brain-w${i}`, version: '1.0.0', _brain: 'tokens', _count: 10, _host: 'registry.npmjs.org' }));
      }
      const results = await Promise.all(runs);
      const stamps = results.flatMap(r => r.stamps).filter(s => s.granted).map(s => s.t).sort((a, b) => a - b);
      assert(stamps.length === 40, `all 40 requests eventually granted (got ${stamps.length})`);
      // The leak scenario (per-thread buckets) grants ~4×RATE in the first
      // second. With ONE brain, a sliding 1s window can legitimately hold up
      // to 2×RATE (initial burst + the refill landing inside the window) but
      // NEVER 4×RATE — that bound is what separates one shared budget from
      // four independent ones.
      const RATE = limiter.RATE_LIMIT_PER_SEC;
      let worst = 0;
      for (let i = 0; i < stamps.length; i++) {
        let j = i;
        while (j < stamps.length && stamps[j] < stamps[i] + 1000) j++;
        worst = Math.max(worst, j - i);
      }
      assert(worst <= 2 * RATE, `aggregate must respect the single budget: worst 1s window ${worst} > 2×RATE ${2 * RATE} (per-thread leak shape)`);
      limiter.resetLimiter();
    });
  });

  await asyncTest('BRAIN: a 429 signaled by one worker pauses the MAIN brain (no split-brain)', async () => {
    await withStubWorker(async () => {
      limiter.resetLimiter();
      await queue.runScanInWorker('/tmp/x', 10000,
        { name: 'brain-429', version: '1.0.0', _brain: 'signal-429', _host: 'registry.npmjs.org' });
      const st = limiter.getRateLimiterState('registry.npmjs.org');
      assert(st.backoffCount >= 1, `the worker's 429 must reach the main brain (backoffCount ${st.backoffCount})`);
      assert(st.pauseRemainingMs > 0, `the main bucket must be paused by the worker's 429 (${st.pauseRemainingMs}ms)`);
      limiter.resetLimiter();
    });
  });

  await asyncTest('BRAIN: a worker killed with a pending token request leaks nothing', async () => {
    await withStubWorker(async () => {
      limiter.resetLimiter();
      limiter.signal429('registry.npmjs.org'); // park the next request behind a pause
      const p = queue.runScanInWorker('/tmp/x', 30000,
        { name: 'brain-hang', version: '1.0.0', _brain: 'request-hang', _host: 'registry.npmjs.org' });
      await new Promise(r => setTimeout(r, 400)); // worker boots, request parked
      queue.terminateAllWorkers();
      try { await p; } catch { /* terminated — expected */ }
      // The brain must keep serving after the death of a waiter.
      const { granted } = await limiter.awaitRateToken('registry.npmjs.org', { maxWaitMs: 5000 });
      assert(granted, 'main-thread token must still be granted after a worker died waiting');
      limiter.resetLimiter();
    });
  });

  await asyncTest('BRAIN: a worker WITHOUT rateBrain uses a local bucket and never hangs', async () => {
    const { Worker } = require('worker_threads');
    const result = await new Promise((resolve, reject) => {
      const w = new Worker(BRAIN_STUB, {
        workerData: { scanContext: { _brain: 'tokens', _count: 3, _host: 'registry.npmjs.org' } } // NO rateBrain
      });
      const t = setTimeout(() => { w.terminate(); reject(new Error('no-rateBrain worker hung')); }, 8000);
      w.on('message', (msg) => { clearTimeout(t); w.terminate(); resolve(msg); });
      w.on('error', (e) => { clearTimeout(t); reject(e); });
    });
    assert(result.type === 'result' && result.data.stamps.length === 3 && result.data.stamps.every(s => s.granted),
      'local-bucket worker must grant its own tokens without a brain');
  });
}

module.exports = { runNetworkBrainTests };
