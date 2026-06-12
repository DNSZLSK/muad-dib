const { asyncTest, assert } = require('../test-utils');

/**
 * HTTP limiter tests (src/shared/http-limiter.js).
 *
 * Regression context (2026-06-12, C3 palier 12): the original token bucket
 * resolved queued waiters unconditionally after one refill window, so under
 * contention the effective send rate was the demand, not RATE_LIMIT_PER_SEC —
 * ~5 sustained 429/s against npm, insensitive to MUADDIB_REGISTRY_RATE. The
 * 429 backoff was also a fixed ~1s pause with a full-bucket re-burst.
 *
 * All tests load a fresh limiter instance with small env-tuned rates/backoffs
 * (the envs are read at module load), then restore env + module cache so other
 * test files keep the default instance.
 */

const LIMITER_PATH = require.resolve('../../src/shared/http-limiter.js');

function freshLimiter(env) {
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    process.env[k] = String(v);
  }
  delete require.cache[LIMITER_PATH];
  const limiter = require(LIMITER_PATH);
  const restore = () => {
    limiter.resetLimiter();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    delete require.cache[LIMITER_PATH];
  };
  return { limiter, restore };
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function runHttpLimiterTests() {
  console.log('\n=== HTTP LIMITER TESTS ===\n');

  // --- Rate cap under contention (the token-leak regression) ---

  await asyncTest('LIMITER: token bucket enforces the per-second cap under contention (leak regression)', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 3,
      MUADDIB_REGISTRY_CONCURRENCY: 50,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 1000
    });
    try {
      let resolved = 0;
      const all = [];
      for (let i = 0; i < 12; i++) {
        all.push(limiter.acquireRegistrySlot().then(() => {
          resolved++;
          limiter.releaseRegistrySlot();
        }));
      }
      await sleep(80);
      assert(resolved === 3, `initial burst grants exactly RATE tokens (got ${resolved})`);
      await sleep(1150); // ~t=1.2s: exactly one refill window has passed
      // The leaky implementation released ALL queued waiters here (resolved=12).
      assert(resolved <= 6, `one refill grants at most RATE more — leak detected if all pass (got ${resolved})`);
      assert(resolved >= 4, `refill must grant new tokens (got ${resolved})`);
      await Promise.all(all); // ~4s total at 3/s: nobody starves
      assert(resolved === 12, `all waiters eventually acquire (got ${resolved})`);
    } finally { restore(); }
  });

  // --- 429 backoff escalation ---

  await asyncTest('LIMITER: 429 backoff escalates exponentially across pause windows', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 100,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 80,
      MUADDIB_REGISTRY_BACKOFF_MAX_MS: 100000
    });
    try {
      limiter.signal429();
      let s = limiter.getRateLimiterState();
      assert(s.consecutive429 === 1 && s.lastPauseMs === 80,
        `first 429 pauses for base (got level ${s.consecutive429}, pause ${s.lastPauseMs})`);

      limiter.signal429(); // still inside the 80ms pause
      s = limiter.getRateLimiterState();
      assert(s.consecutive429 === 1 && s.lastPauseMs === 80,
        `429s within an active pause do not escalate (got level ${s.consecutive429}, pause ${s.lastPauseMs})`);
      assert(s.backoffCount === 2, `every 429 still counts in backoffCount (got ${s.backoffCount})`);

      await sleep(110); // pause expired
      limiter.signal429();
      s = limiter.getRateLimiterState();
      assert(s.lastPauseMs === 160, `second window doubles the pause (got ${s.lastPauseMs})`);

      await sleep(190); // second pause expired
      limiter.signal429();
      s = limiter.getRateLimiterState();
      assert(s.lastPauseMs === 320, `third window doubles again (got ${s.lastPauseMs})`);
    } finally { restore(); }
  });

  await asyncTest('LIMITER: 429 backoff is capped at BACKOFF_MAX_MS', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 100,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 60,
      MUADDIB_REGISTRY_BACKOFF_MAX_MS: 150
    });
    try {
      limiter.signal429(); // 60
      await sleep(80);
      limiter.signal429(); // 120
      await sleep(140);
      limiter.signal429(); // would be 240 → capped at 150
      const s = limiter.getRateLimiterState();
      assert(s.lastPauseMs === 150, `pause caps at BACKOFF_MAX_MS (got ${s.lastPauseMs})`);
    } finally { restore(); }
  });

  await asyncTest('LIMITER: escalation level resets after a quiet period', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 100,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 40,
      MUADDIB_REGISTRY_BACKOFF_MAX_MS: 100000
    });
    try {
      limiter.signal429(); // level 1, pause 40
      await sleep(60);
      limiter.signal429(); // level 2, pause 80
      // quiet threshold = lastPause*2 + base*5 = 160 + 200 = 360ms
      await sleep(500);
      limiter.signal429();
      const s = limiter.getRateLimiterState();
      assert(s.consecutive429 === 1 && s.lastPauseMs === 40,
        `a quiet period restarts escalation at base (got level ${s.consecutive429}, pause ${s.lastPauseMs})`);
    } finally { restore(); }
  });

  await asyncTest('LIMITER: an active 429 pause blocks token grants until it expires', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 5,
      MUADDIB_REGISTRY_CONCURRENCY: 50,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 250
    });
    try {
      limiter.signal429(); // tokens drained, grants paused 250ms
      let resolved = false;
      const p = limiter.acquireRegistrySlot().then(() => {
        resolved = true;
        limiter.releaseRegistrySlot();
      });
      await sleep(100);
      assert(resolved === false, 'no token may be granted while the 429 pause is active');
      await p; // resolves after the pause via the shared grant timer
      assert(resolved === true, 'waiter is granted a token once the pause expires');
    } finally { restore(); }
  });

  // --- Semaphore behavior preserved ---

  await asyncTest('LIMITER: concurrency semaphore still caps in-flight slots', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 100,
      MUADDIB_REGISTRY_CONCURRENCY: 2
    });
    try {
      await limiter.acquireRegistrySlot();
      await limiter.acquireRegistrySlot();
      let third = false;
      const p = limiter.acquireRegistrySlot().then(() => { third = true; });
      await sleep(60);
      assert(third === false, 'third acquire must wait while 2 slots are held');
      limiter.releaseRegistrySlot();
      await p;
      assert(third === true, 'released slot transfers to the queued waiter');
      assert(limiter.getActiveSemaphore().active === 2, 'slot transfer keeps the active count');
    } finally { restore(); }
  });

  // --- Reset hygiene (a reset between tests must never leave the suite hanging) ---

  await asyncTest('LIMITER: resetLimiter releases pending waiters and clears backoff state', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 1,
      MUADDIB_REGISTRY_CONCURRENCY: 50,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 60000 // pause would outlive the suite without reset
    });
    try {
      await limiter.acquireRegistrySlot(); // consumes the only token
      limiter.signal429();                 // arms a 60s pause
      let released = 0;
      const pending = [
        limiter.acquireRegistrySlot().then(() => { released++; }),
        limiter.acquireRegistrySlot().then(() => { released++; })
      ];
      await sleep(30);
      assert(released === 0, 'waiters are parked behind the pause');
      limiter.resetLimiter();
      await Promise.all(pending);
      assert(released === 2, `reset must release parked waiters (got ${released})`);
      const s = limiter.getRateLimiterState();
      assert(s.consecutive429 === 0 && s.pauseRemainingMs === 0 && s.pendingWaiters === 0,
        'reset clears backoff and queue state');
    } finally { restore(); }
  });
}

module.exports = { runHttpLimiterTests };
