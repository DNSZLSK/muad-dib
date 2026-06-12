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
  // Bucket-contract tests assume a full bucket at load: disable the boot
  // slow start (phase A) unless a test opts into it explicitly.
  const effective = { MUADDIB_REGISTRY_BOOT_SLOWSTART_MS: 0, ...env };
  const saved = {};
  for (const [k, v] of Object.entries(effective)) {
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

  // --- Retry token bypass (each network attempt must pay its own token) ---

  await asyncTest('LIMITER: awaitRateToken consumes real tokens and respects an active 429 pause', async () => {
    const { limiter, restore } = freshLimiter({
      MUADDIB_REGISTRY_RATE: 2,
      MUADDIB_REGISTRY_CONCURRENCY: 50,
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: 250
    });
    try {
      await limiter.awaitRateToken();
      await limiter.awaitRateToken(); // both immediate: 2 tokens in the bucket
      let third = false;
      const p = limiter.awaitRateToken().then(() => { third = true; });
      await sleep(80);
      assert(third === false, 'third token must wait for the next refill');
      await p;
      assert(third === true, 'third token granted at refill');
      limiter.signal429(); // arms a 250ms pause
      let granted = false;
      const q = limiter.awaitRateToken().then(() => { granted = true; });
      await sleep(100);
      assert(granted === false, 'awaitRateToken is parked while the 429 pause is active');
      await q;
      assert(granted === true, 'awaitRateToken resolves after the pause');
    } finally { restore(); }
  });

  await asyncTest('REGISTRY+LIMITER: a 429 retry pays a rate token (no bucket bypass during backoff)', async () => {
    // fetchWithRetry's first attempt is paid by the caller's acquireRegistrySlot;
    // the regression was that retries fetched again WITHOUT a token, hammering a
    // 429ing registry straight through its own backoff pause. Discrimination by
    // duration: the 429 arms a 3000ms pause (env below) while the retry's own
    // Retry-After sleep is only 500-1000ms — a retry that pays its token cannot
    // complete before ~3s; the bypassing one completed at ~1s.
    const savedEnv = {};
    for (const [k, v] of Object.entries({
      MUADDIB_REGISTRY_RATE: '100',
      MUADDIB_REGISTRY_BACKOFF_BASE_MS: '3000',
      MUADDIB_REGISTRY_BACKOFF_MAX_MS: '60000',
      MUADDIB_REGISTRY_BOOT_SLOWSTART_MS: '0'
    })) { savedEnv[k] = process.env[k]; process.env[k] = v; }
    const REGISTRY_PATH = require.resolve('../../src/scanner/npm-registry.js');
    const originalFetch = globalThis.fetch;
    delete require.cache[LIMITER_PATH];
    delete require.cache[REGISTRY_PATH];
    try {
      const limiter = require(LIMITER_PATH);
      const { getPackageMetadata } = require(REGISTRY_PATH);
      const registryResponse = {
        time: { created: '2023-01-01T00:00:00Z', '1.0.0': '2023-01-01T00:00:00Z' },
        'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} }
      };
      let metaCalls = 0;
      globalThis.fetch = async (url) => {
        if (url.includes('api.npmjs.org/downloads')) {
          return { ok: true, status: 200, json: async () => ({ downloads: 10 }), headers: new Map() };
        }
        metaCalls++;
        if (metaCalls === 1) {
          return { ok: false, status: 429, text: async () => 'Too Many Requests', headers: new Map([['retry-after', '1']]) };
        }
        return { ok: true, status: 200, json: async () => registryResponse, headers: new Map() };
      };
      const t0 = Date.now();
      const result = await getPackageMetadata('retry-pays-token-pkg');
      const elapsed = Date.now() - t0;
      assert(result !== null, 'metadata succeeds after the 429 retry');
      assert(metaCalls >= 2, `second attempt happened (got ${metaCalls} calls)`);
      assert(elapsed >= 2000, `retry must wait out the backoff pause via its token (elapsed ${elapsed}ms)`);
      limiter.resetLimiter();
    } finally {
      globalThis.fetch = originalFetch;
      delete require.cache[LIMITER_PATH];
      delete require.cache[REGISTRY_PATH];
      for (const [k, v] of Object.entries(savedEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });
}

module.exports = { runHttpLimiterTests };
