'use strict';

/**
 * Centralized HTTP concurrency + rate limiter for registry requests — the
 * process-wide "network brain" (governors program, phase A).
 *
 * Three layers of protection, ALL host-keyed (registry.npmjs.org, pypi.org,
 * files.pythonhosted.org… — a 429 from npm must never freeze PyPI):
 *   1. Concurrency semaphore (REGISTRY_SEMAPHORE_MAX, env MUADDIB_REGISTRY_CONCURRENCY)
 *      — caps in-flight requests per host. ALWAYS thread-local: a proxied slot
 *      would leak permanently every time a worker dies mid-request (workers
 *      are ephemeral, one per scan — death in flight is the normal case).
 *   2. Token bucket (RATE_LIMIT_PER_SEC, env MUADDIB_REGISTRY_RATE) — caps
 *      requests/second per host. FIFO grants against REAL tokens only. In the
 *      daemon, worker threads PROXY token acquisition to the main thread
 *      (parentPort messages), so the whole process shares ONE budget and ONE
 *      backoff state per host — the per-thread buckets of 2026-06-12 meant
 *      (1 + N workers) × RATE aggregate and a split-brain backoff (main at
 *      level 19 while workers kept poking npm at level 3).
 *   3. 429 backoff, escalating AND de-escalating (AIMD):
 *      - escalation ×2 per expired pause window (1s → … → BACKOFF_MAX_MS),
 *        one step per window, 429s inside an active pause never re-escalate;
 *      - de-escalation level−1 after a clean window (AIMD_WINDOW_MS with
 *        ≥ AIMD_MIN_GRANTS grants and zero 429) — without this the recovery
 *        was binary: a single 429 per probe pinned the system at 60s pauses
 *        forever while npm was only rejecting a fraction of requests;
 *      - full quiet (2× last pause + 5× base with no 429) still resets to 0;
 *      - slow start after every pause (half budget) and at boot
 *        (RATE/4 for BOOT_SLOWSTART_MS — a full-bucket boot burst plus the
 *        catch-up poll used to re-trip a cooling npm penalty on every restart).
 *
 * Worker proxy mode is gated on `!isMainThread && workerData.rateBrain === true`
 * (set ONLY by runScanInWorker). Any other worker — tests, harnesses, future
 * tools — keeps a local bucket and can never hang waiting for a brain that
 * isn't there. CLI one-shots are isMainThread and in-process, unchanged.
 *
 * Proxy protocol (see queue.js registerWorkerMessageHandler glue):
 *   worker → main : {type:'rate-token-request', id, host, maxWaitMs}
 *                   {type:'rate-429', host}
 *   main → worker : {type:'rate-token-grant'|'rate-token-denied', id}
 * The main side is stateless per worker (a grant to a dead worker is a caught
 * postMessage failure = one lost token, self-healing) so worker death cannot
 * leak anything.
 *
 * Consumers: queue.js (downloadToFile), temporal-analysis.js, npm-registry.js,
 * trusted-dep-diff.js, pypi-registry.js, ingestion.js.
 * NOT covered: api.npmjs.org (different server), replicate.npmjs.com (CouchDB changes stream).
 */

const { isMainThread, parentPort, workerData } = require('worker_threads');

// Env-tunable so a constrained client (e.g. local/Windows `evaluate` runs) can
// dial the burst down without code edits. Defaults preserve prior behavior.
const REGISTRY_SEMAPHORE_MAX = Math.max(1, parseInt(process.env.MUADDIB_REGISTRY_CONCURRENCY, 10) || 20);
const RATE_LIMIT_PER_SEC = Math.max(1, parseInt(process.env.MUADDIB_REGISTRY_RATE, 10) || 30);
// Backoff envs exist as test seams + emergency overrides; the defaults are the contract.
const BACKOFF_BASE_MS = Math.max(10, parseInt(process.env.MUADDIB_REGISTRY_BACKOFF_BASE_MS, 10) || 1000);
const BACKOFF_MAX_MS = Math.max(BACKOFF_BASE_MS, parseInt(process.env.MUADDIB_REGISTRY_BACKOFF_MAX_MS, 10) || 60_000);
// AIMD de-escalation: a window is "clean" when it saw ≥ MIN_GRANTS grants and 0 429s.
const AIMD_WINDOW_MS = Math.max(1000, parseInt(process.env.MUADDIB_REGISTRY_AIMD_WINDOW_MS, 10) || 30_000);
const AIMD_MIN_GRANTS = Math.max(1, parseInt(process.env.MUADDIB_REGISTRY_AIMD_MIN_GRANTS, 10) || 10);
// Boot slow start: RATE/4 for this long after module init. 0 disables (tests).
const BOOT_SLOWSTART_MS = (() => {
  const v = parseInt(process.env.MUADDIB_REGISTRY_BOOT_SLOWSTART_MS, 10);
  return Number.isFinite(v) && v >= 0 ? v : 60_000;
})();
// Default deadline for awaitRateToken callers that pass none (worker fetches):
// long enough to ride out a base pause, short enough not to blow the 45s scan budget.
const TOKEN_DEFAULT_DEADLINE_MS = Math.max(1000, parseInt(process.env.MUADDIB_REGISTRY_TOKEN_DEADLINE_MS, 10) || 20_000);

const DEFAULT_HOST = 'registry.npmjs.org';

const PROXY_MODE = !isMainThread && !!(workerData && workerData.rateBrain === true);

let _bootAt = Date.now();

// ─── Pure backoff/AIMD core (exported for tests — no timers, no I/O) ───
//
// state: {level, pauseUntil, lastPauseMs, last429At, windowStart, grantsInWindow, saw429InWindow}
// event: {type:'429'|'grant', now}
// Returns the NEXT state plus {escalated, deescalated, pauseMs}.
function computeBackoffTransition(state, event, consts = {}) {
  const base = consts.base || BACKOFF_BASE_MS;
  const max = consts.max || BACKOFF_MAX_MS;
  const windowMs = consts.windowMs || AIMD_WINDOW_MS;
  const minGrants = consts.minGrants || AIMD_MIN_GRANTS;
  const s = { ...state };
  const out = { escalated: false, deescalated: false, pauseMs: 0 };
  const now = event.now;

  if (event.type === '429') {
    if (now < s.pauseUntil) {
      // Same in-flight burst: the pause is already armed, never re-escalate.
      s.last429At = now;
      s.saw429InWindow = true;
      return { state: s, ...out };
    }
    // Full-quiet reset (the incident is over, restart at base).
    const quietResetMs = s.lastPauseMs * 2 + base * 5;
    if (s.last429At && now - s.last429At > quietResetMs) s.level = 0;
    s.level += 1;
    const pause = Math.min(max, base * 2 ** (s.level - 1));
    s.lastPauseMs = pause;
    s.last429At = now;
    s.pauseUntil = now + pause;
    // A 429 ends the current observation window.
    s.windowStart = now;
    s.grantsInWindow = 0;
    s.saw429InWindow = false;
    out.escalated = true;
    out.pauseMs = pause;
    return { state: s, ...out };
  }

  // event.type === 'grant'
  if (now < s.pauseUntil) return { state: s, ...out }; // defensive: no grants during a pause
  if (!s.windowStart) s.windowStart = now;
  s.grantsInWindow += 1;
  if (now - s.windowStart >= windowMs) {
    if (!s.saw429InWindow && s.grantsInWindow >= minGrants && s.level > 0) {
      s.level -= 1;
      out.deescalated = true;
    }
    s.windowStart = now;
    s.grantsInWindow = 0;
    s.saw429InWindow = false;
  }
  return { state: s, ...out };
}

// ─── Per-host bucket state ───

function _newBucket() {
  return {
    // semaphore (thread-local always)
    sem: { active: 0, queue: [] },
    // token bucket — the INITIAL fill honors the boot slow start too: a full
    // bucket at boot was exactly the burst that re-tripped a cooling npm penalty.
    tokens: _effectiveRate(),
    lastRefill: Date.now(),
    rateWaiters: [], // FIFO of {grant(granted:boolean), deadlineAt|0}
    grantTimer: null,
    // backoff/AIMD
    backoffCount: 0,
    bo: { level: 0, pauseUntil: 0, lastPauseMs: 0, last429At: 0, windowStart: 0, grantsInWindow: 0, saw429InWindow: false }
  };
}

const _buckets = new Map(); // host → bucket
function _bucket(host) {
  const h = host || DEFAULT_HOST;
  let b = _buckets.get(h);
  if (!b) { b = _newBucket(); _buckets.set(h, b); }
  return b;
}

/** Derive the bucket host from a URL (unknown hosts get their own bucket). */
function hostForUrl(url) {
  try { return new URL(url).hostname || DEFAULT_HOST; } catch { return DEFAULT_HOST; }
}

function _effectiveRate() {
  if (BOOT_SLOWSTART_MS > 0 && Date.now() - _bootAt < BOOT_SLOWSTART_MS) {
    return Math.max(1, Math.floor(RATE_LIMIT_PER_SEC / 4));
  }
  return RATE_LIMIT_PER_SEC;
}

function _refillTokens(b) {
  const now = Date.now();
  if (now < b.bo.pauseUntil) return; // backoff pause: no refills, no grants
  const rate = _effectiveRate();
  if (b.bo.pauseUntil > b.lastRefill) {
    // First refill after a backoff pause: slow start at half budget.
    b.tokens = Math.max(1, Math.floor(rate / 2));
    b.lastRefill = now;
    return;
  }
  const elapsed = now - b.lastRefill;
  if (elapsed >= 1000) {
    b.tokens = Math.min(rate, b.tokens + Math.floor(elapsed / 1000) * rate);
    b.lastRefill = now;
  }
}

function _drainRateWaiters(b) {
  b.grantTimer = null;
  _refillTokens(b);
  const now = Date.now();
  // Expire deadlined waiters first (FIFO order preserved for the rest).
  for (let i = b.rateWaiters.length - 1; i >= 0; i--) {
    const w = b.rateWaiters[i];
    if (w.deadlineAt && now >= w.deadlineAt) {
      b.rateWaiters.splice(i, 1);
      w.grant(false);
    }
  }
  while (b.tokens > 0 && b.rateWaiters.length > 0 && now >= b.bo.pauseUntil) {
    b.tokens--;
    const w = b.rateWaiters.shift();
    b.bo = computeBackoffTransition(b.bo, { type: 'grant', now }).state;
    w.grant(true);
  }
  if (b.rateWaiters.length > 0) _scheduleGrant(b);
}

function _scheduleGrant(b) {
  if (b.grantTimer) return;
  const now = Date.now();
  let wakeAt = Math.max(b.bo.pauseUntil, b.lastRefill + 1000);
  // Wake earlier if a waiter's deadline lands before the next grant opportunity.
  for (const w of b.rateWaiters) {
    if (w.deadlineAt && w.deadlineAt < wakeAt) wakeAt = w.deadlineAt;
  }
  b.grantTimer = setTimeout(() => _drainRateWaiters(b), Math.max(10, wakeAt - now));
}

function _acquireRateTokenLocal(b, maxWaitMs) {
  _refillTokens(b);
  const now = Date.now();
  if (b.tokens > 0 && b.rateWaiters.length === 0 && now >= b.bo.pauseUntil) {
    b.tokens--;
    b.bo = computeBackoffTransition(b.bo, { type: 'grant', now }).state;
    return Promise.resolve(true);
  }
  return new Promise(resolve => {
    b.rateWaiters.push({
      grant: resolve,
      deadlineAt: Number.isFinite(maxWaitMs) && maxWaitMs > 0 ? now + maxWaitMs : 0
    });
    _scheduleGrant(b);
  });
}

// ─── Worker proxy plumbing (PROXY_MODE only) ───

let _nextReqId = 1;
const _pendingTokenReqs = new Map(); // id → resolve(granted:boolean)

if (PROXY_MODE && parentPort) {
  parentPort.on('message', (msg) => {
    if (!msg || (msg.type !== 'rate-token-grant' && msg.type !== 'rate-token-denied')) return;
    const resolve = _pendingTokenReqs.get(msg.id);
    if (resolve) {
      _pendingTokenReqs.delete(msg.id);
      resolve(msg.type === 'rate-token-grant');
    }
  });
  // CRITICAL: a 'message' listener REFs the port — without unref the worker's
  // event loop never empties and the worker NEVER exits after posting its
  // result (zombie workers piling up scan after scan; caught by the worker-mem
  // e2e test, exit entry missing). unref keeps delivery working while the loop
  // is alive; during a token wait the loop is held by the REF'd backstop timer
  // in _acquireRateTokenProxy (cleared on grant), so a grant can always land.
  parentPort.unref();
}

function _acquireRateTokenProxy(host, maxWaitMs) {
  return new Promise(resolve => {
    const id = _nextReqId++;
    // Bounded requests get their deadline + grace; "unbounded" (maxWaitMs 0)
    // gets a generous 90s backstop — long enough to ride out a capped 60s
    // pause in one round trip, short enough that a dead main can't hang us.
    const deadline = (Number.isFinite(maxWaitMs) && maxWaitMs > 0 ? maxWaitMs + 5000 : 90_000);
    // Local backstop: if the main thread never answers (blocked event loop,
    // daemon shutting down), deny locally — a denied token is a failed fetch,
    // never a hung scan. Deliberately REF'd: parentPort is unref'd (see module
    // init), so during a token wait THIS timer is what keeps the worker's
    // event loop alive long enough for the grant message to land. Cleared on
    // resolution, so a completed scan still lets the worker exit naturally.
    const t = setTimeout(() => {
      if (_pendingTokenReqs.delete(id)) resolve(false);
    }, deadline);
    _pendingTokenReqs.set(id, (granted) => { clearTimeout(t); resolve(granted); });
    try {
      parentPort.postMessage({ type: 'rate-token-request', id, host: host || DEFAULT_HOST, maxWaitMs });
    } catch {
      clearTimeout(t);
      _pendingTokenReqs.delete(id);
      resolve(false);
    }
  });
}

// ─── Public API ───

/**
 * Wait for a rate token WITHOUT touching the concurrency semaphore. Never
 * rejects; resolves {granted:boolean}. Callers treat granted:false as a failed
 * fetch (best-effort enrichment contract). Default deadline
 * TOKEN_DEFAULT_DEADLINE_MS; pass maxWaitMs:0 for an unbounded wait.
 */
function awaitRateToken(host = DEFAULT_HOST, opts = {}) {
  const maxWaitMs = opts.maxWaitMs === undefined ? TOKEN_DEFAULT_DEADLINE_MS : opts.maxWaitMs;
  const p = PROXY_MODE
    ? _acquireRateTokenProxy(host, maxWaitMs)
    : _acquireRateTokenLocal(_bucket(host), maxWaitMs);
  return p.then(granted => ({ granted }));
}

/**
 * Acquire an in-flight slot + a rate token for `host`. The semaphore is
 * thread-local; the token comes from the process-wide brain in worker proxy
 * mode. Unbounded wait (back-pressure semantics for ingestion/downloads).
 */
function acquireRegistrySlot(host = DEFAULT_HOST) {
  const b = _bucket(host);
  const takeToken = async () => {
    if (!PROXY_MODE) { await _acquireRateTokenLocal(b, 0); return; }
    // Unbounded semantics via repeated bounded proxy requests: each request
    // has a local backstop (so a dead/blocked main can never hang the worker
    // forever — the outer scan timeout is the real bound), and a denial loops
    // into a fresh request instead of proceeding WITHOUT a token (that would
    // silently bypass the brain during the very pauses it exists for).
    // eslint-disable-next-line no-await-in-loop
    while (!(await _acquireRateTokenProxy(host, 0))) { /* re-request */ }
  };
  if (b.sem.active < REGISTRY_SEMAPHORE_MAX) {
    b.sem.active++;
    return takeToken();
  }
  return new Promise(resolve => {
    b.sem.queue.push(() => { takeToken().then(resolve); });
  });
}

function releaseRegistrySlot(host = DEFAULT_HOST) {
  const b = _bucket(host);
  if (b.sem.queue.length > 0) {
    const next = b.sem.queue.shift();
    next(); // transfers the slot (active count unchanged)
  } else if (b.sem.active > 0) {
    b.sem.active--;
  }
}

/**
 * Call on a 429 response. Suspends ALL token grants for `host` for an
 * escalating pause; in worker proxy mode the signal is forwarded to the main
 * brain so every thread backs off together.
 */
function signal429(host = DEFAULT_HOST) {
  if (PROXY_MODE) {
    try { parentPort.postMessage({ type: 'rate-429', host }); } catch { /* main gone */ }
    _localProxyBackoffCount++;
    return;
  }
  const b = _bucket(host);
  b.backoffCount++;
  b.tokens = 0;
  const r = computeBackoffTransition(b.bo, { type: '429', now: Date.now() });
  b.bo = r.state;
  if (r.escalated && (b.backoffCount % 10 === 1 || r.pauseMs >= BACKOFF_BASE_MS * 8)) {
    console.warn(`[HTTP-LIMITER] 429 rate limited by ${host} (total: ${b.backoffCount}, pause ${r.pauseMs}ms, level ${b.bo.level})`);
  }
  if (b.rateWaiters.length > 0) _scheduleGrant(b);
}

let _localProxyBackoffCount = 0; // proxy-mode local counter (tests/back-compat)

function getBackoffCount(host = DEFAULT_HOST) {
  if (PROXY_MODE) return _localProxyBackoffCount;
  return _bucket(host).backoffCount;
}

/** Observability seam (tests, degradation registry, hourly log) — never control flow. */
function getRateLimiterState(host = DEFAULT_HOST) {
  const b = _bucket(host);
  return {
    tokens: b.tokens,
    pendingWaiters: b.rateWaiters.length,
    consecutive429: b.bo.level,
    pauseRemainingMs: Math.max(0, b.bo.pauseUntil - Date.now()),
    lastPauseMs: b.bo.lastPauseMs,
    backoffCount: b.backoffCount
  };
}

/** Brain state across hosts (degradation registry + hourly Stability log). */
function getBrainState(host) {
  if (host) {
    const s = getRateLimiterState(host);
    return { host, level: s.consecutive429, ...s };
  }
  const all = {};
  for (const [h, b] of _buckets.entries()) {
    all[h] = {
      level: b.bo.level,
      pauseRemainingMs: Math.max(0, b.bo.pauseUntil - Date.now()),
      backoffCount: b.backoffCount,
      pendingWaiters: b.rateWaiters.length
    };
  }
  return all;
}

function resetLimiter() {
  for (const b of _buckets.values()) {
    if (b.grantTimer) { clearTimeout(b.grantTimer); b.grantTimer = null; }
    // Release anything queued so a reset between tests can never hang the suite.
    while (b.rateWaiters.length > 0) b.rateWaiters.shift().grant(true);
    b.sem.active = 0;
    b.sem.queue.length = 0;
  }
  _buckets.clear();
  _pendingTokenReqs.clear();
  _localProxyBackoffCount = 0;
  _bootAt = Date.now() - BOOT_SLOWSTART_MS; // tests get full rate unless they opt into slow start
}

/** Test seam: re-arm the boot slow-start window as if the process just booted. */
function _restartBootSlowStartForTests() {
  _bootAt = Date.now();
}

function getActiveSemaphore(host = DEFAULT_HOST) {
  return _bucket(host).sem;
}

module.exports = {
  REGISTRY_SEMAPHORE_MAX,
  RATE_LIMIT_PER_SEC,
  DEFAULT_HOST,
  acquireRegistrySlot,
  releaseRegistrySlot,
  awaitRateToken,
  signal429,
  getBackoffCount,
  getRateLimiterState,
  getBrainState,
  computeBackoffTransition,
  hostForUrl,
  resetLimiter,
  _restartBootSlowStartForTests,
  getActiveSemaphore
};
