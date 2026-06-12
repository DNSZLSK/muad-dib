'use strict';

/**
 * Centralized HTTP concurrency + rate limiter for npm registry requests.
 *
 * Two layers of protection:
 *   1. Concurrency semaphore (REGISTRY_SEMAPHORE_MAX, default 20, env MUADDIB_REGISTRY_CONCURRENCY) — caps in-flight requests
 *   2. Rate limiter (RATE_LIMIT_PER_SEC, default 30, env MUADDIB_REGISTRY_RATE) — caps requests/second via token bucket
 *
 * Without rate limiting, 10 concurrent slots × fast-completing requests = 100+ req/s
 * bursts that trigger npm 429 responses → exponential backoff → scan times 10s→90s.
 *
 * Token grants are FIFO and only ever issued against a real token: a waiter that
 * reaches the head of the queue during an exhausted second waits for the next
 * refill instead of proceeding at zero. (The original implementation resolved
 * waiters unconditionally after one refill window — under contention every
 * queued caller passed at once and the effective send rate was the demand, not
 * RATE_LIMIT_PER_SEC. Observed 2026-06-12: ~5 sustained 429/s at 12 workers,
 * insensitive to MUADDIB_REGISTRY_RATE.)
 *
 * 429 backoff escalates: the first 429 pauses all token grants for
 * BACKOFF_BASE_MS; each new 429 arriving after the previous pause expired
 * doubles the pause (capped at BACKOFF_MAX_MS). 429s landing while a pause is
 * already active (the rest of an in-flight burst) extend nothing and do not
 * escalate — one escalation step per pause window. The escalation level resets
 * after a quiet period (no 429 for 2× the last pause + 5× base). After a pause
 * expires, the bucket restarts at half budget (slow start) before resuming the
 * full per-second rate.
 *
 * Caveat: this module is per-thread state. Scan workers (worker_threads) each
 * load their own instance, so the aggregate send rate across the daemon is up
 * to (1 + N workers) × RATE_LIMIT_PER_SEC if every thread is registry-heavy.
 * In practice the registry hot paths (ingestion, centralized metadata) run on
 * the main thread; the escalating backoff is the feedback that bounds each
 * thread when npm signals overload.
 *
 * Consumers: queue.js (downloadToFile), temporal-analysis.js, npm-registry.js.
 * NOT covered: api.npmjs.org (different server), replicate.npmjs.com (CouchDB changes stream).
 */

// Env-tunable so a constrained client (e.g. local/Windows `evaluate` runs that hit npm 429s during
// the ~1644-request metadata burst over 548 packages) can dial the burst down without code edits.
// Defaults preserve prior behavior (20 in-flight / 30 req/s).
const REGISTRY_SEMAPHORE_MAX = Math.max(1, parseInt(process.env.MUADDIB_REGISTRY_CONCURRENCY, 10) || 20);
const RATE_LIMIT_PER_SEC = Math.max(1, parseInt(process.env.MUADDIB_REGISTRY_RATE, 10) || 30);
// Backoff envs exist as test seams + emergency overrides; the defaults are the contract.
const BACKOFF_BASE_MS = Math.max(10, parseInt(process.env.MUADDIB_REGISTRY_BACKOFF_BASE_MS, 10) || 1000);
const BACKOFF_MAX_MS = Math.max(BACKOFF_BASE_MS, parseInt(process.env.MUADDIB_REGISTRY_BACKOFF_MAX_MS, 10) || 60_000);

// --- Concurrency semaphore ---

const _semaphore = { active: 0, queue: [] };

function acquireRegistrySlot() {
  if (_semaphore.active < REGISTRY_SEMAPHORE_MAX) {
    _semaphore.active++;
    return _acquireRateToken();
  }
  return new Promise(resolve => {
    _semaphore.queue.push(() => {
      _acquireRateToken().then(resolve);
    });
  });
}

function releaseRegistrySlot() {
  if (_semaphore.queue.length > 0) {
    const next = _semaphore.queue.shift();
    next(); // Transfers slot to next waiter (active count stays the same)
  } else {
    _semaphore.active--;
  }
}

// --- Token bucket rate limiter ---
// Refills RATE_LIMIT_PER_SEC tokens per second. Each request consumes 1 token.
// Exhausted → the caller joins a FIFO queue and is resolved only when a refill
// actually hands it a token (one shared grant timer, not one timer per waiter).

let _tokens = RATE_LIMIT_PER_SEC;
let _lastRefill = Date.now();
const _rateWaiters = [];
let _grantTimer = null;

// 429 backoff escalation state
let _backoffCount = 0;    // total 429s seen (logging, tests, getBackoffCount export)
let _consecutive429 = 0;  // escalation level (one step per expired pause window)
let _pauseUntil = 0;      // token grants suspended until this timestamp
let _lastPauseMs = 0;
let _last429At = 0;

function _refillTokens() {
  const now = Date.now();
  if (now < _pauseUntil) return; // backoff pause: no refills, no grants
  if (_pauseUntil > _lastRefill) {
    // First refill after a backoff pause: slow start at half budget so the
    // recovery doesn't reopen with a full-rate burst against a server that
    // just told us to back off.
    _tokens = Math.max(1, Math.floor(RATE_LIMIT_PER_SEC / 2));
    _lastRefill = now;
    return;
  }
  const elapsed = now - _lastRefill;
  if (elapsed >= 1000) {
    _tokens = Math.min(RATE_LIMIT_PER_SEC, _tokens + Math.floor(elapsed / 1000) * RATE_LIMIT_PER_SEC);
    _lastRefill = now;
  }
}

function _drainRateWaiters() {
  _grantTimer = null;
  _refillTokens();
  while (_tokens > 0 && _rateWaiters.length > 0) {
    _tokens--;
    const grant = _rateWaiters.shift();
    grant();
  }
  if (_rateWaiters.length > 0) _scheduleGrant();
}

function _scheduleGrant() {
  if (_grantTimer) return;
  const now = Date.now();
  // Next grant opportunity: end of the backoff pause, or the next refill boundary.
  const wakeAt = Math.max(_pauseUntil, _lastRefill + 1000);
  _grantTimer = setTimeout(_drainRateWaiters, Math.max(10, wakeAt - now));
}

function _acquireRateToken() {
  _refillTokens();
  // Fast path only when nobody is queued — a token freed by a refill belongs
  // to the FIFO head, not to whoever calls next.
  if (_tokens > 0 && _rateWaiters.length === 0) {
    _tokens--;
    return Promise.resolve();
  }
  return new Promise(resolve => {
    _rateWaiters.push(resolve);
    _scheduleGrant();
  });
}

/**
 * Wait for a rate token WITHOUT touching the concurrency semaphore. For retry
 * loops that already hold a slot (acquireRegistrySlot pays the token for the
 * FIRST attempt only): each subsequent network attempt must pay its own token,
 * otherwise retries bypass the bucket and keep hammering a 429ing server
 * (observed 2026-06-12: ~50 req/min reaching npm during a full backoff pause,
 * prolonging the IP penalty).
 */
function awaitRateToken() {
  return _acquireRateToken();
}

// --- 429 backoff helper ---
// Call this when a 429 response is received. Suspends ALL token grants for an
// escalating pause so every in-flight caller backs off together.

function signal429() {
  const now = Date.now();
  _backoffCount++;
  _tokens = 0;
  if (now < _pauseUntil) {
    // Remaining 429s from the same in-flight burst: the pause is already
    // armed, don't escalate once per response.
    _last429At = now;
    return;
  }
  // Quiet long enough since the last 429 → the incident is over, restart at base.
  const quietResetMs = _lastPauseMs * 2 + BACKOFF_BASE_MS * 5;
  if (_last429At && now - _last429At > quietResetMs) {
    _consecutive429 = 0;
  }
  _consecutive429++;
  const pause = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (_consecutive429 - 1));
  _lastPauseMs = pause;
  _last429At = now;
  _pauseUntil = now + pause;
  if (_backoffCount % 10 === 1 || pause >= BACKOFF_BASE_MS * 8) {
    console.warn(`[HTTP-LIMITER] 429 rate limited by npm registry (total: ${_backoffCount}, pause ${pause}ms, level ${_consecutive429})`);
  }
  // Re-aim the wake timer at the new pause end (no-op if none is pending).
  if (_rateWaiters.length > 0) _scheduleGrant();
}

function getBackoffCount() {
  return _backoffCount;
}

/** Observability seam (tests, debugging): never used for control flow. */
function getRateLimiterState() {
  return {
    tokens: _tokens,
    pendingWaiters: _rateWaiters.length,
    consecutive429: _consecutive429,
    pauseRemainingMs: Math.max(0, _pauseUntil - Date.now()),
    lastPauseMs: _lastPauseMs,
    backoffCount: _backoffCount
  };
}

function resetLimiter() {
  _semaphore.active = 0;
  _semaphore.queue.length = 0;
  _tokens = RATE_LIMIT_PER_SEC;
  _lastRefill = Date.now();
  _backoffCount = 0;
  _consecutive429 = 0;
  _pauseUntil = 0;
  _lastPauseMs = 0;
  _last429At = 0;
  if (_grantTimer) {
    clearTimeout(_grantTimer);
    _grantTimer = null;
  }
  // Release anything still queued so a reset between tests can never hang the suite.
  while (_rateWaiters.length > 0) {
    const grant = _rateWaiters.shift();
    grant();
  }
}

function getActiveSemaphore() {
  return _semaphore;
}

module.exports = {
  REGISTRY_SEMAPHORE_MAX,
  RATE_LIMIT_PER_SEC,
  acquireRegistrySlot,
  releaseRegistrySlot,
  awaitRateToken,
  signal429,
  getBackoffCount,
  getRateLimiterState,
  resetLimiter,
  getActiveSemaphore
};
