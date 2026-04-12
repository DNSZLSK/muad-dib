'use strict';

/**
 * Centralized HTTP concurrency + rate limiter for npm registry requests.
 *
 * Two layers of protection:
 *   1. Concurrency semaphore (REGISTRY_SEMAPHORE_MAX = 10) — caps in-flight requests
 *   2. Rate limiter (RATE_LIMIT_PER_SEC = 30) — caps requests/second via token bucket
 *
 * Without rate limiting, 10 concurrent slots × fast-completing requests = 100+ req/s
 * bursts that trigger npm 429 responses → exponential backoff → scan times 10s→90s.
 *
 * Consumers: queue.js (downloadToFile), temporal-analysis.js, npm-registry.js.
 * NOT covered: api.npmjs.org (different server), replicate.npmjs.com (CouchDB changes stream).
 */

const REGISTRY_SEMAPHORE_MAX = 20;
const RATE_LIMIT_PER_SEC = 30;

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
// If no tokens available, waits until the next refill.

let _tokens = RATE_LIMIT_PER_SEC;
let _lastRefill = Date.now();

function _refillTokens() {
  const now = Date.now();
  const elapsed = now - _lastRefill;
  if (elapsed >= 1000) {
    _tokens = Math.min(RATE_LIMIT_PER_SEC, _tokens + Math.floor(elapsed / 1000) * RATE_LIMIT_PER_SEC);
    _lastRefill = now;
  }
}

function _acquireRateToken() {
  _refillTokens();
  if (_tokens > 0) {
    _tokens--;
    return Promise.resolve();
  }
  // Wait until next refill
  const waitMs = 1000 - (Date.now() - _lastRefill);
  return new Promise(resolve => {
    setTimeout(() => {
      _refillTokens();
      _tokens = Math.max(0, _tokens - 1);
      resolve();
    }, Math.max(10, waitMs));
  });
}

// --- 429 backoff helper ---
// Call this when a 429 response is received. Drains all tokens to force
// a ~1s pause on subsequent requests (token bucket naturally refills).

let _backoffCount = 0;

function signal429() {
  _tokens = 0;
  _lastRefill = Date.now() + 1000; // Force 1s pause
  _backoffCount++;
  if (_backoffCount % 10 === 1) {
    console.warn(`[HTTP-LIMITER] 429 rate limited by npm registry (total: ${_backoffCount})`);
  }
}

function getBackoffCount() {
  return _backoffCount;
}

function resetLimiter() {
  _semaphore.active = 0;
  _semaphore.queue.length = 0;
  _tokens = RATE_LIMIT_PER_SEC;
  _lastRefill = Date.now();
  _backoffCount = 0;
}

function getActiveSemaphore() {
  return _semaphore;
}

module.exports = {
  REGISTRY_SEMAPHORE_MAX,
  RATE_LIMIT_PER_SEC,
  acquireRegistrySlot,
  releaseRegistrySlot,
  signal429,
  getBackoffCount,
  resetLimiter,
  getActiveSemaphore
};
