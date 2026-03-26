'use strict';

/**
 * Centralized HTTP concurrency limiter for npm registry requests.
 *
 * With 16 monitor workers × 7+ HTTP requests/package, uncapped concurrency
 * reaches 112+ simultaneous requests — well above npm's implicit rate limit.
 * This module caps ALL registry.npmjs.org requests to a single semaphore
 * so that no more than REGISTRY_SEMAPHORE_MAX requests are in-flight at once.
 *
 * Consumers: temporal-analysis.js, temporal-ast-diff.js, monitor.js (getNpmLatestTarball),
 *            npm-registry.js (fetchWithRetry to registry.npmjs.org).
 * NOT covered: api.npmjs.org (different server), replicate.npmjs.com (CouchDB changes stream).
 */

const REGISTRY_SEMAPHORE_MAX = 10;

const _semaphore = { active: 0, queue: [] };

function acquireRegistrySlot() {
  if (_semaphore.active < REGISTRY_SEMAPHORE_MAX) {
    _semaphore.active++;
    return Promise.resolve();
  }
  return new Promise(resolve => {
    _semaphore.queue.push(resolve);
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

function resetLimiter() {
  _semaphore.active = 0;
  _semaphore.queue.length = 0;
}

function getActiveSemaphore() {
  return _semaphore;
}

module.exports = {
  REGISTRY_SEMAPHORE_MAX,
  acquireRegistrySlot,
  releaseRegistrySlot,
  resetLimiter,
  getActiveSemaphore
};
