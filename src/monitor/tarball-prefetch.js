'use strict';

/**
 * Capture-at-publish tarball prefetch.
 *
 * PROBLEM (Miasma / Leo Platform, June 2026). Fast-takedown supply-chain
 * campaigns unpublish the malicious version within minutes-to-hours of
 * publishing it. The scan path downloads the tarball at DEQUEUE time
 * (queue.js `scanPackage` -> `downloadToFile`), which can sit hours behind
 * ingestion when the scan queue is backlogged. By then npm returns E404 for
 * the malicious version and the worker scans the surviving benign neighbour
 * instead. Measured on the Leo compromise: malicious `leo-sdk@6.0.19` ->
 * E404 (unpublished); we only ever saw `7.1.21` (clean, scored 4/100), and
 * the Phantom Gyp detector had no malicious `binding.gyp` to fire on.
 *
 * Pure throughput cannot fix this: even with zero backlog you would still
 * race npm's takedown at scan time. This is a CAPTURE problem, not a COMPUTE
 * problem.
 *
 * FIX. Capture the bytes the moment the publish event is ingested — ingestion
 * (reading the npm changes feed) runs ahead of the scan queue, so it wins the
 * race against the takedown. The bytes are stored in the SAME tarball cache
 * the scan path already prefers (the cache-hit branch in `scanPackage`), so a
 * successful prefetch is consumed transparently with NO scan-side change. If
 * anything fails, the scan falls back to its own download exactly as today
 * (zero scan loss).
 *
 * SCOPE & BOUNDS (CLAUDE.md "Bounded resources" / "Defensive by default").
 *   - Only the `cacheTrigger.shouldCache` subset (ioc_match / typosquat_signal
 *     / first_publish) is captured — NOT the ~108k publishes/day. This is the
 *     exact population fast-takedown campaigns fall into (a coordinated burst
 *     from one maintainer is `first_publish` for the new lines).
 *   - Bounded concurrency (MUADDIB_PREFETCH_CONCURRENCY, default 4) gated by
 *     the shared registry semaphore so it cannot thunder-herd the registry.
 *   - Bounded in-flight set (MUADDIB_PREFETCH_MAX_INFLIGHT, default 256); a
 *     burst past the cap is dropped (counted), degrading to scan-time download.
 *   - Per-tarball timeout + size cap inherited from `downloadToFile`.
 *   - Best-effort & non-blocking: `schedulePrefetch()` returns immediately and
 *     never throws; the downloads run in a background pool.
 *   - Kill switch: MUADDIB_PREFETCH=0 disables it entirely.
 *
 * The synchronous ingestion path stays I/O-free: eligibility + dedup are pure
 * in-memory checks, and the only filesystem touch (the "already cached" probe)
 * happens inside the bounded async task, not in the tight ingestion loop.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

// Capture-at-publish is ON by default. It is best-effort with graceful
// fallback (worst case == today's behaviour), so the safe default is "on".
// Set MUADDIB_PREFETCH=0 (or "false") to disable for a gated rollout.
const DEFAULT_ENABLED = true;

function isEnabled() {
  const v = process.env.MUADDIB_PREFETCH;
  if (v === undefined || v === '') return DEFAULT_ENABLED;
  return v !== '0' && v.toLowerCase() !== 'false';
}

// Read limits dynamically so they stay tunable (and testable) at runtime.
function getConcurrency() {
  return Math.max(1, parseInt(process.env.MUADDIB_PREFETCH_CONCURRENCY, 10) || 4);
}
function getMaxInflight() {
  const c = getConcurrency();
  return Math.max(c, parseInt(process.env.MUADDIB_PREFETCH_MAX_INFLIGHT, 10) || 256);
}

// --- bounded async pool state ---
const _pending = [];               // FIFO of queued capture tasks
const _inFlightKeys = new Set();   // dedup: cache keys currently pending or active
let _active = 0;                   // tasks currently downloading
let _idleResolvers = [];           // resolvers awaiting an idle pool (test seam)

// Lazily-resolved real dependencies. Lazy require avoids any load-time cycle
// (ingestion -> tarball-prefetch -> state) and keeps unit tests from pulling in
// the whole monitor: tests pass their own `deps`.
let _realDeps = null;
function realDeps() {
  if (_realDeps) return _realDeps;
  const dl = require('../shared/download.js');
  const state = require('./state.js');
  const limiter = require('../shared/http-limiter.js');
  _realDeps = {
    downloadToFile: dl.downloadToFile,
    cacheTarball: state.cacheTarball,
    tarballCacheKey: state.tarballCacheKey,
    tarballCachePath: state.tarballCachePath,
    acquireRegistrySlot: limiter.acquireRegistrySlot,
    releaseRegistrySlot: limiter.releaseRegistrySlot,
    tmpDir: os.tmpdir()
  };
  return _realDeps;
}

/**
 * An item is eligible iff ingestion flagged it for caching AND it has been
 * resolved enough to fetch and key. `_cacheTrigger` carries {reason,
 * retentionDays}; `tarballUrl` + `version` are filled by preResolve*Batch.
 */
function _eligible(item) {
  return !!(item
    && item._cacheTrigger
    && item._cacheTrigger.shouldCache
    && item.tarballUrl
    && item.version);
}

/**
 * Schedule a best-effort prefetch for every eligible item in `items`.
 * Non-blocking: returns synchronously with a small summary. Downloads run in
 * the bounded background pool.
 *
 * @param {Array<Object>} items - ingestion items (post tarballUrl resolution)
 * @param {Object} [opts]
 * @param {Object} [opts.stats]  - monitor stats object for counters
 * @param {Object} [opts.deps]   - dependency overrides (tests)
 * @returns {{scheduled:number, skipped:number}}
 */
function schedulePrefetch(items, opts = {}) {
  if (!isEnabled()) return { scheduled: 0, skipped: 0 };
  const d = opts.deps || realDeps();
  const stats = opts.stats || null;
  const maxInflight = getMaxInflight();

  let scheduled = 0;
  let skipped = 0;

  for (const item of items || []) {
    if (!_eligible(item)) { skipped++; continue; }

    const key = d.tarballCacheKey(item.name, item.version);
    if (_inFlightKeys.has(key)) { skipped++; continue; } // already pending/active this session

    if (_pending.length + _active >= maxInflight) {
      // Bound hit: drop (the scan-time download remains the fallback).
      if (stats) stats.prefetchDropped = (stats.prefetchDropped || 0) + 1;
      skipped++;
      continue;
    }

    _inFlightKeys.add(key);
    _pending.push({
      name: item.name,
      version: item.version,
      tarballUrl: item.tarballUrl,
      reason: item._cacheTrigger.reason,
      retentionDays: item._cacheTrigger.retentionDays,
      key,
      deps: d,
      stats
    });
    scheduled++;
  }

  _pump();
  return { scheduled, skipped };
}

function _pump() {
  const concurrency = getConcurrency();
  while (_active < concurrency && _pending.length > 0) {
    const task = _pending.shift();
    _active++;
    _runTask(task).catch(() => { /* _runTask never rejects; defensive */ }).then(() => {
      _active--;
      _inFlightKeys.delete(task.key);
      _pump();
      _settleIdle();
    });
  }
  // No work in flight at all -> notify any idle waiters.
  if (_active === 0 && _pending.length === 0) _settleIdle();
}

async function _runTask(task) {
  const { name, version, tarballUrl, reason, retentionDays, key, deps: d, stats } = task;

  // "Already cached" probe lives here (off the synchronous ingestion path).
  try {
    if (fs.existsSync(d.tarballCachePath(key))) {
      if (stats) stats.prefetchAlreadyCached = (stats.prefetchAlreadyCached || 0) + 1;
      return;
    }
  } catch { /* probe failure is non-fatal — proceed to download */ }

  const tmp = path.join(d.tmpDir, `muaddib-prefetch-${key}-${process.pid}.tgz`);
  await d.acquireRegistrySlot();
  try {
    await d.downloadToFile(tarballUrl, tmp);
    d.cacheTarball(name, version, tmp, reason, retentionDays);
    if (stats) stats.prefetchCaptured = (stats.prefetchCaptured || 0) + 1;
  } catch (err) {
    // Best-effort: a miss here just means the scan path downloads later (or the
    // version is already gone, which is the case this whole module mitigates).
    if (stats) stats.prefetchFailed = (stats.prefetchFailed || 0) + 1;
    console.warn(`[MONITOR] PREFETCH miss for ${name}@${version}: ${err.message}`);
  } finally {
    d.releaseRegistrySlot();
    try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch { /* tmp cleanup best-effort */ }
  }
}

function _settleIdle() {
  if (_active === 0 && _pending.length === 0 && _idleResolvers.length > 0) {
    const resolvers = _idleResolvers;
    _idleResolvers = [];
    for (const r of resolvers) r();
  }
}

/** Observability: current pool occupancy. */
function getStats() {
  return { pending: _pending.length, active: _active, inFlight: _inFlightKeys.size };
}

/** Test seam: resolve once the pool is idle. */
function _drain() {
  if (_active === 0 && _pending.length === 0) return Promise.resolve();
  return new Promise(resolve => { _idleResolvers.push(resolve); });
}

/** Test seam: clear pool state between tests. */
function _reset() {
  _pending.length = 0;
  _inFlightKeys.clear();
  _active = 0;
  _idleResolvers = [];
  _realDeps = null;
}

module.exports = {
  schedulePrefetch,
  isEnabled,
  getStats,
  // test seams
  _drain,
  _reset,
  _eligible
};
