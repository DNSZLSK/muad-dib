/**
 * Shared bounded enqueue for the scan queue.
 *
 * CLAUDE.md §2 (bounded resources): every in-memory structure needs an explicit max.
 * The scan queue had none — ingestion pushed straight into a plain array, so a
 * backpressure gap or the burst-publish path could grow it without bound. enqueueScan
 * caps it at MAX_SCAN_QUEUE and drops the OLDEST item when full (newest packages are the
 * most likely to still exist on the registry for a later re-scan — the same policy as
 * the EMERGENCY queue truncation in daemon.js). Drops are counted (stats.queueHardDrops)
 * and logged (rate-limited) so a coverage loss can't hide — CLAUDE.md "no silent caps".
 *
 * Lives in its own module so both ingestion.js and queue.js can import it without a
 * circular require (queue.js already requires ingestion.js).
 */

// Hard ceiling on live queue growth. Sits above the 30K soft-backpressure threshold
// (ingestion.js pauses polling at 30K), so it only fires if backpressure is bypassed
// (e.g. the burst path) or breaks. Env-tunable for ops.
const MAX_SCAN_QUEUE = (() => {
  const v = parseInt(process.env.MUADDIB_MAX_SCAN_QUEUE, 10);
  return Number.isFinite(v) && v > 0 ? v : 50_000;
})();

const HARD_DROP_LOG_INTERVAL_MS = 10_000;
let _lastHardDropLog = 0;

// Phase 2b: classes we never want to drop blindly when the queue caps out — the
// specifically-targeted scans (known-malicious, burst/ATO, first-publish). Eviction drops
// the oldest UNPROTECTED item instead; only if a bounded head-window is entirely protected
// do we fall back to strict-oldest (still ledgered, with a distinct source).
function _isProtected(item) {
  return !!(item && (item.isIOCMatch || item.isBurst || item.firstPublish || item.atoSignal || item.isATOBurstExtra));
}

// How far from the head we scan for an unprotected victim. Protected items are a small
// fraction of the flood, so a victim is almost always found within a few slots; the bound
// keeps eviction O(window) under sustained overflow (CLAUDE.md §2 bounded resources).
const PROTECTED_EVICTION_SCAN_MAX = (() => {
  const v = parseInt(process.env.MUADDIB_PROTECTED_EVICTION_SCAN_MAX, 10);
  return Number.isFinite(v) && v > 0 ? v : 1024;
})();

/**
 * Push an item onto the scan queue, enforcing the hard cap when at capacity. Evicts the
 * oldest UNPROTECTED item (within a bounded head-window), falling back to strict-oldest if
 * that window is all-protected. `max` defaults to MAX_SCAN_QUEUE (overridable for tests).
 * Returns true iff an item was dropped to make room.
 */
function enqueueScan(scanQueue, item, stats, max = MAX_SCAN_QUEUE) {
  let dropped = false;
  if (scanQueue.length >= max) {
    // Victim = oldest unprotected item within the bounded head-window; else strict oldest.
    let victimIdx = -1;
    const scanLimit = Math.min(scanQueue.length, PROTECTED_EVICTION_SCAN_MAX);
    for (let i = 0; i < scanLimit; i++) {
      if (!_isProtected(scanQueue[i])) { victimIdx = i; break; }
    }
    const protectedFallback = victimIdx === -1;
    const evicted = protectedFallback ? scanQueue.shift() : scanQueue.splice(victimIdx, 1)[0];
    dropped = true;
    if (stats) stats.queueHardDrops = (stats.queueHardDrops || 0) + 1;
    // Phase 0a: record the dropped item so a coverage loss keeps an identity — answers
    // "which versions were never scanned" (e.g. the Miasma 72s/96-version burst). Lazy
    // require avoids any top-level coupling with state.js; best-effort, never throws.
    // A dropped PROTECTED item (all-protected head-window) gets a distinct source so the
    // rare case stays visible in the 0b ledger rollup.
    try {
      if (evicted && evicted.name) {
        require('./state.js').appendScanLedger({
          name: evicted.name, version: evicted.version, ecosystem: evicted.ecosystem,
          outcome: 'dropped', source: protectedFallback ? 'queue_cap_protected' : 'queue_cap'
        });
      }
    } catch { /* ledger is best-effort */ }
    const now = Date.now();
    if (now - _lastHardDropLog > HARD_DROP_LOG_INTERVAL_MS) {
      _lastHardDropLog = now;
      console.warn(`[MONITOR] QUEUE_HARD_DROP: scan queue at cap ${max} — dropping ${protectedFallback ? 'OLDEST (head-window all protected)' : 'oldest unprotected'} item(s) (total dropped this session: ${stats ? stats.queueHardDrops : '?'}). Ingestion is outrunning scanning.`);
    }
  }
  scanQueue.push(item);
  return dropped;
}

module.exports = { enqueueScan, MAX_SCAN_QUEUE };
