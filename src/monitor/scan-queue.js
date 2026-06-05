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

/**
 * Push an item onto the scan queue, enforcing the hard cap by dropping the oldest item
 * when at capacity. `max` defaults to MAX_SCAN_QUEUE (overridable for tests). Returns
 * true iff an item was dropped to make room.
 */
function enqueueScan(scanQueue, item, stats, max = MAX_SCAN_QUEUE) {
  let dropped = false;
  if (scanQueue.length >= max) {
    scanQueue.shift(); // drop oldest
    dropped = true;
    if (stats) stats.queueHardDrops = (stats.queueHardDrops || 0) + 1;
    const now = Date.now();
    if (now - _lastHardDropLog > HARD_DROP_LOG_INTERVAL_MS) {
      _lastHardDropLog = now;
      console.warn(`[MONITOR] QUEUE_HARD_DROP: scan queue at cap ${max} — dropping oldest item(s) (total dropped this session: ${stats ? stats.queueHardDrops : '?'}). Ingestion is outrunning scanning.`);
    }
  }
  scanQueue.push(item);
  return dropped;
}

module.exports = { enqueueScan, MAX_SCAN_QUEUE };
