/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

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
  return !!(item && (item.isIOCMatch || item.isBurst || item.firstPublish || item.atoSignal || item.isATOBurstExtra || item.interrupted));
}

// IOC-aware anti-spill (2026-07, @longzy DPRK campaign post-mortem): a queued package whose
// NAME is already in the IOC database is known-malicious, and confirming it is a cheap name
// lookup — so it must never be shed under memory pressure, even when its enqueue-time
// `isIOCMatch` flag is stale (the IOC DB refreshed while the item sat in the backlog) or was
// version-gated. Name-level: a wildcard (all-versions-malicious) OR any specific-version entry
// counts. Best-effort — a missing/malformed index yields false (the exact prior behavior).
function _isIOCKnownByName(item, iocIndex) {
  if (!item || !item.name || !iocIndex) return false;
  const wild = iocIndex.wildcardPackages;
  const pkgs = iocIndex.packagesMap;
  return !!((wild && typeof wild.has === 'function' && wild.has(item.name)) ||
            (pkgs && typeof pkgs.has === 'function' && pkgs.has(item.name)));
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
    // Spill-to-disk waiting list (MUADDIB_QUEUE_SPILL=1): the evicted item goes to
    // data/scan-backlog.jsonl for re-ingestion during calm periods instead of being
    // lost. Lazy require (same pattern as state.js below) — spill.js requires this
    // module for isProtected, so a top-level import would be a cycle. On spill
    // failure (or flag off) the behavior degrades to the pre-spill drop, ledgered.
    let spilled = false;
    try {
      const spillMod = require('./spill.js');
      if (spillMod.isSpillEnabled() && evicted && evicted.name) {
        spilled = spillMod.spillItems([evicted]) === 1;
        if (spilled && stats) stats.spilled = (stats.spilled || 0) + 1;
      }
    } catch { /* spill is best-effort — fall through to the drop ledger */ }
    // Phase 0a: record the dropped item so a coverage loss keeps an identity — answers
    // "which versions were never scanned" (e.g. the Miasma 72s/96-version burst). Lazy
    // require avoids any top-level coupling with state.js; best-effort, never throws.
    // A dropped PROTECTED item (all-protected head-window) gets a distinct source so the
    // rare case stays visible in the 0b ledger rollup.
    try {
      if (evicted && evicted.name) {
        require('./state.js').appendScanLedger({
          name: evicted.name, version: evicted.version, ecosystem: evicted.ecosystem,
          outcome: spilled ? 'spilled' : 'dropped',
          source: (protectedFallback ? 'queue_cap_protected' : 'queue_cap') + (spilled ? '_spill' : ''),
          // AUDIT-A1 observability (see evictFromScanQueueBulk)
          firstPublish: !!evicted.firstPublish, isBurstExtra: !!evicted.isATOBurstExtra
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

/**
 * Bulk-evict the scan queue down to `targetKeep`, honoring the SAME protection predicate
 * as enqueueScan and ledgering EVERY dropped item — the single-source-of-truth eviction
 * the daemon's EMERGENCY memory breaker must use instead of a raw `splice(0, n)`.
 *
 * Selection: drop the oldest UNPROTECTED items first; only dip into protected items
 * (oldest-first) if there aren't enough unprotected ones to reach the target. This keeps
 * IOC-match / burst / first-publish / ATO scans alive through a memory emergency, exactly
 * like the per-item cap path — closing the gap where the v2.10.88 circuit breaker silently
 * dropped protected scans (CLAUDE.md "ne jamais perdre de scan" / "no silent caps").
 *
 * In-place compaction (write-pointer, O(n), preserves insertion order, no giant spread) so
 * the daemon (which holds the same array reference) sees the mutation. Best-effort ledger;
 * never throws. `ledgerFn` is injectable for tests; defaults to state.appendScanLedger.
 *
 * `opts.iocIndex` (optional {packagesMap, wildcardPackages}) additionally protects any queued
 * NAME already in the IOC DB from being shed — a known-malicious package must never be lost to
 * memory pressure (IOC-aware anti-spill). Injected by the daemon (the live 10s-singleton), not
 * auto-loaded here, so callers that omit it keep the exact prior behavior.
 *
 * @returns {{dropped:number, droppedProtected:number}}
 */
function evictFromScanQueueBulk(scanQueue, targetKeep, source = 'bulk_evict', ledgerFn = null, opts = {}) {
  const before = scanQueue.length;
  const keep = Math.max(0, targetKeep | 0);
  if (before <= keep) return { dropped: 0, droppedProtected: 0 };
  const toDrop = before - keep;

  // IOC-aware anti-spill: on top of the standard _isProtected classes, protect any queued
  // NAME already in the IOC DB. The index is INJECTED (daemon passes the live 10s-singleton;
  // tests pass a fabricated one) — no auto-load here, so callers that omit it keep the exact
  // prior behavior (and unit paths don't drag in the 237MB DB).
  const iocIndex = opts.iocIndex || null;
  const isKept = iocIndex
    ? (item) => _isProtected(item) || _isIOCKnownByName(item, iocIndex)
    : _isProtected;

  // Victim set: oldest unkept first, then (only if short) oldest kept item.
  const dropSet = new Set();
  for (let i = 0; i < before && dropSet.size < toDrop; i++) {
    if (!isKept(scanQueue[i])) dropSet.add(i);
  }
  let droppedProtected = 0;
  if (dropSet.size < toDrop) {
    // Not enough unprotected items: every unprotected one is already marked, so the
    // remaining oldest-first items are protected — drop them as a last resort.
    for (let i = 0; i < before && dropSet.size < toDrop; i++) {
      if (!dropSet.has(i)) { dropSet.add(i); droppedProtected++; }
    }
  }

  // Resolve the ledger sink once (per-call require would be 500+ lookups under emergency).
  let appendLedger = ledgerFn;
  if (!appendLedger) {
    try { appendLedger = require('./state.js').appendScanLedger; } catch { appendLedger = null; }
  }

  // Compact survivors in place, collecting the evicted items for the spill below.
  const evictedItems = [];
  let w = 0;
  for (let r = 0; r < before; r++) {
    if (dropSet.has(r)) evictedItems.push(scanQueue[r]);
    else scanQueue[w++] = scanQueue[r];
  }
  scanQueue.length = w;

  // Spill-to-disk waiting list (MUADDIB_QUEUE_SPILL=1): ONE batched append for the
  // whole eviction (an EMERGENCY evicts thousands — per-item appends would thrash).
  // spillItems is all-or-nothing per call (single buffered write), so `spilled`
  // cleanly selects the ledger outcome for the batch. Lazy require: spill.js
  // imports isProtected from this module — a top-level import would be a cycle.
  // On spill failure (or flag off) the behavior degrades to the pre-spill drop.
  let spilled = false;
  try {
    const spillMod = require('./spill.js');
    if (spillMod.isSpillEnabled() && evictedItems.length > 0) {
      spilled = spillMod.spillItems(evictedItems) > 0;
    }
  } catch { /* spill is best-effort */ }

  // Ledger each evicted item with an identity-preserving source (protected drops get
  // a distinct suffix so the rare case stays visible in the rollup).
  for (const item of evictedItems) {
    if (!appendLedger || !item || !item.name) continue;
    try {
      appendLedger({
        name: item.name, version: item.version, ecosystem: item.ecosystem,
        outcome: spilled ? 'spilled' : 'dropped',
        source: (isKept(item) ? `${source}_protected` : source) + (spilled ? '_spill' : ''),
        // AUDIT-A1 observability: record whether a DROPPED item was a first-publish
        // (real coverage loss) vs a burst-extra (version-spam, expected). Lets us
        // measure if the memory breaker is evicting genuine new packages.
        firstPublish: !!item.firstPublish,
        isBurstExtra: !!item.isATOBurstExtra
      });
    } catch { /* ledger is best-effort — must never break the breaker */ }
  }

  return { dropped: toDrop, droppedProtected, spilled: spilled ? evictedItems.length : 0 };
}

// ── AUDIT A2: optional priority dequeue (gated OFF by default) ──────────────
// Default dequeue is strict FIFO (scanQueue.shift()). When enabled, the worker pulls
// the OLDEST high-value item (first-publish / known-malicious / burst-MAIN) within a
// bounded head-window before falling back to FIFO — so a genuine new package never
// ages out behind a deep version-spam backlog. Gated behind an env flag so deploying
// the code is INERT until ops flips it on (tune on the AUDIT-A1 first-publish-coverage
// data first — see brief). Burst EXTRAS (isATOBurstExtra) and regular items stay FIFO.
const PRIORITY_DEQUEUE = (() => {
  const v = process.env.MUADDIB_PRIORITY_DEQUEUE;
  return v === '1' || v === 'true';
})();
const PRIORITY_DEQUEUE_WINDOW = (() => {
  const v = parseInt(process.env.MUADDIB_PRIORITY_DEQUEUE_WINDOW, 10);
  return Number.isFinite(v) && v > 0 ? v : 2048;
})();

// ── Fresh-first scheduling (throughput plan Phase 2; gated OFF by default) ───
// When MUADDIB_FRESH_FIRST=1 AND a real backlog exists (queue > split threshold),
// most worker lanes dequeue the NEWEST item (tail) so a freshly-published package
// is scanned in minutes instead of aging ~hours behind a FIFO backlog, while a
// reserved `drainLanes` keep draining the OLDEST (anti-starvation). Below the
// threshold all lanes stay strict FIFO ("back to the normal flow" once drained).
// Pure ordering change — every item is still scanned; inert until the flag is on.
const FRESH_FIRST = (() => {
  const v = process.env.MUADDIB_FRESH_FIRST;
  return v === '1' || v === 'true';
})();
const BACKLOG_DRAIN_LANES = (() => {
  const v = parseInt(process.env.MUADDIB_BACKLOG_DRAIN_LANES, 10);
  return Number.isFinite(v) && v > 0 ? v : 2;
})();
const BACKLOG_SPLIT_THRESHOLD = (() => {
  const v = parseInt(process.env.MUADDIB_BACKLOG_SPLIT_THRESHOLD, 10);
  return Number.isFinite(v) && v > 0 ? v : 5000;
})();

function _isPriority(item) {
  return !!(item && (item.firstPublish || item.isIOCMatch || (item.isBurst && !item.isATOBurstExtra)));
}

/**
 * Remove and return the next item to scan. Strict FIFO by default (unchanged). With
 * MUADDIB_PRIORITY_DEQUEUE=1: oldest priority item within a bounded head-window, else
 * FIFO. Single-threaded → splice/shift are atomic w.r.t. other workers.
 * @param {Array} scanQueue
 * @param {{priority?: boolean, window?: number}} [opts] test overrides
 */
function dequeueScan(scanQueue, opts = {}) {
  if (scanQueue.length === 0) return scanQueue.shift();
  // Fresh-first lanes take the NEWEST item (tail). Takes precedence over priority:
  // the freshest publish is the one we most want to be first on.
  if (opts.newest) return scanQueue.pop();
  const priority = opts.priority !== undefined ? opts.priority : PRIORITY_DEQUEUE;
  if (!priority) return scanQueue.shift();
  const win = Math.min(scanQueue.length, opts.window || PRIORITY_DEQUEUE_WINDOW);
  for (let i = 0; i < win; i++) {
    if (_isPriority(scanQueue[i])) return i === 0 ? scanQueue.shift() : scanQueue.splice(i, 1)[0];
  }
  return scanQueue.shift();
}

/**
 * Fresh-first dequeue decision (Phase 2, gated by MUADDIB_FRESH_FIRST). True → this
 * dequeue should take the NEWEST item (tail); false → oldest (FIFO/priority head).
 * Splits only above BACKLOG_SPLIT_THRESHOLD; below it everything stays FIFO. Of
 * `target` concurrent lanes, `drainLanes` keep pulling oldest (anti-starvation), the
 * rest go fresh. `seq` is a shared monotonic dequeue counter (single-threaded →
 * consistent). Pure; `opts` override the env gates for tests.
 */
function shouldPullNewest(seq, queueLen, target, opts = {}) {
  const enabled = opts.enabled !== undefined ? opts.enabled : FRESH_FIRST;
  if (!enabled) return false;
  const threshold = opts.threshold !== undefined ? opts.threshold : BACKLOG_SPLIT_THRESHOLD;
  if (queueLen <= threshold) return false;
  const drainLanes = opts.drainLanes !== undefined ? opts.drainLanes : BACKLOG_DRAIN_LANES;
  const lanes = Math.max(2, target || 2);
  const drain = Math.min(drainLanes, lanes - 1);   // always leave ≥1 fresh lane
  return (seq % lanes) >= drain;                    // first `drain` slots → oldest; rest → newest
}

module.exports = { enqueueScan, evictFromScanQueueBulk, dequeueScan, shouldPullNewest, isProtected: _isProtected, MAX_SCAN_QUEUE };
