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

'use strict';

/**
 * spill.js — disk-backed waiting list for the scan queue.
 *
 * Today an EMERGENCY memory purge (and the queue hard-cap) DROPS evicted scans:
 * ledgered, but lost (91K mem_emergency drops / 64K distinct never-scanned
 * versions in the 2026-06-11 24h window). The queue entries are tiny metadata —
 * dropping them frees almost nothing; the memory relief comes from the
 * container/worker kills the breaker also performs. This module converts those
 * drops into DEFERRALS: evicted items append to a bounded JSONL backlog and are
 * re-ingested progressively during calm periods (12h/24 have zero drops — the
 * baseline flow is fully absorbed; losses are burst-shaped).
 *
 * Defensive priority (mirrors scan-queue.js `isProtected`): malicious packages
 * are often unpublished quickly — draining late can mean the tarball is gone.
 *   - drain: protected items first (IOC match / burst / first-publish / ATO),
 *     then FIFO. No LIFO: under repeated spikes the oldest would never drain —
 *     a disguised loss.
 *   - cap compaction: evict oldest UNPROTECTED first, protected as last resort
 *     (the evictFromScanQueueBulk contract), every eviction ledgered. We lose
 *     noise before we lose signal.
 *
 * Bounds & resilience (CLAUDE.md production rules):
 *   - MUADDIB_SPILL_MAX entries (default 200 000 ≈ 30 MB ≈ ~2 days of worst-case
 *     spikes). The cap should never be reached if the drain converges — if it
 *     is, evictions are ledgered (`spill_cap`), never silent.
 *   - All writes are append-one-line or tmp+rename rewrites; a crash mid-drain
 *     at worst re-drains the same items, deduplicated by the caller.
 *   - Every function is never-throw: a spill failure must degrade to the old
 *     behavior (drop, ledgered), not break the breaker.
 *
 * Env (read at call time): MUADDIB_QUEUE_SPILL=1 (master switch, default OFF),
 * MUADDIB_SPILL_FILE (override, tests), MUADDIB_SPILL_MAX.
 */

const fs = require('fs');
const path = require('path');

const { isProtected } = require('./scan-queue.js');

const DEFAULT_SPILL_FILE = path.join(__dirname, '..', '..', 'data', 'scan-backlog.jsonl');
const DEFAULT_MAX_ENTRIES = 200_000;

// Fields persisted per item — everything re-enqueue + protection need, nothing
// else (bounded line size ≈ 150-250 bytes).
const SPILL_FIELDS = [
  'name', 'version', 'ecosystem', 'tarballUrl',
  'firstPublish', 'isIOCMatch', 'isBurst', 'atoSignal', 'isATOBurstExtra',
  // Phase C: without persisting the retry counter, every re-spill restarted
  // at 0 — an attacker whose package triggers an EMERGENCY on every scan
  // would loop forever (amplification). 'interrupted' marks the item
  // protected (drain re-ingests protected-first).
  'interrupted', 'interruptRetries'
];

function isSpillEnabled() {
  return globalThis.process.env.MUADDIB_QUEUE_SPILL === '1';
}

function _spillFile() {
  return globalThis.process.env.MUADDIB_SPILL_FILE || DEFAULT_SPILL_FILE;
}

function _maxEntries() {
  const raw = globalThis.process.env.MUADDIB_SPILL_MAX;
  const n = raw ? parseInt(raw, 10) : NaN;
  return (Number.isFinite(n) && n >= 10 && n <= 5_000_000) ? n : DEFAULT_MAX_ENTRIES;
}

function _readEntries(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const out = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line);
      if (e && e.name) out.push(e);
    } catch { /* truncated/corrupt line (crash mid-write) — skip */ }
  }
  return out;
}

function _writeEntries(file, entries) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, entries.length ? entries.map(e => JSON.stringify(e)).join('\n') + '\n' : '', 'utf8');
  fs.renameSync(tmp, file);
}

// Conservative upper bound on a spilled line's byte size (the SPILL_FIELDS
// record + ts + newline run ~150-250 bytes). Used for the O(1) stat-gated
// compaction trigger below — overestimating only makes compaction fire a bit
// late, never early, so the file ceiling stays ~MUADDIB_SPILL_MAX.
const SPILL_LINE_BYTES_EST = 256;

/**
 * Append evicted queue items to the backlog. Never throws; on write failure the
 * caller's fallback is the pre-spill behavior (drop, ledgered).
 *
 * HOT PATH — runs INSIDE the EMERGENCY memory handler (evictFromScanQueueBulk),
 * so it MUST be append-only and allocation-free beyond the write buffer. The
 * 2026-06-11 freeze was caused by calling _compactBacklog (which reads + parses
 * the WHOLE backlog) on every spill: a large allocation during a reclaim stall
 * that wedged the handler before it could free RSS. Compaction now fires ONLY
 * when a cheap statSync shows the file is genuinely near the cap (normally
 * never during an EMERGENCY — the backlog is far below the byte budget there),
 * and the calm-time drain also keeps it bounded.
 * @param {Array<object>} items evicted scan-queue items
 * @returns {number} how many items were actually persisted
 */
function spillItems(items) {
  if (!Array.isArray(items) || items.length === 0) return 0;
  const file = _spillFile();
  let written = 0;
  try {
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    let buf = '';
    for (const item of items) {
      if (!item || !item.name) continue;
      const rec = { ts: new Date().toISOString() };
      for (const f of SPILL_FIELDS) {
        if (item[f] !== undefined && item[f] !== null && item[f] !== false) rec[f] = item[f];
      }
      buf += JSON.stringify(rec) + '\n';
      written++;
    }
    if (buf) fs.appendFileSync(file, buf, 'utf8');
    // O(1) stat-gated compaction: only read+rewrite the file when it is actually
    // near the cap. NO whole-file read on the normal EMERGENCY spill path.
    let size = 0;
    try { size = fs.statSync(file).size; } catch { /* fresh file */ }
    if (size > _maxEntries() * SPILL_LINE_BYTES_EST) _compactBacklog(file);
  } catch {
    return 0; // degrade to drop-with-ledger at the call site
  }
  return written;
}

/**
 * Cap enforcement: evict down to MUADDIB_SPILL_MAX — oldest UNPROTECTED first,
 * protected last resort. Every eviction is ledgered (`spill_cap` /
 * `spill_cap_protected`): a backlog overflow is a real loss and must be visible.
 */
function _compactBacklog(file, ledgerFn = null) {
  try {
    const max = _maxEntries();
    const entries = _readEntries(file);
    if (entries.length <= max) return;
    const toDrop = entries.length - max;
    const dropSet = new Set();
    for (let i = 0; i < entries.length && dropSet.size < toDrop; i++) {
      if (!isProtected(entries[i])) dropSet.add(i);
    }
    for (let i = 0; i < entries.length && dropSet.size < toDrop; i++) {
      if (!dropSet.has(i)) dropSet.add(i); // protected, last resort
    }
    let appendLedger = ledgerFn;
    if (!appendLedger) {
      try { appendLedger = require('./state.js').appendScanLedger; } catch { appendLedger = null; }
    }
    const kept = [];
    for (let i = 0; i < entries.length; i++) {
      if (!dropSet.has(i)) { kept.push(entries[i]); continue; }
      const e = entries[i];
      if (appendLedger) {
        try {
          appendLedger({
            name: e.name, version: e.version, ecosystem: e.ecosystem,
            outcome: 'dropped',
            source: isProtected(e) ? 'spill_cap_protected' : 'spill_cap',
            firstPublish: !!e.firstPublish, isBurstExtra: !!e.isATOBurstExtra
          });
        } catch { /* best-effort */ }
      }
    }
    _writeEntries(file, kept);
    console.warn(`[MONITOR] SPILL_CAP: backlog over ${max} — evicted ${toDrop} oldest (ledgered). The drain is not keeping up.`);
  } catch { /* never throw */ }
}

/**
 * Pure drain predicate (exported for tests + the daemon main loop): drain only
 * when memory pressure is fully cleared AND the live queue is below the drain
 * ceiling. `threshold` is a MARGE ceiling (a margin below the ingestion
 * backpressure point — see daemon.js SPILL_DRAIN_THRESHOLD), NOT a "queue nearly
 * empty" low-water mark: the latter (the old 500/5000) was unreachable in steady
 * state, so the backlog never drained. With the marge ceiling the drain is a
 * self-throttling trickle — it auto-stops the moment pressure rises (≥ ELEVATED)
 * or the queue climbs toward backpressure, so it never starves fresh ingestion.
 */
function shouldDrain(pressureLevel, queueLen, threshold) {
  return pressureLevel === 0 && queueLen < threshold;
}

/**
 * Re-ingest up to maxItems from the backlog into the live scan queue.
 * Protected entries drain first (oldest-first within each class), then FIFO.
 * Remaining entries are rewritten atomically (tmp+rename). Crash-resilient: a
 * kill between enqueue and rewrite re-drains the same items on the next tick —
 * the caller's isDuplicate (recentlyScanned + in-queue keys) absorbs replays.
 *
 * @param {Array} scanQueue   live queue (enqueued via injected enqueueFn)
 * @param {object|null} stats monitor stats (spillDrained / spillDeduped counters)
 * @param {object} opts
 * @param {number}   opts.maxItems    batch bound (required > 0)
 * @param {Function} opts.enqueueFn   (scanQueue, item, stats) => void — scan-queue.enqueueScan
 * @param {Function} [opts.isDuplicate] (key "name@version") => boolean
 * @returns {{drained:number, deduped:number, remaining:number}}
 */
// ─── SYNCHRONICITY INVARIANT (F-C5, do not break) ───
// drainBacklog does a read→rewrite (tmp+rename) of the backlog file while
// spillItems does append-one-line writes. An append landing BETWEEN the read
// and the rename would be silently LOST. This is safe today ONLY because both
// run synchronously on the main thread's event loop AND their triggers exclude
// each other in time (drain requires pressure NONE; the bulk spill paths run
// at EMERGENCY / shutdown). If drainBacklog ever becomes async, or spillItems
// ever becomes buffered/async, add real file locking first.
function drainBacklog(scanQueue, stats, opts = {}) {
  const res = { drained: 0, deduped: 0, remaining: 0 };
  try {
    const file = _spillFile();
    const maxItems = opts.maxItems | 0;
    if (maxItems <= 0 || typeof opts.enqueueFn !== 'function') return res;
    let st;
    try { st = fs.statSync(file); } catch { return res; } // no backlog — cheap exit
    if (!st.size) return res;

    const entries = _readEntries(file);
    if (entries.length === 0) { res.remaining = 0; return res; }

    // Selection AND enqueue order: protected first (oldest-first within the
    // class), then FIFO — bounded by maxItems. Order matters: the live queue
    // is consumed FIFO, so protected items must be enqueued ahead of plain
    // ones, not merely included in the batch.
    const takeIdx = new Set();
    const takeOrder = [];
    for (let i = 0; i < entries.length && takeOrder.length < maxItems; i++) {
      if (isProtected(entries[i])) { takeIdx.add(i); takeOrder.push(i); }
    }
    for (let i = 0; i < entries.length && takeOrder.length < maxItems; i++) {
      if (!takeIdx.has(i)) { takeIdx.add(i); takeOrder.push(i); }
    }

    for (const i of takeOrder) {
      const e = entries[i];
      // The caller owns the dedupe-key format (the monitor uses
      // `${ecosystem}/${name}@${version}` for recentlyScanned) — pass the
      // whole entry instead of imposing a key shape here.
      if (opts.isDuplicate && opts.isDuplicate(e)) {
        res.deduped++;
        continue; // already scanned or already queued — discard from backlog
      }
      const { ts: _ts, ...item } = e; // strip the spill timestamp, restore the queue item shape
      opts.enqueueFn(scanQueue, item, stats);
      res.drained++;
    }
    const remaining = entries.filter((_, i) => !takeIdx.has(i));
    _writeEntries(file, remaining);
    res.remaining = remaining.length;
    if (stats) {
      stats.spillDrained = (stats.spillDrained || 0) + res.drained;
      stats.spillDeduped = (stats.spillDeduped || 0) + res.deduped;
    }
  } catch { /* never throw — worst case the same items drain next tick */ }
  return res;
}

/** Entry count (0 on missing/unreadable file). */
function getBacklogSize() {
  return _readEntries(_spillFile()).length;
}

module.exports = {
  isSpillEnabled,
  spillItems,
  drainBacklog,
  shouldDrain,
  getBacklogSize,
  // test seams
  _compactBacklog,
  SPILL_FIELDS
};
