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
 * Event-loop stall ATTRIBUTION (2026-06-18). Pure observability — NO change to
 * scan behavior, scoring, or detection.
 *
 * Why: every in-process OOM defense — the RSS circuit breaker, the memory
 * governor's RSS feed (`updateGovernorRss`), the EMERGENCY queue purge — runs on
 * the main-thread `setInterval` poll loop (`daemon.js`). A long SYNCHRONOUS op on
 * that loop wedges it: none of those timers fire, so RSS climbs to the cgroup
 * MemoryMax (9.5G) unchecked → kernel SIGKILL (cgroup OOM). Measured signature
 * 2026-06-17/18: 4-6 min of ZERO scan completions AND zero daemon log lines
 * immediately before EVERY OOM kill. Leading suspect for the block: adm-zip
 * `extractAllTo` (synchronous), which `extractArchive` runs on the main thread for
 * the large-package quick-scan (4071 size_skip/24h) and pre-worker extraction.
 *
 * This module does NOT fix the stall — it NAMES it, so the next refactor targets
 * the confirmed culprit instead of a guess:
 *   - `beginOp`/`endOp` leave a breadcrumb naming the op (and package) in flight.
 *   - `startLagSampler` runs its OWN low-frequency timer; its tardiness measures
 *     how long the loop was blocked (the sampler is starved the same way the
 *     breaker is, but decoupled so it can't perturb the breaker). On a stall it
 *     reports the op whose lifetime OVERLAPS the blocked window — the still-running
 *     op, or the one that just ended (the blocking op has usually returned by the
 *     time the loop frees and the sampler can finally fire).
 * Resolving stalls share their source with the fatal one, so attributing the
 * resolving precursors pins the culprit.
 *
 * Bounded (CLAUDE.md §2): a single current + single last-ended breadcrumb slot;
 * the stall log is size-capped. Instrumentation NEVER throws.
 */

const fs = require('fs');
const path = require('path');

const STALL_LOG_FILE = process.env.MUADDIB_LOOP_STALL_FILE
  || path.join(__dirname, '..', '..', 'data', 'loop-stalls.jsonl');
const STALL_LOG_MAX_BYTES = 256 * 1024; // bounded: truncate-then-append past this

// Threshold 5s: far above normal GC/IO jitter (sub-100ms) and a full scan's
// main-thread slice, far below the multi-minute fatal stalls — catches the
// resolving precursors without noise. Sampler cadence 1s.
const DEFAULT_INTERVAL_MS = 1000;
const DEFAULT_THRESHOLD_MS = 5000;

// Injectable clock (tests drive it via _reset(clockFn)); default real time.
let _clock = () => Date.now();
function _now() { return _clock(); }

// ─── Breadcrumb: the op currently / most-recently on the main thread ───
let _current = null;   // { label, meta, startedAt }
let _lastEnded = null; // { label, meta, startedAt, endedAt }

/** Mark the start of a (potentially blocking, synchronous) main-thread op. */
function beginOp(label, meta) {
  _current = { label: String(label || 'op'), meta: meta || null, startedAt: _now() };
  return _current;
}

/** Mark it done. Token optional; a mismatched token is ignored (nesting-safe). */
function endOp(token) {
  if (!_current) return;
  if (token && token !== _current) return;
  _lastEnded = { ..._current, endedAt: _now() };
  _current = null;
}

/**
 * Run a synchronous, potentially-blocking main-thread op UNDER a breadcrumb so a
 * concurrent lag-sampler stall attributes itself to THIS op instead of reporting
 * `op:null`. Mirrors the sandbox `dockerSync` wrapper (sandbox/index.js). Passes
 * fn's return value through; the breadcrumb is cleared in `finally` even when fn
 * throws (and the error re-thrown). Single-slot model (see file header) — the
 * wrapped fn must NOT itself call beginOp/endOp/runInstrumented (no nesting).
 */
function runInstrumented(label, meta, fn) {
  const token = beginOp(label, meta);
  try {
    return fn();
  } finally {
    endOp(token);
  }
}

/**
 * The op whose lifetime overlaps [windowStartMs, windowEndMs] — i.e. the op on
 * the thread during the blocked window. Prefers the still-running op, else the
 * one that ended inside the window. Null when nothing was instrumented (a real
 * signal: widen the breadcrumbs).
 */
function opOverlapping(windowStartMs, windowEndMs) {
  if (_current && _current.startedAt <= windowEndMs) {
    return { label: _current.label, meta: _current.meta, running: true, elapsedMs: _now() - _current.startedAt };
  }
  if (_lastEnded && _lastEnded.endedAt >= windowStartMs && _lastEnded.startedAt <= windowEndMs) {
    return { label: _lastEnded.label, meta: _lastEnded.meta, running: false, durationMs: _lastEnded.endedAt - _lastEnded.startedAt };
  }
  return null;
}

// ─── Lag core (pure, unit-testable: timestamps in, no timers) ───
const _state = { lastTickMs: null, intervalMs: DEFAULT_INTERVAL_MS, thresholdMs: DEFAULT_THRESHOLD_MS, maxLagMs: 0, stalls: 0 };

function configure(opts = {}) {
  if (Number.isFinite(opts.intervalMs)) _state.intervalMs = opts.intervalMs;
  if (Number.isFinite(opts.thresholdMs)) _state.thresholdMs = opts.thresholdMs;
}

/**
 * Feed one sampler tick. Returns { lagMs, windowStartMs, firstTick }. lagMs = how
 * much LATER than the configured interval this tick fired = the time the loop was
 * blocked since the previous tick. First call seeds (lag 0).
 */
function observeTick(nowMs) {
  if (_state.lastTickMs === null) {
    _state.lastTickMs = nowMs;
    return { lagMs: 0, windowStartMs: nowMs, firstTick: true };
  }
  const windowStartMs = _state.lastTickMs;
  const lagMs = Math.max(0, nowMs - _state.lastTickMs - _state.intervalMs);
  _state.lastTickMs = nowMs;
  if (lagMs > _state.maxLagMs) _state.maxLagMs = lagMs;
  return { lagMs, windowStartMs, firstTick: false };
}

function isStall(lagMs, thresholdMs = _state.thresholdMs) { return lagMs >= thresholdMs; }
function getMaxLagMs() { return _state.maxLagMs; }
function getStallCount() { return _state.stalls; }

function _appendStall(record) {
  try {
    try {
      const st = fs.statSync(STALL_LOG_FILE);
      if (st.size > STALL_LOG_MAX_BYTES) fs.truncateSync(STALL_LOG_FILE, 0); // bounded
    } catch { /* absent — first write */ }
    fs.appendFileSync(STALL_LOG_FILE, JSON.stringify(record) + '\n');
  } catch { /* instrumentation must never throw */ }
}

/** Build the structured stall record for a detected lag (pure; exported for tests). */
function buildStallRecord(lagMs, windowStartMs, nowMs) {
  const op = opOverlapping(windowStartMs, nowMs);
  return {
    ts: new Date(nowMs).toISOString(),
    lagMs,
    blockedSec: Math.round(lagMs / 100) / 10,
    op: op
      ? { label: op.label, meta: op.meta, running: op.running, durationMs: op.running ? op.elapsedMs : op.durationMs }
      : null,
    rssMb: Math.round(process.memoryUsage().rss / 1024 / 1024)
  };
}

/**
 * Start the lag sampler. Its OWN tardiness measures loop lag. unref'd: a pure
 * monitor never keeps the process alive on its own. Returns a stop fn.
 * onStall(record) is an optional extra sink (the daemon logs it); every stall is
 * also appended to STALL_LOG_FILE for post-hoc analysis.
 */
function startLagSampler(opts = {}) {
  configure(opts);
  _state.lastTickMs = null;
  const onStall = typeof opts.onStall === 'function' ? opts.onStall : null;
  const timer = setInterval(() => {
    const now = Date.now();
    const { lagMs, windowStartMs, firstTick } = observeTick(now);
    if (firstTick || !isStall(lagMs)) return;
    _state.stalls += 1;
    const record = buildStallRecord(lagMs, windowStartMs, now);
    _appendStall(record);
    if (onStall) { try { onStall(record); } catch { /* ignore */ } }
  }, _state.intervalMs);
  if (timer && typeof timer.unref === 'function') timer.unref();
  return () => clearInterval(timer);
}

/** Test helper: clear all state; optionally install a deterministic clock. */
function _reset(clockFn) {
  _current = null;
  _lastEnded = null;
  _state.lastTickMs = null;
  _state.intervalMs = DEFAULT_INTERVAL_MS;
  _state.thresholdMs = DEFAULT_THRESHOLD_MS;
  _state.maxLagMs = 0;
  _state.stalls = 0;
  _clock = typeof clockFn === 'function' ? clockFn : (() => Date.now());
}

module.exports = {
  beginOp,
  endOp,
  runInstrumented,
  opOverlapping,
  configure,
  observeTick,
  isStall,
  getMaxLagMs,
  getStallCount,
  buildStallRecord,
  startLagSampler,
  _reset,
  _state,
  STALL_LOG_FILE
};
