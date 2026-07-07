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
 * Adaptive concurrency controller for the scan worker pool.
 *
 * Adjusts target concurrency every ADJUST_INTERVAL_MS based on three signals:
 *   1. Queue depth — scale up when backlog grows, down when idle
 *   2. Memory pressure — always reduce under system RAM pressure
 *   3. Timeout rate — reduce when system is saturated (I/O contention)
 *
 * Scale-up is aggressive (+4) because backlog = lost coverage.
 * Scale-down is gradual (-2) to avoid thrashing.
 * Memory pressure overrides everything (OOM kills lose the in-memory queue).
 */

const os = require('os');

const MIN_CONCURRENCY = 4;
const BASE_CONCURRENCY = Math.max(MIN_CONCURRENCY, parseInt(process.env.MUADDIB_SCAN_CONCURRENCY, 10) || 8);
const MAX_CONCURRENCY = Math.max(BASE_CONCURRENCY, parseInt(process.env.MUADDIB_MAX_CONCURRENCY, 10) || 16);
const ADJUST_INTERVAL_MS = 30_000;

// Queue depth thresholds
const QUEUE_BACKLOG_THRESHOLD = 1000;
const QUEUE_IDLE_THRESHOLD = 100;

// System pressure thresholds
// Uses os.freemem()/os.totalmem() (real system RAM), NOT process.memoryUsage()
// heapUsed/heapTotal. V8 adjusts heapTotal dynamically — the ratio is structurally
// 75-85% even when the OS has 8+ GB free. On a 12GB VPS with 3MB heap,
// heapUsed/heapTotal = 76% but freemem/totalmem = 75% (8.3GB available).
const MEMORY_FREE_THRESHOLD = 0.15; // < 15% system RAM free = pressure
const TIMEOUT_RATE_THRESHOLD = 0.15;
const TIMEOUT_RATE_MIN_SAMPLES = 20;

// Track previous stats snapshot for delta computation
let _prevScanned = 0;
let _prevTimeouts = 0;

// Throughput plateau detection: if we scaled up but throughput didn't increase
// over MULTIPLE consecutive windows, we've hit I/O saturation.
// Requires 2 consecutive flat windows to trigger — a single 30s window has too
// much variance from sandbox timeouts (90-270s) to be reliable.
let _prevThroughput = 0;
let _lastScaleDirection = 0; // +1 = scaled up, -1 = scaled down, 0 = stable
let _plateauStreak = 0;      // consecutive windows where throughput didn't improve after scale-up
const PLATEAU_STREAK_REQUIRED = 2; // must see flat throughput N times before triggering

/**
 * Compute new target concurrency from system signals.
 * Uses stats deltas (not cumulative) for timeout rate — avoids stale data.
 *
 * @param {number} current - Current target concurrency
 * @param {number} queueDepth - scanQueue.length
 * @param {Object} stats - Monitor stats object (scanned, errorsByType.static_timeout)
 * @returns {{ target: number, reason: string }}
 */
function computeTarget(current, queueDepth, stats) {
  // Priority 0: V8 heap pressure — os.freemem() misses this entirely.
  // With --max-old-space-size=8192 on a 12GB VPS, system RAM can show 7GB free
  // while V8 heap is at 90% and GC is thrashing. Use the daemon's circuit breaker
  // level to gate concurrency before system RAM pressure kicks in.
  try {
    const { getMemoryPressureLevel, MEMORY_PRESSURE_LEVELS } = require('./daemon.js');
    const heapPressure = getMemoryPressureLevel();
    if (heapPressure >= MEMORY_PRESSURE_LEVELS.HIGH) {
      const target = clamp(MIN_CONCURRENCY);
      _prevScanned = stats.scanned || 0;
      _prevTimeouts = (stats.errorsByType && stats.errorsByType.static_timeout) || 0;
      return { target, reason: `heap_pressure_high (level=${heapPressure}, dropping to min=${MIN_CONCURRENCY})` };
    }
    if (heapPressure >= MEMORY_PRESSURE_LEVELS.ELEVATED) {
      const target = clamp(Math.min(current, BASE_CONCURRENCY));
      _prevScanned = stats.scanned || 0;
      _prevTimeouts = (stats.errorsByType && stats.errorsByType.static_timeout) || 0;
      return { target, reason: `heap_elevated (level=${heapPressure}, capping at base=${BASE_CONCURRENCY})` };
    }
  } catch { /* daemon.js not loaded yet on first tick — proceed with system RAM check */ }

  // Use system RAM, not V8 heap ratio (see MEMORY_FREE_THRESHOLD comment above)
  const freeMem = os.freemem();
  const totalMem = os.totalmem();
  const freeRatio = totalMem > 0 ? freeMem / totalMem : 1;

  // Priority 1: System memory pressure — always reduce, overrides everything
  if (freeRatio < MEMORY_FREE_THRESHOLD) {
    const target = clamp(current - 4);
    _prevScanned = stats.scanned || 0;
    _prevTimeouts = (stats.errorsByType && stats.errorsByType.static_timeout) || 0;
    const freeMB = Math.round(freeMem / 1024 / 1024);
    return { target, reason: `memory_pressure (${freeMB}MB free, ${(freeRatio * 100).toFixed(0)}%)` };
  }

  // Compute timeout rate from stats deltas (sliding window between adjustments)
  const scannedNow = stats.scanned || 0;
  const timeoutsNow = (stats.errorsByType && stats.errorsByType.static_timeout) || 0;
  const scannedDelta = scannedNow - _prevScanned;
  const timeoutDelta = timeoutsNow - _prevTimeouts;
  _prevScanned = scannedNow;
  _prevTimeouts = timeoutsNow;

  const timeoutRate = scannedDelta >= TIMEOUT_RATE_MIN_SAMPLES ? timeoutDelta / scannedDelta : 0;

  // Priority 2: High timeout rate — system saturated, adding workers makes it worse
  if (timeoutRate > TIMEOUT_RATE_THRESHOLD) {
    const target = clamp(current - 2);
    _prevThroughput = scannedDelta;
    _lastScaleDirection = target < current ? -1 : 0;
    return { target, reason: `high_timeout_rate (${(timeoutRate * 100).toFixed(0)}%, ${timeoutDelta}/${scannedDelta})` };
  }

  // Priority 3: Throughput plateau — scaled up recently but throughput flat/down.
  // Requires PLATEAU_STREAK_REQUIRED consecutive flat windows to trigger.
  // A single bad window (sandbox timeout finishing in wrong 30s slot) is noise, not saturation.
  if (_lastScaleDirection > 0 && _prevThroughput > 0 && scannedDelta > 0 && scannedDelta <= _prevThroughput) {
    _plateauStreak++;
    if (_plateauStreak >= PLATEAU_STREAK_REQUIRED) {
      const prevTp = _prevThroughput;
      _prevThroughput = scannedDelta;
      _lastScaleDirection = -1;
      _plateauStreak = 0;
      return { target: clamp(current - 2), reason: `throughput_plateau (${prevTp}→${scannedDelta} scans/30s × ${PLATEAU_STREAK_REQUIRED} windows)` };
    }
    // Not enough consecutive flat windows yet — keep current level, don't scale up further
    _prevThroughput = scannedDelta;
    return { target: current, reason: `plateau_warning (${_plateauStreak}/${PLATEAU_STREAK_REQUIRED}, ${scannedDelta} scans/30s)` };
  }
  // Throughput improved or no scale-up context — reset streak
  _plateauStreak = 0;

  // Priority 4: Queue depth — scale up for backlog, down toward base when idle
  if (queueDepth > QUEUE_BACKLOG_THRESHOLD) {
    const target = clamp(current + 4);
    // Record throughput at the point of scale-up — next tick compares against this
    _prevThroughput = scannedDelta;
    _lastScaleDirection = target > current ? 1 : 0;
    return { target, reason: `backlog (queue=${queueDepth})` };
  }

  if (queueDepth < QUEUE_IDLE_THRESHOLD) {
    // Converge toward BASE, not MIN — normal traffic needs BASE capacity
    const target = Math.max(BASE_CONCURRENCY, clamp(current - 2));
    _lastScaleDirection = target < current ? -1 : 0;
    return { target, reason: `idle (queue=${queueDepth})` };
  }

  _lastScaleDirection = 0;
  return { target: current, reason: 'stable' };
}

function clamp(n) {
  return Math.max(MIN_CONCURRENCY, Math.min(MAX_CONCURRENCY, n));
}

/**
 * Reset delta tracking (e.g. after daily stats reset).
 */
function resetDeltas() {
  _prevScanned = 0;
  _prevTimeouts = 0;
  _prevThroughput = 0;
  _lastScaleDirection = 0;
  _plateauStreak = 0;
}

module.exports = {
  MIN_CONCURRENCY,
  BASE_CONCURRENCY,
  MAX_CONCURRENCY,
  ADJUST_INTERVAL_MS,
  computeTarget,
  resetDeltas,
  clamp
};
