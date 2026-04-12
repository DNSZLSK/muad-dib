'use strict';

/**
 * Adaptive concurrency controller for the scan worker pool.
 *
 * Adjusts target concurrency every ADJUST_INTERVAL_MS based on three signals:
 *   1. Queue depth — scale up when backlog grows, down when idle
 *   2. Memory pressure — always reduce under heap pressure
 *   3. Timeout rate — reduce when system is saturated (I/O contention)
 *
 * Scale-up is aggressive (+4) because backlog = lost coverage.
 * Scale-down is gradual (-2) to avoid thrashing.
 * Memory pressure overrides everything (OOM kills lose the in-memory queue).
 */

const MIN_CONCURRENCY = 4;
const BASE_CONCURRENCY = Math.max(MIN_CONCURRENCY, parseInt(process.env.MUADDIB_SCAN_CONCURRENCY, 10) || 8);
const MAX_CONCURRENCY = Math.max(BASE_CONCURRENCY, parseInt(process.env.MUADDIB_MAX_CONCURRENCY, 10) || 32);
const ADJUST_INTERVAL_MS = 30_000;

// Queue depth thresholds
const QUEUE_BACKLOG_THRESHOLD = 1000;
const QUEUE_IDLE_THRESHOLD = 100;

// System pressure thresholds
const MEMORY_PRESSURE_THRESHOLD = 0.75;
const TIMEOUT_RATE_THRESHOLD = 0.15;
const TIMEOUT_RATE_MIN_SAMPLES = 20;

// Track previous stats snapshot for delta computation
let _prevScanned = 0;
let _prevTimeouts = 0;

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
  const mem = process.memoryUsage();
  const memPressure = mem.heapUsed / mem.heapTotal;

  // Priority 1: Memory pressure — always reduce, overrides everything
  if (memPressure > MEMORY_PRESSURE_THRESHOLD) {
    const target = clamp(current - 4);
    _prevScanned = stats.scanned || 0;
    _prevTimeouts = (stats.errorsByType && stats.errorsByType.static_timeout) || 0;
    return { target, reason: `memory_pressure (${(memPressure * 100).toFixed(0)}%)` };
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
    return { target, reason: `high_timeout_rate (${(timeoutRate * 100).toFixed(0)}%, ${timeoutDelta}/${scannedDelta})` };
  }

  // Priority 3: Queue depth — scale up for backlog, down toward base when idle
  if (queueDepth > QUEUE_BACKLOG_THRESHOLD) {
    const target = clamp(current + 4);
    return { target, reason: `backlog (queue=${queueDepth})` };
  }

  if (queueDepth < QUEUE_IDLE_THRESHOLD) {
    // Converge toward BASE, not MIN — normal traffic needs BASE capacity
    const target = Math.max(BASE_CONCURRENCY, clamp(current - 2));
    return { target, reason: `idle (queue=${queueDepth})` };
  }

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
