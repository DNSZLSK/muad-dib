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
 * Heavy-lane semaphore (C2, 2026-06-11) — bound the daemon's RSS by limiting
 * how many MEMORY-heavy static scans run concurrently.
 *
 * Measured (worker-mem.jsonl, n=461 workers): per-worker isolate heap peaks
 * are BIMODAL — p50 = 12MB, but 12.6% of scans jump straight to 0.9-2.1GB
 * (giant minified JS bundles; the AST cache accumulates across every parsable
 * file, executor.js only skips files > getMaxFileSize() individually). With
 * 8 concurrent workers a handful of heavies coincide → process RSS > the
 * 8.5GB breaker → EMERGENCY. The heavies are identifiable BEFORE the worker
 * spawns (total parsable-JS bytes on disk), so instead of killing them (a
 * 768MB worker cap would cost 12% of coverage) we serialize them: at most
 * MUADDIB_HEAVY_SCAN_MAX run at once, lights are NEVER blocked.
 * Worst-case RSS ≈ baseline 2GB + 2×2GB heavies + N×12MB lights ≈ 5-6GB.
 *
 * Same {active, queue[]} semaphore pattern as src/shared/http-limiter.js and
 * the sandbox slots (src/sandbox/index.js), plus two extensions those never
 * needed: an abort-aware acquire and a wait-timeout. Both MUST remove their
 * waiter from the queue on the way out — a release would otherwise hand the
 * slot to a dead waiter and leak it permanently.
 */

// Max number of HEAVY_LANE_WAIT_TIMEOUT requeues before an item's final pass
// runs without the wait bound (abort-aware only, still bounded by the outer
// SCAN_TIMEOUT_MS). Guarantees an item cannot loop in the queue forever.
const HEAVY_REQUEUE_MAX = 3;

// Env knobs (read at call time so tests can flip them around resetHeavyLane()):
// - MUADDIB_HEAVY_SCAN_MAX: concurrent heavy scans (default 2, 0 = lane off)
// - MUADDIB_HEAVY_SCAN_BYTES: heavy threshold on total parsable-JS bytes.
//   Default 3 MiB — the measured distribution has a HOLE between light
//   (≤12MB heap ⇔ <~1MB JS) and heavy (≥512MB heap ⇔ ≥~8MB JS); 3 MiB sits
//   in the hole with ~3× margin both ways. A false-heavy costs a short wait;
//   a false-light risks an EMERGENCY — hence the deliberately low default.
// - MUADDIB_HEAVY_WAIT_MAX_MS: wait bound before requeue (default 120s —
//   ~2.5 slot services of 45s, leaves >150s of the 300s scan budget).
function heavyScanMax() {
  const v = parseInt(process.env.MUADDIB_HEAVY_SCAN_MAX, 10);
  return Number.isFinite(v) && v >= 0 ? v : 2;
}

function heavyScanBytesThreshold() {
  const v = parseInt(process.env.MUADDIB_HEAVY_SCAN_BYTES, 10);
  return Number.isFinite(v) && v > 0 ? v : 3 * 1024 * 1024;
}

function heavyWaitMaxMs() {
  const v = parseInt(process.env.MUADDIB_HEAVY_WAIT_MAX_MS, 10);
  return Number.isFinite(v) && v >= 0 ? v : 120000;
}

const _lane = { active: 0, queue: [] };

/**
 * Pure classifier. `truncated` (the bounded measurement walk overflowed its
 * depth/file caps) classifies heavy by default — defensive: an unmeasurable
 * package is exactly the kind that blows a worker. Compares weightedJsBytes
 * (plain + ×12 minified — see measureJsWeight in queue.js: raw bytes alone
 * missed the minified explosions, powerlines 517KB → 1151MB heap) and falls
 * back to totalJsBytes for callers that don't weight. `oversize` (any single
 * JS file > getMaxFileSize) also forces heavy — content scanners load such a
 * file whole even though the AST skips it (omnius: a 30MB index.js → 1347MB).
 * @param {{totalJsBytes: number, weightedJsBytes?: number, oversize?: boolean, truncated: boolean}|null} weight
 * @param {number} [thresholdBytes]
 */
function isHeavyScan(weight, thresholdBytes = heavyScanBytesThreshold()) {
  if (!weight) return false;
  if (weight.truncated) return true;
  if (weight.oversize) return true; // a single JS file > getMaxFileSize — content scanners load it whole
  const effective = Number.isFinite(weight.weightedJsBytes) ? weight.weightedJsBytes : (weight.totalJsBytes || 0);
  return effective >= thresholdBytes;
}

/**
 * Acquire a heavy-lane slot. Resolves true when a slot is held, false when
 * the lane is disabled (MUADDIB_HEAVY_SCAN_MAX=0 — nothing to release).
 * FIFO when saturated.
 *
 * @param {Object} [opts]
 * @param {AbortSignal} [opts.signal] - outer scan abort: rejects err.code='ABORT_ERR'
 * @param {number} [opts.maxWaitMs] - wait bound; 0/absent = unbounded.
 *   On expiry rejects err.code='HEAVY_LANE_WAIT_TIMEOUT' (caller requeues).
 * @returns {Promise<boolean>}
 */
function acquireHeavySlot(opts = {}) {
  const max = heavyScanMax();
  if (max === 0) return Promise.resolve(false);
  if (_lane.active < max) {
    _lane.active++;
    return Promise.resolve(true);
  }
  const { signal, maxWaitMs } = opts;
  return new Promise((resolve, reject) => {
    let timer = null;
    const cleanup = () => {
      if (timer) { clearTimeout(timer); timer = null; }
      if (signal) { try { signal.removeEventListener('abort', onAbort); } catch { /* not added */ } }
    };
    const waiter = () => {
      cleanup();
      resolve(true); // slot transferred by releaseHeavySlot (active unchanged)
    };
    // Leaving the queue WITHOUT being woken: splice the waiter out, or the
    // next release hands the slot to this dead waiter and leaks it (trap #1).
    const bail = (err) => {
      const i = _lane.queue.indexOf(waiter);
      if (i === -1) return; // already woken — the release path owns the slot
      _lane.queue.splice(i, 1);
      cleanup();
      reject(err);
    };
    const onAbort = () => {
      const err = new Error('Heavy-lane wait aborted (outer scan timeout)');
      err.code = 'ABORT_ERR';
      bail(err);
    };
    // Push BEFORE wiring abort/timeout: bail() rejects only when it finds the
    // waiter in the queue (its index check guards the already-woken race) —
    // a pre-aborted signal firing before the push would otherwise bail into
    // the guard and leave the promise forever pending.
    _lane.queue.push(waiter);
    if (signal) {
      if (signal.aborted) { onAbort(); return; }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    if (Number.isFinite(maxWaitMs) && maxWaitMs > 0) {
      // Deliberately NOT unref'd: a pending acquire is active work (a scan
      // holding tmp disk and a pool slot) — it must keep the process alive.
      timer = setTimeout(() => {
        const err = new Error(`Heavy-lane slot not acquired within ${maxWaitMs}ms`);
        err.code = 'HEAVY_LANE_WAIT_TIMEOUT';
        bail(err);
      }, maxWaitMs);
    }
  });
}

function releaseHeavySlot() {
  if (_lane.queue.length > 0) {
    const next = _lane.queue.shift();
    next(); // transfers the slot to the next waiter (active count unchanged)
  } else if (_lane.active > 0) {
    _lane.active--;
  }
}

function getHeavyLaneState() {
  return { active: _lane.active, waiting: _lane.queue.length, max: heavyScanMax() };
}

/** Test helper — same role as resetSandboxLimiter in src/sandbox/index.js. */
function resetHeavyLane() {
  _lane.active = 0;
  _lane.queue.length = 0;
}

module.exports = {
  acquireHeavySlot,
  releaseHeavySlot,
  isHeavyScan,
  getHeavyLaneState,
  resetHeavyLane,
  heavyScanBytesThreshold,
  heavyWaitMaxMs,
  HEAVY_REQUEUE_MAX
};
