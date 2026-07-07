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
 * Per-worker memory instrumentation (off-heap RSS attribution, 2026-06).
 *
 * The EMERGENCY breaker fires on process RSS while the heap sits at ~15% —
 * the driver is off-heap (malloc arenas + tarball Buffers) and mem-trend.jsonl
 * only samples the whole process. This module attributes memory to individual
 * scan workers / packages so the worker_threads → child_process decision can
 * be made on data:
 *   H1: RSS stays high AFTER workers die  → arenas never returned to the OS
 *   H2: RSS peaks only WHILE workers live → concurrent in-flight peak
 *
 * Producers:
 *   - queue.js (parent): ev:'spawn' / ev:'exit' around each scan worker,
 *     with process-wide RSS (delta attributable per package, noisy but
 *     aggregable over 24-48h).
 *   - scan-worker.js (worker): ev:'sample' every sampleIntervalMs() with the
 *     isolate-local heapUsed/external/arrayBuffers (rss there is process-wide).
 *
 * Same hot-path safety rules as spill.js (2026-06-11 prod-freeze lesson):
 * append-only, stat-gated O(1) rotation, never read the file back, never throw.
 * OFF unless MUADDIB_WORKER_MEM=1 (staged rollout, same pattern as
 * MUADDIB_WORKER_MAX_OLD_MB) so tests and CLI runs never touch data/.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.join(__dirname, '..', '..', 'data', 'worker-mem.jsonl');
const DEFAULT_MAX_MB = 64;        // rotate past 64MB (file + .1 = 128MB worst case, ~2.5 days at concurrency 8)
const DEFAULT_SAMPLE_MS = 10000;  // per-worker isolate sample cadence

function workerMemEnabled() {
  return process.env.MUADDIB_WORKER_MEM === '1';
}

function workerMemFile() {
  return process.env.MUADDIB_WORKER_MEM_FILE || DEFAULT_FILE;
}

/** 0 = sampling disabled (instrumentation off, or explicit MUADDIB_WORKER_MEM_SAMPLE_MS=0). */
function sampleIntervalMs() {
  if (!workerMemEnabled()) return 0;
  const v = parseInt(process.env.MUADDIB_WORKER_MEM_SAMPLE_MS, 10);
  if (Number.isFinite(v) && v >= 0) return v;
  return DEFAULT_SAMPLE_MS;
}

/**
 * Append one instrumentation entry (ts stamped here). Bounded resource
 * (CLAUDE.md §2): stat-gated truncate-rotate, no read-back on the hot path.
 * @returns {boolean} true if a line was written
 */
function appendWorkerMem(entry) {
  if (!workerMemEnabled()) return false;
  try {
    const file = workerMemFile();
    const maxMb = parseInt(process.env.MUADDIB_WORKER_MEM_MAX_MB, 10);
    const maxBytes = (Number.isFinite(maxMb) && maxMb > 0 ? maxMb : DEFAULT_MAX_MB) * 1024 * 1024;
    try {
      const st = fs.statSync(file);
      if (st.size > maxBytes) fs.renameSync(file, file + '.1');
    } catch { /* no file yet — fine */ }
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', 'utf8');
    return true;
  } catch { /* instrumentation must never crash the daemon or a worker */
    return false;
  }
}

module.exports = { appendWorkerMem, sampleIntervalMs, workerMemEnabled, workerMemFile };
