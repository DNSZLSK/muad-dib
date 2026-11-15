/*
 * MUAD'DIB - Supply-chain threat detection for npm & PyPI
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
 * Hard wall-clock bound for a one-shot CLI scan (architecture lot 2).
 *
 * The scanners are synchronous: while one runs, no timer of the main thread can fire. The
 * per-scanner budgets stop between files, so a single file that is slow to analyze (an
 * unknown super-linear path, like the quadratic deobfuscation fixed in 2.12.3) could still
 * hold a CLI or GitHub Action scan indefinitely. The monitor already terminates its scan
 * worker; this gives the CLI the same guarantee.
 *
 * A watchdog thread waits for the deadline. If the scan has not disarmed it by then, it
 * writes the reason to stderr with a direct fd write (the main thread is busy and cannot
 * flush its streams) and kills the process: there is no result, and the exit status is
 * non-zero, so a pipeline that runs the scan fails closed. SIGKILL on POSIX because a
 * JavaScript signal handler of the busy main thread could never run.
 *
 * MUADDIB_SCAN_HARD_TIMEOUT_S: whole seconds, strict parse, default 600, 0 disables.
 */

const path = require('path');
const { Worker } = require('worker_threads');

const DEFAULT_HARD_TIMEOUT_S = 600;

function hardTimeoutSeconds(env = process.env) {
  const raw = env.MUADDIB_SCAN_HARD_TIMEOUT_S;
  if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) return parseInt(raw.trim(), 10);
  return DEFAULT_HARD_TIMEOUT_S;
}

/**
 * Arm the watchdog. Returns a disarm function (idempotent). With a 0 budget nothing is
 * started and the disarm function is a no-op.
 * @param {number} [seconds]
 * @returns {() => void}
 */
function armHardTimeout(seconds = hardTimeoutSeconds()) {
  if (!Number.isFinite(seconds) || seconds <= 0) return () => {};
  let worker;
  try {
    worker = new Worker(path.join(__dirname, 'hard-timeout-worker.js'), { workerData: { seconds, pid: process.pid } });
  } catch {
    // Threads unavailable: the per-scanner budgets still apply; never block the scan on this.
    return () => {};
  }
  // The watchdog must never keep a finished scan alive.
  worker.unref();
  worker.on('error', () => { /* a dead watchdog only loses the bound */ });
  let armed = true;
  return () => {
    if (!armed) return;
    armed = false;
    worker.terminate().catch(() => {});
  };
}

module.exports = { armHardTimeout, hardTimeoutSeconds, DEFAULT_HARD_TIMEOUT_S };
