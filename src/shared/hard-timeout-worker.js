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

// Watchdog thread of hard-timeout.js. Kept free of any other require: it must start fast
// and keep working while the main thread is blocked in synchronous analysis.

const { workerData } = require('worker_threads');
const fs = require('fs');

if (workerData && Number.isFinite(workerData.seconds) && workerData.seconds > 0) {
  setTimeout(() => {
    try {
      fs.writeSync(2, '\n[MUADDIB] Scan exceeded the hard time limit (' + workerData.seconds +
        ' s, MUADDIB_SCAN_HARD_TIMEOUT_S): process terminated, no result. The analysis is INCONCLUSIVE.\n');
    } catch { /* stderr closed */ }
    // SIGKILL on POSIX: a JavaScript signal handler of the busy main thread could never run.
    process.kill(workerData.pid, process.platform === 'win32' ? undefined : 'SIGKILL');
  }, workerData.seconds * 1000);
}
