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

const path = require('path');

// Directory of the monitor / feed / ML state files (detections, alerts, ledger, stats, queue
// state, cursors...). Default: `<repo>/data`, as before. MUADDIB_DATA_DIR moves all of them at
// once; tests/run-tests.js points it at a temporary directory so that no test, present or
// future, writes into a production data directory (`npm test` in a deployed checkout used to
// append test detections and alerts to the real files). Per-file overrides such as
// MUADDIB_DETECTIONS_FILE keep precedence where they exist. Read at call time.
const DEFAULT_DATA_DIR = path.join(__dirname, '..', '..', 'data');

function dataDir() {
  const v = process.env.MUADDIB_DATA_DIR;
  return typeof v === 'string' && v.trim() !== '' ? path.resolve(v.trim()) : DEFAULT_DATA_DIR;
}

function dataPath(...parts) {
  return path.join(dataDir(), ...parts);
}

module.exports = { dataDir, dataPath, DEFAULT_DATA_DIR };
