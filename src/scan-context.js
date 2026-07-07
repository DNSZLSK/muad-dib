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
 * Centralized per-scan state reset.
 *
 * Multiple modules own mutable state that must be cleared between scans
 * to prevent cross-scan leakage. This module provides a single resetAll()
 * that calls every reset function, so callers never forget one.
 *
 * State owners:
 *   utils.js          — file list cache, content cache, extra excludes
 *   scoring.js        — severity weights, risk thresholds (config overrides)
 *   shared/constants.js — max file size (config override), AST cache
 */

const { setExtraExcludes, clearFileListCache } = require('./utils.js');
const { resetConfigOverrides } = require('./scoring.js');
const { resetMaxFileSize, clearASTCache } = require('./shared/constants.js');

/**
 * Reset all per-scan mutable state.
 * Call at the end of every scan (both normal and _capture modes).
 */
function resetAll() {
  setExtraExcludes([]);
  clearFileListCache();
  resetConfigOverrides();
  resetMaxFileSize();
  clearASTCache();
}

module.exports = { resetAll };
