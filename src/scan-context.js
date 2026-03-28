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
const { resetMaxFileSize } = require('./shared/constants.js');

/**
 * Reset all per-scan mutable state.
 * Call at the end of every scan (both normal and _capture modes).
 */
function resetAll() {
  setExtraExcludes([]);
  clearFileListCache();
  resetConfigOverrides();
  resetMaxFileSize();
}

module.exports = { resetAll };
