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
 * Incompleteness contract (architecture lot 1).
 *
 * Every internal bound that an attacker can fill to hide a verdict (timeouts,
 * graph node/edge limits, flow-candidate limit, function-BFS limit, file cap)
 * records itself here. The processor turns a non-empty record into
 * `analysis.status = 'INCONCLUSIVE'`. Free-text warnings (IOC staleness,
 * config notices) never change the status: only these structured entries do.
 *
 * Scope: one record per scan. `run()` opens it with `withScanRecord()`, backed by
 * AsyncLocalStorage, so the record follows the scan through await / setImmediate
 * and two scans running at the same time in one process (`muaddib watch` starts a
 * re-scan without awaiting the previous one) never share or wipe each other's
 * entries: a wiped entry would turn a bounded scan into a false COMPLETE.
 * Callers outside a scan (unit tests driving one module directly) fall back to a
 * module-level record, cleared by resetCompleteness().
 *
 * Bounded: one entry per (component, reason) pair, MAX_ENTRIES overall.
 */

const { AsyncLocalStorage } = require('async_hooks');

const MAX_ENTRIES = 32;

const scanStore = new AsyncLocalStorage();
let fallback = [];

function currentRecord() {
  const rec = scanStore.getStore();
  return rec || fallback;
}

/**
 * Run `fn` with a fresh incompleteness record bound to its async context.
 * @template T
 * @param {() => Promise<T>|T} fn
 * @returns {Promise<T>|T}
 */
function withScanRecord(fn) {
  return scanStore.run([], fn);
}

/**
 * Record that a part of the analysis did not run to completion.
 * @param {string} component - e.g. 'moduleGraph', 'reachability', 'analyzeAST'
 * @param {string} reason - e.g. 'timeout', 'edge-limit', 'flow-candidate-limit'
 * @param {Object} [details] - { limit, observed } numbers, kept as-is
 */
function markIncomplete(component, reason, details = {}) {
  const entries = currentRecord();
  if (entries.some(e => e.component === component && e.reason === reason)) return;
  if (entries.length >= MAX_ENTRIES) return;
  const entry = { component: String(component), reason: String(reason) };
  if (details.limit !== undefined) entry.limit = details.limit;
  if (details.observed !== undefined) entry.observed = details.observed;
  entries.push(entry);
}

/** @returns {Array<{component: string, reason: string, limit?: number, observed?: number}>} copy */
function getIncomplete() {
  return currentRecord().map(e => ({ ...e }));
}

/** Human-readable one-liner for an entry (CLI warning, SARIF notification). */
function describe(entry) {
  let s = `${entry.component}: ${entry.reason}`;
  if (entry.limit !== undefined) s += ` (limit ${entry.limit}`;
  if (entry.limit !== undefined && entry.observed !== undefined) s += `, observed ${entry.observed}`;
  if (entry.limit !== undefined) s += ')';
  return s;
}

/**
 * Clear the current record: the scan's own record inside withScanRecord(), the
 * module-level fallback otherwise. Never touches another scan's record.
 */
function resetCompleteness() {
  const rec = scanStore.getStore();
  if (rec) rec.length = 0;
  else fallback = [];
}

module.exports = { markIncomplete, getIncomplete, describe, resetCompleteness, withScanRecord, MAX_ENTRIES };
