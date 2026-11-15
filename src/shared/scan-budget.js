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
 * Stop rule of the heavy scanners (architecture lot 2), checked before each file.
 *
 * - `byteBudget`: source characters analyzed. A count, so the CLI and the GitHub Action stop
 *   at the same file on every machine.
 * - `deadline` (epoch ms): set only by the monitor. Its scan worker is killed at 45 s and a
 *   killed scan has no verdict at all (`static_timeout`, about 1 % of the static scans on the
 *   VPS on 2026-11-14/15, concentrated on a few large packages republished at every version).
 *   A soft deadline before that kill lets the scan finish with the findings already made, the
 *   executed files first. A count cannot do this: the VPS speed depends on its load.
 *
 * @returns {{ byteBudget: number|null, deadline: number|null }}
 */
function readBudget(options = {}) {
  return {
    byteBudget: Number.isFinite(options.byteBudget) && options.byteBudget >= 0 ? options.byteBudget : null,
    deadline: Number.isFinite(options.deadline) ? options.deadline : null
  };
}

/** @returns {null|'work-budget'|'deadline'} why the next file must not be analyzed */
function budgetStop(budget, analyzedChars) {
  if (budget.byteBudget !== null && analyzedChars >= budget.byteBudget) return 'work-budget';
  if (budget.deadline !== null && Date.now() >= budget.deadline) return 'deadline';
  return null;
}

/** Details recorded with the incompleteness entry for a stop reason. */
function stopDetails(reason, budget, analyzedChars) {
  return reason === 'deadline'
    ? { observed: analyzedChars }
    : { limit: budget.byteBudget, observed: analyzedChars };
}

module.exports = { readBudget, budgetStop, stopDetails };
