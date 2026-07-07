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

const { classifyTaintSource, isHarvestEnv } = require('./taint-tracker.js');

/**
 * Visit `assignment` nodes at module level (scope_depth === 0) and populate
 * `ctx.moduleTaint`. Cleared on reassignment.
 *
 * V1 restrictions (intentional — see plan file Phase 1b):
 *  - module level only ; assignments inside functions/classes/lambdas are ignored
 *  - LHS must be a bare identifier (no tuple unpack, no attribute, no subscript)
 *  - single hop only (no alias propagation A → B → sink)
 *  - reassignment to a non-source value CLEARS the taint
 */
function handleAssignment(node, ctx, scopeDepth) {
  // crypto_exfil harvest leg (PyPI, file-level — runs at ANY scope, unlike moduleTaint):
  // `secret = os.environ['AWS_SECRET']` even inside a function sets the harvest flag.
  if (!ctx.hasSensitiveHarvestPy) {
    const rhs = node.childForFieldName('right');
    if (rhs) {
      const t = classifyTaintSource(rhs);
      if (t && t.sourceType === 'env' && isHarvestEnv(t.envVarName)) {
        ctx.hasSensitiveHarvestPy = true;
      }
    }
  }

  if (scopeDepth !== 0) return;
  if (!ctx.moduleTaint) return; // defensive — should always be initialised per-file

  const left = node.childForFieldName('left');
  const right = node.childForFieldName('right');
  if (!left || !right) return;

  // Tuple/list LHS, attribute LHS, subscript LHS — V1 skips (Phase 3 alias
  // tracking will handle attribute/subscript). Bare identifier only.
  if (left.type !== 'identifier') return;

  const taint = classifyTaintSource(right);
  if (taint) {
    ctx.moduleTaint.set(left.text, taint);
  } else if (ctx.moduleTaint.has(left.text)) {
    // Reassignment to a non-source value — clear previous taint.
    // Prevents FP where `payload = source(); payload = "harmless"; exec(payload)`
    // would otherwise still flag based on the original taint.
    ctx.moduleTaint.delete(left.text);
  }
}

module.exports = { handleAssignment };
