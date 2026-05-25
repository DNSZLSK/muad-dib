'use strict';

const { classifyTaintSource } = require('./taint-tracker.js');

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
