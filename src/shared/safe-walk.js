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
 * Stack-safe versions of acorn-walk's simple() and ancestor().
 *
 * acorn parses a member chain (`o.a.a.a...`) or a call chain (`o.a().a()...`) with a loop,
 * but acorn-walk visits it recursively, one stack frame group per link. Measured
 * 2026-11-15: 5 000 links (15 KB) overflow the stack, the file's analysis throws, and a
 * payload in the same file scored 0. The parse succeeds, so the parse-failure fallback of
 * ast.js never runs.
 *
 * These walkers keep an explicit stack instead of recursing, and reproduce acorn-walk 8.x
 * exactly: the same base visitors enumerate the children, children are visited in the
 * same order and fully before their parent (post-order), `override` types (Expression,
 * Statement, Pattern...) are resolved the same way, and ancestor() passes the same live
 * ancestors array. tests/unit/safe-walk.test.js compares the visit sequences with
 * acorn-walk on real files.
 */

const acornWalk = require('acorn-walk');

const base = acornWalk.base;

function baseFor(baseVisitor, type) {
  const fn = baseVisitor[type];
  if (fn == null) throw new Error('No walker function defined for node type ' + type);
  return fn;
}

// Expands one frame: the children its base visitor would recurse into, in call order.
function childrenOf(baseVisitor, type, node, st) {
  const children = [];
  baseFor(baseVisitor, type)(node, st, (child, childSt, childOverride) => {
    children.push({ node: child, st: childSt, override: childOverride });
  });
  return children;
}

function simple(node, visitors, baseVisitor, state, override) {
  if (!baseVisitor) baseVisitor = base;
  // Frame: [node, st, type, expanded]
  const stack = [[node, state, override || node.type, false]];
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    if (frame[3]) {
      stack.pop();
      const visitor = visitors[frame[2]];
      if (visitor) visitor(frame[0], frame[1]);
      continue;
    }
    frame[3] = true;
    const children = childrenOf(baseVisitor, frame[2], frame[0], frame[1]);
    for (let i = children.length - 1; i >= 0; i--) {
      const c = children[i];
      stack.push([c.node, c.st, c.override || c.node.type, false]);
    }
  }
}

function ancestor(node, visitors, baseVisitor, state, override) {
  const ancestors = [];
  if (!baseVisitor) baseVisitor = base;
  // Frame: [node, st, type, expanded, pushedAncestor]
  const stack = [[node, state, override || node.type, false, false]];
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    if (frame[3]) {
      stack.pop();
      const visitor = visitors[frame[2]];
      if (visitor) visitor(frame[0], frame[1] || ancestors, ancestors);
      if (frame[4]) ancestors.pop();
      continue;
    }
    frame[3] = true;
    if (frame[0] !== ancestors[ancestors.length - 1]) {
      ancestors.push(frame[0]);
      frame[4] = true;
    }
    const children = childrenOf(baseVisitor, frame[2], frame[0], frame[1]);
    for (let i = children.length - 1; i >= 0; i--) {
      const c = children[i];
      stack.push([c.node, c.st, c.override || c.node.type, false, false]);
    }
  }
}

module.exports = { simple, ancestor, base };
