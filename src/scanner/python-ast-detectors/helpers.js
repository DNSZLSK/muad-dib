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
 * Shared helpers for Python AST detectors (mirror of `src/scanner/ast-detectors/helpers.js`).
 *
 * Tree-sitter-python CST primer:
 *  - `module`               : root node
 *  - `function_definition`  : `def f(...): ...`
 *  - `class_definition`     : `class C: ...`
 *  - `lambda`               : `lambda x: ...`
 *  - `call`                 : `f(arg1, kw=val)`  ; children fields: `function`, `arguments`
 *  - `attribute`            : `obj.attr`         ; children fields: `object`, `attribute`
 *  - `identifier`           : bare name
 *  - `string`               : full string literal (children: `string_start`, `string_content`, `string_end`)
 *  - `argument_list`        : positional + keyword args inside a call
 *  - `keyword_argument`     : `kw=val`            ; children fields: `name`, `value`
 *  - `dictionary` / `pair`  : `{k: v}` literal
 *  - `import_statement` / `import_from_statement`
 *
 * Scope tracking: a `function_definition`, `class_definition`, or `lambda` is a
 * "scope boundary". Anything strictly inside one of these has `scopeDepth >= 1`
 * and therefore does NOT execute at module import time. Anything at
 * `scopeDepth == 0` executes when the file is imported / installed — that's
 * the malicious surface we want to flag.
 */

const SCOPE_BOUNDARY_TYPES = new Set([
  'function_definition',
  'class_definition',
  'lambda'
]);

/**
 * Walks the CST and dispatches each node to the matching visitor in
 * `visitors[node.type]`. The visitor receives `(node, ctx, scopeDepth)`
 * where `scopeDepth` is the number of enclosing function/class/lambda
 * scopes at the point where this node lives.
 *
 * Visitors mutate `ctx.threats`. They MUST NOT mutate the AST.
 */
function walk(node, ctx, visitors, scopeDepth = 0) {
  if (!node) return;
  const visitor = visitors[node.type];
  if (visitor) {
    try {
      visitor(node, ctx, scopeDepth);
    } catch (e) {
      // A buggy detector must NEVER crash the whole scan. Log and move on.
      if (process.env.MUADDIB_DEBUG) {
        // eslint-disable-next-line no-console
        console.error(`[python-ast] visitor ${node.type} failed:`, e.message);
      }
    }
  }
  const childScope = SCOPE_BOUNDARY_TYPES.has(node.type) ? scopeDepth + 1 : scopeDepth;
  for (const child of node.children) {
    walk(child, ctx, visitors, childScope);
  }
}

/**
 * Returns the dotted-name string of an `attribute` or `identifier` callee.
 *  - `os.system` → "os.system"
 *  - `subprocess.Popen` → "subprocess.Popen"
 *  - `exec` → "exec"
 *  - `obj.method.chain` → "obj.method.chain"
 *  - anything weird → null
 */
function calleeDottedName(callNode) {
  const fn = callNode.childForFieldName('function');
  if (!fn) return null;
  return dottedName(fn);
}

function dottedName(node) {
  if (!node) return null;
  if (node.type === 'identifier') return node.text;
  if (node.type === 'attribute') {
    const obj = node.childForFieldName('object');
    const attr = node.childForFieldName('attribute');
    const left = dottedName(obj);
    if (!left || !attr) return null;
    return `${left}.${attr.text}`;
  }
  return null;
}

/**
 * Returns true if the call's argument_list contains a keyword argument
 * with `name === kwName` whose value matches `predicate(valueNode)`.
 */
function hasKeywordArg(callNode, kwName, predicate) {
  const args = callNode.childForFieldName('arguments');
  if (!args) return false;
  for (const child of args.children) {
    if (child.type !== 'keyword_argument') continue;
    const nameNode = child.childForFieldName('name');
    if (!nameNode || nameNode.text !== kwName) continue;
    const valueNode = child.childForFieldName('value');
    if (predicate(valueNode)) return true;
  }
  return false;
}

/**
 * Returns the first positional argument node of a call, or null.
 */
function firstPositionalArg(callNode) {
  const args = callNode.childForFieldName('arguments');
  if (!args) return null;
  for (const child of args.children) {
    if (child.type === 'keyword_argument') continue;
    if (child.type === '(' || child.type === ')' || child.type === ',') continue;
    return child;
  }
  return null;
}

/**
 * Returns the string content of a `string` node, or null if the node isn't
 * a plain string literal (f-strings with interpolation return null).
 */
function stringLiteralValue(node) {
  if (!node || node.type !== 'string') return null;
  // f-strings have interpolation children; bail out — value isn't a constant.
  for (const child of node.children) {
    if (child.type === 'interpolation') return null;
  }
  // Concatenate all string_content children. There can be more than one for
  // implicit string concatenation like "foo" "bar".
  let out = '';
  for (const child of node.children) {
    if (child.type === 'string_content') out += child.text;
  }
  return out;
}

/**
 * Returns true if the value node is a Python literal that evaluates truthy.
 * Used for `shell=True`-style kwarg checks. We accept `True` (identifier) and
 * the integer `1`.
 */
function isTruthyLiteral(valueNode) {
  if (!valueNode) return false;
  if (valueNode.type === 'true') return true;
  if (valueNode.type === 'identifier' && valueNode.text === 'True') return true;
  if (valueNode.type === 'integer' && valueNode.text === '1') return true;
  return false;
}

/**
 * Returns the row (1-indexed line number) where the node starts.
 */
function lineOf(node) {
  return node && node.startPosition ? node.startPosition.row + 1 : null;
}

module.exports = {
  walk,
  calleeDottedName,
  dottedName,
  hasKeywordArg,
  firstPositionalArg,
  stringLiteralValue,
  isTruthyLiteral,
  lineOf
};
