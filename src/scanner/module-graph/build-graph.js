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
const { findFiles, EXCLUDED_DIRS, debugLog } = require('../../utils');
const { MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_TAINT_DEPTH } = require('./constants.js');
const { parseFile, isLocalImport, resolveLocal, toRel } = require('./parse-utils.js');

/**
 * Build a dependency graph of local modules within a package.
 * Only tracks local imports (./  ../) — node_modules are ignored.
 *
 * @param {string} packagePath
 * @param {Object} [meta] - Optional out-param: mutated with { fileCount, truncated, maxNodes }
 *                          so the caller can emit a `large_package_graph_truncated` threat
 *                          when the package exceeds MAX_GRAPH_NODES (audit DF-C1).
 */
function buildModuleGraph(packagePath, meta = {}) {
  const graph = {};
  // maxFiles: 0 (unlimited) — we need the true count to detect monorepo / large package
  // truncation. MAX_GRAPH_NODES below caps the AST work; MODULE_GRAPH_TIMEOUT_MS in
  // executor.js bounds the wall-time (audit DF-C1).
  const files = findFiles(packagePath, {
    extensions: ['.js', '.mjs', '.cjs'],
    excludedDirs: EXCLUDED_DIRS,
    maxFiles: 0,
  });

  meta.fileCount = files.length;
  meta.maxNodes = MAX_GRAPH_NODES;

  // Bounded path: skip module graph for very large packages
  if (files.length > MAX_GRAPH_NODES) {
    debugLog(`[MODULE-GRAPH] Skipping: ${files.length} files exceeds MAX_GRAPH_NODES (${MAX_GRAPH_NODES})`);
    meta.truncated = true;
    return graph;
  }

  let totalEdges = 0;
  for (const absFile of files) {
    const relFile = toRel(absFile, packagePath);
    const imports = extractLocalImports(absFile, packagePath);
    totalEdges += imports.length;
    if (totalEdges > MAX_GRAPH_EDGES) {
      debugLog(`[MODULE-GRAPH] Edge limit reached (${totalEdges} > ${MAX_GRAPH_EDGES}), returning partial graph`);
      graph[relFile] = imports;
      break;
    }
    graph[relFile] = imports;
  }
  return graph;
}

function extractLocalImports(filePath, packagePath) {
  const ast = parseFile(filePath);
  if (!ast) return [];

  const imports = [];
  const fileDir = path.dirname(filePath);

  for (const node of ast.body) {
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      const spec = node.source.value;
      if (isLocalImport(spec)) {
        const resolved = resolveLocal(fileDir, spec, packagePath);
        if (resolved) imports.push(resolved);
      }
    }
  }
  walkForRequires(ast, fileDir, packagePath, imports);
  return [...new Set(imports)];
}

/**
 * Try to resolve string concatenation in require arguments.
 * require('./a' + '/b') → './a/b'
 * @param {Object} node - BinaryExpression AST node
 * @returns {string|null} Resolved string or null
 */
function tryResolveConcatRequire(node, depth) {
  if (depth === undefined) depth = 0;
  if (depth > 20) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = tryResolveConcatRequire(node.left, depth + 1);
    if (left === null) return null;
    const right = tryResolveConcatRequire(node.right, depth + 1);
    if (right === null) return null;
    return left + right;
  }
  return null;
}

function walkForRequires(node, fileDir, packagePath, imports, depth) {
  if (depth === undefined) depth = 0;
  if (depth > MAX_TAINT_DEPTH) return;
  if (!node || typeof node !== 'object') return;
  if (
    node.type === 'CallExpression' &&
    node.callee && node.callee.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments.length === 1
  ) {
    const arg = node.arguments[0];
    let spec = null;
    if (arg.type === 'Literal' && typeof arg.value === 'string') {
      spec = arg.value;
    } else if (arg.type === 'BinaryExpression') {
      // Fix #25: Resolve simple string concatenation in require args
      spec = tryResolveConcatRequire(arg);
    }
    if (spec && isLocalImport(spec)) {
      const resolved = resolveLocal(fileDir, spec, packagePath);
      if (resolved) imports.push(resolved);
    }
  }
  for (const key of Object.keys(node)) {
    if (key === 'type') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) {
          walkForRequires(item, fileDir, packagePath, imports, depth + 1);
        }
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkForRequires(child, fileDir, packagePath, imports, depth + 1);
    }
  }
}


module.exports = { buildModuleGraph, extractLocalImports, tryResolveConcatRequire };
