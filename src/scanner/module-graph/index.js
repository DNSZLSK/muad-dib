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

const { MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS, MAX_TAINT_DEPTH } = require('./constants.js');
const { parseFile, resolveLocal, isLocalImport, toRel, isFileExists } = require('./parse-utils.js');
const { buildModuleGraph, extractLocalImports, tryResolveConcatRequire } = require('./build-graph.js');
const { annotateTaintedExports } = require('./annotate-tainted.js');
const { detectCrossFileFlows, filterFirstPartyNetworkFlows } = require('./detect-cross-file.js');
const { annotateSinkExports } = require('./annotate-sinks.js');
const { detectCallbackCrossFileFlows } = require('./detect-callback-flows.js');
const { detectEventEmitterFlows } = require('./detect-event-flows.js');

module.exports = {
  buildModuleGraph, annotateTaintedExports, detectCrossFileFlows, filterFirstPartyNetworkFlows,
  annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows,
  resolveLocal, extractLocalImports, parseFile, isLocalImport, toRel, isFileExists,
  tryResolveConcatRequire,
  MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS, MAX_TAINT_DEPTH
};
