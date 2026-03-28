'use strict';

const { MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS, MAX_TAINT_DEPTH } = require('./constants.js');
const { parseFile, resolveLocal, isLocalImport, toRel, isFileExists } = require('./parse-utils.js');
const { buildModuleGraph, extractLocalImports, tryResolveConcatRequire } = require('./build-graph.js');
const { annotateTaintedExports } = require('./annotate-tainted.js');
const { detectCrossFileFlows } = require('./detect-cross-file.js');
const { annotateSinkExports } = require('./annotate-sinks.js');
const { detectCallbackCrossFileFlows } = require('./detect-callback-flows.js');
const { detectEventEmitterFlows } = require('./detect-event-flows.js');

module.exports = {
  buildModuleGraph, annotateTaintedExports, detectCrossFileFlows,
  annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows,
  resolveLocal, extractLocalImports, parseFile, isLocalImport, toRel, isFileExists,
  tryResolveConcatRequire,
  MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS, MAX_TAINT_DEPTH
};
