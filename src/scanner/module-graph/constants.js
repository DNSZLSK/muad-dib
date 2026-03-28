'use strict';

const { ACORN_OPTIONS: BASE_ACORN_OPTIONS } = require('../../shared/constants.js');

// --- Bounded path limits ---
const MAX_GRAPH_NODES = 100;  // Max files in dependency graph (covers ~86% of npm packages)
const MAX_GRAPH_EDGES = 400;  // Max total import edges
const MAX_FLOWS = 20;         // Max cross-file flow findings per package
const MAX_TAINT_DEPTH = 50;   // Max AST recursion depth (DoS guard)

// --- Sensitive source patterns ---
const SENSITIVE_MODULES = new Set(['fs', 'child_process', 'dns', 'os', 'dgram']);

const ACORN_OPTIONS = {
  ...BASE_ACORN_OPTIONS,
  allowReturnOutsideFunction: true,
  allowImportExportEverywhere: true,
};

// --- Sink patterns for cross-file detection ---
const SINK_CALLEE_NAMES = new Set(['fetch', 'eval', 'Function', 'WebSocket', 'XMLHttpRequest']);
const SINK_MEMBER_METHODS = new Set([
  'https.request', 'https.get', 'http.request', 'http.get',
  'child_process.exec', 'child_process.execSync', 'child_process.spawn',
  'dns.resolveTxt', 'dns.resolve', 'dns.resolve4', 'dns.resolve6',
]);
const SINK_INSTANCE_METHODS = new Set(['connect', 'write', 'send']);


module.exports = {
  MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS, MAX_TAINT_DEPTH,
  SENSITIVE_MODULES, ACORN_OPTIONS, SINK_CALLEE_NAMES, SINK_MEMBER_METHODS, SINK_INSTANCE_METHODS
};
