'use strict';

const { ACORN_OPTIONS: BASE_ACORN_OPTIONS } = require('../../shared/constants.js');

// --- Bounded path limits ---
const MAX_GRAPH_NODES = 5000; // Max files in dependency graph (covers ~99.5% of npm packages — audit DF-C1 v2.11.15)
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
const SINK_CALLEE_NAMES = new Set(['fetch', 'eval', 'Function', 'WebSocket', 'XMLHttpRequest', 'axios']);
const SINK_MEMBER_METHODS = new Set([
  'https.request', 'https.get', 'http.request', 'http.get',
  'child_process.exec', 'child_process.execSync', 'child_process.spawn',
  'dns.resolveTxt', 'dns.resolve', 'dns.resolve4', 'dns.resolve6',
  // axios as a cross-file network sink (axios.get(taintedData) etc.). Instance form
  // (const c = axios.create(); c.get(...)) is NOT added to SINK_INSTANCE_METHODS — that
  // would match every .get/.post receiver and explode FPs; it's a known follow-up gap.
  'axios.get', 'axios.post', 'axios.put', 'axios.patch', 'axios.delete', 'axios.request',
]);
const SINK_INSTANCE_METHODS = new Set(['connect', 'write', 'send']);

// Receiver roots that make connect/write/send LOCAL I/O or IPC, never external-network
// exfil: `process.stdout/stderr.write`, `process.send` (child IPC to the parent), and any
// `console.*`. SINK_INSTANCE_METHODS matches by method name alone, so without this a
// console/stderr write of a tainted value reads as a cross-file network sink (segment-A FP
// driver: contextdevkit, amicus). Real socket/ws/req sinks (receivers `socket`/`ws`/`req`/
// `net.connect()`…) are unaffected. Globals are trusted here as they are everywhere else.
const NON_NETWORK_SINK_RECEIVER_ROOTS = new Set(['process', 'console']);


module.exports = {
  MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS, MAX_TAINT_DEPTH,
  SENSITIVE_MODULES, ACORN_OPTIONS, SINK_CALLEE_NAMES, SINK_MEMBER_METHODS, SINK_INSTANCE_METHODS,
  NON_NETWORK_SINK_RECEIVER_ROOTS
};
