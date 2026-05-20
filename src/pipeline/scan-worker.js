'use strict';

/**
 * Worker thread entry point for static analysis.
 * Runs the full scan pipeline in an isolated V8 isolate.
 * The parent can call worker.terminate() to kill synchronous code
 * (V8::TerminateExecution) — this is the only way to enforce a real
 * timeout on synchronous AST parsing and tree-walking.
 *
 * Communication:
 *   parentPort.postMessage({ type: 'result', data: scanResult })
 *   parentPort.postMessage({ type: 'error', message: string })
 */

const { parentPort, workerData } = require('worker_threads');

if (!parentPort) {
  // Not running as a worker — exit gracefully
  process.exit(1);
}

const { run } = require('../index.js');

(async () => {
  try {
    // scanContext (optional) carries monitor-side info that opt-in scanners need
    // (e.g. trusted-dep-diff requires package name + version to query the registry).
    // It is spread INTO the pipeline options, but `_capture: true` always wins so
    // the worker keeps returning the result object — never prints.
    const scanContext = workerData.scanContext || {};
    const result = await run(workerData.extractedDir, { ...scanContext, _capture: true });
    parentPort.postMessage({ type: 'result', data: result });
  } catch (err) {
    parentPort.postMessage({ type: 'error', message: err.message || String(err) });
  }
})();
