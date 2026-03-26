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

const { run } = require('./index.js');

(async () => {
  try {
    const result = await run(workerData.extractedDir, { _capture: true });
    parentPort.postMessage({ type: 'result', data: result });
  } catch (err) {
    parentPort.postMessage({ type: 'error', message: err.message || String(err) });
  }
})();
