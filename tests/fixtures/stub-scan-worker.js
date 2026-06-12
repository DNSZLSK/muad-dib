'use strict';
// Stub scan-worker for the A0 message-dispatch tests (spawned by
// runScanInWorker via the MUADDIB_SCAN_WORKER_PATH test seam). Behavior is
// driven by workerData.scanContext._stub:
//   'side-then-result'  → posts a side-channel message, then a result
//   'side-only'         → posts a side-channel message, then stays alive
//                         (the static timeout must still fire)
//   'result'            → posts a result immediately
const { parentPort, workerData } = require('worker_threads');

const mode = (workerData && workerData.scanContext && workerData.scanContext._stub) || 'result';
const RESULT = { threats: [], summary: { total: 0, riskScore: 0 } };

if (mode === 'side-then-result') {
  parentPort.postMessage({ type: 'rate-token-request', id: 1, host: 'registry.npmjs.org' });
  parentPort.postMessage({ type: 'totally-unknown-type', blob: 'x' });
  setTimeout(() => parentPort.postMessage({ type: 'result', data: RESULT }), 50);
} else if (mode === 'side-only') {
  parentPort.postMessage({ type: 'rate-token-request', id: 2, host: 'registry.npmjs.org' });
  // Keep the worker alive well past the test's short timeout so the ONLY way
  // the promise can settle is the timer (ref'd timeout, then exit cleanly).
  setTimeout(() => {}, 5000);
} else {
  parentPort.postMessage({ type: 'result', data: RESULT });
}
