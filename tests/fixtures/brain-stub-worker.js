'use strict';
// Stub worker for the phase-A network-brain tests. Spawned through
// runScanInWorker (MUADDIB_SCAN_WORKER_PATH seam) so the FULL production
// plumbing is exercised: workerData.rateBrain → http-limiter proxy mode →
// parentPort messages → queue.js registered handlers → main-thread brain.
// Behavior driven by workerData.scanContext:
//   _brain: 'tokens'        → request `_count` tokens on `_host`, report grant timestamps
//   _brain: 'signal-429'    → signal a 429 on `_host`, then report
//   _brain: 'request-hang'  → leave one token request pending and stay alive (kill test)
const { parentPort, workerData } = require('worker_threads');
const limiter = require('../../src/shared/http-limiter.js');

const ctx = (workerData && workerData.scanContext) || {};
const host = ctx._host || 'registry.npmjs.org';

(async () => {
  if (ctx._brain === 'tokens') {
    const stamps = [];
    for (let i = 0; i < (ctx._count || 5); i++) {
      const { granted } = await limiter.awaitRateToken(host, { maxWaitMs: ctx._maxWaitMs || 30000 });
      stamps.push({ t: Date.now(), granted });
    }
    parentPort.postMessage({ type: 'result', data: { stamps } });
  } else if (ctx._brain === 'signal-429') {
    limiter.signal429(host);
    // Give the fire-and-forget message a beat to reach the main thread.
    setTimeout(() => parentPort.postMessage({ type: 'result', data: { sent: true } }), 100);
  } else if (ctx._brain === 'request-hang') {
    limiter.awaitRateToken(host, { maxWaitMs: 60000 }); // deliberately left pending
    parentPort.postMessage({ type: 'result', data: { requested: true } });
    setTimeout(() => {}, 60000); // stay alive until terminated
  } else {
    parentPort.postMessage({ type: 'result', data: {} });
  }
})().catch(e => parentPort.postMessage({ type: 'error', message: e.message }));
