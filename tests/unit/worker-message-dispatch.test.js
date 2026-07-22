const { asyncTest, assert } = require('../test-utils');
const path = require('path');

/**
 * A0 (governors program): runScanInWorker message dispatch.
 *
 * Regression context (2026-06-12 pressure-test, F-A1): the previous handler
 * called done() on EVERY worker message — a single non-result message settled
 * nothing but disarmed the static timeout, removed the worker from
 * _liveWorkers (invisible to terminateAllWorkers) and left the scan promise
 * pending until the outer 300s abort. The dispatch now settles ONLY on
 * 'result'/'error'; other types go to registerWorkerMessageHandler handlers;
 * unknown types are ignored.
 *
 * Uses the MUADDIB_SCAN_WORKER_PATH test seam (read at call time) to spawn a
 * stub worker that emits side-channel types the real scan-worker never sends.
 */

const STUB = path.join(__dirname, '..', 'fixtures', 'stub-scan-worker.js');

async function runWorkerMessageDispatchTests() {
  console.log('\n=== WORKER MESSAGE DISPATCH TESTS (A0) ===\n');

  const queue = require('../../src/monitor/queue.js');

  async function withStub(fn) {
    const saved = process.env.MUADDIB_SCAN_WORKER_PATH;
    process.env.MUADDIB_SCAN_WORKER_PATH = STUB;
    try { return await fn(); } finally {
      if (saved === undefined) delete process.env.MUADDIB_SCAN_WORKER_PATH;
      else process.env.MUADDIB_SCAN_WORKER_PATH = saved;
    }
  }

  await asyncTest('A0: side-channel messages reach their registered handler and the scan still resolves', async () => {
    await withStub(async () => {
      const seen = [];
      // Own test type: registering over a PRODUCTION type (rate-token-request)
      // would replace the network-brain grant handler for the whole process.
      queue.registerWorkerMessageHandler('test-side-channel', (worker, msg) => {
        seen.push(msg);
      });
      try {
        const result = await queue.runScanInWorker('/tmp/does-not-matter', 5000,
          { name: 'stub-pkg', version: '1.0.0', _stub: 'side-then-result' });
        assert(result && result.summary && result.summary.total === 0,
          'scan resolves with the stub result despite earlier side-channel messages');
        assert(seen.length === 1 && seen[0].id === 1 && seen[0].host === 'registry.npmjs.org',
          `registered handler received the side-channel message exactly once (got ${seen.length})`);
      } finally {
        // Do not leak the test handler into the process-global registry (it would
        // outlive this test and affect later suites sharing queue.js).
        queue.unregisterWorkerMessageHandler('test-side-channel');
      }
    });
  });

  await asyncTest('A0: an unknown message type alone does NOT settle the scan — the static timeout still fires', async () => {
    await withStub(async () => {
      const t0 = Date.now();
      let timedOut = false;
      try {
        await queue.runScanInWorker('/tmp/does-not-matter', 600,
          { name: 'stub-pkg-2', version: '1.0.0', _stub: 'side-only' });
      } catch (e) {
        timedOut = /timeout/i.test(e.message);
      }
      const elapsed = Date.now() - t0;
      assert(timedOut, 'the scan must end via the static timeout, not via the side-channel message');
      assert(elapsed >= 550, `the 600ms timer must NOT be disarmed by the side-channel message (elapsed ${elapsed}ms)`);
    });
  });

  await asyncTest('A0: a worker emitting side-channel messages stays visible to terminateAllWorkers', async () => {
    await withStub(async () => {
      const p = queue.runScanInWorker('/tmp/does-not-matter', 4000,
        { name: 'stub-pkg-3', version: '1.0.0', _stub: 'side-only' });
      // Give the worker time to boot and post its side-channel message.
      await new Promise(r => setTimeout(r, 400));
      const killed = queue.terminateAllWorkers();
      assert(killed >= 1, `worker must still be in _liveWorkers after a side-channel message (terminated ${killed})`);
      // Worker exit code from terminate() is non-zero → the scan rejects; both
      // outcomes (exit-code reject / abort) are acceptable, it must just settle.
      let settled = false;
      try { await p; settled = true; } catch { settled = true; }
      assert(settled, 'the scan promise settles after terminate');
    });
  });

  await asyncTest('A0: handler exceptions never break the scan', async () => {
    await withStub(async () => {
      queue.registerWorkerMessageHandler('totally-unknown-type', () => {
        throw new Error('handler bug');
      });
      try {
        const result = await queue.runScanInWorker('/tmp/does-not-matter', 5000,
          { name: 'stub-pkg-4', version: '1.0.0', _stub: 'side-then-result' });
        assert(result && result.summary,
          'a throwing side-channel handler must not reject or hang the scan');
      } finally {
        // A throwing handler must not persist into other suites.
        queue.unregisterWorkerMessageHandler('totally-unknown-type');
      }
    });
  });
}

module.exports = { runWorkerMessageDispatchTests };
