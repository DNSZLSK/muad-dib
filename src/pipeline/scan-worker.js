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

const { parentPort, workerData, threadId } = require('worker_threads');

if (!parentPort) {
  // Not running as a worker — exit gracefully
  process.exit(1);
}

const { run } = require('../index.js');
const { appendWorkerMem, sampleIntervalMs } = require('../monitor/worker-mem.js');

// Reactive heap watermark (C2 volet B): the static heavy-lane classifier
// predicts the peak from on-disk bytes and WILL miss cases (omnius: 39KB JS →
// 1347MB). This is the prediction-free backstop — the worker watches its OWN
// isolate heap and bails before it contributes to a process-wide RSS spike.
// CAVEAT: a watchdog timer can only fire when the event loop yields, so it
// catches PROGRESSIVE (multi-file, async-between-files) growth; a single
// synchronous 30MB parse never yields and is caught only by the V8 hard cap
// (MUADDIB_WORKER_MAX_OLD_MB resourceLimits). The two are complementary.
// Phase B (governors): the metric is COMBINED — heapUsed + external +
// arrayBuffers (watermark.js). heapUsed alone was blind to extraction
// Buffers/external strings: the 2026-06-12 RSS emergencies ran at heap 4% /
// RSS 96% and this watchdog stayed silent. Default 2600MB (above the old
// heap-only 2200: legitimate ~1.3GB-heap scans also carry external buffers —
// a too-tight combined threshold converts them into watermark-inconclusive).
// Legacy MUADDIB_WORKER_HEAP_WATERMARK_MB is honored as a VALUE if the new
// env is unset, but always applied to the combined metric. 0 disables.
const { watermarkLimitMb, watermarkBreached, combinedWorkerMemBytes } = require('./watermark.js');
const HEAP_WATERMARK_MB = watermarkLimitMb();
const HEAP_WATERMARK_CHECK_MS = 1000;

(async () => {
  // Off-heap attribution samples (worker-mem.jsonl): heapUsed/external/
  // arrayBuffers are isolate-local here, rss is process-wide. The samples go
  // to DISK, not through parentPort — historically because the parent settled
  // the scan promise on the first message of ANY type; the parent now
  // dispatches by msg.type (queue.js _workerMessageHandlers) and ignores
  // unknown types, but the samples stay on disk by design: they are offline
  // attribution data, and this sampler starves during long synchronous parses
  // anyway (exactly the moments that matter live) — the admission freeze keys
  // on process RSS instead. unref() so the timer never keeps the worker alive.
  const scanContext = workerData.scanContext || {};
  const everyMs = sampleIntervalMs();
  let sampler = null;
  if (everyMs > 0) {
    const sampleNow = () => {
      const m = process.memoryUsage();
      appendWorkerMem({
        ev: 'sample', tid: threadId,
        name: scanContext.name, version: scanContext.version,
        heapUsed: m.heapUsed, external: m.external, arrayBuffers: m.arrayBuffers, rss: m.rss
      });
    };
    // One immediate baseline sample, deterministically: a mostly-synchronous
    // scan (small package, sync AST walks, microtask-only awaits) can starve
    // the event loop for its whole lifetime, so the interval alone may never
    // fire (bit CI on 2026-06-11). The baseline also gives the per-package
    // delta a clean starting point.
    sampleNow();
    sampler = setInterval(sampleNow, everyMs);
    sampler.unref();
  }

  // Heap-watermark watchdog. On breach, post a tagged error and exit — the
  // parent maps the WORKER_HEAP_WATERMARK message onto its existing worker_oom
  // path (inconclusive, ledgered, NOT counted clean). NOT unref'd: while the
  // scan is in flight this watchdog must stay live to fire.
  let watchdog = null;
  if (HEAP_WATERMARK_MB > 0) {
    watchdog = setInterval(() => {
      const m = process.memoryUsage();
      if (watermarkBreached(m, HEAP_WATERMARK_MB)) {
        clearInterval(watchdog); watchdog = null;
        if (sampler) clearInterval(sampler);
        try {
          const usedMb = Math.round(combinedWorkerMemBytes(m) / 1024 / 1024);
          parentPort.postMessage({
            type: 'error',
            // Keep the WORKER_HEAP_WATERMARK tag: the parent's worker_oom
            // mapping (queue.js) matches on it.
            message: `WORKER_HEAP_WATERMARK: isolate memory (heap+external+arrayBuffers=${usedMb}MB) exceeded ${HEAP_WATERMARK_MB}MB (${scanContext.name}@${scanContext.version})`
          });
        } catch { /* parent gone */ }
        // Exit NON-ZERO so the parent settles even if the message above is lost
        // in the post/exit race: the worker.on('exit') handler rejects on any
        // non-zero code, and the catch matches WORKER_HEAP_WATERMARK when the
        // message did arrive, or the generic scan_error path when it didn't —
        // never clean, never a hung promise. (exit(0) would let the exit
        // handler no-op and hang the scan until the 300s outer timeout.)
        process.exit(1);
      }
    }, HEAP_WATERMARK_CHECK_MS);
  }
  try {
    // scanContext (optional) carries monitor-side info that opt-in scanners need
    // (e.g. trusted-dep-diff requires package name + version to query the registry).
    // It is spread INTO the pipeline options, but `_capture: true` always wins so
    // the worker keeps returning the result object — never prints.
    const result = await run(workerData.extractedDir, { ...scanContext, _capture: true });
    parentPort.postMessage({ type: 'result', data: result });
  } catch (err) {
    parentPort.postMessage({ type: 'error', message: err.message || String(err) });
  } finally {
    if (sampler) clearInterval(sampler);
    if (watchdog) clearInterval(watchdog);
  }
})();
