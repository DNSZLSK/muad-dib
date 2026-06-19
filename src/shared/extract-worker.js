'use strict';

/**
 * Worker-thread entry for off-main-thread archive extraction (OOM fix 2026-06-19).
 *
 * extractArchive() runs a SYNCHRONOUS extractor — adm-zip `extractAllTo` (.zip/
 * .whl) or `execFileSync('tar', …)` (.tgz). On the main thread that wedges the
 * event loop for the whole extraction (measured: up to 148s on large packages,
 * data/loop-stalls.jsonl). With the loop wedged the RSS circuit breaker, the
 * memory governor's RSS feed, and the EMERGENCY queue purge — all main-thread
 * `setInterval` timers (daemon.js) — never fire, so RSS climbs to the cgroup
 * MemoryMax unchecked → kernel SIGKILL. Running the same sync extractor here
 * blocks only the WORKER loop; the parent's loop stays live so those defenses run.
 *
 * Contract: workerData = { archivePath, destDir, format }. Posts exactly one
 * message — { ok: true, dir } on success, { ok: false, error } on failure — and
 * never throws to the thread (the parent also handles a worker 'error', but an
 * explicit message keeps the failure path uniform). All extraction hardening
 * (zip-slip, zip-bomb uncompressed-size cap) lives in extractArchive and runs here.
 */
const { workerData, parentPort } = require('worker_threads');
const { extractArchive } = require('./download.js');

try {
  const opts = workerData && workerData.format ? { format: workerData.format } : {};
  const dir = extractArchive(workerData.archivePath, workerData.destDir, opts);
  parentPort.postMessage({ ok: true, dir });
} catch (err) {
  parentPort.postMessage({ ok: false, error: err && err.message ? err.message : String(err) });
}
