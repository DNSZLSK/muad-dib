'use strict';

/**
 * Persistent worker-thread pool for off-main-thread archive extraction.
 *
 * Why a pool, not download.js extractArchiveOffThread (spawn-per-call): the
 * monitor extracts thousands of small packages on its main thread. The
 * spawn-per-call offloader pays a fresh Worker (V8 isolate + module load,
 * ~10-40ms) every time, which is why queue.js gated it to archives > 4MB and
 * ran everything smaller INLINE (synchronous extractArchive). Those inline
 * extractions are exactly what wedge the event loop: adm-zip `extractAllTo` is
 * fully synchronous and slow on many-file trees regardless of total size
 * (data/loop-stalls.jsonl: `extract:prework` up to 229s; a 2MB many-file
 * package blocks 5s+). A wedged loop starves the RSS breaker / memory governor /
 * EMERGENCY purge (all main-thread timers) → restart.
 *
 * A pool of N reusable workers removes BOTH costs: no extraction ever runs on
 * the main thread (at any size), and there is no per-package spawn. The size
 * gate in queue.js then becomes unnecessary (its inline window defaults to 0).
 *
 * Each worker runs extract-pool-worker.js — a request/response loop that calls
 * the SAME extractArchive, so all hardening (zip-slip, zip-bomb uncompressed
 * cap) stays centralized there and runs in the worker.
 *
 * Bounded + crash-resilient (CLAUDE.md "Production Engineering"):
 *  - POOL_SIZE workers max, spawned lazily on demand; idle workers are `unref`'d
 *    so the pool never keeps the process alive on its own.
 *  - One job per worker; excess jobs wait in a FIFO bounded to MAX_PENDING —
 *    past the cap a job rejects immediately (the caller treats it as an extract
 *    failure → size_skip, ledgered) so a slow extractor cannot grow memory
 *    without bound.
 *  - Per-job timeout terminates and drops a wedged worker and rejects that job —
 *    a pathological archive cannot pin a slot forever.
 *  - A worker that errors or exits mid-job rejects its in-flight job and is
 *    removed; the next dispatch lazily respawns up to POOL_SIZE.
 */

const path = require('path');

const POOL_SIZE = (() => {
  const v = parseInt(process.env.MUADDIB_EXTRACT_POOL_SIZE, 10);
  if (Number.isFinite(v) && v >= 1) return v;
  let cores = 4;
  try { cores = require('os').cpus().length || 4; } catch { /* default 4 */ }
  return Math.max(2, Math.min(4, cores - 2));
})();

const JOB_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.MUADDIB_EXTRACT_POOL_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 120_000;
})();

const MAX_PENDING = (() => {
  const v = parseInt(process.env.MUADDIB_EXTRACT_POOL_MAX_PENDING, 10);
  return Number.isFinite(v) && v > 0 ? v : 512;
})();

const WORKER_FILE = path.join(__dirname, 'extract-pool-worker.js');

// Pool state (lazy-init on first extractInPool). Each worker entry:
// { worker, busy, job }. `pending` is the FIFO of jobs waiting for a free slot.
let workers = [];
let pending = [];
let jobSeq = 0;
let destroyed = false;

function _settle(job, err, dir) {
  if (job.settled) return;
  job.settled = true;
  if (job.timer) { clearTimeout(job.timer); job.timer = null; }
  if (err) job.reject(err);
  else job.resolve(dir);
}

function _removeWorker(entry) {
  const i = workers.indexOf(entry);
  if (i !== -1) workers.splice(i, 1);
}

function _spawnWorker() {
  const { Worker } = require('worker_threads');
  const entry = { worker: null, busy: false, job: null };
  const w = new Worker(WORKER_FILE);
  entry.worker = w;
  // Idle workers must not keep the process alive; an in-flight job is kept alive
  // by the caller's awaited Promise, not by the worker handle.
  if (typeof w.unref === 'function') w.unref();
  w.on('message', (msg) => _onMessage(entry, msg));
  w.on('error', (err) => _onWorkerError(entry, err));
  w.on('exit', (code) => _onWorkerExit(entry, code));
  workers.push(entry);
  return entry;
}

function _onMessage(entry, msg) {
  const job = entry.job;
  entry.busy = false;
  entry.job = null;
  if (job && msg && msg.id === job.id) {
    if (msg.ok) _settle(job, null, msg.dir);
    else _settle(job, new Error(msg.error || 'extract-pool: worker reported failure'));
  }
  _dispatch();
}

function _onWorkerError(entry, err) {
  const job = entry.job;
  entry.busy = false;
  entry.job = null;
  _removeWorker(entry);
  if (job) _settle(job, err instanceof Error ? err : new Error(String(err)));
  _dispatch();
}

function _onWorkerExit(entry, code) {
  const job = entry.job;
  entry.busy = false;
  entry.job = null;
  _removeWorker(entry);
  if (job) _settle(job, new Error(`extract-pool: worker exited (${code}) mid-job`));
  _dispatch();
}

function _assign(entry, job) {
  entry.busy = true;
  entry.job = job;
  job.timer = setTimeout(() => {
    // Worker is wedged on a pathological archive: terminate it (best-effort) and
    // drop it from the pool, reject the job, let _dispatch respawn lazily.
    entry.busy = false;
    entry.job = null;
    _removeWorker(entry);
    try { entry.worker.terminate(); } catch { /* already gone */ }
    _settle(job, new Error(`extract-pool: timeout after ${JOB_TIMEOUT_MS}ms: ${path.basename(job.archivePath)}`));
    _dispatch();
  }, JOB_TIMEOUT_MS);
  if (job.timer && typeof job.timer.unref === 'function') job.timer.unref();
  entry.worker.postMessage({ id: job.id, archivePath: job.archivePath, destDir: job.destDir, format: job.format });
}

function _dispatch() {
  if (destroyed) return;
  while (pending.length > 0) {
    let entry = workers.find((e) => !e.busy);
    if (!entry) {
      if (workers.length < POOL_SIZE) entry = _spawnWorker();
      else break; // all workers busy and at cap — wait for a completion
    }
    _assign(entry, pending.shift());
  }
}

/**
 * Extract an archive off the main thread via the pool. Same contract as
 * download.js extractArchive (resolves to the extracted package root) but never
 * blocks the caller's event loop.
 *
 * @param {string} archivePath
 * @param {string} destDir  - must already exist
 * @param {Object} [options]
 * @param {'targz'|'zip'} [options.format] - override auto-detection
 * @returns {Promise<string>} extracted package root
 */
function extractInPool(archivePath, destDir, options = {}) {
  return new Promise((resolve, reject) => {
    if (destroyed) { reject(new Error('extract-pool: pool destroyed')); return; }
    if (pending.length >= MAX_PENDING) {
      reject(new Error(`extract-pool: pending queue full (${MAX_PENDING}) — extraction is not keeping up`));
      return;
    }
    const job = {
      id: ++jobSeq,
      archivePath,
      destDir,
      format: (options && options.format) || null,
      resolve,
      reject,
      settled: false,
      timer: null,
    };
    pending.push(job);
    _dispatch();
  });
}

/**
 * Terminate all workers and reject any in-flight / pending jobs. Idempotent and
 * reusable: after it resolves the pool lazily re-inits on the next extractInPool
 * (the daemon calls this once during gracefulShutdown; tests call it between
 * cases).
 * @returns {Promise<void>}
 */
async function destroyExtractPool() {
  destroyed = true;
  const inflight = workers.slice();
  const queued = pending.slice();
  workers = [];
  pending = [];
  for (const job of queued) _settle(job, new Error('extract-pool: pool destroyed'));
  await Promise.all(inflight.map((entry) => {
    if (entry.job) _settle(entry.job, new Error('extract-pool: pool destroyed'));
    try { return entry.worker.terminate(); } catch { return Promise.resolve(); }
  }));
  destroyed = false;
}

/** Observability snapshot (live workers / busy / pending), all bounded. */
function getPoolStats() {
  return {
    size: workers.length,
    max: POOL_SIZE,
    busy: workers.filter((e) => e.busy).length,
    pending: pending.length,
  };
}

module.exports = { extractInPool, destroyExtractPool, getPoolStats, POOL_SIZE };
