'use strict';

/**
 * Worker memory watermark — pure decision core (governors phase B).
 *
 * The original watchdog compared `process.memoryUsage().heapUsed` alone to a
 * threshold. That misses everything off the V8 heap: extraction Buffers and
 * large external strings live in `external`/`arrayBuffers` — the allocations behind
 * the 2026-06-12 RSS emergencies (heap 4%, RSS 96%). The combined metric is
 * heapUsed + external + arrayBuffers (all isolate-local, all already sampled
 * by worker-mem attribution).
 *
 * Threshold resolution:
 *   - MUADDIB_WORKER_MEM_WATERMARK_MB: the combined-metric threshold.
 *     Default 2600 — deliberately above the old heap-only 2200: legitimate
 *     ~1.3GB-heap scans also carry external buffers, and a too-tight combined
 *     threshold would convert them into watermark-inconclusive (coverage loss).
 *   - Legacy MUADDIB_WORKER_HEAP_WATERMARK_MB (if set and the new env is not):
 *     its VALUE is honored but applied to the COMBINED metric — keeping the
 *     old env name from silently re-opening the off-heap blind spot.
 *   - 0 disables the watchdog (either env).
 */

const DEFAULT_MEM_WATERMARK_MB = 2600;

function watermarkLimitMb(env = process.env) {
  const combined = parseInt(env.MUADDIB_WORKER_MEM_WATERMARK_MB, 10);
  if (Number.isFinite(combined) && combined >= 0) return combined;
  const legacy = parseInt(env.MUADDIB_WORKER_HEAP_WATERMARK_MB, 10);
  if (Number.isFinite(legacy) && legacy >= 0) return legacy;
  return DEFAULT_MEM_WATERMARK_MB;
}

/** Combined isolate-local footprint in bytes. */
function combinedWorkerMemBytes(mem) {
  return (mem.heapUsed || 0) + (mem.external || 0) + (mem.arrayBuffers || 0);
}

/**
 * Pure breach check. `mem` is a process.memoryUsage() sample (or any object
 * with heapUsed/external/arrayBuffers). limitMb 0 → never breaches.
 */
function watermarkBreached(mem, limitMb) {
  if (!limitMb || limitMb <= 0) return false;
  return combinedWorkerMemBytes(mem) > limitMb * 1024 * 1024;
}

module.exports = {
  DEFAULT_MEM_WATERMARK_MB,
  watermarkLimitMb,
  combinedWorkerMemBytes,
  watermarkBreached
};
