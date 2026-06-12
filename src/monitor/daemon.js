const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const v8 = require('v8');
const { isDockerAvailable, SANDBOX_CONCURRENCY_MAX, killAllSandboxContainers } = require('../sandbox/index.js');
const { banner } = require('../utils.js');
const { setVerboseMode, isSandboxEnabled, isCanaryEnabled, isLlmDetectiveEnabled, getLlmDetectiveMode, DOWNLOADS_CACHE_TTL } = require('./classify.js');
const { loadState, saveState, loadDailyStats, saveDailyStats, purgeTarballCache, isDailyReportDue, atomicWriteFileSync, saveNpmSeq, ALERTS_FILE, runStateMigrations, loadRecentlyScanned, saveRecentlyScanned } = require('./state.js');
const { isTemporalEnabled, isTemporalAstEnabled, isTemporalPublishEnabled, isTemporalMaintainerEnabled } = require('./temporal.js');
const { pendingGrouped, flushScopeGroup, sendDailyReport, redeliverPendingReportOnBoot, alertedPackageRules, ALERTED_PACKAGES_MAX: MAX_ALERTED_PACKAGES } = require('./webhook.js');
const { poll, getPollBackoffMs } = require('./ingestion.js');
const { ensureWorkers, drainWorkers, getTargetConcurrency, setTargetConcurrency, getActiveWorkers, terminateAllWorkers, getInFlightItems, computeInterruptDisposition } = require('./queue.js');
const { computeTarget, ADJUST_INTERVAL_MS, BASE_CONCURRENCY } = require('./adaptive-concurrency.js');
const { startHealthcheck } = require('./healthcheck.js');
const { startDeferredWorker, stopDeferredWorker, persistDeferredQueue, restoreDeferredQueue, clearDeferredQueue } = require('./deferred-sandbox.js');
const { evictFromScanQueueBulk, enqueueScan } = require('./scan-queue.js');
const { isSpillEnabled, shouldDrain, drainBacklog, getBacklogSize } = require('./spill.js');
const { startGhsaPoller, stopGhsaPoller } = require('../ioc/ghsa-poller.js');
const { cleanupOldArchives, getRetentionDays, startPeriodicCleanup } = require('./tarball-archive.js');
const { clearMetadataCache } = require('../scanner/temporal-analysis.js');
// Caches not previously cleared by handleMemoryPressure (OOM fix). These live
// in the main thread and are populated by temporal-ast-diff and the typosquat
// scanner, neither of which runs in the static-scan worker.
const { clearMetadataCache: clearTyposquatMetadataCache } = require('../scanner/typosquat.js');
const { clearFileListCache } = require('../utils.js');
const { clearASTCache } = require('../shared/constants.js');

const POLL_INTERVAL = 60_000;
const PROCESS_LOOP_INTERVAL = 2_000;    // Queue check interval when empty

// ── Spill drain (disk waiting list re-ingestion) ──
// Drain only when pressure is fully cleared AND the live queue has headroom; the
// 12 calm hours/day do the catch-up of burst-time evictions. Rate-limited to one
// batch per interval (the main loop ticks every 2s — unthrottled it would re-spike
// the queue in seconds). All env-tunable for the staged rollout.
// C7: how long the shutdown waits for in-flight scans before spilling them.
// Must stay well under systemd TimeoutStopSec (default 90s) so the ledger,
// spill and queue persist ALWAYS run before any SIGKILL.
const SHUTDOWN_DRAIN_MAX_MS = (() => {
  const v = parseInt(process.env.MUADDIB_SHUTDOWN_DRAIN_MAX_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 20_000;
})();

const SPILL_DRAIN_THRESHOLD = (() => {
  const v = parseInt(process.env.MUADDIB_SPILL_DRAIN_THRESHOLD, 10);
  return Number.isFinite(v) && v > 0 ? v : 500;
})();
const SPILL_DRAIN_BATCH = (() => {
  const v = parseInt(process.env.MUADDIB_SPILL_DRAIN_BATCH, 10);
  return Number.isFinite(v) && v > 0 ? v : 200;
})();
const SPILL_DRAIN_INTERVAL_MS = (() => {
  const v = parseInt(process.env.MUADDIB_SPILL_DRAIN_INTERVAL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 30_000;
})();
const QUEUE_WARNING_THRESHOLD = 5_000;  // Warn if queue depth exceeds this
const QUEUE_PERSIST_INTERVAL = 60_000;  // Persist queue to disk every 60s
const QUEUE_STATE_FILE = path.join(__dirname, '..', '..', 'data', 'queue-state.json');
const QUEUE_STATE_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24h expiry
const MAX_QUEUE_PERSIST_SIZE = 200_000; // Don't persist if queue > 200K items (OOM guard)
const MAX_RESTORE_QUEUE_SIZE = 100_000; // Cap restored queue at 100K items

// ─── Poll-loop watchdog ───
// The decoupled poll runs on a setInterval guarded by a `pollInProgress` flag.
// If a poll cycle's awaited promise never settles (e.g. an HTTP response whose
// body trickles forever, so the socket-inactivity timeout in httpsGet never
// fires and it only resolves on 'end'), `pollInProgress` would stay `true` and
// every subsequent tick would silently early-return — wedging ingestion at 0
// scanned until a manual `systemctl restart`. The watchdog bounds every cycle
// so the flag is ALWAYS released; shouldSkipPoll() adds a stale-flag backstop
// for any future hang path that bypasses runPollCycle().
const POLL_WATCHDOG_MS = Math.max(60_000, parseInt(process.env.MUADDIB_POLL_WATCHDOG_MS, 10) || 300_000);

/**
 * Run ONE poll cycle bounded by a watchdog so the caller's pollInProgress flag
 * can never stay stuck. On timeout it REJECTS (does not resolve) with a
 * 'poll watchdog' error, so the caller's existing catch logs it and the finally
 * resets the flag — the next tick retries. The local timer is cleared on every
 * settle path, so a fast poll leaves no dangling timer.
 * @param {Function} pollFn - injectable for tests; defaults to the real poll().
 * @returns {Promise<void>}
 */
async function runPollCycle(state, scanQueue, stats, watchdogMs = POLL_WATCHDOG_MS, pollFn = poll) {
  let timer;
  const watchdog = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`poll watchdog: poll exceeded ${Math.round(watchdogMs / 1000)}s`)),
      watchdogMs
    );
  });
  try {
    await Promise.race([pollFn(state, scanQueue, stats), watchdog]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Decide whether the poll scheduler should skip this tick, and whether the
 * pollInProgress flag is stale enough to force-reset. Pure — unit-testable
 * without timers. forceReset fires only when a cycle has been "in flight" for
 * longer than watchdogMs + one interval, i.e. a hang path that bypassed the
 * per-cycle watchdog (runPollCycle always settles within watchdogMs).
 * @returns {{skip: boolean, forceReset: boolean}}
 */
function shouldSkipPoll(pollInProgress, pollStartedAt, now, watchdogMs, interval) {
  if (!pollInProgress) return { skip: false, forceReset: false };
  if (now - pollStartedAt > watchdogMs + interval) return { skip: false, forceReset: true };
  return { skip: true, forceReset: false };
}

// ─── Heap diagnostics (restart root-cause) ───
// mem-trend shows the main-thread heap balloons to 6-7GB in the worker-starved
// regime while documented structures sum to <1GB — i.e. ~5GB+ unaccounted. These
// helpers localise it: a cheap always-on heap-spaces line (retention vs churn)
// plus an OPT-IN, disk-guarded, one-shot v8 heap snapshot for dominator-tree
// analysis. Snapshot is OFF unless MUADDIB_HEAPSNAPSHOT_MB is set (writing a
// multi-GB snapshot blocks the event loop ~10-60s — must be deliberate).
const HEAPSNAPSHOT_MB = parseInt(process.env.MUADDIB_HEAPSNAPSHOT_MB, 10) || 0; // 0 = disabled
const HEAPSNAPSHOT_MIN_FREE_GB = Math.max(1, parseInt(process.env.MUADDIB_HEAPSNAPSHOT_MIN_FREE_GB, 10) || 12);
const HEAPSNAPSHOT_DIR = process.env.MUADDIB_HEAPSNAPSHOT_DIR || path.join(__dirname, '..', '..', 'data');
let heapSnapshotTaken = false;

/**
 * Pure decision: write a heap snapshot now? Separated from the I/O so it is
 * unit-testable without producing a multi-GB file.
 * @returns {{take: boolean, reason: string}}
 */
function shouldSnapshot(heapUsedMB, thresholdMB, alreadyTaken, freeGB, minFreeGB) {
  if (!thresholdMB || thresholdMB <= 0) return { take: false, reason: 'disabled' };
  if (alreadyTaken) return { take: false, reason: 'already-taken' };
  if (heapUsedMB < thresholdMB) return { take: false, reason: 'below-threshold' };
  if (freeGB < minFreeGB) return { take: false, reason: `low-disk(${Math.round(freeGB)}<${minFreeGB}GB)` };
  return { take: true, reason: 'ok' };
}

/**
 * Compact one-line summary of v8.getHeapSpaceStatistics() used sizes (MB).
 * old_space high ⇒ retained objects (leak); large_object_space high ⇒ big
 * strings/arrays; new_space high ⇒ allocation churn. Pure — unit-testable.
 */
function formatHeapSpaces(stats) {
  return (stats || [])
    .map(s => `${s.space_name}=${(s.space_used_size / 1024 / 1024).toFixed(0)}`)
    .join(' ');
}

function getFreeDiskGB(dir) {
  try {
    const st = fs.statfsSync(dir);
    return (st.bavail * st.bsize) / (1024 ** 3);
  } catch {
    return Infinity; // statfsSync unavailable (older Node) — don't block on disk
  }
}

// Opt-in, one-shot, disk-guarded heap snapshot. BLOCKS the event loop while
// writing (≈ size of the live heap) — only fires when explicitly enabled.
function maybeHeapSnapshot(heapUsedMB) {
  if (!HEAPSNAPSHOT_MB || heapSnapshotTaken || heapUsedMB < HEAPSNAPSHOT_MB) return;
  const decision = shouldSnapshot(heapUsedMB, HEAPSNAPSHOT_MB, heapSnapshotTaken, getFreeDiskGB(HEAPSNAPSHOT_DIR), HEAPSNAPSHOT_MIN_FREE_GB);
  if (!decision.take) {
    console.log(`[MONITOR] HEAP-SNAPSHOT skipped: ${decision.reason} (heap=${heapUsedMB}MB)`);
    return;
  }
  heapSnapshotTaken = true; // set BEFORE writing so a failed/slow write can't loop
  const file = path.join(HEAPSNAPSHOT_DIR, `heap-${new Date().toISOString().replace(/[:.]/g, '-')}.heapsnapshot`);
  try {
    console.log(`[MONITOR] HEAP-SNAPSHOT writing (heap=${heapUsedMB}MB) → ${file} — blocks the event loop`);
    v8.writeHeapSnapshot(file);
    console.log(`[MONITOR] HEAP-SNAPSHOT written → ${file} (scp it off + open in Chrome DevTools → dominator tree)`);
  } catch (err) {
    console.error(`[MONITOR] HEAP-SNAPSHOT failed: ${err.message}`);
  }
}

// ─── Memory pressure circuit breaker ───
// Graduated response based on V8 heap usage against heap_size_limit.
// Threat model: when GC thrashing starts (>90% heap limit), throughput drops to 0
// and the queue grows unbounded because ingestion continues. Without a circuit
// breaker, the only recovery is OOM kill or manual restart.
//
// Denominator: v8.getHeapStatistics().heap_size_limit (NOT process.memoryUsage().heapTotal).
// V8 dynamically adjusts heapTotal so heapUsed/heapTotal is structurally 70-85%
// even when actual usage is 0.1% of the --max-old-space-size limit. heap_size_limit
// reflects the actual V8 ceiling (~3264MB with --max-old-space-size=3072).
//
// Levels:
//   NONE    (<75%)  — normal operation
//   ELEVATED (75%)  — log warning, reduce concurrency target
//   HIGH    (85%)  — prune caches, stop spawning new workers
//   CRITICAL (90%) — stop ingestion, clear scanner caches, force GC
//   EMERGENCY (95%) — truncate queue to most recent N items, clear deferred queue
//
// The key insight from the 2026-04-13 incident: emergency prune at 85% only cleared
// ~4MB of auxiliary caches (recentlyScanned, downloadsCache, alertedPackageRules) on a
// 3571MB heap. The real memory was held by N concurrent scan workers retaining AST trees,
// scan results, and extracted file references. Stopping worker spawning is the only way
// to let running scans finish and release their memory.
const MEMORY_PRESSURE_LEVELS = {
  NONE: 0,
  ELEVATED: 1,
  HIGH: 2,
  CRITICAL: 3,
  EMERGENCY: 4
};
const MEMORY_THRESHOLD_ELEVATED = 0.75;
const MEMORY_THRESHOLD_HIGH = 0.85;
const MEMORY_THRESHOLD_CRITICAL = 0.90;
const MEMORY_THRESHOLD_EMERGENCY = 0.92;
// RSS budget (OOM fix). The heap thresholds above miss the real failure mode: the
// process dies from total RSS (off-heap — worker isolates, gVisor sandboxes, tarball
// buffers) while heapUsed/heap_size_limit sits at ~20%. Gate on
// process.memoryUsage().rss against an absolute budget so EMERGENCY fires before the
// kernel OOM-killer. Default 8500MB on the 11.7GB VPS (~3GB headroom for
// docker / gVisor / kernel). Override via MUADDIB_RSS_LIMIT_MB.
const RSS_LIMIT_MB = (() => {
  const parsed = parseInt(process.env.MUADDIB_RSS_LIMIT_MB, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 8500;
})();
// When truncating queue under EMERGENCY, keep the N most recent items.
// These are the newest packages — most likely to still be on npm for re-scan.
const EMERGENCY_QUEUE_KEEP = 500;
// Memory check interval adapts: 5min under NONE/ELEVATED, 15s under HIGH+.
// Fast checks are critical because at 50 pkg/min ingestion, 5min = 250 new items.
const MEMORY_LOG_INTERVAL_NORMAL = 300_000;   // 5 minutes
const MEMORY_LOG_INTERVAL_PRESSURE = 15_000;  // 15 seconds
let _memoryPressureLevel = MEMORY_PRESSURE_LEVELS.NONE;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Persist scanQueue to disk so it survives restarts.
 * Uses atomicWriteFileSync (write-to-tmp + rename) for crash safety.
 * Skips if queue is empty or exceeds MAX_QUEUE_PERSIST_SIZE.
 */
function persistQueue(scanQueue, state) {
  try {
    if (scanQueue.length === 0) {
      // Empty queue — remove stale file if it exists
      try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
      return;
    }
    if (scanQueue.length > MAX_QUEUE_PERSIST_SIZE) {
      console.log(`[MONITOR] WARNING: queue too large to persist (${scanQueue.length} > ${MAX_QUEUE_PERSIST_SIZE})`);
      return;
    }
    const payload = JSON.stringify({
      savedAt: new Date().toISOString(),
      lastSeq: state.npmLastSeq || null,
      count: scanQueue.length,
      items: scanQueue
    });
    atomicWriteFileSync(QUEUE_STATE_FILE, payload);
  } catch (err) {
    console.error('[MONITOR] Failed to persist queue:', err.message);
  }
}

/**
 * Restore scanQueue from disk on boot. Items are appended to the (empty) scanQueue.
 * File is deleted after successful restore to prevent double-restore.
 * Skips if file is missing, corrupt, or older than 24h.
 */
function restoreQueue(scanQueue) {
  // Cleanup orphan .tmp from previous crash / disk-full (ENOSPC)
  const tmpFile = QUEUE_STATE_FILE + '.tmp';
  try {
    if (fs.existsSync(tmpFile)) {
      console.log(`[MONITOR] Cleaning up orphan ${path.basename(tmpFile)}`);
      fs.unlinkSync(tmpFile);
    }
  } catch { /* best-effort */ }

  try {
    if (!fs.existsSync(QUEUE_STATE_FILE)) return 0;
    const raw = fs.readFileSync(QUEUE_STATE_FILE, 'utf8');
    const data = JSON.parse(raw);

    // Validate structure
    if (!data || !Array.isArray(data.items) || !data.savedAt) {
      console.log('[MONITOR] Queue state file invalid — ignoring');
      try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
      return 0;
    }

    // Check age — discard if > 24h
    const ageMs = Date.now() - new Date(data.savedAt).getTime();
    if (ageMs > QUEUE_STATE_MAX_AGE_MS) {
      console.log(`[MONITOR] Queue state expired (${Math.round(ageMs / 3600000)}h old) — ignoring`);
      try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
      return 0;
    }

    // Restore items (cap at MAX_RESTORE_QUEUE_SIZE to prevent OOM from stale persisted queues)
    let items = data.items;
    if (items.length > MAX_RESTORE_QUEUE_SIZE) {
      console.log(`[MONITOR] Truncating restored queue from ${items.length} to ${MAX_RESTORE_QUEUE_SIZE} items`);
      items = items.slice(0, MAX_RESTORE_QUEUE_SIZE);
    }
    const count = items.length;
    if (count === 0) {
      try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
      return 0;
    }
    scanQueue.push(...items);
    console.log(`[MONITOR] Restored ${count} packages from queue state (saved at ${data.savedAt})`);

    // Delete after successful restore
    try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
    return count;
  } catch (err) {
    console.log(`[MONITOR] WARNING: could not restore queue state: ${err.message}`);
    try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
    return 0;
  }
}

function cleanupOrphanTmpDirs() {
  const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
  try {
    if (!fs.existsSync(tmpBase)) return;
    const entries = fs.readdirSync(tmpBase);
    for (const entry of entries) {
      const fullPath = path.join(tmpBase, entry);
      try {
        fs.rmSync(fullPath, { recursive: true, force: true });
      } catch {}
    }
    if (entries.length > 0) {
      console.log(`[MONITOR] Cleaned up ${entries.length} orphan temp dir(s)`);
    }
  } catch {}
}

function cleanupOrphanContainers() {
  try {
    // List running containers with the sandbox name prefix (npm-audit-*)
    const output = execFileSync('docker', ['ps', '-q', '--filter', 'name=npm-audit-'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 10000
    }).toString().trim();
    if (!output) return;
    const ids = output.split(/\s+/).filter(Boolean);
    for (const id of ids) {
      try {
        execFileSync('docker', ['rm', '-f', id], { stdio: 'pipe', timeout: 10000 });
      } catch {}
    }
    console.log(`[MONITOR] Cleaned up ${ids.length} orphan sandbox container(s)`);
  } catch {
    // Docker not available or command failed — skip silently
  }
}

/**
 * Clean up orphan gVisor runtime directories in /tmp/runsc.
 * runsc creates per-container state dirs that are NOT cleaned up when gVisor or
 * Docker crashes. In production this reached 61GB and filled the disk (ENOSPC),
 * cascading into 0-byte .tmp files and total persistence failure.
 * Removes directories older than maxAgeMs (default: 1h).
 */
function cleanupRunscOrphans(maxAgeMs = 3600_000) {
  const runscDir = process.env.MUADDIB_GVISOR_LOG_DIR || '/tmp/runsc';
  try {
    if (!fs.existsSync(runscDir)) return 0;
    const entries = fs.readdirSync(runscDir);
    const now = Date.now();
    let cleaned = 0;
    for (const entry of entries) {
      const fullPath = path.join(runscDir, entry);
      try {
        const stat = fs.statSync(fullPath);
        if (now - stat.mtimeMs > maxAgeMs) {
          fs.rmSync(fullPath, { recursive: true, force: true });
          cleaned++;
        }
      } catch { /* skip unreadable entries */ }
    }
    if (cleaned > 0) {
      console.log(`[MONITOR] Cleaned up ${cleaned} orphan runsc dir(s) in ${runscDir}`);
    }
    return cleaned;
  } catch {
    return 0;
  }
}

/**
 * Check disk usage at boot. Warns if root partition > 90% full and logs
 * the largest consumers in /tmp/ and data/ to aid diagnosis.
 * Uses df + du — Linux-only, silently skips on other platforms.
 */
function checkDiskSpace() {
  try {
    // df --output=pcent / → "Use%\n 42%\n"
    const dfOutput = execFileSync('df', ['--output=pcent', '/'], {
      encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000
    });
    const match = dfOutput.match(/(\d+)%/);
    if (!match) return;
    const usagePercent = parseInt(match[1], 10);
    if (usagePercent < 90) return;

    console.warn(`[MONITOR] WARNING: disk usage at ${usagePercent}% — persistence may fail (ENOSPC)`);

    // Top consumers in /tmp/
    try {
      const tmpDu = execFileSync('du', ['-sh', '--max-depth=1', '/tmp/'], {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      const lines = tmpDu.trim().split('\n')
        .map(l => { const m = l.match(/^([\d.]+[KMGT]?)\s+(.+)/); return m ? { size: m[1], path: m[2] } : null; })
        .filter(Boolean)
        .sort((a, b) => b.size.localeCompare(a.size))
        .slice(0, 5);
      if (lines.length > 0) {
        console.warn('[MONITOR]   Top /tmp/ consumers:');
        for (const l of lines) console.warn(`[MONITOR]     ${l.size}\t${l.path}`);
      }
    } catch { /* du failed */ }

    // Top consumers in data/
    const dataDir = path.join(__dirname, '..', '..', 'data');
    try {
      const dataDu = execFileSync('du', ['-sh', '--max-depth=1', dataDir], {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      const lines = dataDu.trim().split('\n')
        .map(l => { const m = l.match(/^([\d.]+[KMGT]?)\s+(.+)/); return m ? { size: m[1], path: m[2] } : null; })
        .filter(Boolean)
        .sort((a, b) => b.size.localeCompare(a.size))
        .slice(0, 5);
      if (lines.length > 0) {
        console.warn('[MONITOR]   Top data/ consumers:');
        for (const l of lines) console.warn(`[MONITOR]     ${l.size}\t${l.path}`);
      }
    } catch { /* du failed */ }
  } catch {
    // df not available (non-Linux) — skip silently
  }
}

// --- Memory management ---

const MAX_RECENTLY_SCANNED = 50_000;
// MAX_ALERTED_PACKAGES is imported from webhook.js (single source of truth — the
// alertedPackageRules Map lives there and FIFO-caps itself at insert with the same value).
const MAX_DOWNLOADS_CACHE = 20_000; // hard size cap on top of the 24h TTL (bounded resource)

/**
 * Compute current memory pressure level from V8 heap usage.
 * Returns one of MEMORY_PRESSURE_LEVELS and updates the module-level _memoryPressureLevel.
 * Cheap call (~0.1ms) — safe to run every 2s in the main loop.
 *
 * IMPORTANT: Uses v8.getHeapStatistics().heap_size_limit as the denominator,
 * NOT process.memoryUsage().heapTotal. V8 adjusts heapTotal dynamically so
 * heapUsed/heapTotal is structurally 70-85% even when actual usage is 0.1%
 * of the --max-old-space-size limit. This caused the initial v2.10.88 circuit
 * breaker to trigger at ELEVATED/HIGH permanently in normal operation.
 *
 * heap_size_limit reflects the actual V8 ceiling:
 *   - With --max-old-space-size=3072: ~3264MB (3072 + new space overhead)
 *   - Without the flag: ~4288MB (V8 default on 64-bit)
 */
function computeMemoryPressure(memSample = null, rssLimitMb = RSS_LIMIT_MB) {
  const mem = memSample || process.memoryUsage();
  const heapLimit = v8.getHeapStatistics().heap_size_limit;
  const ratio = heapLimit > 0 ? mem.heapUsed / heapLimit : 0;
  const rssLimitBytes = rssLimitMb * 1024 * 1024;
  const rssRatio = rssLimitBytes > 0 ? mem.rss / rssLimitBytes : 0;

  // Pressure is the WORSE of heap and RSS. The RSS arm catches the off-heap leak
  // that the heap ratio is structurally blind to (heap sat at ~20% during every OOM
  // while RSS climbed to 10.3GB). `ratio` stays the heap ratio for backward compat.
  const worst = Math.max(ratio, rssRatio);

  if (worst >= MEMORY_THRESHOLD_EMERGENCY) {
    _memoryPressureLevel = MEMORY_PRESSURE_LEVELS.EMERGENCY;
  } else if (worst >= MEMORY_THRESHOLD_CRITICAL) {
    _memoryPressureLevel = MEMORY_PRESSURE_LEVELS.CRITICAL;
  } else if (worst >= MEMORY_THRESHOLD_HIGH) {
    _memoryPressureLevel = MEMORY_PRESSURE_LEVELS.HIGH;
  } else if (worst >= MEMORY_THRESHOLD_ELEVATED) {
    _memoryPressureLevel = MEMORY_PRESSURE_LEVELS.ELEVATED;
  } else {
    _memoryPressureLevel = MEMORY_PRESSURE_LEVELS.NONE;
  }
  return { level: _memoryPressureLevel, mem, ratio, rssRatio };
}

/**
 * Get the current memory pressure level.
 * Used by ingestion.js to decide whether to skip polling.
 */
function getMemoryPressureLevel() {
  return _memoryPressureLevel;
}

/**
 * Prune in-memory caches to prevent unbounded growth between daily resets.
 * Called hourly from the main loop. Targets:
 * - recentlyScanned: Set used for 24h dedup (no TTL, only cleared at daily report)
 * - downloadsCache: Map with 24h TTL but no proactive eviction
 * - alertedPackageRules: Map for webhook dedup (only cleared at daily report)
 */
function pruneMemoryCaches(recentlyScanned, downloadsCache, alertedPackageRules) {
  let pruned = 0;

  // 1. recentlyScanned — cap size (FIFO semantics: oldest entries are irrelevant)
  if (recentlyScanned.size > MAX_RECENTLY_SCANNED) {
    console.log(`[MONITOR] PRUNE: recentlyScanned ${recentlyScanned.size} > ${MAX_RECENTLY_SCANNED} — clearing`);
    recentlyScanned.clear();
    pruned++;
  }

  // 2. downloadsCache — evict entries past 24h TTL
  const now = Date.now();
  for (const [key, entry] of downloadsCache) {
    if (now - entry.fetchedAt > DOWNLOADS_CACHE_TTL) {
      downloadsCache.delete(key);
      pruned++;
    }
  }
  // 2b. downloadsCache — hard size cap (FIFO) on top of TTL. A Map preserves
  // insertion order, so the first key is the oldest (bounded resource).
  while (downloadsCache.size > MAX_DOWNLOADS_CACHE) {
    downloadsCache.delete(downloadsCache.keys().next().value);
    pruned++;
  }

  // 3. alertedPackageRules — cap size
  if (alertedPackageRules.size > MAX_ALERTED_PACKAGES) {
    console.log(`[MONITOR] PRUNE: alertedPackageRules ${alertedPackageRules.size} > ${MAX_ALERTED_PACKAGES} — clearing`);
    alertedPackageRules.clear();
    pruned++;
  }

  if (pruned > 0) {
    console.log(`[MONITOR] PRUNE: ${pruned} cache entries/collections pruned`);
  }
}

/**
 * Graduated memory pressure response. Called from the main loop when
 * computeMemoryPressure() detects a level >= HIGH.
 *
 * The key principle: clearing caches alone is futile when the real memory is held
 * by N concurrent scan workers retaining AST trees, scan results, and extracted
 * file references. The only effective response is to STOP creating new work and
 * let running scans finish/timeout and release their memory.
 *
 * Level actions (cumulative — higher levels include lower-level actions):
 *   HIGH (85%):     clear auxiliary caches (recentlyScanned, downloadsCache, etc.)
 *   CRITICAL (90%): clear scanner caches (temporal metadata), force GC, log loudly
 *   EMERGENCY (95%): truncate queue to EMERGENCY_QUEUE_KEEP, clear deferred queue
 *
 * Worker spawning is gated separately in the main loop (ensureWorkers skipped at HIGH+).
 * Ingestion is gated in ingestion.js via getMemoryPressureLevel() (skipped at CRITICAL+).
 */
function handleMemoryPressure(level, ratio, rssRatio, recentlyScanned, downloadsCache, scanQueue, stats) {
  const pct = (ratio * 100).toFixed(0);
  // Show BOTH arms: an EMERGENCY almost always fires on RSS (off-heap — gVisor containers,
  // tarball buffers) while the heap sits low (~15%). Logging only heap made every breaker
  // line read "heap at 15%" and hid the real cause; memPctLabel surfaces which arm tripped.
  const rssPct = (rssRatio != null && isFinite(rssRatio)) ? (rssRatio * 100).toFixed(0) : '?';
  const memPctLabel = `heap ${pct}% / rss ${rssPct}%`;
  // Structured summary of what the breaker actually did this tick. Returned (the poll loop
  // at the call site ignores it) so the reclaim is observable to callers and tests without
  // scraping console output — CLAUDE.md §3 "Toujours logger un resume". The two kill fields
  // stay `undefined` until the EMERGENCY branch sets them, so a reader can distinguish
  // "reclaim never ran" (undefined) from "ran, nothing to free" (0) from "reclaim threw" (-1).
  const summary = { level, cachesCleared: false, queueDropped: 0, deferredDropped: 0 };

  // HIGH (85%+): clear auxiliary caches — same as old emergency prune
  if (level >= MEMORY_PRESSURE_LEVELS.HIGH) {
    console.error(`[MONITOR] MEMORY PRESSURE HIGH: ${memPctLabel} — pruning caches, stopping new workers`);
    recentlyScanned.clear();
    downloadsCache.clear();
    alertedPackageRules.clear();
    summary.cachesCleared = true;
  }

  // CRITICAL (90%+): clear scanner caches, force GC
  if (level >= MEMORY_PRESSURE_LEVELS.CRITICAL) {
    console.error(`[MONITOR] MEMORY PRESSURE CRITICAL: ${memPctLabel} — stopping ingestion, clearing scanner caches`);
    // temporal-analysis._metadataCache (200 entries × full npm registry metadata)
    try { clearMetadataCache(); } catch {}
    // typosquat metadataCache (500 entries × npm registry metadata for typosquat scoring)
    try { clearTyposquatMetadataCache(); } catch {}
    // utils._fileListCache, utils._fileContentCache, shared/constants._astCache
    // — populated by temporal-ast-diff (main-thread tarball download + AST parse).
    // Each AST entry can be MB-sized for bundled outputs.
    try { clearFileListCache(); } catch {}
    try { clearASTCache(); } catch {}
    // pendingGrouped webhook buffers
    for (const [, group] of pendingGrouped) {
      clearTimeout(group.timer);
    }
    pendingGrouped.clear();
    // Force GC if available (requires --expose-gc)
    if (global.gc) {
      global.gc();
      console.log('[MONITOR] Forced garbage collection');
    }
  }

  // EMERGENCY (95%+): queue truncation + deferred queue clear
  if (level >= MEMORY_PRESSURE_LEVELS.EMERGENCY) {
    const queueBefore = scanQueue.length;
    if (queueBefore > EMERGENCY_QUEUE_KEEP) {
      // Protected-aware bulk eviction — SINGLE SOURCE OF TRUTH with the queue-cap path
      // (scan-queue.js evictFromScanQueueBulk / enqueueScan share _isProtected). Keeps
      // IOC-match / burst / first-publish / ATO scans, drops the oldest UNPROTECTED items
      // first (newest survive — most likely to still exist for re-scan), protected only as
      // a last resort, and LEDGERS every drop. Closes the v2.10.88 gap where the raw
      // splice(0,n) silently dropped protected scans (CLAUDE.md "ne jamais perdre de scan").
      const { dropped, droppedProtected, spilled } = evictFromScanQueueBulk(scanQueue, EMERGENCY_QUEUE_KEEP, 'mem_emergency');
      summary.queueDropped = dropped;
      summary.queueDroppedProtected = droppedProtected;
      summary.queueSpilled = spilled || 0;
      if (stats) {
        stats.queueEmergencyDrops = (stats.queueEmergencyDrops || 0) + dropped;
        if (droppedProtected) stats.queueEmergencyProtectedDrops = (stats.queueEmergencyProtectedDrops || 0) + droppedProtected;
        if (spilled) stats.spilled = (stats.spilled || 0) + spilled;
      }
      console.error(`[MONITOR] MEMORY EMERGENCY: ${memPctLabel} — truncated queue ${queueBefore} → ${scanQueue.length} (${spilled ? `SPILLED ${spilled} to disk backlog` : `dropped ${dropped} oldest UNPROTECTED${droppedProtected ? ` + ${droppedProtected} protected as last resort` : ''}`}, all ledgered)`);
    }
    // Clear deferred sandbox queue (holds full staticResult objects)
    const deferredDropped = clearDeferredQueue();
    summary.deferredDropped = deferredDropped;
    if (deferredDropped > 0) {
      // Observability only (counter, NOT a ledger 'dropped' entry): the deferred queue holds
      // post-scan sandbox ENRICHMENT for packages already statically scanned + alerted, so
      // clearing it is not a coverage loss — ledgering them as 'dropped' would mislabel them.
      if (stats) stats.deferredDroppedEmergency = (stats.deferredDroppedEmergency || 0) + deferredDropped;
      console.error(`[MONITOR] MEMORY EMERGENCY: cleared ${deferredDropped} deferred sandbox items (post-scan enrichment only — primary alerts already sent)`);
    }
    // Free the off-heap leak that queue truncation can't touch: orphaned sandbox
    // containers (gVisor runsc survives `docker kill`) and wedged scan workers.
    // Under a real RSS leak this — not the queue splice — is what reclaims memory.
    try {
      const killed = killAllSandboxContainers();
      summary.containersKilled = killed;
      if (killed > 0) console.error(`[MONITOR] MEMORY EMERGENCY: force-removed ${killed} sandbox container(s)`);
    } catch (err) { summary.containersKilled = -1; console.error(`[MONITOR] EMERGENCY container kill failed: ${err.message}`); }
    try {
      const terminated = terminateAllWorkers();
      summary.workersTerminated = terminated;
      if (terminated > 0) console.error(`[MONITOR] MEMORY EMERGENCY: terminated ${terminated} scan worker(s)`);
    } catch (err) { summary.workersTerminated = -1; console.error(`[MONITOR] EMERGENCY worker terminate failed: ${err.message}`); }
    // Second GC pass after freeing queue + deferred references
    if (global.gc) {
      global.gc();
    }
  }
  return summary;
}

function reportStats(stats) {
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';
  const { t1, t1a, t1b, t2, t3 } = stats.suspectByTier;
  console.log(`[MONITOR] Stats: ${stats.scanned} scanned, ${stats.clean} clean, ${stats.suspect} suspect (T1a:${t1a} T1b:${t1b} T1:${t1} T2:${t2} T3:${t3}), ${stats.errors} error${stats.errors !== 1 ? 's' : ''}, avg ${avg}s/pkg`);
  if (stats.temporalLoadShed || stats.queueHardDrops || (stats.restartsToday || 0) > 1 || stats.spilled || stats.workerOom) {
    // Backlog size read best-effort: the convergence signal for the spill rollout
    // (must oscillate, not grow monotonically — see plan validation step 4).
    let backlog = 0;
    try { if (isSpillEnabled()) backlog = getBacklogSize(); } catch { /* best-effort */ }
    console.log(`[MONITOR]   Stability: restarts(24h)=${stats.restartsToday || 0}, temporal load-shed=${stats.temporalLoadShed || 0}, queue hard-drops=${stats.queueHardDrops || 0}, spilled=${stats.spilled || 0}, drained=${stats.spillDrained || 0}, backlog=${backlog}, workerOom=${stats.workerOom || 0}`);
  }
  if (stats.changesStreamPackages) {
    console.log(`[MONITOR]   Changes stream packages: ${stats.changesStreamPackages}`);
  }
  // Network-brain state (governors phase A): one line per host that has seen
  // any backoff — the observation signal for the A deployment gate (AIMD
  // de-escalations visible, no sustained max-level) and phase D's input.
  try {
    const { getBrainState } = require('../shared/http-limiter.js');
    const brain = getBrainState();
    const noisy = Object.entries(brain).filter(([, s]) => s.backoffCount > 0 || s.level > 0 || s.pendingWaiters > 0);
    if (noisy.length > 0) {
      const line = noisy.map(([h, s]) => `${h}: level=${s.level} pause=${s.pauseRemainingMs}ms 429s=${s.backoffCount} waiters=${s.pendingWaiters}`).join(' | ');
      console.log(`[MONITOR]   Brain: ${line}`);
    }
  } catch { /* observability only */ }
  if (stats.rssFallbackCount) {
    console.log(`[MONITOR]   RSS fallback activations: ${stats.rssFallbackCount}`);
  }
  if (stats.iocPreAlerts) {
    console.log(`[MONITOR]   IOC pre-alerts: ${stats.iocPreAlerts}`);
  }
  if (stats.tarballCacheHits) {
    console.log(`[MONITOR]   Tarball cache hits: ${stats.tarballCacheHits}`);
  }
  if (stats.sandboxDeferred || stats.deferredProcessed) {
    const { getDeferredQueueStats } = require('./deferred-sandbox.js');
    const dq = getDeferredQueueStats();
    console.log(`[MONITOR]   Deferred sandbox: ${stats.sandboxDeferred || 0} enqueued, ${stats.deferredProcessed || 0} processed, ${stats.deferredExpired || 0} expired, ${stats.deferredSkipped || 0} skipped, ${dq.size} pending`);
  }
  stats.lastReportTime = Date.now();
}

// isDailyReportDue is the canonical gate in state.js (imported above) — re-exported below
// so monitor.js (daemonModule.isDailyReportDue) keeps resolving. The old local copy used a
// `hour !== 8` gate that lost a whole day whenever the daemon missed the single 08:00 minute
// (OOM crash-loop); state.js uses the catch-up `hour >= 8` gate instead.

// ─── P1.0 — memory-trend instrumentation ───
// Append one sample per memory-watchdog tick so the off-heap leak can be localised
// offline: rss climbing while heapUsed stays flat points at external/arrayBuffers
// (native tarball/AST buffers) vs liveWorkers (worker-isolate heaps) vs runscDirs
// (gVisor /tmp/runsc state dirs that survive `docker kill`). The heap-only breaker is
// blind to all three — this is the data needed to choose the P1.2/P1.3 fix.
const MEM_TREND_FILE = path.join(__dirname, '..', '..', 'data', 'mem-trend.jsonl');
const MEM_TREND_MAX_BYTES = 5 * 1024 * 1024; // bounded: truncate-rotate past 5MB

function countRunscDirs() {
  try {
    const dir = process.env.MUADDIB_GVISOR_LOG_DIR || '/tmp/runsc';
    return fs.existsSync(dir) ? fs.readdirSync(dir).length : 0;
  } catch { return 0; }
}

function appendMemTrend(currentMem, liveWorkers, queueLen) {
  try {
    // Bounded resource (CLAUDE.md §2): rotate the JSONL once past the cap.
    try {
      const st = fs.statSync(MEM_TREND_FILE);
      if (st.size > MEM_TREND_MAX_BYTES) fs.renameSync(MEM_TREND_FILE, MEM_TREND_FILE + '.1');
    } catch { /* no file yet — fine */ }
    const entry = {
      ts: new Date().toISOString(),
      rss: currentMem.rss,
      heapUsed: currentMem.heapUsed,
      heapTotal: currentMem.heapTotal,
      external: currentMem.external || 0,
      arrayBuffers: currentMem.arrayBuffers || 0,
      liveWorkers,
      queueLen,
      runscDirs: countRunscDirs(),
    };
    fs.appendFileSync(MEM_TREND_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch { /* instrumentation must never crash the daemon */ }
}

// ─── P2.1 / P2.4 — restart tracking + crash-loop alert ───
// The chronic ~10×/day OOM crash-loop went unnoticed for weeks because NOTHING counted
// restarts. Record each boot, expose the 24h count for the daily report, and fire an
// alert (journal + rate-limited webhook) when the daemon is restarting abnormally often.
const RESTARTS_FILE = path.join(__dirname, '..', '..', 'data', 'restarts.jsonl');
const RESTARTS_MAX_LINES = 500;               // bounded resource (CLAUDE.md §2)
const CRASH_LOOP_THRESHOLD_24H = 6;           // restarts/24h above this = alert
const CRASH_LOOP_ALERT_MARKER = path.join(__dirname, '..', '..', 'data', '.crashloop-alert.json');
const CRASH_LOOP_ALERT_INTERVAL_MS = 6 * 3600 * 1000; // webhook at most once per 6h

function countRecentRestarts(windowMs = 24 * 3600 * 1000) {
  try {
    if (!fs.existsSync(RESTARTS_FILE)) return 0;
    const cutoff = Date.now() - windowMs;
    let n = 0;
    for (const line of fs.readFileSync(RESTARTS_FILE, 'utf8').split('\n')) {
      if (!line) continue;
      try { if (new Date(JSON.parse(line).ts).getTime() >= cutoff) n++; } catch { /* skip bad line */ }
    }
    return n;
  } catch { return 0; }
}

function maybeSendCrashLoopWebhook(count24h) {
  try {
    let last = 0;
    try { last = JSON.parse(fs.readFileSync(CRASH_LOOP_ALERT_MARKER, 'utf8')).ts || 0; } catch { /* no marker */ }
    if (Date.now() - last < CRASH_LOOP_ALERT_INTERVAL_MS) return; // rate-limited
    const { getWebhookUrl, sendWebhook } = require('../webhook.js');
    const url = (typeof getWebhookUrl === 'function' && getWebhookUrl()) || process.env.MUADDIB_WEBHOOK_URL;
    if (!url) return;
    atomicWriteFileSync(CRASH_LOOP_ALERT_MARKER, JSON.stringify({ ts: Date.now(), count24h }));
    const payload = { content: `🚨 MUAD'DIB crash-loop: ${count24h} restarts in the last 24h (threshold ${CRASH_LOOP_THRESHOLD_24H}). Likely OOM — check data/mem-trend.jsonl (rss vs external/arrayBuffers).` };
    Promise.resolve(sendWebhook(url, payload)).catch(() => { /* best-effort */ });
  } catch { /* never block boot on alerting */ }
}

function recordRestart() {
  try {
    fs.appendFileSync(RESTARTS_FILE, JSON.stringify({ ts: new Date().toISOString(), pid: process.pid }) + '\n', 'utf8');
    try {
      const lines = fs.readFileSync(RESTARTS_FILE, 'utf8').split('\n').filter(Boolean);
      if (lines.length > RESTARTS_MAX_LINES) fs.writeFileSync(RESTARTS_FILE, lines.slice(-RESTARTS_MAX_LINES).join('\n') + '\n', 'utf8');
    } catch { /* trim best-effort */ }
  } catch { /* best-effort: never block boot on telemetry */ }
  const count24h = countRecentRestarts();
  if (count24h > CRASH_LOOP_THRESHOLD_24H) {
    console.error(`[MONITOR] CRASH-LOOP ALERT: ${count24h} restarts in the last 24h (threshold ${CRASH_LOOP_THRESHOLD_24H}) — daemon restarting abnormally often (OOM?). Check data/mem-trend.jsonl.`);
    maybeSendCrashLoopWebhook(count24h);
  } else {
    console.log(`[MONITOR] BOOT: restart #${count24h} in the last 24h (pid ${process.pid})`);
  }
  return count24h;
}

async function startMonitor(options, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailableRef) {
  if (options && options.verbose) {
    setVerboseMode(true);
  }

  // Disk space check — early warning before ENOSPC cascading failure
  checkDiskSpace();
  // Cleanup temp dirs from previous runs (SIGTERM/crash may leave orphans)
  cleanupOrphanTmpDirs();
  // Kill orphan sandbox containers from previous crash (npm-audit-* prefix)
  cleanupOrphanContainers();
  // Clean up stale gVisor runtime dirs (runsc leak — caused 61GB disk fill in prod).
  // At boot the previous process (often OOM-killed mid-scan in the ~10×/day crash-loop)
  // owns NO live container, so every runsc dir is an orphan → clear them ALL (age 0),
  // not just those >1h old. The hourly call below keeps the default age for live runtime.
  cleanupRunscOrphans(0);
  // P2.1/P2.4: record this boot, expose the 24h restart count, alert if crash-looping.
  stats.restartsToday = recordRestart();
  // Layer 3: Purge expired cached tarballs on startup
  purgeTarballCache();
  // Purge archived tarballs older than MUADDIB_ARCHIVE_RETENTION_DAYS (default 7).
  // Runs in-process at startup AND every 6h via setInterval so no external cron is required.
  // Required to prevent the disk-fill cascade observed on 2026-05-24 (96GB filled,
  // .claude.json corrupted, +89K monitor errors): startup-only cleanup never ran on a
  // long-uptime service, and 30-day default + 4.5GB/day average exceeded the 96GB disk.
  try { cleanupOldArchives(getRetentionDays()); } catch (err) {
    console.warn(`[Archive] Startup cleanup failed: ${err.message}`);
  }
  try { startPeriodicCleanup(); } catch (err) {
    console.warn(`[Archive] Failed to start periodic cleanup: ${err.message}`);
  }

  // RSS fix (C2): make sure the lean IOC projection exists & is fresh BEFORE any
  // scan worker spawns. Workers load the ~24MB lean instead of the ~223MB full
  // (heap-snapshot-confirmed ~900MB→~50MB per IOC-matching scan). The full read
  // here is paid ONCE by this long-lived daemon (never by a one-shot worker).
  try {
    const { ensureLeanIOCFile } = require('../ioc/updater.js');
    const r = ensureLeanIOCFile();
    if (r.generated) console.log(`[MONITOR] IOC lean projection regenerated (${(r.bytes / 1024 / 1024).toFixed(1)}MB) — workers avoid the 223MB full load`);
  } catch (err) {
    console.warn(`[MONITOR] IOC lean bootstrap failed (workers fall back to full file): ${err.message}`);
  }

  console.log('\n' + banner([
    "MUAD'DIB - Registry Monitor",
    'Scanning npm + PyPI new packages'
  ]) + '\n');

  // Note: alerts file migrated from .json to .jsonl in v2.10.89
  const oldAlertsJson = ALERTS_FILE.replace('.jsonl', '.json');
  if (fs.existsSync(oldAlertsJson)) {
    try {
      const sizeMB = (fs.statSync(oldAlertsJson).size / 1024 / 1024).toFixed(0);
      console.log(`[MONITOR] Legacy ${path.basename(oldAlertsJson)} found (${sizeMB}MB). Safe to archive — alerts now use JSONL.`);
    } catch {}
  }

  // Check sandbox availability
  if (isSandboxEnabled()) {
    sandboxAvailableRef.value = isDockerAvailable();
    if (sandboxAvailableRef.value) {
      console.log('[MONITOR] Docker detected — sandbox enabled for HIGH/CRITICAL findings');
    } else {
      console.log('[MONITOR] WARNING: Docker not available — running static analysis only');
    }
  } else {
    console.log('[MONITOR] Sandbox disabled (MUADDIB_MONITOR_SANDBOX=false)');
  }

  // Canary tokens status
  if (isCanaryEnabled()) {
    console.log('[MONITOR] Canary tokens enabled — honey tokens injected in sandbox for exfiltration detection');
  } else {
    console.log('[MONITOR] Canary tokens disabled (MUADDIB_MONITOR_CANARY=false)');
  }

  // LLM Detective status
  if (isLlmDetectiveEnabled()) {
    const llmMode = getLlmDetectiveMode();
    const llmLimit = parseInt(process.env.MUADDIB_LLM_DAILY_LIMIT, 10) || 100;
    console.log(`[MONITOR] LLM Detective enabled — mode: ${llmMode}, daily limit: ${llmLimit}, model: claude-haiku-4-5`);
  } else {
    const reason = !process.env.ANTHROPIC_API_KEY ? 'no ANTHROPIC_API_KEY' : 'MUADDIB_LLM_ENABLED=false';
    console.log(`[MONITOR] LLM Detective disabled (${reason})`);
  }

  // Temporal analysis status
  if (isTemporalEnabled()) {
    console.log('[MONITOR] Temporal lifecycle analysis enabled — detecting sudden lifecycle script changes');
  } else {
    console.log('[MONITOR] Temporal lifecycle analysis disabled (MUADDIB_MONITOR_TEMPORAL=false)');
  }

  if (isTemporalAstEnabled()) {
    console.log('[MONITOR] Temporal AST analysis enabled — detecting sudden dangerous API additions');
  } else {
    console.log('[MONITOR] Temporal AST analysis disabled (MUADDIB_MONITOR_TEMPORAL_AST=false)');
  }

  if (isTemporalPublishEnabled()) {
    console.log('[MONITOR] Publish frequency analysis enabled — detecting publish bursts, dormant spikes');
  } else {
    console.log('[MONITOR] Publish frequency analysis disabled (MUADDIB_MONITOR_TEMPORAL_PUBLISH=false)');
  }

  if (isTemporalMaintainerEnabled()) {
    console.log('[MONITOR] Maintainer change analysis enabled — detecting maintainer changes, account takeovers');
  } else {
    console.log('[MONITOR] Maintainer change analysis disabled (MUADDIB_MONITOR_TEMPORAL_MAINTAINER=false)');
  }

  // Webhook filtering mode
  console.log('[MONITOR] Strict webhook mode — webhooks sent ONLY for:');
  console.log('[MONITOR]   - IOC match (225K+ package database)');
  console.log('[MONITOR]   - Static score >= 50 with CRITICAL or HIGH findings');
  console.log('[MONITOR]   - Sandbox score > 0');
  console.log('[MONITOR]   - Canary token exfiltration');
  console.log('[MONITOR]   NEVER sent: temporal anomaly, AST anomaly, publish anomaly, maintainer change, MEDIUM-only packages');

  // External healthcheck (Healthchecks.io) — sends /start ping now, heartbeat every 10 min
  const healthcheck = startHealthcheck();

  // OOM fix: convert legacy detections.json / temporal-detections.json into
  // append-only JSONL on first boot after upgrade. Idempotent and safe to call
  // every boot (skips when JSONL already exists).
  try { runStateMigrations(); } catch (err) {
    console.error(`[MONITOR] runStateMigrations failed: ${err.message}`);
  }

  const state = loadState(stats);
  loadDailyStats(stats, dailyAlerts); // Restore counters from previous run (survives restarts)
  console.log(`[MONITOR] State loaded — npm last: ${state.npmLastPackage || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}, npm seq: ${state.npmLastSeq || 'none'}`);
  console.log('[MONITOR] npm changes stream enabled (replicate.npmjs.com) with RSS fallback');
  console.log(`[MONITOR] Scan concurrency: adaptive ${BASE_CONCURRENCY}→${getTargetConcurrency()} (base MUADDIB_SCAN_CONCURRENCY=${BASE_CONCURRENCY}, max MUADDIB_MAX_CONCURRENCY)`);
  console.log(`[MONITOR] Sandbox concurrency: ${SANDBOX_CONCURRENCY_MAX} (MUADDIB_SANDBOX_CONCURRENCY to override)`);
  const heapLimitMB = (v8.getHeapStatistics().heap_size_limit / 1024 / 1024).toFixed(0);
  console.log(`[MONITOR] Memory circuit breaker: heap limit ${heapLimitMB}MB, thresholds HIGH=${(MEMORY_THRESHOLD_HIGH * 100).toFixed(0)}% CRITICAL=${(MEMORY_THRESHOLD_CRITICAL * 100).toFixed(0)}% EMERGENCY=${(MEMORY_THRESHOLD_EMERGENCY * 100).toFixed(0)}%, GC=${typeof global.gc === 'function' ? 'available' : 'unavailable (start with --expose-gc)'}`);
  console.log(`[MONITOR] Polling every ${POLL_INTERVAL / 1000}s (decoupled from processing). Ctrl+C to stop.\n`);

  let running = true;
  let pollIntervalHandle = null;   // Decoupled poll timer — set after initial poll
  let queuePersistHandle = null;   // Queue persistence timer
  let concurrencyAdjustHandle = null; // Adaptive concurrency timer

  // Restore queue from previous run (if file exists and is < 24h old)
  const restoredCount = restoreQueue(scanQueue);
  if (restoredCount > 0) {
    console.log(`[MONITOR] ${restoredCount} packages pre-loaded from previous session`);
  }

  // Restore the dedup Set so the restored backlog isn't re-scanned from scratch
  // (an empty dedup set after each of ~10 daily restarts = thousands of wasted re-scans).
  loadRecentlyScanned(recentlyScanned);

  // Restore deferred sandbox queue from previous run
  const deferredRestored = restoreDeferredQueue();
  if (deferredRestored > 0) {
    console.log(`[MONITOR] ${deferredRestored} deferred sandbox items restored from previous session`);
  }

  // Graceful shutdown handler (shared by SIGINT and SIGTERM)
  // Daily report is NEVER sent on shutdown — it only fires at 08:00 Paris time.
  // Counters are persisted to disk so they survive the restart.
  async function gracefulShutdown(signal) {
    console.log(`\n[MONITOR] Received ${signal} — shutting down...`);
    running = false;
    if (pollIntervalHandle) {
      clearInterval(pollIntervalHandle);
      pollIntervalHandle = null;
    }
    if (queuePersistHandle) {
      clearInterval(queuePersistHandle);
      queuePersistHandle = null;
    }
    if (concurrencyAdjustHandle) {
      clearInterval(concurrencyAdjustHandle);
      concurrencyAdjustHandle = null;
    }
    // Bounded drain (phase C, C7). The old unbounded `await drainWorkers()`
    // could outlive systemd's TimeoutStopSec (scans run up to 300s): SIGKILL
    // then landed MID-drain, persistQueue never ran, and every in-flight scan
    // plus up to 60s of queue mutations were lost UNLEDGERED on each manual
    // restart — the exact deployment mode of this program. Drain for up to
    // SHUTDOWN_DRAIN_MAX_MS, then spill the survivors (protected, bounded
    // retries) so the next boot re-scans them.
    console.log(`[MONITOR] Draining ${getActiveWorkers()} active worker(s) (bounded ${SHUTDOWN_DRAIN_MAX_MS / 1000}s)...`);
    await Promise.race([
      drainWorkers(),
      new Promise(resolve => setTimeout(resolve, SHUTDOWN_DRAIN_MAX_MS).unref())
    ]);
    try {
      const leftovers = getInFlightItems();
      if (leftovers.length > 0) {
        const { isSpillEnabled: spillOn, spillItems } = require('./spill.js');
        const { appendScanLedger } = require('./state.js');
        let spilledN = 0;
        for (const it of leftovers) {
          const { retries, giveUp } = computeInterruptDisposition(it);
          recentlyScanned.delete(`${it.ecosystem}/${it.name}@${it.version}`);
          if (giveUp) {
            appendScanLedger({ name: it.name, version: it.version, ecosystem: it.ecosystem, outcome: 'dropped', source: 'interrupted_max' });
            continue;
          }
          appendScanLedger({ name: it.name, version: it.version, ecosystem: it.ecosystem, outcome: 'interrupted', source: 'shutdown_drain' });
          if (spillOn() && spillItems([{ ...it, interrupted: true, interruptRetries: retries }]) === 1) spilledN++;
        }
        console.log(`[MONITOR] Shutdown: ${leftovers.length} in-flight scan(s) did not finish in time — ${spilledN} spilled for re-scan, all ledgered`);
      }
    } catch (e) {
      console.error(`[MONITOR] Shutdown in-flight spill failed: ${e.message}`);
    }
    // Persist remaining queue items so they survive the restart
    persistQueue(scanQueue, state);
    saveRecentlyScanned(recentlyScanned); // Persist dedup set too (avoid re-scan storm on restart)
    // Stop deferred sandbox worker and persist its queue
    stopDeferredWorker();
    persistDeferredQueue();
    stopGhsaPoller();
    healthcheck.stop();
    // Flush all pending scope groups before exit
    for (const [scope, group] of pendingGrouped) {
      clearTimeout(group.timer);
      await flushScopeGroup(scope);
    }
    pendingGrouped.clear();
    saveDailyStats(stats, dailyAlerts);
    saveState(state, stats);
    reportStats(stats);
    console.log('[MONITOR] State saved. Bye!');
    process.exit(0);
  }

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

  // ─── Deferred sandbox worker ───
  // Started BEFORE the first processQueue so it can process T1b/T2 packages
  // that get deferred during the initial batch (which blocks for 30min-2h).
  if (isSandboxEnabled() && sandboxAvailableRef.value) {
    startDeferredWorker(stats);
    console.log('[MONITOR] Deferred sandbox worker started (30s interval, dedicated slot)');
  }

  // Phase 2c part 2: active GHSA malware-advisory poller (~15 min). Independent of the
  // sandbox — it surfaces fresh advisories (pre-alert), records withdrawn ones to the
  // ledger, and accumulates the denominator the Phase 5 coverage-audit joins against.
  // Best-effort and fire-and-forget; never blocks the daemon.
  startGhsaPoller(stats);

  // AUDIT 3: if the last daily report failed to deliver (e.g. a DNS blip at 08:00),
  // it sits on disk with delivered=false. Redeliver it once now. Fire-and-forget —
  // never blocks startup, never throws (legacy reports without the flag are skipped).
  redeliverPendingReportOnBoot().catch(() => { /* logged inside; non-fatal */ });

  // ─── Initial poll ───
  // Fills the queue with pending packages. Processing starts in the main loop
  // via ensureWorkers (non-blocking) — NOT await processQueue (blocking).
  // A blocking processQueue here would prevent adaptive concurrency from
  // firing until the entire initial batch is drained at BASE_CONCURRENCY.
  await poll(state, scanQueue, stats);
  // Atomicity fix: persist queue AND seq together after each poll.
  // Previously, seq was saved inside pollNpmChanges() but queue persisted
  // every 60s — crash between the two lost queued items permanently.
  persistQueue(scanQueue, state);
  saveNpmSeq(state.npmLastSeq);
  saveState(state, stats);
  console.log(`[MONITOR] Initial poll complete — ${scanQueue.length} packages queued for processing`);

  // ─── Adaptive concurrency ───
  // Set up BEFORE the main loop so it fires during the initial batch.
  // Adjusts scan worker count every 30s based on queue depth, memory, timeout rate.
  // Scale-up is aggressive (+4) during backlog, scale-down is gradual (-2) when idle.
  concurrencyAdjustHandle = setInterval(() => {
    if (!running) return;
    const current = getTargetConcurrency();
    const { target, reason } = computeTarget(current, scanQueue.length, stats);
    if (target !== current) {
      console.log(`[MONITOR] ADAPTIVE: concurrency ${current} → ${target} (${reason}, active=${getActiveWorkers()})`);
      setTargetConcurrency(target);
      // Immediately spawn new workers if scaling up (don't wait for next loop tick)
      if (target > current) {
        ensureWorkers(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);
      }
    }
  }, ADJUST_INTERVAL_MS);

  // ─── Decoupled polling ───
  // Poll runs on its own interval, independent of processing.
  // This ensures new packages are ingested even while a large batch is being scanned.
  // Backpressure: poll() skips when queue >= 30K or memory pressure >= CRITICAL (90%).
  // Adaptive concurrency adjusts scan throughput to match ingestion rate.
  let pollInProgress = false;
  let pollStartedAt = 0;
  let backoffUntil = 0;
  pollIntervalHandle = setInterval(async () => {
    if (!running) return;
    // Backoff window after consecutive total-registry failures. Hoisted out of
    // poll() (it used to `await sleep(backoff)` while holding pollInProgress, up
    // to POLL_MAX_BACKOFF=16min) so the watchdog can stay sized to poll *work*.
    if (Date.now() < backoffUntil) return;
    // Skip if a cycle is already in flight, unless the flag is stale — a
    // backstop for any hang path that bypasses runPollCycle()'s watchdog.
    const { skip, forceReset } = shouldSkipPoll(pollInProgress, pollStartedAt, Date.now(), POLL_WATCHDOG_MS, POLL_INTERVAL);
    if (forceReset) {
      console.warn(`[MONITOR] Poll flag stuck for ${((Date.now() - pollStartedAt) / 1000).toFixed(0)}s — force-resetting`);
      pollInProgress = false;
    } else if (skip) {
      return;
    }
    pollInProgress = true;
    pollStartedAt = Date.now();
    try {
      await runPollCycle(state, scanQueue, stats);
      // Atomicity: persist queue + seq together after each poll
      persistQueue(scanQueue, state);
      saveNpmSeq(state.npmLastSeq);
      saveState(state, stats);
      if (scanQueue.length > QUEUE_WARNING_THRESHOLD) {
        console.log(`[MONITOR] WARNING: scan queue depth ${scanQueue.length} — processing may be lagging behind ingestion`);
      }
      // Apply hoisted poll backoff (set after consecutive total-registry failures).
      const backoffMs = getPollBackoffMs();
      if (backoffMs > 0) {
        backoffUntil = Date.now() + backoffMs;
        console.log(`[MONITOR] Poll backoff: skipping ticks for ${(backoffMs / 1000).toFixed(0)}s after consecutive registry failures`);
      } else {
        backoffUntil = 0;
      }
    } catch (err) {
      console.error('[MONITOR] Poll error (interval):', err.message);
    } finally {
      pollInProgress = false;
    }
  }, POLL_INTERVAL);

  // ─── Queue persistence ───
  // Periodic snapshot as safety net (in addition to post-poll persist).
  queuePersistHandle = setInterval(() => {
    if (!running) return;
    persistQueue(scanQueue, state);
    saveRecentlyScanned(recentlyScanned); // Piggyback: persist dedup set on the same 60s interval
    persistDeferredQueue(); // Piggyback: persist deferred sandbox queue on same interval
  }, QUEUE_PERSIST_INTERVAL);

  // ─── Continuous processing loop ───
  // Non-blocking: ensureWorkers spawns fire-and-forget background workers.
  // This loop tops up workers every 2s AND runs housekeeping (memory, daily report)
  // without being blocked by long-running scans.
  let lastMemoryLogTime = Date.now();
  let lastSpillDrainTime = 0;

  while (running) {
    // ─── Memory circuit breaker (every iteration) ───
    // computeMemoryPressure() is cheap (~0.1ms). Running every 2s ensures fast
    // reaction to memory spikes — the 2026-04-13 incident showed that checking
    // every 5min is too slow (250 packages ingested between checks).
    const { level: pressureLevel, mem: currentMem, ratio: heapRatio, rssRatio } = computeMemoryPressure();

    // Phase B (memory governor): feed the admission gate the REAL process RSS
    // from this same 2s breaker loop — the governor's freeze keys on it (the
    // worker-mem disk samples are 10s-cadence and starve during sync parses).
    try { require('./memory-governor.js').updateGovernorRss(currentMem.rss); } catch { /* governor optional */ }

    // Top up workers ONLY when memory pressure is below HIGH.
    // At HIGH+, existing workers continue (they'll finish or timeout) but no new
    // ones are spawned. This is the core mechanism: let running scans release their
    // memory (AST trees, scan results, extracted files) before starting new ones.
    if (pressureLevel < MEMORY_PRESSURE_LEVELS.HIGH) {
      ensureWorkers(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);
    }

    // ─── Spill drain (MUADDIB_QUEUE_SPILL=1) ───
    // Re-ingest evicted scans from the disk backlog during calm windows: pressure
    // fully NONE + queue headroom, one bounded batch per SPILL_DRAIN_INTERVAL_MS.
    // Protected items (IOC/burst/first-publish/ATO) drain first — a malicious
    // package is often unpublished quickly, late drains lose the tarball.
    if (isSpillEnabled() &&
        Date.now() - lastSpillDrainTime >= SPILL_DRAIN_INTERVAL_MS &&
        shouldDrain(pressureLevel, scanQueue.length, SPILL_DRAIN_THRESHOLD)) {
      lastSpillDrainTime = Date.now();
      try {
        // Dedup against recentlyScanned (same key format as processQueueItem) AND
        // the live queue (small here by the shouldDrain threshold).
        const inQueue = new Set(scanQueue.map(it => `${it.ecosystem}/${it.name}@${it.version}`));
        const r = drainBacklog(scanQueue, stats, {
          maxItems: Math.min(SPILL_DRAIN_BATCH, Math.max(1, SPILL_DRAIN_THRESHOLD - scanQueue.length)),
          enqueueFn: enqueueScan,
          isDuplicate: (e) => {
            const key = `${e.ecosystem}/${e.name}@${e.version}`;
            return recentlyScanned.has(key) || inQueue.has(key);
          }
        });
        if (r.drained > 0 || r.deduped > 0) {
          console.log(`[MONITOR] SPILL_DRAIN: re-ingested ${r.drained} (${r.deduped} deduped, backlog ${r.remaining} remaining)`);
        }
      } catch (err) {
        console.error(`[MONITOR] SPILL_DRAIN failed: ${err.message}`);
      }
    }

    // ─── Memory watchdog (adaptive interval) ───
    // Log every 5min normally, every 15s under pressure.
    const memLogInterval = pressureLevel >= MEMORY_PRESSURE_LEVELS.HIGH
      ? MEMORY_LOG_INTERVAL_PRESSURE
      : MEMORY_LOG_INTERVAL_NORMAL;

    if (Date.now() - lastMemoryLogTime >= memLogInterval) {
      const heapUsedMB = (currentMem.heapUsed / 1024 / 1024).toFixed(0);
      const heapLimitMB = (v8.getHeapStatistics().heap_size_limit / 1024 / 1024).toFixed(0);
      const rssMB = (currentMem.rss / 1024 / 1024).toFixed(0);
      const pctUsed = (heapRatio * 100).toFixed(0);
      const levelName = Object.keys(MEMORY_PRESSURE_LEVELS).find(k => MEMORY_PRESSURE_LEVELS[k] === pressureLevel) || 'UNKNOWN';
      console.log(`[MONITOR] MEMORY: heap=${heapUsedMB}MB/${heapLimitMB}MB (${pctUsed}%), rss=${rssMB}MB (${(rssRatio * 100).toFixed(0)}%/${RSS_LIMIT_MB}MB), queue=${scanQueue.length}, dedup=${recentlyScanned.size}, downloads=${downloadsCache.size}, alerts=${alertedPackageRules.size}, dailyAlerts=${dailyAlerts.length}, pressure=${levelName}`);
      // P1.0: persist the same sample as a time series for offline leak localisation.
      appendMemTrend(currentMem, getActiveWorkers(), scanQueue.length);

      // Heap diagnostics (restart root-cause): cheap heap-spaces breakdown
      // (retention vs churn) + opt-in one-shot snapshot at MUADDIB_HEAPSNAPSHOT_MB.
      console.log(`[MONITOR] HEAP-SPACES: ${formatHeapSpaces(v8.getHeapSpaceStatistics())}`);
      maybeHeapSnapshot(Number(heapUsedMB));

      // Graduated response at HIGH+
      if (pressureLevel >= MEMORY_PRESSURE_LEVELS.HIGH) {
        handleMemoryPressure(pressureLevel, heapRatio, rssRatio, recentlyScanned, downloadsCache, scanQueue, stats);
      }
      lastMemoryLogTime = Date.now();
    }

    // Hourly stats report + cache purge + runsc cleanup + memory pruning
    if (Date.now() - stats.lastReportTime >= 3600_000) {
      reportStats(stats);
      purgeTarballCache();
      cleanupRunscOrphans();
      pruneMemoryCaches(recentlyScanned, downloadsCache, alertedPackageRules);
    }

    // Daily webhook report at 08:00 Paris time
    if (isDailyReportDue(stats)) {
      await sendDailyReport(stats, dailyAlerts, recentlyScanned, downloadsCache);
      // Auto-relabel JSONL training data after daily report (once per day).
      // Checks registry takedown status for unconfirmed packages.
      // Guard: relabel reads the entire JSONL into memory (21-100MB). Skip if
      // heap is already under pressure — will fire tomorrow instead.
      try {
        const relabelPressure = computeMemoryPressure();
        if (relabelPressure.level >= MEMORY_PRESSURE_LEVELS.HIGH) {
          console.log(`[MONITOR] Auto-relabel SKIPPED: memory pressure at ${(relabelPressure.ratio * 100).toFixed(0)}% — will retry tomorrow`);
        } else {
          const { relabelDataset } = require('./auto-labeler.js');
          const summary = await relabelDataset({});
          const totalRelabeled = summary.relabeled_malicious + summary.relabeled_benign + summary.relabeled_likely_benign;
          if (totalRelabeled > 0) {
            console.log(`[MONITOR] Auto-relabel: ${summary.relabeled_malicious} malicious, ${summary.relabeled_benign} benign, ${summary.relabeled_likely_benign} likely_benign (${summary.checked} checked)`);
          }
        }
      } catch (err) {
        // Non-fatal: relabel failure must never crash the monitor
        console.error(`[MONITOR] Auto-relabel failed: ${err.message}`);
      }
    }

    // Short pause before re-checking queue — yields event loop for poll interval
    await sleep(PROCESS_LOOP_INTERVAL);
  }
}

module.exports = {
  startMonitor,
  cleanupOrphanTmpDirs,
  cleanupOrphanContainers,
  cleanupRunscOrphans,
  checkDiskSpace,
  reportStats,
  isDailyReportDue,
  sleep,
  persistQueue,
  restoreQueue,
  appendMemTrend,
  countRunscDirs,
  recordRestart,
  countRecentRestarts,
  POLL_INTERVAL,
  POLL_WATCHDOG_MS,
  runPollCycle,
  shouldSkipPoll,
  shouldSnapshot,
  formatHeapSpaces,
  PROCESS_LOOP_INTERVAL,
  QUEUE_WARNING_THRESHOLD,
  QUEUE_PERSIST_INTERVAL,
  QUEUE_STATE_FILE,
  QUEUE_STATE_MAX_AGE_MS,
  MAX_QUEUE_PERSIST_SIZE,
  MAX_RESTORE_QUEUE_SIZE,
  pruneMemoryCaches,
  MAX_RECENTLY_SCANNED,
  MAX_ALERTED_PACKAGES,
  MAX_DOWNLOADS_CACHE,
  // Memory circuit breaker
  computeMemoryPressure,
  getMemoryPressureLevel,
  handleMemoryPressure,
  MEMORY_PRESSURE_LEVELS,
  MEMORY_THRESHOLD_ELEVATED,
  MEMORY_THRESHOLD_HIGH,
  MEMORY_THRESHOLD_CRITICAL,
  MEMORY_THRESHOLD_EMERGENCY,
  RSS_LIMIT_MB,
  EMERGENCY_QUEUE_KEEP,
  MEMORY_LOG_INTERVAL_NORMAL,
  MEMORY_LOG_INTERVAL_PRESSURE
};
