const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { isDockerAvailable, SANDBOX_CONCURRENCY_MAX } = require('../sandbox/index.js');
const { setVerboseMode, isSandboxEnabled, isCanaryEnabled, isLlmDetectiveEnabled, getLlmDetectiveMode, DOWNLOADS_CACHE_TTL } = require('./classify.js');
const { loadState, saveState, loadDailyStats, saveDailyStats, purgeTarballCache, getParisHour, atomicWriteFileSync, saveNpmSeq } = require('./state.js');
const { isTemporalEnabled, isTemporalAstEnabled, isTemporalPublishEnabled, isTemporalMaintainerEnabled } = require('./temporal.js');
const { pendingGrouped, flushScopeGroup, sendDailyReport, DAILY_REPORT_HOUR, alertedPackageRules } = require('./webhook.js');
const { poll } = require('./ingestion.js');
const { processQueue, ensureWorkers, drainWorkers, getTargetConcurrency, setTargetConcurrency, getActiveWorkers, SCAN_CONCURRENCY } = require('./queue.js');
const { computeTarget, ADJUST_INTERVAL_MS, BASE_CONCURRENCY, resetDeltas } = require('./adaptive-concurrency.js');
const { startHealthcheck } = require('./healthcheck.js');
const { startDeferredWorker, stopDeferredWorker, persistDeferredQueue, restoreDeferredQueue } = require('./deferred-sandbox.js');

const POLL_INTERVAL = 60_000;
const PROCESS_LOOP_INTERVAL = 2_000;    // Queue check interval when empty
const QUEUE_WARNING_THRESHOLD = 5_000;  // Warn if queue depth exceeds this
const QUEUE_PERSIST_INTERVAL = 60_000;  // Persist queue to disk every 60s
const QUEUE_STATE_FILE = path.join(__dirname, '..', '..', 'data', 'queue-state.json');
const QUEUE_STATE_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24h expiry
const MAX_QUEUE_PERSIST_SIZE = 200_000; // Don't persist if queue > 200K items (OOM guard)
const MAX_RESTORE_QUEUE_SIZE = 100_000; // Cap restored queue at 100K items
// MAX_SCAN_QUEUE removed: backpressure no longer skips polling.
// Queue grows unbounded in memory (entries are ~300B, 100K = 30MB on 12GB VPS).
// Adaptive concurrency adjusts processing speed to match ingestion rate.

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
const MAX_ALERTED_PACKAGES = 5_000;

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

function reportStats(stats) {
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';
  const { t1, t1a, t1b, t2, t3 } = stats.suspectByTier;
  console.log(`[MONITOR] Stats: ${stats.scanned} scanned, ${stats.clean} clean, ${stats.suspect} suspect (T1a:${t1a} T1b:${t1b} T1:${t1} T2:${t2} T3:${t3}), ${stats.errors} error${stats.errors !== 1 ? 's' : ''}, avg ${avg}s/pkg`);
  if (stats.changesStreamPackages) {
    console.log(`[MONITOR]   Changes stream packages: ${stats.changesStreamPackages}`);
  }
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

function isDailyReportDue(stats) {
  const hour = getParisHour();
  if (hour !== DAILY_REPORT_HOUR) return false;
  // Check if already sent today
  const { hasReportBeenSentToday } = require('./state.js');
  return !hasReportBeenSentToday(stats);
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
  // Clean up stale gVisor runtime dirs (runsc leak — caused 61GB disk fill in prod)
  cleanupRunscOrphans();
  // Layer 3: Purge expired cached tarballs on startup
  purgeTarballCache();

  console.log(`
╔════════════════════════════════════════════╗
║     MUAD'DIB - Registry Monitor           ║
║     Scanning npm + PyPI new packages      ║
╚════════════════════════════════════════════╝
  `);

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

  const state = loadState(stats);
  loadDailyStats(stats, dailyAlerts); // Restore counters from previous run (survives restarts)
  console.log(`[MONITOR] State loaded — npm last: ${state.npmLastPackage || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}, npm seq: ${state.npmLastSeq || 'none'}`);
  console.log('[MONITOR] npm changes stream enabled (replicate.npmjs.com) with RSS fallback');
  console.log(`[MONITOR] Scan concurrency: adaptive ${BASE_CONCURRENCY}→${getTargetConcurrency()} (base MUADDIB_SCAN_CONCURRENCY=${BASE_CONCURRENCY}, max MUADDIB_MAX_CONCURRENCY)`);
  console.log(`[MONITOR] Sandbox concurrency: ${SANDBOX_CONCURRENCY_MAX} (MUADDIB_SANDBOX_CONCURRENCY to override)`);
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
    // Wait for in-flight scans to complete (soft drain)
    console.log(`[MONITOR] Draining ${getActiveWorkers()} active worker(s)...`);
    await drainWorkers();
    // Persist remaining queue items so they survive the restart
    persistQueue(scanQueue, state);
    // Stop deferred sandbox worker and persist its queue
    stopDeferredWorker();
    persistDeferredQueue();
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

  // Initial poll + scan (sequential for first run)
  await poll(state, scanQueue, stats);
  // Atomicity fix: persist queue AND seq together after each poll.
  // Previously, seq was saved inside pollNpmChanges() but queue persisted
  // every 60s ��� crash between the two lost queued items permanently.
  persistQueue(scanQueue, state);
  saveNpmSeq(state.npmLastSeq);
  saveState(state, stats);
  await processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);

  // ─── Decoupled polling ───
  // Poll runs on its own interval, independent of processing.
  // This ensures new packages are ingested even while a large batch is being scanned.
  // Backpressure removed: polling ALWAYS runs. Queue grows unbounded in memory
  // (entries ~300B, 100K = 30MB). Adaptive concurrency adjusts scan throughput.
  let pollInProgress = false;
  pollIntervalHandle = setInterval(async () => {
    if (!running || pollInProgress) return;
    pollInProgress = true;
    try {
      await poll(state, scanQueue, stats);
      // Atomicity: persist queue + seq together after each poll
      persistQueue(scanQueue, state);
      saveNpmSeq(state.npmLastSeq);
      saveState(state, stats);
      if (scanQueue.length > QUEUE_WARNING_THRESHOLD) {
        console.log(`[MONITOR] WARNING: scan queue depth ${scanQueue.length} — processing may be lagging behind ingestion`);
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
    persistDeferredQueue(); // Piggyback: persist deferred sandbox queue on same interval
  }, QUEUE_PERSIST_INTERVAL);

  // ─── Adaptive concurrency ───
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

  // ─── Continuous processing loop ───
  // Non-blocking: ensureWorkers spawns fire-and-forget background workers.
  // This loop tops up workers every 2s AND runs housekeeping (memory, daily report)
  // without being blocked by long-running scans.
  const MEMORY_LOG_INTERVAL = 300_000; // 5 minutes
  const MEMORY_PRESSURE_THRESHOLD = 0.85; // 85% heap usage triggers emergency prune
  let lastMemoryLogTime = Date.now();

  while (running) {
    // Top up workers (non-blocking — spawns missing workers as background promises)
    ensureWorkers(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);

    // ─── Memory watchdog (every 5 min) ───
    if (Date.now() - lastMemoryLogTime >= MEMORY_LOG_INTERVAL) {
      const mem = process.memoryUsage();
      const heapUsedMB = (mem.heapUsed / 1024 / 1024).toFixed(0);
      const heapTotalMB = (mem.heapTotal / 1024 / 1024).toFixed(0);
      const rssMB = (mem.rss / 1024 / 1024).toFixed(0);
      console.log(`[MONITOR] MEMORY: heap=${heapUsedMB}MB/${heapTotalMB}MB, rss=${rssMB}MB, queue=${scanQueue.length}, dedup=${recentlyScanned.size}, downloads=${downloadsCache.size}, alerts=${alertedPackageRules.size}`);

      // Emergency prune under memory pressure
      if (mem.heapUsed / mem.heapTotal > MEMORY_PRESSURE_THRESHOLD) {
        console.error(`[MONITOR] MEMORY PRESSURE: heap at ${((mem.heapUsed / mem.heapTotal) * 100).toFixed(0)}% — emergency prune`);
        recentlyScanned.clear();
        downloadsCache.clear();
        alertedPackageRules.clear();
        // Force GC if available (requires --expose-gc)
        if (global.gc) {
          global.gc();
          console.log('[MONITOR] Forced garbage collection');
        }
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
      try {
        const { relabelDataset } = require('./auto-labeler.js');
        const summary = await relabelDataset({});
        const totalRelabeled = summary.relabeled_malicious + summary.relabeled_benign + summary.relabeled_likely_benign;
        if (totalRelabeled > 0) {
          console.log(`[MONITOR] Auto-relabel: ${summary.relabeled_malicious} malicious, ${summary.relabeled_benign} benign, ${summary.relabeled_likely_benign} likely_benign (${summary.checked} checked)`);
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
  POLL_INTERVAL,
  PROCESS_LOOP_INTERVAL,
  QUEUE_WARNING_THRESHOLD,
  QUEUE_PERSIST_INTERVAL,
  QUEUE_STATE_FILE,
  QUEUE_STATE_MAX_AGE_MS,
  MAX_QUEUE_PERSIST_SIZE,
  MAX_RESTORE_QUEUE_SIZE,
  pruneMemoryCaches,
  MAX_RECENTLY_SCANNED,
  MAX_ALERTED_PACKAGES
};
