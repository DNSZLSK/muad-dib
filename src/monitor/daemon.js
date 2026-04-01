const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { isDockerAvailable, SANDBOX_CONCURRENCY_MAX } = require('../sandbox/index.js');
const { setVerboseMode, isSandboxEnabled, isCanaryEnabled, isLlmDetectiveEnabled, getLlmDetectiveMode } = require('./classify.js');
const { loadState, saveState, loadDailyStats, saveDailyStats, purgeTarballCache, getParisHour, atomicWriteFileSync } = require('./state.js');
const { isTemporalEnabled, isTemporalAstEnabled, isTemporalPublishEnabled, isTemporalMaintainerEnabled } = require('./temporal.js');
const { pendingGrouped, flushScopeGroup, sendDailyReport, DAILY_REPORT_HOUR } = require('./webhook.js');
const { poll } = require('./ingestion.js');
const { processQueue, SCAN_CONCURRENCY } = require('./queue.js');
const { startHealthcheck } = require('./healthcheck.js');

const POLL_INTERVAL = 60_000;
const PROCESS_LOOP_INTERVAL = 2_000;    // Queue check interval when empty
const QUEUE_WARNING_THRESHOLD = 5_000;  // Warn if queue depth exceeds this
const QUEUE_PERSIST_INTERVAL = 60_000;  // Persist queue to disk every 60s
const QUEUE_STATE_FILE = path.join(__dirname, '..', '..', 'data', 'queue-state.json');
const QUEUE_STATE_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24h expiry
const MAX_QUEUE_PERSIST_SIZE = 100_000; // Don't persist if queue > 100K items

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

    // Restore items
    const count = data.items.length;
    if (count === 0) {
      try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
      return 0;
    }
    scanQueue.push(...data.items);
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

  // Cleanup temp dirs from previous runs (SIGTERM/crash may leave orphans)
  cleanupOrphanTmpDirs();
  // Kill orphan sandbox containers from previous crash (npm-audit-* prefix)
  cleanupOrphanContainers();
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
  console.log(`[MONITOR] Scan concurrency: ${SCAN_CONCURRENCY} (MUADDIB_SCAN_CONCURRENCY to override)`);
  console.log(`[MONITOR] Sandbox concurrency: ${SANDBOX_CONCURRENCY_MAX} (MUADDIB_SANDBOX_CONCURRENCY to override)`);
  console.log(`[MONITOR] Polling every ${POLL_INTERVAL / 1000}s (decoupled from processing). Ctrl+C to stop.\n`);

  let running = true;
  let pollIntervalHandle = null;   // Decoupled poll timer — set after initial poll
  let queuePersistHandle = null;   // Queue persistence timer

  // Restore queue from previous run (if file exists and is < 24h old)
  const restoredCount = restoreQueue(scanQueue);
  if (restoredCount > 0) {
    console.log(`[MONITOR] ${restoredCount} packages pre-loaded from previous session`);
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
    // Persist remaining queue items so they survive the restart
    persistQueue(scanQueue, state);
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

  // Initial poll + scan (sequential for first run)
  await poll(state, scanQueue, stats);
  saveState(state, stats);
  await processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);

  // ─── Decoupled polling ───
  // Poll runs on its own interval, independent of processing.
  // This ensures new packages are ingested even while a large batch is being scanned.
  // Without this, a 2h processing batch blocks all polling — packages published and
  // removed during that window are never seen (e.g. axios/plain-crypto-js 2026-03-30).
  let pollInProgress = false;
  pollIntervalHandle = setInterval(async () => {
    if (!running || pollInProgress) return;
    pollInProgress = true;
    try {
      await poll(state, scanQueue, stats);
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
  // Snapshot queue to disk every 60s so items survive restarts/crashes.
  // Without this, the decoupled poll advances the CouchDB seq but queued
  // items are lost on restart — they won't be re-polled.
  queuePersistHandle = setInterval(() => {
    if (!running) return;
    persistQueue(scanQueue, state);
  }, QUEUE_PERSIST_INTERVAL);

  // ─── Continuous processing loop ───
  // Consumes scanQueue independently of polling. Workers inside processQueue
  // check scanQueue.length > 0 after each item, so items added by a concurrent
  // poll are picked up immediately by running workers.
  while (running) {
    if (scanQueue.length > 0) {
      await processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);
    }

    // Hourly stats report + cache purge
    if (Date.now() - stats.lastReportTime >= 3600_000) {
      reportStats(stats);
      purgeTarballCache();
    }

    // Daily webhook report at 08:00 Paris time
    if (isDailyReportDue(stats)) {
      await sendDailyReport(stats, dailyAlerts, recentlyScanned, downloadsCache);
    }

    // Short pause before re-checking queue — yields event loop for poll interval
    await sleep(PROCESS_LOOP_INTERVAL);
  }
}

module.exports = {
  startMonitor,
  cleanupOrphanTmpDirs,
  cleanupOrphanContainers,
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
  MAX_QUEUE_PERSIST_SIZE
};
