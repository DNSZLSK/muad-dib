const fs = require('fs');
const path = require('path');
const os = require('os');
const { isDockerAvailable } = require('../sandbox/index.js');
const { setVerboseMode, isSandboxEnabled, isCanaryEnabled } = require('./classify.js');
const { loadState, saveState, loadDailyStats, saveDailyStats, purgeTarballCache, getParisHour } = require('./state.js');
const { isTemporalEnabled, isTemporalAstEnabled, isTemporalPublishEnabled, isTemporalMaintainerEnabled } = require('./temporal.js');
const { pendingGrouped, flushScopeGroup, sendDailyReport, DAILY_REPORT_HOUR } = require('./webhook.js');
const { poll } = require('./ingestion.js');
const { processQueue, SCAN_CONCURRENCY } = require('./queue.js');

const POLL_INTERVAL = 60_000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

  const state = loadState(stats);
  loadDailyStats(stats, dailyAlerts); // Restore counters from previous run (survives restarts)
  console.log(`[MONITOR] State loaded — npm last: ${state.npmLastPackage || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}, npm seq: ${state.npmLastSeq || 'none'}`);
  console.log('[MONITOR] npm changes stream enabled (replicate.npmjs.com) with RSS fallback');
  console.log(`[MONITOR] Scan concurrency: ${SCAN_CONCURRENCY} (MUADDIB_SCAN_CONCURRENCY to override)`);
  console.log(`[MONITOR] Polling every ${POLL_INTERVAL / 1000}s. Ctrl+C to stop.\n`);

  let running = true;

  // Graceful shutdown handler (shared by SIGINT and SIGTERM)
  // Daily report is NEVER sent on shutdown — it only fires at 08:00 Paris time.
  // Counters are persisted to disk so they survive the restart.
  async function gracefulShutdown(signal) {
    console.log(`\n[MONITOR] Received ${signal} — shutting down...`);
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
    running = false;
    process.exit(0);
  }

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

  // Initial poll + scan
  await poll(scanQueue, stats);
  saveState(state, stats);
  await processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);

  // Interval polling
  while (running) {
    await sleep(POLL_INTERVAL);
    if (!running) break;
    await poll(scanQueue, stats);
    saveState(state, stats);
    await processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailableRef.value);

    // Hourly stats report + cache purge
    if (Date.now() - stats.lastReportTime >= 3600_000) {
      reportStats(stats);
      purgeTarballCache();
    }

    // Daily webhook report at 08:00 Paris time
    if (isDailyReportDue(stats)) {
      await sendDailyReport(stats, dailyAlerts, recentlyScanned, downloadsCache);
    }
  }
}

module.exports = {
  startMonitor,
  cleanupOrphanTmpDirs,
  reportStats,
  isDailyReportDue,
  sleep,
  POLL_INTERVAL
};
