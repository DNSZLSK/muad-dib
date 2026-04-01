/**
 * MUAD'DIB Registry Monitor — Orchestrator
 *
 * This module defines shared mutable state, imports from sub-modules,
 * creates wrapper functions that bind state, and re-exports the full public API.
 *
 * Sub-modules:
 *   monitor/state.js     — persistence (files, scan memory, tarball cache, daily stats)
 *   monitor/classify.js  — classification constants and helpers
 *   monitor/webhook.js   — Discord webhook formatting, alerts, daily reports
 *   monitor/temporal.js  — temporal anomaly checks (lifecycle, AST, publish, maintainer)
 *   monitor/ingestion.js — CouchDB changes, RSS, PyPI polling
 *   monitor/queue.js     — scan queue, workers, package scanning
 *   monitor/daemon.js    — main loop, signal handlers, startup
 */

const { downloadToFile, extractTarGz } = require('./shared/download.js');
const { MAX_TARBALL_SIZE } = require('./shared/constants.js');
const { relabelRecords, getStats: getTrainingStats } = require('./ml/jsonl-writer.js');

// --- Sub-module imports ---
const stateModule = require('./monitor/state.js');
const classifyModule = require('./monitor/classify.js');
const webhookModule = require('./monitor/webhook.js');
const temporalModule = require('./monitor/temporal.js');
const ingestionModule = require('./monitor/ingestion.js');
const queueModule = require('./monitor/queue.js');
const daemonModule = require('./monitor/daemon.js');
const { pingFail: healthcheckPingFail } = require('./monitor/healthcheck.js');

// Prevent unhandled promise rejections from crashing the monitor process
process.on('unhandledRejection', (reason, promise) => {
  console.error('[MONITOR] Unhandled rejection:', reason);
  healthcheckPingFail();
});

// Self-exclude: never scan our own package through the monitor
const SELF_PACKAGE_NAME = require('../package.json').name; // 'muaddib-scanner'

// ═══════════════════════════════════════════════════
// Shared mutable state (owned by this orchestrator)
// ═══════════════════════════════════════════════════

const stats = {
  scanned: 0,
  clean: 0,
  suspect: 0,
  suspectByTier: { t1: 0, t1a: 0, t1b: 0, t2: 0, t3: 0 },
  errors: 0,
  errorsByType: { too_large: 0, tar_failed: 0, http_error: 0, timeout: 0, static_timeout: 0, other: 0 },
  totalTimeMs: 0,
  mlFiltered: 0,
  llmAnalyzed: 0,
  llmSuppressed: 0,
  sandboxDeferred: 0,
  deferredProcessed: 0,
  deferredExpired: 0,
  lastReportTime: Date.now(),
  lastDailyReportDate: null
};

const dailyAlerts = [];
const recentlyScanned = new Set();
const scanQueue = [];
let sandboxAvailable = false;

// ═══════════════════════════════════════════════════
// Wrapper functions (bind shared state to sub-modules)
// ═══════════════════════════════════════════════════

// --- State wrappers ---
function loadState() { return stateModule.loadState(stats); }
function saveState(state) { return stateModule.saveState(state, stats); }
function hasReportBeenSentToday() { return stateModule.hasReportBeenSentToday(stats); }
function loadDailyStats() { return stateModule.loadDailyStats(stats, dailyAlerts); }
function saveDailyStats() { return stateModule.saveDailyStats(stats, dailyAlerts); }
function maybePersistDailyStats() { return stateModule.maybePersistDailyStats(stats, dailyAlerts); }

// --- Classify wrappers ---
function recordError(err) { return classifyModule.recordError(err, stats); }

// --- Webhook wrappers ---
function buildDailyReportEmbed() { return webhookModule.buildDailyReportEmbed(stats, dailyAlerts); }
function sendDailyReport() { return webhookModule.sendDailyReport(stats, dailyAlerts, recentlyScanned, classifyModule.downloadsCache); }
function sendReportNow() { return webhookModule.sendReportNow(stats); }

// --- Ingestion wrappers ---
function pollNpmChanges(state) { return ingestionModule.pollNpmChanges(state, scanQueue, stats); }
function pollNpmRss(state) { return ingestionModule.pollNpmRss(state, scanQueue, stats); }
function pollNpm(state) { return ingestionModule.pollNpm(state, scanQueue, stats); }
function pollPyPI(state) { return ingestionModule.pollPyPI(state, scanQueue); }
function poll(state) { return ingestionModule.poll(state, scanQueue, stats); }

// --- Queue wrappers ---
function processQueue() { return queueModule.processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, classifyModule.downloadsCache, sandboxAvailable); }
function processQueueItem(item) { return queueModule.processQueueItem(item, stats, dailyAlerts, recentlyScanned, classifyModule.downloadsCache, scanQueue, sandboxAvailable); }
function scanPackage(name, version, ecosystem, tarballUrl, registryMeta) { return queueModule.scanPackage(name, version, ecosystem, tarballUrl, registryMeta, stats, dailyAlerts, recentlyScanned, classifyModule.downloadsCache, scanQueue, sandboxAvailable); }
function resolveTarballAndScan(item) { return queueModule.resolveTarballAndScan(item, stats, dailyAlerts, recentlyScanned, classifyModule.downloadsCache, scanQueue, sandboxAvailable); }

// --- Temporal wrappers ---
function runTemporalCheck(name) { return temporalModule.runTemporalCheck(name, dailyAlerts); }
function runTemporalAstCheck(name) { return temporalModule.runTemporalAstCheck(name, dailyAlerts); }
function runTemporalPublishCheck(name) { return temporalModule.runTemporalPublishCheck(name, dailyAlerts); }
function runTemporalMaintainerCheck(name) { return temporalModule.runTemporalMaintainerCheck(name, dailyAlerts); }

// --- Daemon wrappers ---
function reportStats() { return daemonModule.reportStats(stats); }
function isDailyReportDue() { return daemonModule.isDailyReportDue(stats); }
function startMonitor(options) {
  const sandboxRef = { get value() { return sandboxAvailable; }, set value(v) { sandboxAvailable = v; } };
  return daemonModule.startMonitor(options, stats, dailyAlerts, recentlyScanned, classifyModule.downloadsCache, scanQueue, sandboxRef);
}

// ═══════════════════════════════════════════════════
// Re-exports (preserve original API for all consumers)
// ═══════════════════════════════════════════════════

module.exports = {
  startMonitor,
  parseNpmRss: ingestionModule.parseNpmRss,
  parsePyPIRss: ingestionModule.parsePyPIRss,
  pollNpmChanges,
  pollNpmRss,
  loadState,
  saveState,
  STATE_FILE: stateModule.STATE_FILE,
  ALERTS_FILE: stateModule.ALERTS_FILE,
  NPM_SEQ_FILE: stateModule.NPM_SEQ_FILE,
  loadNpmSeq: stateModule.loadNpmSeq,
  saveNpmSeq: stateModule.saveNpmSeq,
  CHANGES_STREAM_URL: stateModule.CHANGES_STREAM_URL,
  SCAN_CONCURRENCY: queueModule.SCAN_CONCURRENCY,
  CHANGES_LIMIT: stateModule.CHANGES_LIMIT,
  CHANGES_CATCHUP_MAX: stateModule.CHANGES_CATCHUP_MAX,
  downloadToFile,
  extractTarGz,
  getNpmTarballUrl: ingestionModule.getNpmTarballUrl,
  getNpmLatestTarball: ingestionModule.getNpmLatestTarball,
  getPyPITarballUrl: ingestionModule.getPyPITarballUrl,
  scanPackage,
  scanQueue,
  processQueue,
  appendAlert: stateModule.appendAlert,
  timeoutPromise: queueModule.timeoutPromise,
  reportStats,
  stats,
  dailyAlerts,
  recentlyScanned,
  alertedPackageRules: webhookModule.alertedPackageRules,
  resolveTarballAndScan,
  MAX_TARBALL_SIZE,
  LARGE_PACKAGE_SIZE: queueModule.LARGE_PACKAGE_SIZE,
  STATIC_SCAN_TIMEOUT_MS: queueModule.STATIC_SCAN_TIMEOUT_MS,
  FIRST_PUBLISH_SANDBOX_MAX_QUEUE: queueModule.FIRST_PUBLISH_SANDBOX_MAX_QUEUE,
  FIRST_PUBLISH_SANDBOX_ENABLED: queueModule.FIRST_PUBLISH_SANDBOX_ENABLED,
  runScanInWorker: queueModule.runScanInWorker,
  KNOWN_BUNDLED_FILES: queueModule.KNOWN_BUNDLED_FILES,
  KNOWN_BUNDLED_PATHS: queueModule.KNOWN_BUNDLED_PATHS,
  isBundledToolingOnly: queueModule.isBundledToolingOnly,
  isSandboxEnabled: classifyModule.isSandboxEnabled,
  hasHighOrCritical: classifyModule.hasHighOrCritical,
  get sandboxAvailable() { return sandboxAvailable; },
  set sandboxAvailable(v) { sandboxAvailable = v; },
  getWebhookUrl: webhookModule.getWebhookUrl,
  shouldSendWebhook: webhookModule.shouldSendWebhook,
  buildMonitorWebhookPayload: webhookModule.buildMonitorWebhookPayload,
  buildAlertData: webhookModule.buildAlertData,
  persistAlert: webhookModule.persistAlert,
  trySendWebhook: webhookModule.trySendWebhook,
  classifyError: classifyModule.classifyError,
  recordError,
  formatErrorBreakdown: classifyModule.formatErrorBreakdown,
  computeRiskLevel: webhookModule.computeRiskLevel,
  computeRiskScore: webhookModule.computeRiskScore,
  computeReputationFactor: webhookModule.computeReputationFactor,
  HIGH_CONFIDENCE_MALICE_TYPES: classifyModule.HIGH_CONFIDENCE_MALICE_TYPES,
  hasHighConfidenceThreat: classifyModule.hasHighConfidenceThreat,
  getWebhookThreshold: webhookModule.getWebhookThreshold,
  extractScope: webhookModule.extractScope,
  pendingGrouped: webhookModule.pendingGrouped,
  bufferScopedWebhook: webhookModule.bufferScopedWebhook,
  flushScopeGroup: webhookModule.flushScopeGroup,
  SCOPE_GROUP_WINDOW_MS: webhookModule.SCOPE_GROUP_WINDOW_MS,
  buildDailyReportEmbed,
  sendDailyReport,
  DAILY_REPORT_HOUR: webhookModule.DAILY_REPORT_HOUR,
  isDailyReportDue,
  getParisHour: stateModule.getParisHour,
  getParisDateString: stateModule.getParisDateString,
  isTemporalEnabled: temporalModule.isTemporalEnabled,
  buildTemporalWebhookEmbed: webhookModule.buildTemporalWebhookEmbed,
  runTemporalCheck,
  isTemporalAstEnabled: temporalModule.isTemporalAstEnabled,
  buildTemporalAstWebhookEmbed: webhookModule.buildTemporalAstWebhookEmbed,
  runTemporalAstCheck,
  isTemporalPublishEnabled: temporalModule.isTemporalPublishEnabled,
  buildPublishAnomalyWebhookEmbed: webhookModule.buildPublishAnomalyWebhookEmbed,
  runTemporalPublishCheck,
  isTemporalMaintainerEnabled: temporalModule.isTemporalMaintainerEnabled,
  buildMaintainerChangeWebhookEmbed: webhookModule.buildMaintainerChangeWebhookEmbed,
  runTemporalMaintainerCheck,
  isCanaryEnabled: classifyModule.isCanaryEnabled,
  buildCanaryExfiltrationWebhookEmbed: webhookModule.buildCanaryExfiltrationWebhookEmbed,
  getTemporalMaxSeverity: temporalModule.getTemporalMaxSeverity,
  isPublishAnomalyOnly: temporalModule.isPublishAnomalyOnly,
  isSafeLifecycleScript: temporalModule.isSafeLifecycleScript,
  hasOnlySafeTemporalFindings: temporalModule.hasOnlySafeTemporalFindings,
  isAstAnomalyCombined: temporalModule.isAstAnomalyCombined,
  isVerboseMode: classifyModule.isVerboseMode,
  setVerboseMode: classifyModule.setVerboseMode,
  hasIOCMatch: classifyModule.hasIOCMatch,
  matchVersionedIOC: webhookModule.matchVersionedIOC,
  hasTyposquat: classifyModule.hasTyposquat,
  isSuspectClassification: classifyModule.isSuspectClassification,
  TIER1_TYPES: classifyModule.TIER1_TYPES,
  TIER2_ACTIVE_TYPES: classifyModule.TIER2_ACTIVE_TYPES,
  TIER3_PASSIVE_TYPES: classifyModule.TIER3_PASSIVE_TYPES,
  LIFECYCLE_INTENT_TYPES: classifyModule.LIFECYCLE_INTENT_TYPES,
  formatFindings: classifyModule.formatFindings,
  IOC_MATCH_TYPES: classifyModule.IOC_MATCH_TYPES,
  getWeeklyDownloads: ingestionModule.getWeeklyDownloads,
  checkTrustedDepDiff: ingestionModule.checkTrustedDepDiff,
  TRUSTED_DEP_AGE_THRESHOLD_MS: ingestionModule.TRUSTED_DEP_AGE_THRESHOLD_MS,
  POPULAR_THRESHOLD: classifyModule.POPULAR_THRESHOLD,
  downloadsCache: classifyModule.downloadsCache,
  DOWNLOADS_CACHE_TTL: classifyModule.DOWNLOADS_CACHE_TTL,
  DETECTIONS_FILE: stateModule.DETECTIONS_FILE,
  appendDetection: stateModule.appendDetection,
  loadDetections: stateModule.loadDetections,
  getDetectionStats: stateModule.getDetectionStats,
  SCAN_STATS_FILE: stateModule.SCAN_STATS_FILE,
  loadScanStats: stateModule.loadScanStats,
  updateScanStats: stateModule.updateScanStats,
  buildReportFromDisk: webhookModule.buildReportFromDisk,
  buildReportEmbedFromDisk: webhookModule.buildReportEmbedFromDisk,
  sendReportNow,
  getReportStatus: webhookModule.getReportStatus,
  cleanupOrphanTmpDirs: daemonModule.cleanupOrphanTmpDirs,
  consecutivePollErrors: {
    get() { return ingestionModule.getConsecutivePollErrors(); },
    set(v) { ingestionModule.setConsecutivePollErrors(v); }
  },
  POLL_MAX_BACKOFF: ingestionModule.POLL_MAX_BACKOFF,
  PROCESS_LOOP_INTERVAL: daemonModule.PROCESS_LOOP_INTERVAL,
  QUEUE_WARNING_THRESHOLD: daemonModule.QUEUE_WARNING_THRESHOLD,
  QUEUE_PERSIST_INTERVAL: daemonModule.QUEUE_PERSIST_INTERVAL,
  QUEUE_STATE_FILE: daemonModule.QUEUE_STATE_FILE,
  QUEUE_STATE_MAX_AGE_MS: daemonModule.QUEUE_STATE_MAX_AGE_MS,
  MAX_QUEUE_PERSIST_SIZE: daemonModule.MAX_QUEUE_PERSIST_SIZE,
  persistQueue: daemonModule.persistQueue,
  restoreQueue: daemonModule.restoreQueue,
  LAST_DAILY_REPORT_FILE: stateModule.LAST_DAILY_REPORT_FILE,
  loadLastDailyReportDate: stateModule.loadLastDailyReportDate,
  saveLastDailyReportDate: stateModule.saveLastDailyReportDate,
  hasReportBeenSentToday,
  DAILY_STATS_FILE: stateModule.DAILY_STATS_FILE,
  DAILY_STATS_PERSIST_INTERVAL: stateModule.DAILY_STATS_PERSIST_INTERVAL,
  loadDailyStats,
  saveDailyStats,
  resetDailyStats: stateModule.resetDailyStats,
  maybePersistDailyStats,
  get scansSinceLastPersist() { return stateModule.getScansSinceLastPersist(); },
  set scansSinceLastPersist(v) { stateModule.setScansSinceLastPersist(v); },
  atomicWriteFileSync: stateModule.atomicWriteFileSync,
  appendTemporalDetection: stateModule.appendTemporalDetection,
  loadTemporalDetections: stateModule.loadTemporalDetections,
  TEMPORAL_DETECTIONS_FILE: stateModule.TEMPORAL_DETECTIONS_FILE,
  ALERTS_LOG_DIR: stateModule.ALERTS_LOG_DIR,
  DAILY_REPORTS_LOG_DIR: stateModule.DAILY_REPORTS_LOG_DIR,
  resolveWritableDir: stateModule.resolveWritableDir,
  SELF_PACKAGE_NAME,
  // C3: Scan memory exports
  SCAN_MEMORY_FILE: stateModule.SCAN_MEMORY_FILE,
  SCAN_MEMORY_EXPIRY_MS: stateModule.SCAN_MEMORY_EXPIRY_MS,
  MAX_MEMORY_ENTRIES: stateModule.MAX_MEMORY_ENTRIES,
  MEMORY_SCORE_TOLERANCE: stateModule.MEMORY_SCORE_TOLERANCE,
  loadScanMemory: stateModule.loadScanMemory,
  saveScanMemory: stateModule.saveScanMemory,
  recordScanMemory: stateModule.recordScanMemory,
  shouldSuppressByMemory: stateModule.shouldSuppressByMemory,
  get scanMemoryCache() { return stateModule.getScanMemoryCache(); },
  set scanMemoryCache(v) { stateModule.setScanMemoryCache(v); },
  get scansSinceLastMemoryPersist() { return stateModule.getScansSinceLastMemoryPersist(); },
  set scansSinceLastMemoryPersist(v) { stateModule.setScansSinceLastMemoryPersist(v); },
  // ML training data exports
  recordTrainingSample: queueModule.recordTrainingSample,
  relabelRecords,
  getTrainingStats,
  // Layer 1: IOC pre-alert
  sendIOCPreAlert: webhookModule.sendIOCPreAlert,
  // Layer 2: CouchDB doc extraction
  extractTarballFromDoc: ingestionModule.extractTarballFromDoc,
  // Layer 3: Tarball cache
  TARBALL_CACHE_DIR: stateModule.TARBALL_CACHE_DIR,
  TARBALL_CACHE_INDEX_FILE: stateModule.TARBALL_CACHE_INDEX_FILE,
  TARBALL_CACHE_DEFAULT_RETENTION_DAYS: stateModule.TARBALL_CACHE_DEFAULT_RETENTION_DAYS,
  TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS: stateModule.TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS,
  TARBALL_CACHE_MAX_SIZE_BYTES: stateModule.TARBALL_CACHE_MAX_SIZE_BYTES,
  loadTarballCacheIndex: stateModule.loadTarballCacheIndex,
  saveTarballCacheIndex: stateModule.saveTarballCacheIndex,
  tarballCacheKey: stateModule.tarballCacheKey,
  tarballCachePath: stateModule.tarballCachePath,
  cacheTarball: stateModule.cacheTarball,
  purgeTarballCache: stateModule.purgeTarballCache,
  evaluateCacheTrigger: classifyModule.evaluateCacheTrigger,
  isFirstPublishHighRisk: classifyModule.isFirstPublishHighRisk,
  quickTyposquatCheck: classifyModule.quickTyposquatCheck,
  POPULAR_NPM_NAMES: classifyModule.POPULAR_NPM_NAMES,
  get tarballCacheIndex() { return stateModule.getTarballCacheIndex(); },
  set tarballCacheIndex(v) { stateModule.setTarballCacheIndex(v); },
  // C2: Alert priority triage
  computeAlertPriority: webhookModule.computeAlertPriority,
  processQueueItem
};

// Standalone entry point: node src/monitor.js
if (require.main === module) {
  startMonitor().catch(err => {
    console.error('[MONITOR] Fatal error:', err.message);
    process.exit(1);
  });
}
