/**
 * Monitor state/persistence functions.
 * Extracted from src/monitor.js — all file I/O, caching, and state management.
 */

const fs = require('fs');
const path = require('path');
const { sanitizePackageName } = require('../shared/download.js');

// --- File path constants ---

const STATE_FILE = path.join(__dirname, '..', '..', 'data', 'monitor-state.json');
const ALERTS_FILE = path.join(__dirname, '..', '..', 'data', 'monitor-alerts.json');
const DETECTIONS_FILE = path.join(__dirname, '..', '..', 'data', 'detections.json');
const SCAN_STATS_FILE = path.join(__dirname, '..', '..', 'data', 'scan-stats.json');
const LAST_DAILY_REPORT_FILE = path.join(__dirname, '..', '..', 'data', 'last-daily-report.json');
const DAILY_STATS_FILE = path.join(__dirname, '..', '..', 'data', 'daily-stats.json');
const TEMPORAL_DETECTIONS_FILE = path.join(__dirname, '..', '..', 'data', 'temporal-detections.json');

// Local log persistence directories (parallel to Discord webhooks for offline analysis)
// Primary: logs/ relative to project root. Fallback: /tmp/ if primary is read-only (EROFS/EACCES).
const PRIMARY_DAILY_REPORTS_DIR = path.join(__dirname, '..', '..', 'logs', 'daily-reports');
const PRIMARY_ALERTS_DIR = path.join(__dirname, '..', '..', 'logs', 'alerts');
const FALLBACK_DAILY_REPORTS_DIR = path.join(require('os').tmpdir(), 'muaddib-daily-reports');
const FALLBACK_ALERTS_DIR = path.join(require('os').tmpdir(), 'muaddib-alerts');

/**
 * Try to ensure a directory exists and is writable. Returns the usable path
 * or a fallback path if the primary is read-only / permission-denied.
 */
function resolveWritableDir(primary, fallback) {
  try {
    fs.mkdirSync(primary, { recursive: true });
    // Verify writability with a probe file
    const probe = path.join(primary, '.write-test');
    fs.writeFileSync(probe, '', 'utf8');
    fs.unlinkSync(probe);
    return primary;
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] WARNING: ${primary} is not writable (${err.code}). Falling back to ${fallback}`);
      try {
        fs.mkdirSync(fallback, { recursive: true });
        return fallback;
      } catch (fallbackErr) {
        console.error(`[MONITOR] ERROR: Fallback ${fallback} also not writable: ${fallbackErr.message}`);
        return fallback; // Return anyway — individual writes will catch errors
      }
    }
    throw err; // Unexpected error — let it propagate
  }
}

const DAILY_REPORTS_LOG_DIR = resolveWritableDir(PRIMARY_DAILY_REPORTS_DIR, FALLBACK_DAILY_REPORTS_DIR);
const ALERTS_LOG_DIR = resolveWritableDir(PRIMARY_ALERTS_DIR, FALLBACK_ALERTS_DIR);

// --- npm seq constants ---

const NPM_SEQ_FILE = path.join(__dirname, '..', '..', 'data', 'npm-seq.json');
const CHANGES_STREAM_URL = 'https://replicate.npmjs.com/registry/_changes';
const CHANGES_LIMIT = 1000;
const CHANGES_CATCHUP_MAX = 500000; // If behind by more than 500k seqs, skip to "now"

// --- Scan memory constants ---

const SCAN_MEMORY_FILE = path.join(__dirname, '..', '..', 'data', 'scan-memory.json');
const SCAN_MEMORY_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const MAX_MEMORY_ENTRIES = 50000;
const MEMORY_SCORE_TOLERANCE = 0.15; // ±15% score tolerance

// --- Tarball cache constants ---

const TARBALL_CACHE_DIR = path.join(__dirname, '..', '..', 'data', 'tarball-cache');
const TARBALL_CACHE_INDEX_FILE = path.join(TARBALL_CACHE_DIR, 'cache-index.json');
const TARBALL_CACHE_DEFAULT_RETENTION_DAYS = 7;
const TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS = 30;
const TARBALL_CACHE_MAX_SIZE_BYTES = (parseInt(process.env.MUADDIB_TARBALL_CACHE_MAX_GB, 10) || 5) * 1024 * 1024 * 1024; // 5GB default

// --- Daily stats persist interval ---

const DAILY_STATS_PERSIST_INTERVAL = 1; // Persist to disk every scan (crash-safe)

// --- Mutable state ---

let scanMemoryCache = null;
let tarballCacheIndex = null;
let scansSinceLastPersist = 0;
let scansSinceLastMemoryPersist = 0;

// --- Mutable state getters/setters ---

function getScanMemoryCache() { return scanMemoryCache; }
function setScanMemoryCache(val) { scanMemoryCache = val; }
function getTarballCacheIndex() { return tarballCacheIndex; }
function setTarballCacheIndex(val) { tarballCacheIndex = val; }
function getScansSinceLastPersist() { return scansSinceLastPersist; }
function setScansSinceLastPersist(val) { scansSinceLastPersist = val; }
function getScansSinceLastMemoryPersist() { return scansSinceLastMemoryPersist; }
function setScansSinceLastMemoryPersist(val) { scansSinceLastMemoryPersist = val; }

// --- Atomic write ---

/**
 * Atomic file write: write to .tmp then rename (crash-safe).
 * Prevents race conditions and partial writes from corrupting data files.
 * On EROFS/EACCES, logs a warning and skips (non-fatal for monitor uptime).
 * @param {string} filePath - Target file path
 * @param {string} data - Content to write
 */
function atomicWriteFileSync(filePath, data) {
  const dir = path.dirname(filePath);
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] Cannot create directory ${dir} (${err.code}) — skipping write to ${path.basename(filePath)}`);
      return;
    }
    if (err.code === 'ENOSPC') {
      console.warn(`[MONITOR] WARNING: disk full (ENOSPC) — cannot create directory ${dir}. Free space immediately.`);
      return;
    }
    throw err;
  }
  const tmpFile = filePath + '.tmp';
  try {
    fs.writeFileSync(tmpFile, data, 'utf8');
    fs.renameSync(tmpFile, filePath);
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] Cannot write ${path.basename(filePath)} (${err.code}) — skipping`);
      try { fs.unlinkSync(tmpFile); } catch (_) { /* ignore */ }
      return;
    }
    if (err.code === 'ENOSPC') {
      console.warn(`[MONITOR] WARNING: disk full (ENOSPC) — cannot write ${path.basename(filePath)}. Free space in /tmp and data/ immediately.`);
      try { fs.unlinkSync(tmpFile); } catch (_) { /* ignore */ }
      return;
    }
    throw err;
  }
}

// --- npm seq persistence ---

/**
 * Load the last processed CouchDB sequence number from the dedicated file.
 * Returns null if no file exists or file is invalid (triggers "now" initialization).
 */
function loadNpmSeq() {
  try {
    if (fs.existsSync(NPM_SEQ_FILE)) {
      const data = JSON.parse(fs.readFileSync(NPM_SEQ_FILE, 'utf8'));
      if (typeof data.lastSeq === 'number' || typeof data.lastSeq === 'string') {
        return data.lastSeq;
      }
    }
  } catch (err) {
    console.warn(`[MONITOR] Failed to load npm seq: ${err.message}`);
  }
  return null;
}

/**
 * Persist the last processed CouchDB sequence number to a dedicated file.
 * Uses atomic write (crash-safe). Also stored in monitor-state.json via saveState().
 */
function saveNpmSeq(seq) {
  atomicWriteFileSync(NPM_SEQ_FILE, JSON.stringify({ lastSeq: seq, updatedAt: new Date().toISOString() }, null, 2));
}

// --- C3: Scan Memory Management ---

/**
 * Load scan memory from disk (with expiration purge).
 * @returns {Object} Map-like object: packageName → { version, score, types, hcTypes, timestamp }
 */
function loadScanMemory() {
  if (scanMemoryCache) return scanMemoryCache;
  const store = Object.create(null);
  try {
    if (fs.existsSync(SCAN_MEMORY_FILE)) {
      const raw = JSON.parse(fs.readFileSync(SCAN_MEMORY_FILE, 'utf8'));
      const now = Date.now();
      let purged = 0;
      for (const [key, entry] of Object.entries(raw)) {
        if (now - entry.timestamp > SCAN_MEMORY_EXPIRY_MS) {
          purged++;
          continue; // expired
        }
        store[key] = entry;
      }
      if (purged > 0) {
        console.log(`[MONITOR] MEMORY: purged ${purged} expired entries`);
      }
    }
  } catch (err) {
    console.warn(`[MONITOR] MEMORY: failed to load scan memory: ${err.message}`);
  }
  scanMemoryCache = store;
  return store;
}

/**
 * Save scan memory to disk (atomic write, max entries enforced).
 */
function saveScanMemory() {
  if (!scanMemoryCache) return;
  const entries = Object.entries(scanMemoryCache);
  // Enforce max entries: evict oldest if over limit
  if (entries.length > MAX_MEMORY_ENTRIES) {
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toRemove = entries.length - MAX_MEMORY_ENTRIES;
    for (let i = 0; i < toRemove; i++) {
      delete scanMemoryCache[entries[i][0]];
    }
  }
  try {
    atomicWriteFileSync(SCAN_MEMORY_FILE, JSON.stringify(scanMemoryCache, null, 2));
  } catch (err) {
    console.warn(`[MONITOR] MEMORY: failed to save scan memory: ${err.message}`);
  }
}

/**
 * Record a scan result in memory.
 * @param {string} name - Package name
 * @param {number} score - Risk score
 * @param {string[]} types - Unique threat types
 * @param {string[]} hcTypes - High-confidence threat types present
 */
function recordScanMemory(name, score, types, hcTypes) {
  const store = loadScanMemory();
  store[name] = {
    score,
    types: types.sort(),
    hcTypes: hcTypes.sort(),
    timestamp: Date.now()
  };
}

/**
 * Check if a webhook should be suppressed based on scan memory.
 * Returns { suppress: boolean, reason?: string }.
 *
 * Suppression conditions (ALL must be true):
 * 1. Previous scan exists and not expired
 * 2. Score within ±15% of previous
 * 3. No NEW threat types (subset or equal)
 * 4. No NEW high-confidence types
 *
 * Bypass conditions (any = don't suppress):
 * - IOC match in current result
 * - New HC types not in previous scan
 */
function shouldSuppressByMemory(name, result) {
  // Late-bound require to avoid circular dependency
  const { HIGH_CONFIDENCE_MALICE_TYPES, hasIOCMatch } = require('./classify.js');

  const store = loadScanMemory();
  const prev = store[name];
  if (!prev) return { suppress: false };

  const currentScore = (result && result.summary) ? (result.summary.riskScore || 0) : 0;
  const currentTypes = [...new Set((result.threats || []).map(t => t.type))].sort();
  const currentHCTypes = (result.threats || [])
    .filter(t => HIGH_CONFIDENCE_MALICE_TYPES.has(t.type) && t.severity !== 'LOW')
    .map(t => t.type);
  const currentHCSet = [...new Set(currentHCTypes)].sort();

  // Bypass: IOC match always sends
  if (hasIOCMatch(result)) return { suppress: false, reason: 'IOC match' };

  // Condition 1: Score within ±15%
  const prevScore = prev.score || 0;
  if (prevScore === 0 && currentScore === 0) {
    // Both zero — suppress (nothing changed)
  } else if (prevScore === 0 || currentScore === 0) {
    // One is zero, other is not — significant change
    return { suppress: false, reason: `score changed (${prevScore} → ${currentScore})` };
  } else {
    const ratio = currentScore / prevScore;
    if (ratio < (1 - MEMORY_SCORE_TOLERANCE) || ratio > (1 + MEMORY_SCORE_TOLERANCE)) {
      return { suppress: false, reason: `score changed (${prevScore} → ${currentScore}, ratio=${ratio.toFixed(2)})` };
    }
  }

  // Condition 2: No new threat types
  const prevTypesSet = new Set(prev.types || []);
  const newTypes = currentTypes.filter(t => !prevTypesSet.has(t));
  if (newTypes.length > 0) {
    return { suppress: false, reason: `new threat types: ${newTypes.join(', ')}` };
  }

  // Condition 3: No new HC types
  const prevHCSet = new Set(prev.hcTypes || []);
  const newHC = currentHCSet.filter(t => !prevHCSet.has(t));
  if (newHC.length > 0) {
    return { suppress: false, reason: `new HC types: ${newHC.join(', ')}` };
  }

  return { suppress: true, reason: `memory match (prev score=${prevScore}, current=${currentScore})` };
}

// --- Layer 3: Tarball cache management ---

/**
 * Load tarball cache index from disk. Creates cache directory if needed.
 * @returns {{ entries: Object }} Cache index
 */
function loadTarballCacheIndex() {
  if (tarballCacheIndex) return tarballCacheIndex;
  const index = { entries: Object.create(null) };
  try {
    if (!fs.existsSync(TARBALL_CACHE_DIR)) {
      fs.mkdirSync(TARBALL_CACHE_DIR, { recursive: true });
    }
    if (fs.existsSync(TARBALL_CACHE_INDEX_FILE)) {
      const raw = JSON.parse(fs.readFileSync(TARBALL_CACHE_INDEX_FILE, 'utf8'));
      if (raw && raw.entries) {
        for (const [key, entry] of Object.entries(raw.entries)) {
          index.entries[key] = entry;
        }
      }
    }
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] TARBALL CACHE: cannot access cache directory (${err.code})`);
    } else {
      console.warn(`[MONITOR] TARBALL CACHE: failed to load index: ${err.message}`);
    }
  }
  tarballCacheIndex = index;
  return index;
}

function saveTarballCacheIndex() {
  if (!tarballCacheIndex) return;
  try {
    atomicWriteFileSync(TARBALL_CACHE_INDEX_FILE, JSON.stringify(tarballCacheIndex, null, 2));
  } catch (err) {
    console.warn(`[MONITOR] TARBALL CACHE: failed to save index: ${err.message}`);
  }
}

function tarballCacheKey(name, version) {
  return `${sanitizePackageName(name)}-${sanitizePackageName(version || 'unknown')}`;
}

function tarballCachePath(key) {
  return path.join(TARBALL_CACHE_DIR, `${key}.tgz`);
}

/**
 * Copy a downloaded tarball into the cache directory.
 * @param {string} name - Package name
 * @param {string} version - Package version
 * @param {string} sourcePath - Path to the downloaded .tgz file
 * @param {string} reason - Why cached (ioc_match, typosquat_signal, first_publish)
 * @param {number} retentionDays - How many days to retain
 */
function cacheTarball(name, version, sourcePath, reason, retentionDays) {
  const index = loadTarballCacheIndex();
  const key = tarballCacheKey(name, version);
  const destPath = tarballCachePath(key);

  if (!fs.existsSync(TARBALL_CACHE_DIR)) {
    fs.mkdirSync(TARBALL_CACHE_DIR, { recursive: true });
  }

  fs.copyFileSync(sourcePath, destPath);
  const fileSize = fs.statSync(destPath).size;

  index.entries[key] = {
    name,
    version,
    cachedAt: Date.now(),
    retentionDays,
    reason,
    size: fileSize
  };

  saveTarballCacheIndex();
  console.log(`[MONITOR] TARBALL CACHE: cached ${name}@${version} (${reason}, ${retentionDays}d, ${(fileSize / 1024).toFixed(0)}KB)`);
}

/**
 * Purge expired entries and enforce size budget.
 * Called at startup and hourly.
 */
function purgeTarballCache() {
  const index = loadTarballCacheIndex();
  const now = Date.now();
  let totalSize = 0;
  let purgedExpired = 0;
  let purgedBudget = 0;

  // Phase 1: Remove expired entries
  for (const [key, entry] of Object.entries(index.entries)) {
    const expiryMs = entry.retentionDays * 24 * 60 * 60 * 1000;
    if (now - entry.cachedAt > expiryMs) {
      try {
        const filePath = tarballCachePath(key);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch { /* ignore cleanup errors */ }
      delete index.entries[key];
      purgedExpired++;
    } else {
      totalSize += entry.size || 0;
    }
  }

  // Phase 2: Enforce size budget — evict oldest first
  if (totalSize > TARBALL_CACHE_MAX_SIZE_BYTES) {
    const sorted = Object.entries(index.entries)
      .sort((a, b) => a[1].cachedAt - b[1].cachedAt);

    for (const [key, entry] of sorted) {
      if (totalSize <= TARBALL_CACHE_MAX_SIZE_BYTES) break;
      try {
        const filePath = tarballCachePath(key);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch { /* ignore */ }
      totalSize -= entry.size || 0;
      delete index.entries[key];
      purgedBudget++;
    }
  }

  if (purgedExpired > 0 || purgedBudget > 0) {
    saveTarballCacheIndex();
    const remaining = Object.keys(index.entries).length;
    console.log(`[MONITOR] TARBALL CACHE: purged ${purgedExpired} expired + ${purgedBudget} budget entries (${remaining} remaining, ${(totalSize / 1024 / 1024).toFixed(1)}MB)`);
  }
}

// --- Temporal detections ---

/**
 * Append a temporal detection to the temporal detections file.
 * @param {string} name - Package name
 * @param {string} version - Package version
 * @param {Array} findings - Temporal findings array
 */
function appendTemporalDetection(name, version, findings) {
  let detections = [];
  try {
    if (fs.existsSync(TEMPORAL_DETECTIONS_FILE)) {
      detections = JSON.parse(fs.readFileSync(TEMPORAL_DETECTIONS_FILE, 'utf8'));
    }
  } catch { /* corrupted file — start fresh */ }
  detections.push({
    name,
    version,
    findings,
    timestamp: new Date().toISOString()
  });
  // Keep last 1000 entries
  if (detections.length > 1000) {
    detections = detections.slice(-1000);
  }
  atomicWriteFileSync(TEMPORAL_DETECTIONS_FILE, JSON.stringify(detections, null, 2));
}

/**
 * Load temporal detections from file.
 * @returns {Array} Array of temporal detection entries
 */
function loadTemporalDetections() {
  try {
    if (fs.existsSync(TEMPORAL_DETECTIONS_FILE)) {
      return JSON.parse(fs.readFileSync(TEMPORAL_DETECTIONS_FILE, 'utf8'));
    }
  } catch { /* ignore */ }
  return [];
}

// --- State persistence ---

function loadState(stats) {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const state = JSON.parse(raw);
    // Restore daily report date so it survives restarts (auto-update, crashes)
    if (typeof state.lastDailyReportDate === 'string') {
      stats.lastDailyReportDate = state.lastDailyReportDate;
    }
    // Also check the dedicated daily report file (crash-safe source of truth)
    const diskDate = loadLastDailyReportDate();
    if (diskDate && (!stats.lastDailyReportDate || diskDate > stats.lastDailyReportDate)) {
      stats.lastDailyReportDate = diskDate;
    }
    return {
      npmLastPackage: typeof state.npmLastPackage === 'string' ? state.npmLastPackage : '',
      pypiLastPackage: typeof state.pypiLastPackage === 'string' ? state.pypiLastPackage : '',
      npmLastSeq: state.npmLastSeq != null ? state.npmLastSeq : loadNpmSeq()
    };
  } catch {
    return { npmLastPackage: '', pypiLastPackage: '', npmLastSeq: loadNpmSeq() };
  }
}

function saveState(state, stats) {
  try {
    const dir = path.dirname(STATE_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    // Persist daily report date so it survives restarts
    const persistedState = {
      ...state,
      lastDailyReportDate: stats.lastDailyReportDate
    };
    // Atomic write: write to .tmp then rename (crash-safe)
    const tmpFile = STATE_FILE + '.tmp';
    fs.writeFileSync(tmpFile, JSON.stringify(persistedState, null, 2), 'utf8');
    fs.renameSync(tmpFile, STATE_FILE);
  } catch (err) {
    console.error(`[MONITOR] Failed to save state: ${err.message}`);
  }
}

// --- Alerts persistence ---

function appendAlert(alert) {
  try {
    const dir = path.dirname(ALERTS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    let alerts = [];
    try {
      alerts = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
    } catch {}
    alerts.push(alert);
    atomicWriteFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to save alert: ${err.message}`);
  }
}

// --- Detection time logging ---

function loadDetections() {
  try {
    const raw = fs.readFileSync(DETECTIONS_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data && Array.isArray(data.detections)) return data;
    return { detections: [] };
  } catch {
    return { detections: [] };
  }
}

function appendDetection(name, version, ecosystem, findings, severity) {
  try {
    const dir = path.dirname(DETECTIONS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data = loadDetections();
    const key = `${name}@${version}`;
    if (data.detections.some(d => `${d.package}@${d.version}` === key)) {
      return; // dedup
    }
    data.detections.push({
      package: name,
      version,
      ecosystem,
      first_seen_at: new Date().toISOString(),
      findings,
      severity,
      advisory_at: null,
      lead_time_hours: null
    });
    atomicWriteFileSync(DETECTIONS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to save detection: ${err.message}`);
  }
}

function getDetectionStats() {
  const data = loadDetections();
  const detections = data.detections;
  const total = detections.length;

  const bySeverity = {};
  const byEcosystem = {};
  for (const d of detections) {
    bySeverity[d.severity] = (bySeverity[d.severity] || 0) + 1;
    byEcosystem[d.ecosystem] = (byEcosystem[d.ecosystem] || 0) + 1;
  }

  const withLeadTime = detections.filter(d => d.advisory_at && d.lead_time_hours != null);
  let leadTime = null;
  if (withLeadTime.length > 0) {
    const hours = withLeadTime.map(d => d.lead_time_hours);
    leadTime = {
      count: withLeadTime.length,
      avg: hours.reduce((a, b) => a + b, 0) / hours.length,
      min: Math.min(...hours),
      max: Math.max(...hours)
    };
  }

  return { total, bySeverity, byEcosystem, leadTime };
}

// --- Scan stats (FP rate tracking) ---

function loadScanStats() {
  try {
    const raw = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data && data.stats && Array.isArray(data.daily)) return data;
    return { stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0, sandbox_inconclusive: 0 }, daily: [] };
  } catch {
    return { stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0, sandbox_inconclusive: 0 }, daily: [] };
  }
}

function updateScanStats(result) {
  const data = loadScanStats();
  data.stats.total_scanned++;
  // Ensure backward compat with old stats files
  if (data.stats.sandbox_inconclusive === undefined) data.stats.sandbox_inconclusive = 0;
  if (data.stats.sandbox_unconfirmed === undefined) data.stats.sandbox_unconfirmed = 0;

  if (result === 'clean') data.stats.clean++;
  else if (result === 'ml_clean') data.stats.clean++; // ML classifier FP filter — counts as clean
  else if (result === 'suspect') data.stats.suspect++;
  else if (result === 'false_positive') data.stats.false_positive++;
  else if (result === 'confirmed') data.stats.confirmed_malicious++;
  else if (result === 'sandbox_inconclusive') data.stats.sandbox_inconclusive++;
  else if (result === 'sandbox_unconfirmed') { data.stats.sandbox_unconfirmed++; }

  const today = getParisDateString();
  let dayEntry = data.daily.find(d => d.date === today);
  if (!dayEntry) {
    dayEntry = { date: today, scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed: 0, sandbox_inconclusive: 0, fp_rate: 0 };
    data.daily.push(dayEntry);
  }
  dayEntry.scanned++;

  if (result === 'clean') dayEntry.clean++;
  else if (result === 'ml_clean') dayEntry.clean++; // ML classifier FP filter — counts as clean
  else if (result === 'suspect') dayEntry.suspect++;
  else if (result === 'false_positive') dayEntry.false_positive++;
  else if (result === 'confirmed') dayEntry.confirmed++;
  else if (result === 'sandbox_inconclusive') { dayEntry.sandbox_inconclusive = (dayEntry.sandbox_inconclusive || 0) + 1; }
  else if (result === 'sandbox_unconfirmed') { dayEntry.sandbox_unconfirmed = (dayEntry.sandbox_unconfirmed || 0) + 1; }

  const denom = dayEntry.false_positive + dayEntry.confirmed;
  dayEntry.fp_rate = denom > 0 ? dayEntry.false_positive / denom : 0;

  try {
    atomicWriteFileSync(SCAN_STATS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to save scan stats: ${err.message}`);
  }
}

// --- Daily stats persistence (survives restarts) ---

function loadDailyStats(stats, dailyAlerts) {
  try {
    const raw = fs.readFileSync(DAILY_STATS_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data && typeof data.scanned === 'number') {
      stats.scanned = data.scanned;
      stats.clean = data.clean || 0;
      stats.suspect = data.suspect || 0;
      if (data.suspectByTier) {
        stats.suspectByTier.t1 = data.suspectByTier.t1 || 0;
        stats.suspectByTier.t1a = data.suspectByTier.t1a || 0;
        stats.suspectByTier.t1b = data.suspectByTier.t1b || 0;
        stats.suspectByTier.t2 = data.suspectByTier.t2 || 0;
        stats.suspectByTier.t3 = data.suspectByTier.t3 || 0;
      }
      stats.errors = data.errors || 0;
      if (data.errorsByType) {
        stats.errorsByType.too_large = data.errorsByType.too_large || 0;
        stats.errorsByType.tar_failed = data.errorsByType.tar_failed || 0;
        stats.errorsByType.http_error = data.errorsByType.http_error || 0;
        stats.errorsByType.timeout = data.errorsByType.timeout || 0;
        stats.errorsByType.static_timeout = data.errorsByType.static_timeout || 0;
        stats.errorsByType.other = data.errorsByType.other || 0;
      }
      stats.totalTimeMs = data.totalTimeMs || 0;
      stats.mlFiltered = data.mlFiltered || 0;
      stats.llmAnalyzed = data.llmAnalyzed || 0;
      stats.llmSuppressed = data.llmSuppressed || 0;
      if (Array.isArray(data.dailyAlerts)) {
        dailyAlerts.length = 0;
        dailyAlerts.push(...data.dailyAlerts);
      }
      console.log(`[MONITOR] Restored daily stats: ${stats.scanned} scanned, ${stats.clean} clean, ${stats.suspect} suspect`);
    }
  } catch {
    // No file or corrupt — start from zero
  }
}

function saveDailyStats(stats, dailyAlerts) {
  try {
    const dir = path.dirname(DAILY_STATS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const data = {
      scanned: stats.scanned,
      clean: stats.clean,
      suspect: stats.suspect,
      suspectByTier: { ...stats.suspectByTier },
      errors: stats.errors,
      errorsByType: { ...stats.errorsByType },
      totalTimeMs: stats.totalTimeMs,
      mlFiltered: stats.mlFiltered,
      llmAnalyzed: stats.llmAnalyzed || 0,
      llmSuppressed: stats.llmSuppressed || 0,
      dailyAlerts: dailyAlerts.slice()
    };
    atomicWriteFileSync(DAILY_STATS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to save daily stats: ${err.message}`);
  }
}

function resetDailyStats() {
  try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
}

/**
 * Persist daily stats to disk every DAILY_STATS_PERSIST_INTERVAL scans.
 * Called after each scan completes in processQueue.
 */
function maybePersistDailyStats(stats, dailyAlerts) {
  scansSinceLastPersist++;
  if (scansSinceLastPersist >= DAILY_STATS_PERSIST_INTERVAL) {
    saveDailyStats(stats, dailyAlerts);
    scansSinceLastPersist = 0;
  }
}

// --- Daily report date persistence ---

/**
 * Load the date (YYYY-MM-DD) of the last daily report sent from disk.
 * Returns null if no file exists or file is invalid.
 */
function loadLastDailyReportDate() {
  try {
    const raw = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8');
    const data = JSON.parse(raw);
    return typeof data.lastReportDate === 'string' ? data.lastReportDate : null;
  } catch {
    return null;
  }
}

/**
 * Persist the date of the last daily report sent (YYYY-MM-DD).
 */
function saveLastDailyReportDate(dateStr) {
  try {
    atomicWriteFileSync(LAST_DAILY_REPORT_FILE, JSON.stringify({ lastReportDate: dateStr }, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to save last daily report date: ${err.message}`);
  }
}

/**
 * Returns true if today's daily report has already been sent.
 * Checks both in-memory state AND disk file for crash resilience.
 */
function hasReportBeenSentToday(stats) {
  const today = getParisDateString();
  if (stats.lastDailyReportDate === today) return true;
  const diskDate = loadLastDailyReportDate();
  if (diskDate === today) return true;
  return false;
}

// --- Paris timezone utilities ---

/**
 * Returns the current hour in Europe/Paris timezone (0-23).
 */
function getParisHour() {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Paris',
    hour: 'numeric',
    hour12: false
  });
  return parseInt(formatter.format(new Date()), 10);
}

/**
 * Returns today's date string in Europe/Paris timezone (YYYY-MM-DD).
 */
function getParisDateString() {
  const formatter = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Paris' });
  return formatter.format(new Date());
}

// --- Raw state loader (CLI report helpers) ---

/**
 * Read raw state file (without restoring into stats).
 */
function loadStateRaw() {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

module.exports = {
  // Constants
  STATE_FILE,
  ALERTS_FILE,
  DETECTIONS_FILE,
  SCAN_STATS_FILE,
  LAST_DAILY_REPORT_FILE,
  DAILY_STATS_FILE,
  TEMPORAL_DETECTIONS_FILE,
  PRIMARY_DAILY_REPORTS_DIR,
  PRIMARY_ALERTS_DIR,
  FALLBACK_DAILY_REPORTS_DIR,
  FALLBACK_ALERTS_DIR,
  DAILY_REPORTS_LOG_DIR,
  ALERTS_LOG_DIR,
  NPM_SEQ_FILE,
  CHANGES_STREAM_URL,
  CHANGES_LIMIT,
  CHANGES_CATCHUP_MAX,
  SCAN_MEMORY_FILE,
  SCAN_MEMORY_EXPIRY_MS,
  MAX_MEMORY_ENTRIES,
  MEMORY_SCORE_TOLERANCE,
  TARBALL_CACHE_DIR,
  TARBALL_CACHE_INDEX_FILE,
  TARBALL_CACHE_DEFAULT_RETENTION_DAYS,
  TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS,
  TARBALL_CACHE_MAX_SIZE_BYTES,
  DAILY_STATS_PERSIST_INTERVAL,

  // Mutable state getters/setters
  getScanMemoryCache,
  setScanMemoryCache,
  getTarballCacheIndex,
  setTarballCacheIndex,
  getScansSinceLastPersist,
  setScansSinceLastPersist,
  getScansSinceLastMemoryPersist,
  setScansSinceLastMemoryPersist,

  // Functions
  resolveWritableDir,
  atomicWriteFileSync,
  loadNpmSeq,
  saveNpmSeq,
  loadScanMemory,
  saveScanMemory,
  recordScanMemory,
  shouldSuppressByMemory,
  loadTarballCacheIndex,
  saveTarballCacheIndex,
  tarballCacheKey,
  tarballCachePath,
  cacheTarball,
  purgeTarballCache,
  appendTemporalDetection,
  loadTemporalDetections,
  loadState,
  saveState,
  appendAlert,
  loadDetections,
  appendDetection,
  getDetectionStats,
  loadScanStats,
  updateScanStats,
  loadDailyStats,
  saveDailyStats,
  resetDailyStats,
  maybePersistDailyStats,
  loadLastDailyReportDate,
  saveLastDailyReportDate,
  hasReportBeenSentToday,
  getParisHour,
  getParisDateString,
  loadStateRaw
};
