/**
 * Monitor state/persistence functions.
 * Extracted from src/monitor.js — all file I/O, caching, and state management.
 */

const fs = require('fs');
const path = require('path');
const { isMainThread, threadId } = require('worker_threads');
const { sanitizePackageName } = require('../shared/download.js');

// --- File path constants ---

const STATE_FILE = path.join(__dirname, '..', '..', 'data', 'monitor-state.json');
const ALERTS_FILE = path.join(__dirname, '..', '..', 'data', 'monitor-alerts.jsonl');
// Detections + temporal detections are append-only JSONL since the OOM fix.
// Legacy *.json files are migrated once at boot via runStateMigrations() and
// kept as *.json.migrated for forensic recovery (no longer read by the monitor).
const DETECTIONS_FILE = path.join(__dirname, '..', '..', 'data', 'detections.jsonl');
const DETECTIONS_FILE_LEGACY = path.join(__dirname, '..', '..', 'data', 'detections.json');
const SCAN_STATS_FILE = path.join(__dirname, '..', '..', 'data', 'scan-stats.json');
const LAST_DAILY_REPORT_FILE = path.join(__dirname, '..', '..', 'data', 'last-daily-report.json');
const DAILY_STATS_FILE = path.join(__dirname, '..', '..', 'data', 'daily-stats.json');
const RECENTLY_SCANNED_FILE = path.join(__dirname, '..', '..', 'data', 'recently-scanned.json');
const TEMPORAL_DETECTIONS_FILE = path.join(__dirname, '..', '..', 'data', 'temporal-detections.jsonl');
const TEMPORAL_DETECTIONS_FILE_LEGACY = path.join(__dirname, '..', '..', 'data', 'temporal-detections.json');

// --- Alerts/detections persistence limits ---
const ALERTS_MAX_SIZE = 100 * 1024 * 1024; // 100MB rotation threshold (matches ml-training.jsonl)
const MAX_DETECTIONS = 10_000;              // Cap detections JSONL — older entries pruned at compaction
const MAX_TEMPORAL_DETECTIONS = 1000;       // Cap temporal detections JSONL — pruned at compaction
const MAX_DAILY_ALERTS = 50_000;            // Cap dailyAlerts array — prevents unbounded growth between daily resets
// Append count between automatic compactions. Compaction is O(file size) so we
// avoid running it on every append. With 350 detections/h on the VPS, a value
// of 100 means ~17 min between compactions, acceptable overhead for the fix.
const DETECTION_COMPACT_INTERVAL = 100;

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
function resolveWritableDir(primary, fallback, isMain = isMainThread) {
  try {
    fs.mkdirSync(primary, { recursive: true });
    // Only the MAIN thread writes reports/alerts. Each of the up-to-16 scan worker
    // threads also loads this module (via the transitive require chain), so if they
    // all ran the probe they'd race on the shared path and throw ENOENT on unlink
    // (8 such errors/day in prod). Workers skip the probe — the main thread's is enough.
    if (isMain) {
      // Unique name per process+thread so overlapping processes (restart storms) and
      // any future multi-thread probing can't collide. force:true on removal tolerates
      // an already-gone probe (the very race this fixes) instead of throwing ENOENT.
      const probe = path.join(primary, `.write-test-${process.pid}-${threadId}`);
      fs.writeFileSync(probe, '', 'utf8');
      fs.rmSync(probe, { force: true });
    }
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

// --- PyPI serial constants ---
//
// PyPI's XML-RPC changelog endpoint is the canonical equivalent of npm's CouchDB
// `_changes` stream: every package event (release, file upload, removal, owner
// change…) gets a strictly monotonic integer "serial". `changelog_since_serial(n)`
// returns every event with serial > n, letting us resume losslessly across restarts.
//
// PYPI_CATCHUP_MAX is the staleness cap: if we are behind by more than this many
// serials (≈ days of activity at ~30k events/day in 2026), skip to "now" rather
// than fetch a monster batch. Mirrors CHANGES_CATCHUP_MAX for npm.
const PYPI_SERIAL_FILE = path.join(__dirname, '..', '..', 'data', 'pypi-serial.json');
const PYPI_XMLRPC_URL = 'https://pypi.org/pypi';
const PYPI_CATCHUP_MAX = 100000;

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

// Detection JSONL state (OOM fix — see runStateMigrations).
// In-memory dedup Set replaces the previous "JSON.parse(file).some(...)" lookup
// that allocated ~15 MB of transient objects per appendDetection call.
let _detectionDedupSet = null;          // Set<"package@version">, lazy-init from JSONL
let _detectionsAppendedSinceCompact = 0; // counter for lazy compaction trigger
let _temporalAppendedSinceCompact = 0;

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
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
      return;
    }
    if (err.code === 'ENOSPC') {
      console.warn(`[MONITOR] WARNING: disk full (ENOSPC) — cannot write ${path.basename(filePath)}. Free space in /tmp and data/ immediately.`);
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
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

// --- PyPI serial persistence ---

/**
 * Load the last processed PyPI changelog serial from the dedicated file.
 * Returns null if no file exists or file is invalid (triggers "now" initialization).
 */
function loadPypiSerial() {
  try {
    if (fs.existsSync(PYPI_SERIAL_FILE)) {
      const data = JSON.parse(fs.readFileSync(PYPI_SERIAL_FILE, 'utf8'));
      if (typeof data.lastSerial === 'number' && Number.isFinite(data.lastSerial)) {
        return data.lastSerial;
      }
    }
  } catch (err) {
    console.warn(`[MONITOR] Failed to load PyPI serial: ${err.message}`);
  }
  return null;
}

/**
 * Persist the last processed PyPI changelog serial to a dedicated file.
 * Atomic write (crash-safe). Also mirrored in monitor-state.json via saveState().
 */
function savePypiSerial(serial) {
  atomicWriteFileSync(
    PYPI_SERIAL_FILE,
    JSON.stringify({ lastSerial: serial, updatedAt: new Date().toISOString() }, null, 2)
  );
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
  // Read-modify-write: preserve fields set out-of-band (notably lastSandboxAt,
  // stamped by markSandboxed when a real sandbox runs) so a record at webhook time
  // does NOT clobber the sandbox-revalidation timestamp the sandbox-skip decision
  // reads. Without this, every webhook record would reset lastSandboxAt and the
  // 7-day canary-revalidation cadence would never settle.
  const prev = store[name] || {};
  store[name] = {
    ...prev,
    score,
    types: types.sort(),
    hcTypes: hcTypes.sort(),
    timestamp: Date.now()
  };
}

/**
 * Stamp lastSandboxAt on a package's scan-memory entry — call when a real sandbox
 * run was just performed. The sandbox-skip decision (queue.js shouldSkipSandbox)
 * uses this to skip re-sandboxing a memory-matched package until SANDBOX_REVALIDATE_MS
 * has elapsed: kills restart-replay / re-publish sandbox waste while retaining canary
 * coverage on a slow cadence. Mutates the in-memory cache; persisted by the next
 * saveScanMemory(). A timestamp is set too so a sandbox-before-first-scan entry still
 * has a valid expiry/eviction key.
 * @param {string} name - Package name
 * @param {number} [at] - Timestamp in ms (defaults to now)
 */
function markSandboxed(name, at) {
  const store = loadScanMemory();
  const ts = at || Date.now();
  const prev = store[name] || {};
  store[name] = { ...prev, lastSandboxAt: ts, timestamp: prev.timestamp || ts };
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

// --- JSONL streaming helper (OOM fix — keeps memory bounded for large files) ---

/**
 * Iterate JSONL lines from a file using chunked sync reads. Avoids loading the
 * full file into memory (which is what the previous read-modify-write pattern
 * did and what triggered the V8 OOM under 16-worker concurrency).
 *
 * Bad lines are silently skipped (the file is human-edited only in incidents).
 * The callback may return `false` to stop iteration early.
 *
 * @param {string} filePath
 * @param {(entry:object) => boolean|void} callback
 */
function _iterateJsonlSync(filePath, callback) {
  if (!fs.existsSync(filePath)) return;
  const BUF_SIZE = 64 * 1024;
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.alloc(BUF_SIZE);
  let leftover = '';
  try {
    while (true) {
      const bytesRead = fs.readSync(fd, buf, 0, BUF_SIZE, null);
      if (bytesRead === 0) break;
      const chunk = leftover + buf.slice(0, bytesRead).toString('utf8');
      const lines = chunk.split('\n');
      leftover = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        let entry;
        try { entry = JSON.parse(line); } catch { continue; }
        if (callback(entry) === false) return;
      }
    }
    if (leftover.trim()) {
      try {
        const entry = JSON.parse(leftover);
        callback(entry);
      } catch { /* trailing partial line — ignore */ }
    }
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Count newline-terminated lines without parsing JSON. Used by compaction to
 * skip the rewrite path when the file is already under the cap.
 */
function _countJsonlLines(filePath) {
  if (!fs.existsSync(filePath)) return 0;
  const BUF_SIZE = 64 * 1024;
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.alloc(BUF_SIZE);
  let count = 0;
  let endsWithNewline = false;
  try {
    while (true) {
      const bytesRead = fs.readSync(fd, buf, 0, BUF_SIZE, null);
      if (bytesRead === 0) break;
      for (let i = 0; i < bytesRead; i++) {
        if (buf[i] === 0x0a) count++;
      }
      endsWithNewline = (buf[bytesRead - 1] === 0x0a);
    }
  } finally {
    fs.closeSync(fd);
  }
  // If the file's last line lacks a trailing newline it still counts as one entry.
  if (!endsWithNewline) {
    try {
      if (fs.statSync(filePath).size > 0) count++;
    } catch { /* ignore */ }
  }
  return count;
}

// --- Temporal detections (append-only JSONL since OOM fix) ---

/**
 * Trim temporal findings to essential fields only.
 * Production findings arrive as { type, data: { suspicious, message, score, findings: [...], ... } }
 * with the data object containing full AST diffs, metadata snapshots, etc (~80KB each).
 * This retains only type, severity, suspicious, message, and score for persistence.
 */
function trimTemporalFindings(findings) {
  return findings.map(f => {
    const trimmed = { type: f.type };
    if (f.severity) trimmed.severity = f.severity;
    if (f.message) trimmed.message = f.message;
    if (f.data) {
      if (f.data.suspicious !== undefined) trimmed.suspicious = f.data.suspicious;
      if (f.data.message) trimmed.message = trimmed.message || f.data.message;
      if (f.data.score !== undefined) trimmed.score = f.data.score;
      if (f.data.severity) trimmed.severity = trimmed.severity || f.data.severity;
    }
    return trimmed;
  });
}

/**
 * Append a temporal detection to the temporal detections JSONL file. Append-only
 * (O(1) regardless of file size) — the previous read-modify-write loaded the
 * entire file on every call which was a major OOM contributor.
 *
 * @param {string} name - Package name
 * @param {string} version - Package version
 * @param {Array} findings - Temporal findings array (will be trimmed)
 */
function appendTemporalDetection(name, version, findings) {
  try {
    const dir = path.dirname(TEMPORAL_DETECTIONS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const entry = {
      name,
      version,
      findings: trimTemporalFindings(findings),
      timestamp: new Date().toISOString()
    };
    fs.appendFileSync(TEMPORAL_DETECTIONS_FILE, JSON.stringify(entry) + '\n', 'utf8');
    _temporalAppendedSinceCompact++;
    if (_temporalAppendedSinceCompact >= DETECTION_COMPACT_INTERVAL) {
      _temporalAppendedSinceCompact = 0;
      _compactTemporalDetectionsJsonl();
    }
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] Permission denied writing temporal detection: ${err.code}`);
      return;
    }
    if (err.code === 'ENOSPC') {
      console.warn('[MONITOR] WARNING: disk full (ENOSPC) — cannot persist temporal detection.');
      return;
    }
    console.error(`[MONITOR] Failed to save temporal detection: ${err.message}`);
  }
}

/**
 * Load temporal detections from file using streaming reads.
 * @returns {Array} Array of temporal detection entries (oldest first, capped to MAX_TEMPORAL_DETECTIONS)
 */
function loadTemporalDetections() {
  const detections = [];
  try {
    _iterateJsonlSync(TEMPORAL_DETECTIONS_FILE, (entry) => { detections.push(entry); });
  } catch { /* ignore */ }
  return detections;
}

/**
 * Compact the temporal detections JSONL file: keep only the most recent
 * MAX_TEMPORAL_DETECTIONS entries. No-op when the file is already under cap.
 * Internal — called from appendTemporalDetection on a counter trigger and from
 * runStateMigrations to enforce caps after migration.
 */
function _compactTemporalDetectionsJsonl() {
  try {
    const total = _countJsonlLines(TEMPORAL_DETECTIONS_FILE);
    if (total <= MAX_TEMPORAL_DETECTIONS) return;
    const toDrop = total - MAX_TEMPORAL_DETECTIONS;
    let skipped = 0;
    const kept = [];
    _iterateJsonlSync(TEMPORAL_DETECTIONS_FILE, (entry) => {
      if (skipped < toDrop) { skipped++; return; }
      kept.push(JSON.stringify(entry));
    });
    const tmpFile = TEMPORAL_DETECTIONS_FILE + '.tmp';
    fs.writeFileSync(tmpFile, kept.length ? kept.join('\n') + '\n' : '', 'utf8');
    fs.renameSync(tmpFile, TEMPORAL_DETECTIONS_FILE);
    console.log(`[MONITOR] COMPACT temporal-detections: ${total} -> ${kept.length} entries`);
  } catch (err) {
    console.error(`[MONITOR] Temporal detections compaction failed: ${err.message}`);
  }
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
      npmLastSeq: state.npmLastSeq != null ? state.npmLastSeq : loadNpmSeq(),
      pypiLastSerial: state.pypiLastSerial != null ? state.pypiLastSerial : loadPypiSerial()
    };
  } catch {
    return {
      npmLastPackage: '',
      pypiLastPackage: '',
      npmLastSeq: loadNpmSeq(),
      pypiLastSerial: loadPypiSerial()
    };
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

// --- Alerts persistence (JSONL append-only) ---

function maybeRotateAlerts() {
  try {
    if (!fs.existsSync(ALERTS_FILE)) return;
    const stat = fs.statSync(ALERTS_FILE);
    if (stat.size < ALERTS_MAX_SIZE) return;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const rotatedName = ALERTS_FILE.replace('.jsonl', `-${timestamp}.jsonl`);
    fs.renameSync(ALERTS_FILE, rotatedName);
    console.log(`[MONITOR] Rotated alerts -> ${path.basename(rotatedName)} (${(stat.size / 1024 / 1024).toFixed(1)}MB)`);
  } catch (err) {
    console.error(`[MONITOR] Alerts rotation failed: ${err.message}`);
  }
}

function appendAlert(alert) {
  try {
    const dir = path.dirname(ALERTS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    maybeRotateAlerts();
    const line = JSON.stringify(alert) + '\n';
    fs.appendFileSync(ALERTS_FILE, line, 'utf8');
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] Permission denied writing alerts: ${err.code}`);
      return;
    }
    console.error(`[MONITOR] Failed to save alert: ${err.message}`);
  }
}

// --- Detection time logging (append-only JSONL since OOM fix) ---

/**
 * Lazy initialization of the in-memory dedup Set. Reading the JSONL file once
 * at first use replaces the per-call read-modify-write that allocated ~15 MB
 * of transient parsed objects on every appendDetection invocation.
 */
function _initDetectionDedupSet() {
  if (_detectionDedupSet !== null) return;
  _detectionDedupSet = new Set();
  try {
    _iterateJsonlSync(DETECTIONS_FILE, (entry) => {
      if (entry && entry.package && entry.version) {
        _detectionDedupSet.add(`${entry.package}@${entry.version}`);
      }
    });
  } catch { /* ignore — Set stays empty */ }
}

/**
 * Reset internal detection state. Test-only: lets the test suite control file
 * lifecycle without leaking dedup state between cases.
 */
function _resetDetectionState() {
  _detectionDedupSet = null;
  _detectionsAppendedSinceCompact = 0;
  _temporalAppendedSinceCompact = 0;
}

/**
 * Load all detections by streaming the JSONL file. Returns the same
 * { detections: [...] } shape as before so downstream consumers
 * (buildReportFromDisk, daily report) are unchanged.
 */
function loadDetections() {
  const detections = [];
  try {
    _iterateJsonlSync(DETECTIONS_FILE, (entry) => { detections.push(entry); });
  } catch { /* ignore */ }
  return { detections };
}

function appendDetection(name, version, ecosystem, findings, severity) {
  try {
    const dir = path.dirname(DETECTIONS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    _initDetectionDedupSet();
    const key = `${name}@${version}`;
    if (_detectionDedupSet.has(key)) return; // dedup

    const entry = {
      package: name,
      version,
      ecosystem,
      first_seen_at: new Date().toISOString(),
      findings,
      severity,
      advisory_at: null,
      lead_time_hours: null
    };
    fs.appendFileSync(DETECTIONS_FILE, JSON.stringify(entry) + '\n', 'utf8');
    _detectionDedupSet.add(key);

    _detectionsAppendedSinceCompact++;
    if (_detectionsAppendedSinceCompact >= DETECTION_COMPACT_INTERVAL) {
      _detectionsAppendedSinceCompact = 0;
      _compactDetectionsJsonl();
    }
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] Permission denied writing detection: ${err.code}`);
      return;
    }
    if (err.code === 'ENOSPC') {
      console.warn('[MONITOR] WARNING: disk full (ENOSPC) — cannot persist detection.');
      return;
    }
    console.error(`[MONITOR] Failed to save detection: ${err.message}`);
  }
}

/**
 * Compute detection stats by streaming the JSONL file: a single accumulator
 * pass that never holds more than one parsed entry in memory at a time.
 */
function getDetectionStats() {
  let total = 0;
  const bySeverity = {};
  const byEcosystem = {};
  const leadHours = [];

  try {
    _iterateJsonlSync(DETECTIONS_FILE, (d) => {
      total++;
      if (d.severity) bySeverity[d.severity] = (bySeverity[d.severity] || 0) + 1;
      if (d.ecosystem) byEcosystem[d.ecosystem] = (byEcosystem[d.ecosystem] || 0) + 1;
      if (d.advisory_at && d.lead_time_hours != null) {
        leadHours.push(d.lead_time_hours);
      }
    });
  } catch { /* fallthrough — return whatever we accumulated */ }

  let leadTime = null;
  if (leadHours.length > 0) {
    let min = leadHours[0];
    let max = leadHours[0];
    let sum = 0;
    for (const h of leadHours) {
      if (h < min) min = h;
      if (h > max) max = h;
      sum += h;
    }
    leadTime = {
      count: leadHours.length,
      avg: sum / leadHours.length,
      min,
      max
    };
  }

  return { total, bySeverity, byEcosystem, leadTime };
}

/**
 * Compact the detections JSONL file: keep only the most recent MAX_DETECTIONS
 * entries. Rebuilds the in-memory dedup Set from the kept entries so dedup
 * stays consistent. No-op when the file is already under cap.
 */
function _compactDetectionsJsonl() {
  try {
    const total = _countJsonlLines(DETECTIONS_FILE);
    if (total <= MAX_DETECTIONS) return;
    const toDrop = total - MAX_DETECTIONS;
    let skipped = 0;
    const kept = [];
    const newDedup = new Set();
    _iterateJsonlSync(DETECTIONS_FILE, (entry) => {
      if (skipped < toDrop) { skipped++; return; }
      kept.push(JSON.stringify(entry));
      if (entry && entry.package && entry.version) {
        newDedup.add(`${entry.package}@${entry.version}`);
      }
    });
    const tmpFile = DETECTIONS_FILE + '.tmp';
    fs.writeFileSync(tmpFile, kept.length ? kept.join('\n') + '\n' : '', 'utf8');
    fs.renameSync(tmpFile, DETECTIONS_FILE);
    _detectionDedupSet = newDedup;
    console.log(`[MONITOR] COMPACT detections: ${total} -> ${kept.length} entries`);
  } catch (err) {
    console.error(`[MONITOR] Detections compaction failed: ${err.message}`);
  }
}

// --- Per-scan ledger (Phase 0a: operational coverage observability) ---
// Append-only record of EVERY package the monitor dequeues + its terminal outcome,
// so we can distinguish never-scanned vs scanned-clean vs suspect vs dropped and
// measure TRUE operational coverage (not just rule-TPR on the static corpus).
// Mirrors the detections JSONL machinery (chunked iterate + periodic compaction).
// Differences vs detections: (1) NO dedup — every scan event is a distinct record;
// (2) higher cap + compaction interval since this logs every scan, not just findings.
const SCAN_LEDGER_FILE = process.env.MUADDIB_SCAN_LEDGER_FILE || path.join(__dirname, '..', '..', 'data', 'scan-ledger.jsonl');
const MAX_SCAN_LEDGER = (() => {
  const raw = process.env.MUADDIB_SCAN_LEDGER_MAX;
  const n = raw ? parseInt(raw, 10) : NaN;
  return (Number.isFinite(n) && n >= 10 && n <= 5_000_000) ? n : 500_000;
})();
const SCAN_LEDGER_COMPACT_INTERVAL = 2000;
let _scanLedgerAppendedSinceCompact = 0;

// Terminal outcomes a dequeued package can reach. Unknown values normalize to 'clean'
// so a typo at a call site can never crash the pipeline.
const SCAN_LEDGER_OUTCOMES = new Set([
  'clean', 'clean_low_signal', 'clean_tooling', 'suspect', 'ml_clean', 'llm_benign',
  'sandbox_inconclusive', 'sandbox_unconfirmed', 'confirmed',
  'static_timeout', 'size_skip', 'dropped', 'error'
]);

/**
 * Append one per-scan ledger entry recording the terminal outcome of a dequeued
 * package. Best-effort: NEVER throws (a ledger failure must not break scanning).
 * No dedup — repeated scans of the same package are intentionally all recorded.
 *
 * @param {object} e
 * @param {string}  e.name        package name (required)
 * @param {string} [e.version]
 * @param {string} [e.ecosystem]  'npm' | 'pypi' | ...
 * @param {string} [e.outcome]    one of SCAN_LEDGER_OUTCOMES (default 'clean')
 * @param {number} [e.score]      riskScore at the terminal decision
 * @param {string} [e.tier]       suspect tier ('1a'|'1b'|2|3) if applicable
 * @param {string} [e.maxSeverity]
 * @param {string[]} [e.types]    threat types (capped to 12)
 * @param {string} [e.sandbox]    'none' | 'run' | 'deferred' | 'skip'
 * @param {boolean} [e.firstPublish]
 * @param {string} [e.source]     where the record originated ('scan','queue_cap',...)
 */
function appendScanLedger(e) {
  try {
    if (!e || !e.name) return;
    const dir = path.dirname(SCAN_LEDGER_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const entry = {
      ts: new Date().toISOString(),
      name: e.name,
      version: e.version || null,
      ecosystem: e.ecosystem || null,
      outcome: SCAN_LEDGER_OUTCOMES.has(e.outcome) ? e.outcome : 'clean',
      score: (typeof e.score === 'number') ? e.score : null,
      tier: (e.tier !== undefined && e.tier !== null) ? String(e.tier) : null,
      maxSeverity: e.maxSeverity || null,
      types: Array.isArray(e.types) ? e.types.slice(0, 12) : [],
      sandbox: e.sandbox || 'none',
      firstPublish: !!e.firstPublish,
      source: e.source || 'scan'
    };
    fs.appendFileSync(SCAN_LEDGER_FILE, JSON.stringify(entry) + '\n', 'utf8');
    _scanLedgerAppendedSinceCompact++;
    if (_scanLedgerAppendedSinceCompact >= SCAN_LEDGER_COMPACT_INTERVAL) {
      _scanLedgerAppendedSinceCompact = 0;
      _compactScanLedgerJsonl();
    }
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') return;
    if (err.code === 'ENOSPC') {
      console.warn('[MONITOR] WARNING: disk full (ENOSPC) — cannot persist scan-ledger.');
      return;
    }
    console.error(`[MONITOR] Failed to write scan-ledger: ${err.message}`);
  }
}

/**
 * Compact the scan-ledger JSONL: keep only the most recent MAX_SCAN_LEDGER entries.
 * No-op when already under cap. Streams (never loads the whole file at once).
 */
function _compactScanLedgerJsonl() {
  try {
    const total = _countJsonlLines(SCAN_LEDGER_FILE);
    if (total <= MAX_SCAN_LEDGER) return;
    const toDrop = total - MAX_SCAN_LEDGER;
    let skipped = 0;
    const kept = [];
    _iterateJsonlSync(SCAN_LEDGER_FILE, (entry) => {
      if (skipped < toDrop) { skipped++; return; }
      kept.push(JSON.stringify(entry));
    });
    const tmpFile = SCAN_LEDGER_FILE + '.tmp';
    fs.writeFileSync(tmpFile, kept.length ? kept.join('\n') + '\n' : '', 'utf8');
    fs.renameSync(tmpFile, SCAN_LEDGER_FILE);
    console.log(`[MONITOR] COMPACT scan-ledger: ${total} -> ${kept.length} entries`);
  } catch (err) {
    console.error(`[MONITOR] Scan-ledger compaction failed: ${err.message}`);
  }
}

/** Stream the scan-ledger into an array (tests + Phase 0b rollup). */
function loadScanLedger() {
  const entries = [];
  try { _iterateJsonlSync(SCAN_LEDGER_FILE, (e) => { entries.push(e); }); } catch { /* ignore */ }
  return entries;
}

// Bounded distinct-key tracking for the `vanished` cross-reference (CLAUDE.md §2).
// Sits above the MAX_SCAN_LEDGER file ceiling so it is a pure safety valve: in normal
// operation the in-window key sets are far smaller than the file, so `exactVanished`
// stays true. Only an operator setting MUADDIB_SCAN_LEDGER_MAX above this would trip it.
const MAX_ROLLUP_KEYS = 1_200_000;

/**
 * Phase 0b: roll up the per-scan ledger into operational-coverage metrics.
 *
 * Single streaming pass (never loads the whole file at once — same machinery as
 * getDetectionStats). It distinguishes:
 *   - scanned : entries that reached a real verdict (outcome !== 'dropped')
 *   - dropped : queue-cap evictions (outcome === 'dropped') — never scanned
 *   - vanished: DISTINCT name@version that were dropped AND never (re)scanned in-window
 *               = a permanent coverage hole (the "which Miasma versions never ran" case)
 *
 * HONEST METRIC NOTE — `alertRate` is (suspect+confirmed) / scanned, i.e. "of what we
 * scanned, the fraction we flagged". It is NOT a true-positive rate: the ledger carries
 * no ground truth. The GHSA-denominated operational TPR (the 105/429 audit number) needs
 * the ledger cross-referenced against the GHSA malware feed — that is the Phase 5
 * coverage-audit, not this rollup. Do not relabel `alertRate` as TPR (CLAUDE.md: pas
 * d'embellissement des métriques).
 *
 * @param {number|string|null} [sinceTs] window start — ms epoch, ISO string, or null for
 *        "whole ledger". Entries with ts < sinceTs (or unparseable ts) are skipped.
 * @param {object} [opts]
 * @param {string} [opts.file] ledger path override (tests). Defaults to SCAN_LEDGER_FILE.
 * @returns {{
 *   generatedAt:string, since:string|null, windowStart:string|null, windowEnd:string|null,
 *   total:number, scanned:number, dropped:number, vanished:number, exactVanished:boolean,
 *   alerted:number, alertRate:number|null,
 *   byOutcome:Object.<string,number>,
 *   byEcosystem:Object.<string,{total:number,scanned:number,dropped:number,alerted:number}>
 * }}
 */
function computeLedgerRollup(sinceTs, opts = {}) {
  const file = opts.file || SCAN_LEDGER_FILE;

  let sinceMs = null;
  if (typeof sinceTs === 'number' && Number.isFinite(sinceTs)) {
    sinceMs = sinceTs;
  } else if (typeof sinceTs === 'string') {
    const p = Date.parse(sinceTs);
    if (!Number.isNaN(p)) sinceMs = p;
  }

  const byOutcome = Object.create(null);
  const byEcosystem = Object.create(null);
  let total = 0, scanned = 0, dropped = 0, alerted = 0;
  let earliest = null, latest = null;
  // Two sets so `vanished` is correct regardless of drop/scan ordering in the file.
  // droppedKeys is small (drops only happen under queue-cap pressure); scannedKeys is
  // bounded by the in-window line count (≤ MAX_SCAN_LEDGER), and further by MAX_ROLLUP_KEYS.
  const scannedKeys = new Set();
  const droppedKeys = new Set();
  let exactVanished = true;
  // Distinct package NAMES (version-collapsed) for honest coverage. A package is
  // "covered" if at least one of its versions reached a real scan (non-dropped).
  // Bounded: names are only added while underCap, so |names| ≤ |keys| ≤ MAX_ROLLUP_KEYS.
  // Exactness mirrors exactVanished (false iff the cap was hit mid-window).
  const allNames = new Set();
  const scannedNames = new Set();

  _iterateJsonlSync(file, (e) => {
    if (!e || !e.name) return;
    let t = null;
    if (e.ts) { const p = Date.parse(e.ts); if (!Number.isNaN(p)) t = p; }
    if (sinceMs !== null && (t === null || t < sinceMs)) return;

    total++;
    if (t !== null) {
      if (earliest === null || t < earliest) earliest = t;
      if (latest === null || t > latest) latest = t;
    }

    const outcome = (typeof e.outcome === 'string' && e.outcome) ? e.outcome : 'clean';
    byOutcome[outcome] = (byOutcome[outcome] || 0) + 1;

    const eco = e.ecosystem || 'unknown';
    let ecoNode = byEcosystem[eco];
    if (!ecoNode) ecoNode = byEcosystem[eco] = { total: 0, scanned: 0, dropped: 0, alerted: 0 };
    ecoNode.total++;

    const key = `${e.name}@${e.version || ''}`;
    const underCap = exactVanished && (scannedKeys.size + droppedKeys.size) < MAX_ROLLUP_KEYS;
    if (outcome === 'dropped') {
      dropped++; ecoNode.dropped++;
      if (underCap) { droppedKeys.add(key); allNames.add(e.name); } else exactVanished = false;
    } else {
      scanned++; ecoNode.scanned++;
      if (outcome === 'suspect' || outcome === 'confirmed') { alerted++; ecoNode.alerted++; }
      if (underCap) { scannedKeys.add(key); allNames.add(e.name); scannedNames.add(e.name); } else exactVanished = false;
    }
  });

  let vanished = 0;
  for (const k of droppedKeys) { if (!scannedKeys.has(k)) vanished++; }

  return {
    generatedAt: new Date().toISOString(),
    since: sinceMs !== null ? new Date(sinceMs).toISOString() : null,
    windowStart: earliest !== null ? new Date(earliest).toISOString() : null,
    windowEnd: latest !== null ? new Date(latest).toISOString() : null,
    total,
    scanned,
    dropped,
    vanished,
    exactVanished,
    alerted,
    // NOT a TPR — see the HONEST METRIC NOTE above. null when nothing was scanned.
    alertRate: scanned > 0 ? alerted / scanned : null,
    // Honest, version-collapsed coverage: distinct package names seen vs scanned.
    // Bounded ≤100% by construction (scannedNames ⊆ allNames). Unlike the raw
    // event-count coverage in the embed, this is immune to version-spam inflation
    // (e.g. a package publishing thousands of versions counts once).
    distinctPackages: allNames.size,
    distinctScanned: scannedNames.size,
    distinctCoverage: allNames.size > 0 ? scannedNames.size / allNames.size : null,
    byOutcome,
    byEcosystem
  };
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
        stats.errorsByType.archive_failed = data.errorsByType.archive_failed || 0;
        stats.errorsByType.unsupported_format = data.errorsByType.unsupported_format || 0;
        stats.errorsByType.http_error = data.errorsByType.http_error || 0;
        stats.errorsByType.timeout = data.errorsByType.timeout || 0;
        stats.errorsByType.static_timeout = data.errorsByType.static_timeout || 0;
        stats.errorsByType.other = data.errorsByType.other || 0;
      }
      stats.totalTimeMs = data.totalTimeMs || 0;
      stats.mlFiltered = data.mlFiltered || 0;
      stats.llmAnalyzed = data.llmAnalyzed || 0;
      stats.llmSuppressed = data.llmSuppressed || 0;
      stats.changesStreamPackages = data.changesStreamPackages || 0;
      stats.uniqueScanAttempts = data.uniqueScanAttempts || 0;
      stats.npmPublishEventsSeen = data.npmPublishEventsSeen || 0;
      stats.pypiChangelogPackages = data.pypiChangelogPackages || 0;
      stats.pypiChangelogEvents = data.pypiChangelogEvents || 0;
      stats.npmCatchupSkippedSeqs = data.npmCatchupSkippedSeqs || 0;
      stats.npmCatchupSkips = data.npmCatchupSkips || 0;
      stats.pypiCatchupSkippedEvents = data.pypiCatchupSkippedEvents || 0;
      stats.pypiCatchupSkips = data.pypiCatchupSkips || 0;
      stats.pypiWheelsScanned = data.pypiWheelsScanned || 0;
      stats.pypiSkippedNoArchive = data.pypiSkippedNoArchive || 0;
      if (Array.isArray(data.dailyAlerts)) {
        const restored = data.dailyAlerts.slice(-MAX_DAILY_ALERTS);
        dailyAlerts.length = 0;
        dailyAlerts.push(...restored);
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
      changesStreamPackages: stats.changesStreamPackages || 0,
      uniqueScanAttempts: stats.uniqueScanAttempts || 0,
      npmPublishEventsSeen: stats.npmPublishEventsSeen || 0,
      pypiChangelogPackages: stats.pypiChangelogPackages || 0,
      pypiChangelogEvents: stats.pypiChangelogEvents || 0,
      npmCatchupSkippedSeqs: stats.npmCatchupSkippedSeqs || 0,
      npmCatchupSkips: stats.npmCatchupSkips || 0,
      pypiCatchupSkippedEvents: stats.pypiCatchupSkippedEvents || 0,
      pypiCatchupSkips: stats.pypiCatchupSkips || 0,
      pypiWheelsScanned: stats.pypiWheelsScanned || 0,
      pypiSkippedNoArchive: stats.pypiSkippedNoArchive || 0,
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

// --- Daily report headline reconciliation (crash-safe) ---
//
// A restart-storm around the daily-report hour can zero/corrupt the in-memory
// `stats` counter (the monitor was OOM-restarted ~10×/day in prod), producing a
// report like "scanned=5" while ~44k packages were actually scanned that day.
// scan-stats.json's `stats.total_scanned` is a MONOTONIC all-time counter, written
// atomically on every scan and NEVER reset — so "scans since the last report" is a
// restart-proof delta. We persist that counter as a per-report baseline and floor
// the published headline at the delta, so a report can never under-count below what
// really happened. No-op on healthy days (in-memory counter >= delta).

/**
 * Snapshot the monotonic all-time scan-stats totals, to persist as a baseline at
 * report time. The next report computes "since last report" as a delta from it.
 */
function captureScanStatsBaseline() {
  const s = loadScanStats().stats || {};
  return {
    total_scanned: s.total_scanned || 0,
    clean: s.clean || 0,
    suspect: s.suspect || 0
  };
}

/**
 * Floor the in-memory daily headline (scanned/clean/suspect) at the durable
 * scan-stats delta since the last report. Mutates `stats` UPWARD only; never lowers
 * a value. Returns { applied, floor, before } for observability and tests. Safe
 * no-op when there is no baseline yet (first report ever) or when the in-memory
 * counter already meets/exceeds the delta.
 */
function reconcileDailyHeadline(stats) {
  const summary = { applied: false, floor: 0, before: stats.scanned };
  let baseline = null;
  try {
    baseline = JSON.parse(fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8')).scanStatsBaseline;
  } catch { /* no file / corrupt — no baseline, treat as first report */ }
  if (!baseline || typeof baseline.total_scanned !== 'number') return summary;
  const cur = loadScanStats().stats || {};
  const dScanned = Math.max(0, (cur.total_scanned || 0) - baseline.total_scanned);
  const dClean = Math.max(0, (cur.clean || 0) - (baseline.clean || 0));
  const dSuspect = Math.max(0, (cur.suspect || 0) - (baseline.suspect || 0));
  summary.floor = dScanned;
  // Trigger on SIGNIFICANT loss (in-memory below 80% of the durable delta = a
  // restart-storm dropped counter increments), not on normal drift. The two counters
  // drift a few percent (in-memory also counts SIZE_REJECT/SKIP-large paths scan-stats
  // doesn't — so on a healthy day delta <= in-memory, making a false trigger require an
  // implausible +25% over-count). 0.8 catches half-catastrophes (e.g. 25k in-memory vs
  // 48k durable) while staying well above the ~5-10% normal-drift band.
  const LOSS_FLOOR_RATIO = 0.8;
  if (dScanned > 100 && stats.scanned < dScanned * LOSS_FLOOR_RATIO) {
    console.warn(`[MONITOR] DAILY RECONCILE: in-memory scanned=${stats.scanned} ≪ durable scan-stats delta=${dScanned} (restart-storm counter loss) — publishing durable count`);
    stats.scanned = dScanned;
    if (dClean > stats.clean) stats.clean = dClean;
    if (dSuspect > stats.suspect) stats.suspect = dSuspect;
    summary.applied = true;
  }
  return summary;
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
 * Persist the date of the last daily report sent (YYYY-MM-DD), and optionally the
 * monotonic scan-stats baseline captured at that moment (used by the next report's
 * crash-safe headline reconciliation). Baseline is optional for backward compat.
 */
function saveLastDailyReportDate(dateStr, scanStatsBaseline) {
  try {
    const payload = { lastReportDate: dateStr };
    if (scanStatsBaseline) payload.scanStatsBaseline = scanStatsBaseline;
    atomicWriteFileSync(LAST_DAILY_REPORT_FILE, JSON.stringify(payload, null, 2));
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

// Hour (Europe/Paris) at/after which the once-daily report may fire. Single source of
// truth — imported by webhook.js, daemon.js and queue.js (each previously redefined it,
// and webhook.js still re-exports it for back-compat).
const DAILY_REPORT_HOUR = 8; // 08:00 Paris time (Europe/Paris)

/**
 * Canonical "is the daily report due?" predicate — the ONE gate, defined here in state.js
 * (a leaf module that daemon.js and queue.js already import, so no require cycle).
 *
 * Catch-up semantics: fire at OR AFTER 08:00 Paris, so a missed 08:00 (e.g. the daemon was
 * down/OOM-restarting at that minute) still fires later the SAME day — losing a whole day
 * was the old daemon.js `hour === 8` behaviour. But NEVER fire during the 00:00–07:59 Paris
 * "dead zone": a fire then stamps the NEW day's date before its 08:00 window and, because
 * hasReportBeenSentToday() keys off the Paris CALENDAR date, permanently suppresses that
 * day's real report. Replaces the two divergent copies (daemon.js `!== 8`, queue.js `< 8`).
 */
function isDailyReportDue(stats) {
  if (getParisHour() < DAILY_REPORT_HOUR) return false;
  return !hasReportBeenSentToday(stats);
}

// --- recentlyScanned dedup-set persistence (survives restarts → no re-scan storm) ---
//
// The dedup Set is in-memory only, so every restart starts it empty and re-scans the
// whole restored backlog (wasted work — the monitor OOM-restarts ~10×/day). We persist
// the keys alongside the queue so the dedup survives. Entries are timestampless (the Set
// is FIFO-capped and cleared at each daily report, so it holds at most ~24h of keys), so
// freshness is guarded at the whole-file level with a savedAt — same shape as queue-state.
const RECENTLY_SCANNED_PERSIST_MAX = 50_000;             // mirrors RECENTLY_SCANNED_MAX (queue.js)
const RECENTLY_SCANNED_MAX_AGE_MS = 24 * 60 * 60 * 1000; // discard a stale file (monitor down >24h)

function saveRecentlyScanned(recentlyScanned) {
  try {
    if (!recentlyScanned || recentlyScanned.size === 0) {
      try { fs.unlinkSync(RECENTLY_SCANNED_FILE); } catch {}
      return;
    }
    let keys = Array.from(recentlyScanned);
    if (keys.length > RECENTLY_SCANNED_PERSIST_MAX) keys = keys.slice(-RECENTLY_SCANNED_PERSIST_MAX);
    atomicWriteFileSync(RECENTLY_SCANNED_FILE, JSON.stringify({ savedAt: new Date().toISOString(), count: keys.length, keys }));
  } catch (err) {
    console.error(`[MONITOR] Failed to persist recentlyScanned: ${err.message}`);
  }
}

/**
 * Restore the dedup Set on boot by adding keys into the passed Set in place. Returns
 * the count restored. Safe no-op on missing / corrupt / stale (>24h) file.
 */
function loadRecentlyScanned(recentlyScanned) {
  try {
    if (!fs.existsSync(RECENTLY_SCANNED_FILE)) return 0;
    const data = JSON.parse(fs.readFileSync(RECENTLY_SCANNED_FILE, 'utf8'));
    if (!data || !Array.isArray(data.keys) || !data.savedAt) return 0;
    const ageMs = Date.now() - new Date(data.savedAt).getTime();
    if (ageMs > RECENTLY_SCANNED_MAX_AGE_MS) {
      console.log(`[MONITOR] recentlyScanned state expired (${Math.round(ageMs / 3600000)}h old) — ignoring`);
      try { fs.unlinkSync(RECENTLY_SCANNED_FILE); } catch {}
      return 0;
    }
    let keys = data.keys;
    if (keys.length > RECENTLY_SCANNED_PERSIST_MAX) keys = keys.slice(-RECENTLY_SCANNED_PERSIST_MAX);
    for (const k of keys) recentlyScanned.add(k);
    console.log(`[MONITOR] Restored ${keys.length} dedup keys from previous session (no re-scan storm)`);
    return keys.length;
  } catch (err) {
    console.log(`[MONITOR] WARNING: could not restore recentlyScanned: ${err.message}`);
    return 0;
  }
}

// --- Raw state loader (CLI report helpers) ---

// --- JSONL migration (one-shot, idempotent) ---

/**
 * Convert a legacy JSON detections file into the new JSONL format.
 * Idempotent: skips when the JSONL file already exists, or when the legacy
 * file is missing. After successful migration the legacy file is renamed to
 * `<basename>.json.migrated` so the next boot is a no-op and a forensic copy
 * remains on disk.
 *
 * @param {object} opts
 * @param {string} opts.legacyFile  - Path to the legacy `*.json` file
 * @param {string} opts.targetFile  - Path to the destination `*.jsonl` file
 * @param {(parsed:any) => any[]|null} opts.extractEntries - Returns the array of
 *   entries from the parsed JSON, or null if the file shape is unexpected.
 * @param {string} opts.label       - Short label used in log messages
 * @returns {{migrated:boolean, entries:number}}
 */
function _migrateJsonToJsonl({ legacyFile, targetFile, extractEntries, label }) {
  if (!fs.existsSync(legacyFile)) return { migrated: false, entries: 0 };
  if (fs.existsSync(targetFile)) {
    // JSONL already in use. Leave the legacy file alone if it's still there
    // (operator may want to inspect it). Renaming it could surprise scripts.
    return { migrated: false, entries: 0 };
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(legacyFile, 'utf8'));
  } catch (err) {
    console.warn(`[MONITOR] MIGRATION ${label}: legacy file unreadable (${err.message}) — leaving in place`);
    return { migrated: false, entries: 0 };
  }
  const entries = extractEntries(parsed);
  if (!Array.isArray(entries)) {
    console.warn(`[MONITOR] MIGRATION ${label}: unexpected legacy shape — leaving in place`);
    return { migrated: false, entries: 0 };
  }
  const tmpFile = targetFile + '.tmp';
  try {
    const dir = path.dirname(targetFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const lines = entries.map(e => JSON.stringify(e));
    fs.writeFileSync(tmpFile, lines.length ? lines.join('\n') + '\n' : '', 'utf8');
    fs.renameSync(tmpFile, targetFile);
    fs.renameSync(legacyFile, legacyFile + '.migrated');
    console.log(`[MONITOR] MIGRATION ${label}: ${entries.length} entries -> ${path.basename(targetFile)} (legacy kept as ${path.basename(legacyFile)}.migrated)`);
    return { migrated: true, entries: entries.length };
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    console.error(`[MONITOR] MIGRATION ${label} failed: ${err.message}`);
    return { migrated: false, entries: 0 };
  }
}

/**
 * Run all state migrations. Called once at startup before any append/load
 * touches the new JSONL files. Idempotent — safe to call on every boot.
 *
 * After migration this function also enforces the post-migration size caps,
 * so an oversized legacy file is immediately compacted instead of waiting
 * for DETECTION_COMPACT_INTERVAL appends.
 */
function runStateMigrations() {
  // Reset internal counters/dedup so the first append re-reads from disk.
  _resetDetectionState();

  const det = _migrateJsonToJsonl({
    legacyFile: DETECTIONS_FILE_LEGACY,
    targetFile: DETECTIONS_FILE,
    extractEntries: (parsed) => (parsed && Array.isArray(parsed.detections)) ? parsed.detections : null,
    label: 'detections'
  });
  if (det.migrated && det.entries > MAX_DETECTIONS) _compactDetectionsJsonl();

  const tmp = _migrateJsonToJsonl({
    legacyFile: TEMPORAL_DETECTIONS_FILE_LEGACY,
    targetFile: TEMPORAL_DETECTIONS_FILE,
    extractEntries: (parsed) => Array.isArray(parsed) ? parsed : null,
    label: 'temporal-detections'
  });
  if (tmp.migrated && tmp.entries > MAX_TEMPORAL_DETECTIONS) _compactTemporalDetectionsJsonl();
}

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
  DETECTIONS_FILE_LEGACY,
  SCAN_STATS_FILE,
  LAST_DAILY_REPORT_FILE,
  DAILY_STATS_FILE,
  TEMPORAL_DETECTIONS_FILE,
  TEMPORAL_DETECTIONS_FILE_LEGACY,
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
  PYPI_SERIAL_FILE,
  PYPI_XMLRPC_URL,
  PYPI_CATCHUP_MAX,
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
  ALERTS_MAX_SIZE,
  MAX_DETECTIONS,
  MAX_TEMPORAL_DETECTIONS,
  MAX_DAILY_ALERTS,
  DETECTION_COMPACT_INTERVAL,
  SCAN_LEDGER_FILE,
  MAX_SCAN_LEDGER,

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
  loadPypiSerial,
  savePypiSerial,
  loadScanMemory,
  saveScanMemory,
  recordScanMemory,
  markSandboxed,
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
  appendScanLedger,
  loadScanLedger,
  computeLedgerRollup,
  _compactScanLedgerJsonl,
  getDetectionStats,
  runStateMigrations,
  // Internal — exported for tests and for the daemon hourly housekeeping.
  _compactDetectionsJsonl,
  _compactTemporalDetectionsJsonl,
  _resetDetectionState,
  _iterateJsonlSync,
  _countJsonlLines,
  loadScanStats,
  updateScanStats,
  loadDailyStats,
  saveDailyStats,
  resetDailyStats,
  maybePersistDailyStats,
  captureScanStatsBaseline,
  reconcileDailyHeadline,
  loadLastDailyReportDate,
  saveLastDailyReportDate,
  hasReportBeenSentToday,
  saveRecentlyScanned,
  loadRecentlyScanned,
  getParisHour,
  getParisDateString,
  DAILY_REPORT_HOUR,
  isDailyReportDue,
  loadStateRaw
};
