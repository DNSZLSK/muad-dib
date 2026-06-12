/**
 * Queue / scanning / worker functions extracted from monitor.js.
 *
 * All shared mutable state (stats, dailyAlerts, recentlyScanned, downloadsCache,
 * scanQueue, sandboxAvailable) is injected as parameters rather than captured
 * from module scope.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { Worker } = require('worker_threads');
const { runSandbox, tryAcquireSandboxSlot } = require('../sandbox/index.js');
const { sendWebhook } = require('../webhook.js');
const { downloadToFile, extractArchive, sanitizePackageName } = require('../shared/download.js');
const { MAX_TARBALL_SIZE, getMaxFileSize } = require('../shared/constants.js');
const { acquireRegistrySlot, releaseRegistrySlot, awaitRateToken: awaitRateTokenForWorker, signal429: signal429ForWorker } = require('../shared/http-limiter.js');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { scanPackageJson } = require('../scanner/package.js');
const { scanShellScripts } = require('../scanner/shell.js');
const { buildTrainingRecord } = require('../ml/feature-extractor.js');
const { appendWorkerMem } = require('./worker-mem.js');
const { acquireHeavySlot, releaseHeavySlot, isHeavyScan, getHeavyLaneState, heavyWaitMaxMs, HEAVY_REQUEUE_MAX } = require('./heavy-lane.js');
const { isGovernorEnabled, classifyWeight, acquireMemoryTicket, releaseMemoryTicket, isFrozen: isGovernorFrozen, getGovernorState } = require('./memory-governor.js');
const { appendRecord: appendTrainingRecord, relabelRecords } = require('../ml/jsonl-writer.js');

// From ./state.js
const {
  cacheTarball,
  updateScanStats,
  appendDetection,
  appendScanLedger,
  maybePersistDailyStats,
  appendTemporalDetection,
  tarballCacheKey,
  tarballCachePath,
  appendAlert,
  isDailyReportDue,
  MAX_DAILY_ALERTS,
  loadScanMemory,
  shouldSuppressByMemory,
  markSandboxed
} = require('./state.js');

// From ./classify.js
const {
  isSuspectClassification,
  hasHighConfidenceThreat,
  isSandboxEnabled,
  isCanaryEnabled,
  recordError,
  formatFindings,
  isFirstPublishHighRisk
} = require('./classify.js');

// From ./webhook.js
const {
  trySendWebhook,
  buildAlertData,
  persistAlert,
  sendIOCPreAlert,
  sendBurstPreAlert,
  matchVersionedIOC,
  buildCanaryExfiltrationWebhookEmbed,
  getWebhookUrl,
  computeReputationFactor,
  triageRisk,
  sendDailyReport,
  alertedPackageRules
} = require('./webhook.js');

// From ./temporal.js
const {
  runTemporalCheck,
  runTemporalAstCheck,
  runTemporalPublishCheck,
  runTemporalMaintainerCheck,
  getTemporalMaxSeverity,
  tryTemporalAlert,
  tryTemporalAstAlert,
  isSafeLifecycleScript
} = require('./temporal.js');

// From ./ingestion.js
const { getNpmLatestTarball, getPyPITarballUrl } = require('./ingestion.js');
const { enqueueScan, dequeueScan } = require('./scan-queue.js');

// From ./tarball-archive.js
const { archiveSuspectTarball } = require('./tarball-archive.js');

// From ./deferred-sandbox.js
const { enqueueDeferred } = require('./deferred-sandbox.js');

// --- Adaptive concurrency ---

const { BASE_CONCURRENCY, MIN_CONCURRENCY, MAX_CONCURRENCY } = require('./adaptive-concurrency.js');

// SCAN_CONCURRENCY kept as getter for backward compatibility (tests, logging)
let _targetConcurrency = BASE_CONCURRENCY;
const SCAN_CONCURRENCY = BASE_CONCURRENCY; // legacy export — tests check this value
let _activeWorkers = 0;
const _workerPromises = new Set();
// Live static-scan Worker threads, mapped to the {name,version,ecosystem} of the scan they
// run — tracked so the daemon's EMERGENCY memory handler can terminate orphaned workers
// (each retains its isolate heap + parsed ASTs) AND name the in-flight scans it kills.
// Bounded by concurrency, so it stays tiny.
const _liveWorkers = new Map();

// Side-channel worker→main messages: anything that is not the scan's terminal
// 'result'/'error'. The dispatch in runScanInWorker NEVER settles the scan
// promise for these types — the handler it replaced called done() on EVERY
// message, so a single non-result message disarmed the static timeout, removed
// the worker from _liveWorkers (invisible to terminateAllWorkers) and left the
// scan pending until the outer 300s abort. Governors register here (phase A:
// 'rate-token-request'/'rate-429'). Handler signature: (worker, msg) => void.
const _workerMessageHandlers = new Map();
function registerWorkerMessageHandler(type, fn) {
  if (_workerMessageHandlers.has(type)) {
    // One handler per type: silently replacing a live handler killed every
    // token grant in-process when a test registered over 'rate-token-request'.
    console.warn(`[MONITOR] registerWorkerMessageHandler: OVERWRITING existing handler for '${type}'`);
  }
  _workerMessageHandlers.set(type, fn);
}

// ─── Network-brain glue (governors phase A) ───
// Workers proxy token acquisition and 429 signals to the main thread so the
// whole process shares ONE budget + ONE backoff state per host. Stateless per
// worker by design: a grant racing a worker's death is a caught postMessage
// (one token lost, self-healing) — nothing to purge on 'exit'.
registerWorkerMessageHandler('rate-token-request', (worker, msg) => {
  awaitRateTokenForWorker(msg.host, { maxWaitMs: msg.maxWaitMs })
    .then(({ granted }) => {
      try {
        worker.postMessage({ type: granted ? 'rate-token-grant' : 'rate-token-denied', id: msg.id });
      } catch { /* worker already terminated — token self-heals at next refill */ }
    });
});
registerWorkerMessageHandler('rate-429', (worker, msg) => {
  signal429ForWorker(msg.host);
});

function getTargetConcurrency() { return _targetConcurrency; }
function setTargetConcurrency(n) { _targetConcurrency = Math.max(MIN_CONCURRENCY, Math.min(MAX_CONCURRENCY, n)); }
function getActiveWorkers() { return _activeWorkers; }

/**
 * Terminate every live static-scan Worker (best-effort). Returns the count.
 * Called by daemon.js handleMemoryPressure() at EMERGENCY — a wedged/slow worker
 * holds its isolate heap and parsed ASTs, part of the off-heap RSS leak.
 */
function terminateAllWorkers() {
  let n = 0;
  const dropped = [];
  for (const [w, item] of Array.from(_liveWorkers.entries())) {
    try {
      // Phase C: mark BEFORE terminate so the exit handler rejects with
      // code='SCAN_INTERRUPTED' — processQueueItem then ledgers 'interrupted'
      // and spills the item for a bounded re-scan instead of a terminal
      // scan_error (the killed scans of 2026-06-12 09:43 were never retried).
      w._muaddibInterrupted = true;
      w.terminate(); n++;
      if (item && item.name) dropped.push(`${item.name}@${item.version || '?'}`);
    } catch { /* already gone */ }
    _liveWorkers.delete(w);
  }
  if (dropped.length) {
    // The terminate rejects each scan's worker promise; that reject propagates to
    // scanPackage's catch, which ledgers it (outcome:'error', source scan_error) — so these
    // in-flight scans are NOT lost from the scan-ledger. This line names them for the operator.
    console.error(`[MONITOR] EMERGENCY worker-terminate killed ${dropped.length} in-flight scan(s): ${dropped.slice(0, 20).join(', ')}${dropped.length > 20 ? ` (+${dropped.length - 20} more)` : ''}`);
  }
  return n;
}
const SCAN_TIMEOUT_MS = 300_000; // 5 minutes per package (3 sandbox runs × 90s + static scan headroom)
const STATIC_SCAN_TIMEOUT_MS = 45_000; // 45s for static analysis only
const LARGE_PACKAGE_SIZE = 10 * 1024 * 1024; // 10MB
const RECENTLY_SCANNED_MAX = 50_000; // FIFO cap for the dedup Set (P0c — bounded resource)

// First-publish sandbox: max pending sandbox items before deferring first-publish clean scans
// Prevents starving T1a sandbox capacity when many first-publish packages arrive at once
const FIRST_PUBLISH_SANDBOX_MAX_QUEUE = parseInt(process.env.MUADDIB_FIRST_PUBLISH_SANDBOX_MAX_QUEUE, 10) || 10;
const FIRST_PUBLISH_SANDBOX_ENABLED = process.env.MUADDIB_FIRST_PUBLISH_SANDBOX !== '0';

// Phase 2b: burst (Miasma) pre-alert. A burst = >= this many versions of ONE name in the
// recent-publish window (the TRUE uncapped count, selectMostRecentVersion.recentWindowCount).
// Default 10: detection is PER-NAME, so legit multi-PLATFORM publishers (different names,
// e.g. @opencode-ai/cli-*-* binaries) are never caught; legit same-name release days rarely
// reach 10; Miasma's 96-in-72s clears it easily. Per-name + deduped + non-scoring (Discord
// heads-up only, no FPR impact). Env-tunable up if a feed proves noisy.
const BURST_PREALERT_MIN_VERSIONS = (() => {
  const n = parseInt(process.env.MUADDIB_BURST_MIN_VERSIONS, 10);
  return Number.isFinite(n) && n >= 2 ? n : 10;
})();
// Burst ping throttle (FPR/notif audit 2026-06): name -> last burst-alert timestamp.
// Was a lifetime Set (dedup once per process), which both (a) silenced a genuine
// re-burst days later and (b) on a process that runs for weeks accumulated spam from
// every monorepo/CI nightly that re-bursts. Now a 24h-cooldown Map: one alert per
// package per day max. Bounded — cleared at the cap so it can never grow without limit.
const _burstAlerted = new Map();
const BURST_ALERTED_MAX = 20_000;
const BURST_ALERT_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24h

// Stage 3 — sandbox gate. Static-score threshold below which T1b/T2 packages
// are NOT sandboxed (static result alone is authoritative). Tightens the prior
// "T1b sandbox if score >= 25 or queue < 20" to remove low-signal sandbox runs
// that consume slots without producing actionable findings (the dominant cost
// in the queue-saturation diagnostic). Validated by axon-enterprise@1.0.0
// (static 52, sandbox confirmed 100) — gate >= 40 still catches it.
// T1a (high-confidence malice) bypasses this gate; it's mandatory.
// Override via env var to widen the gate (lower threshold) for a short
// rollback window without redeploying. Clamped to [0, 100].
function computeSandboxScoreThreshold(envValue) {
  const parsed = parseInt(envValue, 10);
  const value = Number.isFinite(parsed) ? parsed : 40;
  return Math.max(0, Math.min(100, value));
}
const SANDBOX_SCORE_THRESHOLD = computeSandboxScoreThreshold(process.env.MUADDIB_SANDBOX_SCORE_THRESHOLD);

// --- Sandbox waste-cut (v2.11.6x): skip sandbox time that yields no new verdict ---
// Two skip paths, both detection-safe, applied BEFORE the tier sandbox decision:
//  (1) memory match — re-sandboxing a package whose static result is equivalent to a
//      remembered scan produces nothing the webhook wouldn't already memory-suppress.
//      The dominant waste source is restart-replay: recentlyScanned is in-memory (lost on
//      restart) but scan-memory persists 30d, so the changes-stream backlog gets
//      re-sandboxed then suppressed. We skip, but re-sandbox at most once per
//      SANDBOX_REVALIDATE_MS so runtime/canary coverage is retained on a slow cadence.
//  (2) native binary shard — platform-specific prebuilt packages (os/cpu constrained or
//      name like `*-linux-x64`) with trivial JS hang the sandbox install and always time
//      out INCONCLUSIVE. Same guard rails as the large-low-signal skip (queue.js ~768):
//      any lifecycle script, HIGH/CRITICAL finding, or temporal signal → sandbox runs.
const SANDBOX_REVALIDATE_MS = (() => {
  const v = parseInt(process.env.MUADDIB_SANDBOX_REVALIDATE_MS, 10);
  return Number.isFinite(v) && v >= 0 ? v : 7 * 24 * 60 * 60 * 1000; // default 7 days
})();
// npm platform-shard naming: <scope>/<pkg>-<os>-<arch>[-<libc/abi>] (esbuild/swc/turbo pattern).
const NATIVE_SHARD_NAME_RE = /-(linux|darwin|win32|freebsd|openbsd|android|sunos|aix)-(x64|arm64|arm|ia32|ppc64|s390x|riscv64|loong64|mips64el)(-(gnu|gnueabihf|musl|eabi|eabihf|msvc))?$/;
const LIFECYCLE_SCRIPT_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'preuninstall', 'uninstall', 'postuninstall'];
// A genuine prebuilt shard is a thin wrapper around a binary (index.js + index.d.ts at most).
// More JS than this means real logic → not a pure shard → don't skip.
const NATIVE_SHARD_MAX_JS_FILES = 3;

// --- Bundled tooling false-positive filter ---

const KNOWN_BUNDLED_FILES = ['yarn.js', 'webpack.js', 'terser.js', 'esbuild.js', 'polyfills.js'];
const KNOWN_BUNDLED_PATHS = ['_next/static/chunks/', '.next/static/chunks/'];

// --- ML feature extraction constants ---

const ML_EXCLUDED_DIRS = new Set(['node_modules', '.git', '.svn', 'vendor']);
const TEST_PATTERNS = /(?:^|\/)(?:test|tests|spec|specs|__tests__|__test__|__mocks__)\//i;
const TEST_FILE_PATTERN = /\.(?:test|spec)\.[jt]sx?$/i;

// --- Worker path ---

const SCAN_WORKER_PATH = path.join(__dirname, '..', 'scan-worker.js');

// --- Functions ---

function isBundledToolingOnly(threats) {
  if (threats.length === 0) return false;
  return threats.every(t => {
    if (!t.file) return false;
    const basename = path.basename(t.file);
    if (KNOWN_BUNDLED_FILES.includes(basename)) return true;
    const normalized = t.file.replace(/\\/g, '/');
    return KNOWN_BUNDLED_PATHS.some(p => normalized.includes(p));
  });
}

/**
 * Record a JSONL training sample for every scanned package.
 * Called at each decision point in scanPackage() with the appropriate label.
 * Non-fatal: failures are logged but never crash the monitor.
 *
 * @param {Object} result - scan result from run() (can be null for skipped packages)
 * @param {Object} params - { name, version, ecosystem, label, tier, registryMeta, unpackedSize, sandboxResult }
 */
function recordTrainingSample(result, params) {
  try {
    if (!result) return; // No scan result (size skip, tarball error) — nothing to record
    const record = buildTrainingRecord(result, {
      name: params.name,
      version: params.version,
      ecosystem: params.ecosystem,
      unpackedSize: params.unpackedSize || 0,
      registryMeta: params.registryMeta || {},
      npmRegistryMeta: params.npmRegistryMeta || null,
      fileCountTotal: params.fileCountTotal || 0,
      hasTests: params.hasTests || false,
      label: params.label || 'clean',
      tier: params.tier || null,
      sandboxResult: params.sandboxResult || null
    });
    appendTrainingRecord(record);
    // Phase 0a: per-scan coverage ledger — record this terminal outcome (best-effort;
    // appendScanLedger swallows its own write errors and never throws).
    appendScanLedger({
      name: params.name,
      version: params.version,
      ecosystem: params.ecosystem,
      outcome: params.label || 'clean',
      score: (result.summary && typeof result.summary.riskScore === 'number') ? result.summary.riskScore : null,
      tier: params.tier,
      maxSeverity: result.summary ? result.summary.riskLevel : null,
      types: [...new Set((result.threats || []).map(t => t.type))],
      sandbox: params.sandboxResult ? 'run' : 'none',
      source: 'scan',
      // AUDIT-A1: stamped on `result` in scanPackage (single source of truth)
      firstPublish: !!(result && result._firstPublish)
    });
  } catch (err) {
    // Non-fatal: ML export must never crash the monitor
    console.error(`[ML] Failed to record training sample for ${params.name}: ${err.message}`);
  }
}

/**
 * Count total JS files and detect test presence in an extracted package dir.
 * Depth-limited (max 5 levels) to avoid traversal bombs.
 * @param {string} dir - extracted package directory
 * @returns {{ fileCountTotal: number, hasTests: boolean }}
 */
function countPackageFiles(dir) {
  let fileCountTotal = 0;
  let hasTests = false;

  function walk(current, depth) {
    if (depth > 5) return;
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (ML_EXCLUDED_DIRS.has(entry.name)) continue;
        const rel = path.relative(dir, path.join(current, entry.name));
        if (TEST_PATTERNS.test(rel + '/')) hasTests = true;
        walk(path.join(current, entry.name), depth + 1);
      } else if (entry.isFile() && /\.[jt]sx?$/.test(entry.name)) {
        fileCountTotal++;
        if (TEST_FILE_PATTERN.test(entry.name)) hasTests = true;
      }
    }
  }

  walk(dir, 0);
  return { fileCountTotal, hasTests };
}

// C2 heavy-lane measurement bounds. Distinct from countPackageFiles (whose
// depth cap of 5 is an ML-feature contract — do not touch it).
const JS_WEIGHT_MAX_DEPTH = 8;
const JS_WEIGHT_MAX_FILES = 2000;
const JS_WEIGHT_FILE_PATTERN = /\.(?:[cm]?js|[jt]sx?)$/i;
// Minified JS expands SUPER-linearly in the worker (live counter-examples
// from the 16:18 rollout, 2026-06-11: powerlines = 517KB JS of which 449KB
// minified → 1151MB heap, ~2300×; @lethevimlet/sshift = ~1.9MB minified →
// 1.38GB — both sailed under the raw-bytes threshold as 'light'). Plain
// source stays roughly linear (the 12MB-heap mode of the bimodal
// distribution). So minified bytes count ×12 toward the heavy threshold —
// ≥~256KB of minified JS crosses the 3MiB default. Detection: average line
// length over the first 4KB; plain code sits at 40-120 chars, minified
// bundles at 800+ (often a single line). 250 splits cleanly even when a
// license header pads the probe window.
const JS_MINIFIED_WEIGHT = 12;
const JS_MINIFIED_AVG_LINE = 250;
// 64KB, not 4KB: bike4mind sailed under the 4KB probe (a license/banner header
// padded the window; the minified body started later) → mis-classified light →
// 890MB heap. Probe a 64KB window from ~2KB in to skip any header and still
// never load a 30MB file. Cheap (one readSync) at JS_WEIGHT_MAX_FILES files.
const JS_MINIFIED_PROBE_OFFSET = 2048;
const JS_MINIFIED_PROBE_BYTES = 64 * 1024;

/** Probe a 64KB window of a file (never loads the rest) for minification. */
function probeIsMinified(filePath, size) {
  let fd = null;
  try {
    fd = fs.openSync(filePath, 'r');
    const offset = size > JS_MINIFIED_PROBE_OFFSET + JS_MINIFIED_PROBE_BYTES ? JS_MINIFIED_PROBE_OFFSET : 0;
    const buf = Buffer.alloc(JS_MINIFIED_PROBE_BYTES);
    const n = fs.readSync(fd, buf, 0, JS_MINIFIED_PROBE_BYTES, offset);
    if (n <= 0) return false;
    const head = buf.toString('utf8', 0, n);
    return (head.length / head.split('\n').length) > JS_MINIFIED_AVG_LINE;
  } catch {
    return false;
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* best-effort */ } }
  }
}

/**
 * Measure how much parsable JS a package carries — the heavy-lane
 * classification signal. The per-worker isolate heap is driven by the SUM of
 * AST-parsed JS bytes (executor.js skips files > getMaxFileSize()
 * individually, but the AST cache accumulates across files), so we sum the
 * on-disk sizes of parsable JS files, skipping the ones the executor will
 * skip anyway. NEVER use meta.unpackedSize for this — it is absent for PyPI
 * and part of npm (the `|| 0` hole that lets giant bundles bypass the C1
 * size-cap in the first place).
 *
 * Bounded walk; an overflow (depth/file caps) returns truncated:true, which
 * isHeavyScan classifies heavy by default.
 *
 * weightedJsBytes = plain bytes + JS_MINIFIED_WEIGHT × minified bytes — the
 * value isHeavyScan compares against the threshold (raw bytes alone missed
 * the minified explosions, see JS_MINIFIED_WEIGHT above).
 *
 * `oversize` (any single JS file > getMaxFileSize) forces heavy: the AST
 * executor skips such files, but the content scanners (entropy/hash/
 * ioc-strings/deobfuscate) still readFileSync the whole thing — omnius
 * (a 30MB dist/index.js, 39KB of other JS) blew a 'light' worker to 1347MB.
 * So an oversize JS file is the STRONGEST heavy signal, not something to skip.
 *
 * @param {string} dir - extracted package directory
 * @returns {{ totalJsBytes: number, minifiedJsBytes: number, weightedJsBytes: number, maxJsFileBytes: number, oversize: boolean, truncated: boolean }}
 */
function measureJsWeight(dir) {
  let totalJsBytes = 0;
  let minifiedJsBytes = 0;
  let maxJsFileBytes = 0;
  let oversize = false;
  let seen = 0;
  let truncated = false;
  const perFileCap = getMaxFileSize();

  function walk(current, depth) {
    if (truncated) return;
    if (depth > JS_WEIGHT_MAX_DEPTH) { truncated = true; return; }
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (truncated) return;
      if (entry.isDirectory()) {
        if (ML_EXCLUDED_DIRS.has(entry.name)) continue;
        walk(path.join(current, entry.name), depth + 1);
      } else if (entry.isFile() && JS_WEIGHT_FILE_PATTERN.test(entry.name)) {
        if (++seen > JS_WEIGHT_MAX_FILES) { truncated = true; return; }
        const filePath = path.join(current, entry.name);
        let size;
        try { size = fs.statSync(filePath).size; } catch { continue; }
        if (size > maxJsFileBytes) maxJsFileBytes = size;
        if (size > perFileCap) {
          // The AST skips it, but content scanners load it whole → heap blow-up.
          oversize = true;
          continue;
        }
        totalJsBytes += size;
        if (probeIsMinified(filePath, size)) minifiedJsBytes += size;
      }
    }
  }

  walk(dir, 0);
  const weightedJsBytes = (totalJsBytes - minifiedJsBytes) + JS_MINIFIED_WEIGHT * minifiedJsBytes;
  return { totalJsBytes, minifiedJsBytes, weightedJsBytes, maxJsFileBytes, oversize, truncated };
}

/**
 * Pure classifier: is this a prebuilt native-binary platform shard (the kind that
 * hangs the sandbox install and always times out INCONCLUSIVE)? No I/O — the parsed
 * package.json manifest is passed in so this is unit-testable. Mirrors the extracted
 * pure helpers computeWorkersToSpawn / computeTarget.
 *
 * A package is a shard when it declares a platform constraint (npm `os`/`cpu`) OR its
 * name matches the `*-<os>-<arch>` convention, AND it carries only a trivial amount of
 * JS (a real shard is a thin wrapper around a binary). hasLifecycleScripts is returned
 * separately so the caller can keep sandboxing shards that DO run install hooks — the
 * actual supply-chain vector.
 *
 * @param {string} name - Package name
 * @param {number} fileCountTotal - JS/TS file count from countPackageFiles
 * @param {Object|null} manifest - Parsed package.json (or null if unreadable)
 * @returns {{ isShard: boolean, hasLifecycleScripts: boolean }}
 */
function classifyNativeShard(name, fileCountTotal, manifest) {
  const m = manifest || {};
  const scripts = (m.scripts && typeof m.scripts === 'object') ? m.scripts : {};
  const hasLifecycleScripts = LIFECYCLE_SCRIPT_KEYS.some(
    k => typeof scripts[k] === 'string' && scripts[k].trim().length > 0
  );
  const platformConstrained =
    (Array.isArray(m.os) && m.os.length > 0) ||
    (Array.isArray(m.cpu) && m.cpu.length > 0);
  const nameMatches = NATIVE_SHARD_NAME_RE.test(name || '');
  const lowJs = (fileCountTotal || 0) <= NATIVE_SHARD_MAX_JS_FILES;
  return { isShard: (platformConstrained || nameMatches) && lowJs, hasLifecycleScripts };
}

/**
 * Pure decision: should the sandbox be skipped entirely for this package, BEFORE the
 * tier-level run/defer/gate logic? Returns the skip descriptor or null. No I/O — every
 * input is precomputed, so this is unit-testable without launching a real sandbox.
 *
 * Both skip paths are detection-safe:
 *  - skip-memory: only when shouldSuppressByMemory already holds (the webhook would be
 *    suppressed anyway → the sandbox produces nothing actionable) AND we re-sandboxed
 *    this package within revalidateMs. A memory match that is stale (or never sandboxed)
 *    falls through to run, so canary coverage is revalidated on the revalidateMs cadence.
 *    New threat types / new HC types / score shift / IOC match all make memorySuppress
 *    false upstream → never skipped.
 *  - skip-native: only a native binary shard with NO lifecycle script, NO HIGH/CRITICAL
 *    finding and NO temporal signal — same guard rails as the large-low-signal skip.
 *
 * @param {Object} ctx
 * @param {boolean} ctx.memorySuppress - shouldSuppressByMemory(name, result).suppress
 * @param {number} [ctx.lastSandboxAt] - last real sandbox timestamp from scan memory
 * @param {number} ctx.now - current time (ms)
 * @param {number} ctx.revalidateMs - SANDBOX_REVALIDATE_MS
 * @param {boolean} ctx.isNativeShard
 * @param {boolean} ctx.hasLifecycleScripts
 * @param {boolean} ctx.hasHighOrCritical
 * @param {boolean} ctx.hasTemporal
 * @returns {{ action: 'skip-memory'|'skip-native', reason: string } | null}
 */
function shouldSkipSandbox(ctx) {
  const {
    memorySuppress, lastSandboxAt, now, revalidateMs,
    isNativeShard, hasLifecycleScripts, hasHighOrCritical, hasTemporal
  } = ctx;

  // (1) Memory match — skip only if we sandboxed it recently (else revalidate).
  if (memorySuppress) {
    const sandboxedRecently =
      typeof lastSandboxAt === 'number' && (now - lastSandboxAt) < revalidateMs;
    if (sandboxedRecently) {
      const days = ((now - lastSandboxAt) / 86_400_000).toFixed(1);
      return { action: 'skip-memory', reason: `memory match, last sandbox ${days}d ago` };
    }
    // fall through — stale/never-sandboxed memory match revalidates via the normal path
  }

  // (2) Native binary shard — same guard rails as the large-low-signal skip.
  if (isNativeShard && !hasLifecycleScripts && !hasHighOrCritical && !hasTemporal) {
    return { action: 'skip-native', reason: 'native binary shard, no lifecycle' };
  }

  return null;
}

/**
 * Run the static scan in a Worker thread with a hard timeout.
 * worker.terminate() calls V8::TerminateExecution which can interrupt
 * synchronous code (unlike Promise.race + setTimeout on sync code).
 *
 * @param {string} extractedDir - Path to extracted package
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {object} [scanContext] - Monitor-side context spread into pipeline options.
 *   Required by opt-in scanners (e.g. trusted-dep-diff) that need name/version/ecosystem
 *   and a monitorMode flag to perform registry queries.
 * @returns {Promise<object>} Scan result (same shape as run(_, {_capture:true}))
 */
function runScanInWorker(extractedDir, timeoutMs, scanContext = null, signal = null) {
  return new Promise((resolve, reject) => {
    const workerOpts = {
      // rateBrain: opts the worker's http-limiter into proxy mode (tokens and
      // 429s flow through the main-thread brain). ONLY scan workers get this —
      // any other Worker keeps a local bucket and can never hang on a missing brain.
      workerData: { extractedDir, scanContext: scanContext || {}, rateBrain: true }
    };
    // Per-worker V8 memory limits (OOM durable fix): the 2026-06 RSS spikes
    // (8.2-8.8GB with heap ~550MB) are off-heap allocations inside scan workers —
    // one pathological package could blow the WHOLE process toward the EMERGENCY
    // breaker (queue purge + worker kills). With a per-worker cap, that package
    // OOMs ITS worker only: ERR_WORKER_OUT_OF_MEMORY → rejected → ledgered
    // `worker_oom` (never counted clean) while the daemon and its siblings keep
    // running. This is also what allows raising MUADDIB_SCAN_CONCURRENCY back
    // up (it was clamped 12-16 → 8 on 2026-06-08 as the OOM mitigation).
    // OFF unless MUADDIB_WORKER_MAX_OLD_MB is set (staged rollout; suggested 1024).
    const maxOldMb = parseInt(globalThis.process.env.MUADDIB_WORKER_MAX_OLD_MB, 10);
    if (Number.isFinite(maxOldMb) && maxOldMb > 0) {
      const maxYoungMb = parseInt(globalThis.process.env.MUADDIB_WORKER_MAX_YOUNG_MB, 10);
      workerOpts.resourceLimits = {
        maxOldGenerationSizeMb: maxOldMb,
        maxYoungGenerationSizeMb: Number.isFinite(maxYoungMb) && maxYoungMb > 0 ? maxYoungMb : 128,
        codeRangeSizeMb: 64,
        stackSizeMb: 8
      };
    }
    // MUADDIB_SCAN_WORKER_PATH: test seam (read at call time, same spirit as
    // MUADDIB_SPILL_FILE) — lets the message-dispatch tests spawn a stub worker
    // that emits side-channel message types the real scan-worker never sends.
    const worker = new Worker(process.env.MUADDIB_SCAN_WORKER_PATH || SCAN_WORKER_PATH, workerOpts);
    const _sc = scanContext || {};
    _liveWorkers.set(worker, { name: _sc.name, version: _sc.version, ecosystem: _sc.ecosystem });

    // Off-heap attribution (worker-mem.jsonl, gated MUADDIB_WORKER_MEM=1):
    // process RSS around each worker's lifetime. tid captured now — after
    // 'exit' worker.threadId becomes -1.
    const _wmTid = worker.threadId;
    const _wmSpawnedAt = Date.now();
    appendWorkerMem({
      ev: 'spawn', tid: _wmTid,
      name: _sc.name, version: _sc.version, ecosystem: _sc.ecosystem,
      lane: _sc._lane, jsBytes: _sc._jsBytes, jsMin: _sc._jsMin,
      rss: process.memoryUsage().rss
    });

    let settled = false;
    let timer = null;
    const done = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) { try { signal.removeEventListener('abort', onAbort); } catch { /* not added */ } }
      _liveWorkers.delete(worker);
      fn();
    };

    // Outer-timeout abort (processQueueItem's SCAN_TIMEOUT_MS): terminate the worker
    // so a static scan that outlives the whole-package budget cannot keep its isolate
    // (heap + ASTs) alive in the background.
    const onAbort = () => done(() => {
      worker.terminate().finally(() => reject(new Error('Static scan aborted (outer timeout — worker terminated)')));
    });

    timer = setTimeout(() => done(() => {
      worker.terminate()
        .then(() => reject(new Error(`Static scan timeout after ${timeoutMs / 1000}s (worker terminated)`)))
        .catch(() => reject(new Error(`Static scan timeout after ${timeoutMs / 1000}s (worker terminate failed)`)));
    }), timeoutMs);

    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }

    worker.on('message', (msg) => {
      // Terminal types settle the scan promise. Every other type is a
      // side-channel message dispatched to its registered handler WITHOUT
      // touching done() — calling done() here for non-terminal messages would
      // disarm the static timeout, hide the worker from terminateAllWorkers
      // and leave the scan pending until the outer abort (the trap this
      // dispatch replaced). Unknown types are deliberately ignored.
      if (!msg || typeof msg.type !== 'string') return;
      if (msg.type === 'result') { done(() => resolve(msg.data)); return; }
      if (msg.type === 'error') { done(() => reject(new Error(msg.message))); return; }
      const handler = _workerMessageHandlers.get(msg.type);
      if (handler) {
        try { handler(worker, msg); } catch { /* a side-channel handler must never break the scan */ }
      }
    });

    worker.on('error', (err) => done(() => reject(err)));

    worker.on('exit', (code) => {
      // 'exit' fires exactly once per worker (even after terminate/error), so
      // it is the one reliable place to close the spawn/exit RSS pair.
      appendWorkerMem({
        ev: 'exit', tid: _wmTid,
        name: _sc.name, version: _sc.version, code,
        durMs: Date.now() - _wmSpawnedAt,
        rss: process.memoryUsage().rss
      });
      done(() => {
        if (code !== 0) {
          const e = new Error(worker._muaddibInterrupted
            ? 'Scan interrupted (EMERGENCY worker terminate)'
            : `Worker exited with code ${code}`);
          if (worker._muaddibInterrupted) e.code = 'SCAN_INTERRUPTED';
          reject(e);
        }
      });
    });
  });
}

// --- Package scanning ---

async function scanPackage(name, version, ecosystem, tarballUrl, registryMeta, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable, signal = null) {
  const startTime = Date.now();
  const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const tmpDir = fs.mkdtempSync(path.join(tmpBase, `${sanitizePackageName(name)}-`));
  const meta = registryMeta || {};
  const cacheTrigger = meta._cacheTrigger || null;

  try {
    // Pre-download size check: reject packages known to exceed MAX_TARBALL_SIZE
    // from registry metadata, without wasting a download + 300s timeout.
    // unpackedSize is available from getNpmLatestTarball() after lazy resolution.
    const metaSize = meta.unpackedSize || 0;
    if (metaSize > MAX_TARBALL_SIZE) {
      console.log(`[MONITOR] SIZE_REJECT: ${name}@${version} — metadata size ${(metaSize / 1024 / 1024).toFixed(1)}MB exceeds ${(MAX_TARBALL_SIZE / 1024 / 1024).toFixed(0)}MB limit (skipped without download)`);
      stats.scanned++;
      stats.totalTimeMs += Date.now() - startTime;
      return;
    }

    // Pick the local filename extension from the URL so adm-zip / tar both
    // read the magic correctly. PyPI wheels arrive as .whl, npm tarballs as
    // .tgz, sdists as .tar.gz. Anything else falls through to .tar.gz
    // (ingestion now returns null for unsupported types, so this branch is
    // a defensive default rather than a real fallback).
    const urlLower = (tarballUrl || '').toLowerCase();
    const isWheel = urlLower.endsWith('.whl') || urlLower.endsWith('.zip');
    const archiveExt = isWheel ? '.whl' : '.tar.gz';
    const tgzPath = path.join(tmpDir, `package${archiveExt}`);
    if (isWheel && ecosystem === 'pypi') {
      stats.pypiWheelsScanned = (stats.pypiWheelsScanned || 0) + 1;
    }

    // Layer 3: Check tarball cache before downloading
    const cacheKey = tarballCacheKey(name, version);
    const cachedPath = tarballCachePath(cacheKey);
    let usedCache = false;

    if (version && fs.existsSync(cachedPath)) {
      try {
        fs.copyFileSync(cachedPath, tgzPath);
        usedCache = true;
        console.log(`[MONITOR] TARBALL CACHE HIT: ${name}@${version}`);
        stats.tarballCacheHits = (stats.tarballCacheHits || 0) + 1;
      } catch (err) {
        console.warn(`[MONITOR] TARBALL CACHE: read failed for ${name}@${version}: ${err.message}`);
      }
    }

    if (!usedCache) {
      await acquireRegistrySlot();
      try {
        await downloadToFile(tarballUrl, tgzPath);
      } finally {
        releaseRegistrySlot();
      }

      // Layer 3: Cache tarball for high-risk packages
      if (cacheTrigger) {
        try {
          cacheTarball(name, version, tgzPath, cacheTrigger.reason, cacheTrigger.retentionDays);
        } catch (err) {
          console.warn(`[MONITOR] TARBALL CACHE: write failed for ${name}@${version}: ${err.message}`);
        }
      }
    }

    // Check downloaded size
    const fileSize = fs.statSync(tgzPath).size;
    if (fileSize > MAX_TARBALL_SIZE) {
      console.log(`[MONITOR] SKIP: ${name}@${version} — tarball too large (${(fileSize / 1024 / 1024).toFixed(1)}MB)`);
      stats.scanned++;
      stats.totalTimeMs += Date.now() - startTime;
      return;
    }

    // C1: Size cap — skip full scan for large packages (>10MB unpacked).
    // Malware payloads are tiny (<1MB); 10MB has 10x safety margin.
    // Quick scan: extract + check package.json + shell scripts for lifecycle threats.
    const unpackedSize = meta.unpackedSize || 0;
    let extractedDir = null;

    if (unpackedSize > LARGE_PACKAGE_SIZE || meta.fastTrack) {
      // Exception 1: IOC match — always full scan
      let isKnownIOC = false;
      try {
        const iocs = loadCachedIOCs();
        isKnownIOC = (iocs.wildcardPackages && iocs.wildcardPackages.has(name)) ||
                     !!matchVersionedIOC(iocs, name, version);
      } catch { /* IOC load failure — proceed with size cap */ }

      if (isKnownIOC) {
        console.log(`[MONITOR] SIZE CAP BYPASS (IOC): ${name}@${version} (${(unpackedSize / 1024 / 1024).toFixed(1)}MB — known IOC)`);
      } else {
        // Exception 2: Quick scan — extract and check package.json + shell scripts.
        // Validates actual tarball contents (not just registry metadata).
        let bypassQuickScan = false;
        try {
          extractedDir = extractArchive(tgzPath, tmpDir);

          const [pkgThreats, shellThreats] = await Promise.all([
            scanPackageJson(extractedDir),
            scanShellScripts(extractedDir)
          ]);
          const quickThreats = [...pkgThreats, ...shellThreats];

          bypassQuickScan = quickThreats.some(t =>
            t.severity === 'CRITICAL' || t.severity === 'HIGH'
          );

          if (bypassQuickScan) {
            console.log(`[MONITOR] SIZE CAP BYPASS (quick scan): ${name}@${version} (${(unpackedSize / 1024 / 1024).toFixed(1)}MB — ${quickThreats.length} findings)`);
          } else {
            console.log(`[MONITOR] SIZE_SKIP: ${name}@${version} — large package (${(unpackedSize / 1024 / 1024).toFixed(1)}MB, quick scan clean)`);
            stats.scanned++;
            stats.totalTimeMs += Date.now() - startTime;
            stats.clean++;
            updateScanStats('clean');
            appendScanLedger({ name, version, ecosystem, outcome: 'size_skip', score: 0, source: 'size_skip_quick_clean' });
            return;
          }
        } catch {
          // Extract/quick scan failed — fallback to registry metadata check
          extractedDir = null;
          const scripts = meta.registryScripts || {};
          const DANGEROUS_LIFECYCLE = ['preinstall', 'install', 'postinstall'];
          const hasSuspiciousLifecycle = DANGEROUS_LIFECYCLE.some(hook => {
            const val = scripts[hook];
            return val && !isSafeLifecycleScript(val);
          });

          if (hasSuspiciousLifecycle) {
            console.log(`[MONITOR] SIZE CAP BYPASS (lifecycle fallback): ${name}@${version} (${(unpackedSize / 1024 / 1024).toFixed(1)}MB)`);
          } else {
            console.log(`[MONITOR] SIZE_SKIP: ${name}@${version} — large package (${(unpackedSize / 1024 / 1024).toFixed(1)}MB, extract failed)`);
            stats.scanned++;
            stats.totalTimeMs += Date.now() - startTime;
            stats.clean++;
            updateScanStats('clean');
            appendScanLedger({ name, version, ecosystem, outcome: 'size_skip', score: 0, source: 'size_skip_extract_failed' });
            return;
          }
        }
      }
    }

    if (!extractedDir) {
      extractedDir = extractArchive(tgzPath, tmpDir);
    }

    // ML Phase 2a: Count JS files and detect test presence for enriched features
    const { fileCountTotal, hasTests } = countPackageFiles(extractedDir);

    // C2 heavy-lane classification (see heavy-lane.js header): measured on
    // disk, after extraction — registry metadata is not trustworthy here.
    // Measurement failure falls back to the compressed tarball size
    // (conservative: never silently far under the real JS weight).
    let jsWeight;
    try {
      jsWeight = measureJsWeight(extractedDir);
    } catch {
      jsWeight = { totalJsBytes: fileSize, maxJsFileBytes: 0, truncated: false };
    }
    const lane = isHeavyScan(jsWeight) ? 'heavy' : 'light';

    // Hoisted before the worker spawn (per-worker 429-storm fix): fetch the npm
    // registry metadata ONCE on the main thread. The shared http-limiter coordinates
    // it and the temporal cache is warm (npm-registry.js reads it first), so only
    // weekly_downloads + author hit the network. Passed to the worker via scanContext
    // so the worker's processor consumes it instead of re-fetching on its OWN module-
    // level limiter — N worker_threads = N uncoordinated limiters → ~Nx npm throughput
    // → 429 bursts. Also reused below (ML / first-publish / training records /
    // reputation) — previously this was a SECOND main-side fetch after the worker.
    let npmRegistryMeta = null;
    if (ecosystem === 'npm') {
      try {
        const { getPackageMetadata } = require('../scanner/npm-registry.js');
        npmRegistryMeta = await getPackageMetadata(name);
      } catch (err) {
        console.error(`[ML] npm registry fetch failed for ${name}: ${err.message}`);
      }
    }

    // C2 heavy-lane: serialize the memory-heavy scans. Acquired AFTER the
    // registry fetch above (never hold the slot during network I/O); released
    // in the finally right after the static scan — the slot covers ONLY the
    // worker's lifetime (≤ STATIC_SCAN_TIMEOUT_MS), not the sandbox (which
    // has its own semaphore and runs outside the daemon's heap).
    let heavySlotHeld = false;
    let memTicket = null;
    if (isGovernorEnabled()) {
      // Phase B: the memory governor REPLACES the heavy lane at admission —
      // a heavy is simply a big ticket (2 heavies ≈ the whole heavy budget,
      // which reproduces HEAVY_SCAN_MAX=2 by arithmetic instead of by a
      // dedicated semaphore) and the aggregate of mediums is bounded too
      // (the 09:43 ATO-burst shape: 12 sub-threshold scans = 8GB off-heap).
      const t = classifyWeight(jsWeight);
      if (t.cls === 'heavy') stats.heavyScans = (stats.heavyScans || 0) + 1;
      const gov = getGovernorState();
      if (t.cls !== 'light' && (gov.frozen || gov.waiting > 0)) {
        stats.ticketWaits = (stats.ticketWaits || 0) + 1;
        console.log(`[MONITOR] MEM_GOVERNOR: ${name}@${version} waiting for a ${t.cls} ticket (${t.mb}MB; outstanding=${gov.outstandingMb}MB/${gov.budgetMb}MB, frozen=${gov.frozen})`);
      }
      // Same requeue contract as the heavy lane: bounded waits, final pass
      // unbounded (abort-aware only) so an item cannot loop forever.
      const lastPass = (meta._heavyRetries || 0) >= HEAVY_REQUEUE_MAX;
      const waitStart = Date.now();
      memTicket = await acquireMemoryTicket(t.cls, { signal, maxWaitMs: lastPass ? 0 : heavyWaitMaxMs() });
      stats.ticketWaitMsTotal = (stats.ticketWaitMsTotal || 0) + (Date.now() - waitStart);
    } else if (lane === 'heavy') {
      stats.heavyScans = (stats.heavyScans || 0) + 1;
      const laneState = getHeavyLaneState();
      if (laneState.max > 0 && laneState.active >= laneState.max) {
        stats.heavyLaneWaits = (stats.heavyLaneWaits || 0) + 1;
        console.log(`[MONITOR] HEAVY_LANE: ${name}@${version} waiting for a slot (${(jsWeight.totalJsBytes / 1024 / 1024).toFixed(1)}MB JS, active=${laneState.active}, waiting=${laneState.waiting})`);
      }
      // After HEAVY_REQUEUE_MAX requeues the final pass waits unbounded
      // (abort-aware only, still under the outer SCAN_TIMEOUT_MS) so an item
      // cannot loop in the queue forever.
      const lastPass = (meta._heavyRetries || 0) >= HEAVY_REQUEUE_MAX;
      const waitStart = Date.now();
      heavySlotHeld = await acquireHeavySlot({ signal, maxWaitMs: lastPass ? 0 : heavyWaitMaxMs() });
      stats.heavyLaneWaitMsTotal = (stats.heavyLaneWaitMsTotal || 0) + (Date.now() - waitStart);
    }

    let result;
    try {
      // scanContext: feeds monitor-side info (name/version/ecosystem) and the
      // monitorMode + trustedDepDiff flags into opt-in pipeline scanners.
      // The trusted-dep-diff scanner needs both name and version to query the
      // registry for the previous-version dependency list — that information
      // is meaningless in offline CLI mode but available here.
      const scanContext = {
        name,
        version,
        ecosystem,
        monitorMode: true,
        trustedDepDiff: true,
        // Stage 2: set by processQueueItem when MUADDIB_TRIAGE_MODE=enforce.
        // Defaults to 'full' so any CLI/test caller that bypasses triage gets
        // the full 20-scanner pipeline (unchanged behaviour).
        scanMode: (meta && meta.scanMode) || 'full',
        // C2 observability: lane + JS weight flow into the worker-mem spawn
        // event (runScanInWorker) so lane×heap-peak cross-checks are possible
        // post-rollout (hard criterion: zero 'light' scans peaking >512MB).
        _lane: lane,
        _jsBytes: jsWeight.totalJsBytes,
        _jsMin: jsWeight.minifiedJsBytes || 0
      };
      // Hand the main-thread-fetched metadata to the worker so its processor skips
      // the per-worker getPackageMetadata fetch (429-storm fix). npm only; the key
      // is set even when null ("main already tried, don't refetch"). pypi leaves it
      // absent so the worker takes the unchanged CLI/else-if path.
      if (ecosystem === 'npm') scanContext.npmRegistryMeta = npmRegistryMeta;
      result = await runScanInWorker(extractedDir, STATIC_SCAN_TIMEOUT_MS, scanContext, signal);
    } catch (staticErr) {
      if (/static scan timeout/i.test(staticErr.message)) {
        console.error(`[MONITOR] STATIC_TIMEOUT: ${name}@${version} — exceeded ${STATIC_SCAN_TIMEOUT_MS / 1000}s (worker terminated, kept INCONCLUSIVE not clean)`);
        recordError(staticErr, stats);
        stats.scanned++;
        stats.totalTimeMs += Date.now() - startTime;
        // Garde-fou: a static-scan timeout must NOT count as clean — a package that
        // deliberately hangs the parser to evade analysis would otherwise be relabelled
        // benign. Count as inconclusive (excluded from the FP/TP denominator).
        updateScanStats('sandbox_inconclusive');
        // Ledger the inconclusive timeout — the 'static_timeout' outcome existed but was
        // emitted nowhere, so a parser-hang evasion vanished from coverage. Best-effort.
        try {
          appendScanLedger({ name, version, ecosystem, outcome: 'static_timeout', source: 'static_timeout' });
        } catch { /* ledger is best-effort */ }
        return { sandboxResult: null, staticClean: false };
      }
      throw staticErr;
    } finally {
      // Single release point — success, static timeout, EMERGENCY terminate
      // and abort all funnel through here exactly once (heavySlotHeld guard).
      if (memTicket) { releaseMemoryTicket(memTicket); memTicket = null; }
      if (heavySlotHeld) { releaseHeavySlot(); heavySlotHeld = false; }
    }

    // Phase 3 signal — agent-supply-chain lens. Pure observability, no scoring impact.
    // Cisco AI Defense / SkillSieve / Snyk Agent Scan EVO scan skill marketplaces;
    // they don't monitor the npm/PyPI firehose. Tracking which packages bundle a
    // SKILL.md is our unique intersection (npm-package-bundling-malicious-skill).
    try {
      const det = detectSkillMdBundled(extractedDir, result && result.threats);
      if (det.bundled) {
        stats.skillMdBundled = (stats.skillMdBundled || 0) + 1;
        console.log(`[MONITOR] SKILL_MD_BUNDLED: ${name}@${version} (${ecosystem}) — ${det.count} file(s)`);
      }
    } catch { /* observability signal — never let it break the scan */ }

    // First-publish detection: used for sandbox priority below
    const isFirstPublish = cacheTrigger && cacheTrigger.reason === 'first_publish';
    // AUDIT-A1 observability: stamp once so every recordTrainingSample(result, …) call
    // below carries firstPublish into the scan-ledger (all ~10 call sites share this
    // `result`). Pairs with the firstPublish flag on the eviction-drop ledger entries so
    // first-publish coverage (scanned vs dropped) becomes measurable. The "Phase 2a"
    // comment below promised this; the threading was missing until now.
    result._firstPublish = isFirstPublish;

    // npm registry metadata was fetched ONCE before the worker spawn (hoisted above
    // to feed scanContext.npmRegistryMeta) and is reused here for: isFirstPublishHigh-
    // Risk, ML classifier features, JSONL training records, and reputation scoring.
    // Clean packages MUST carry metadata to prevent training-data leakage (model
    // learning "metadata=0 → clean" instead of behavioral signals).

    // First-publish sandbox priority: sandbox even with 0 static findings
    // if the package is from a new/unknown maintainer without a linked repository.
    // First-publish sandbox is npm-only: runSandbox does `npm install <name>` and
    // cannot install PyPI sdists/wheels. PyPI first-publish items still carry the
    // flag + cache trigger + ledger firstPublish (Phase 2a) but skip the sandbox.
    const firstPublishSandbox = isFirstPublish &&
      ecosystem === 'npm' &&
      FIRST_PUBLISH_SANDBOX_ENABLED &&
      isFirstPublishHighRisk(cacheTrigger, npmRegistryMeta) &&
      isSandboxEnabled() && sandboxAvailable &&
      scanQueue.length < FIRST_PUBLISH_SANDBOX_MAX_QUEUE;

    if (result.summary.total === 0) {
      if (firstPublishSandbox) {
        // First-publish sandbox priority: run sandbox even with 0 static findings
        console.log(`[MONITOR] FIRST-PUBLISH SANDBOX: ${name}@${version} (0 findings, sandboxing anyway)`);
        stats.firstPublishSandboxed = (stats.firstPublishSandboxed || 0) + 1;

        let sandboxResult = null;
        try {
          const canary = isCanaryEnabled();
          console.log(`[MONITOR] SANDBOX (first-publish): launching for ${name}@${version}${canary ? ' (canary: on)' : ''}...`);
          sandboxResult = await runSandbox(name, { canary, signal });
          console.log(`[MONITOR] SANDBOX: ${name}@${version} → score: ${sandboxResult.score}, severity: ${sandboxResult.severity}`);
        } catch (err) {
          console.error(`[MONITOR] SANDBOX ERROR: ${name}@${version} — ${err.message}`);
        }

        const sandboxScore = sandboxResult ? (sandboxResult.score || 0) : 0;
        if (sandboxScore > 0) {
          // Sandbox found something — treat as suspect
          stats.suspect++;
          stats.scanned++;
          const elapsed = Date.now() - startTime;
          stats.totalTimeMs += elapsed;
          updateScanStats('suspect');
          recordTrainingSample(result, { name, version, ecosystem, label: 'suspect', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
          return { sandboxResult, staticClean: false, firstPublishSandbox: true };
        } else {
          // Sandbox clean — still CLEAN
          stats.scanned++;
          const elapsed = Date.now() - startTime;
          stats.totalTimeMs += elapsed;
          stats.clean++;
          console.log(`[MONITOR] CLEAN (first-publish sandbox OK): ${name}@${version} (${(elapsed / 1000).toFixed(1)}s)`);
          updateScanStats('clean');
          recordTrainingSample(result, { name, version, ecosystem, label: 'clean', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
          return { sandboxResult, staticClean: true, firstPublishSandbox: true };
        }
      } else {
        stats.scanned++;
        const elapsed = Date.now() - startTime;
        stats.totalTimeMs += elapsed;
        stats.clean++;
        console.log(`[MONITOR] CLEAN: ${name}@${version} (0 findings, ${(elapsed / 1000).toFixed(1)}s)`);
        updateScanStats('clean');
        recordTrainingSample(result, { name, version, ecosystem, label: 'clean', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
        return { sandboxResult: null, staticClean: true };
      }
    } else {
      const counts = [];
      if (result.summary.critical > 0) counts.push(`${result.summary.critical} CRITICAL`);
      if (result.summary.high > 0) counts.push(`${result.summary.high} HIGH`);
      if (result.summary.medium > 0) counts.push(`${result.summary.medium} MEDIUM`);
      if (result.summary.low > 0) counts.push(`${result.summary.low} LOW`);

      // Check if all findings come from bundled tooling files
      if (isBundledToolingOnly(result.threats)) {
        stats.scanned++;
        const elapsed = Date.now() - startTime;
        stats.totalTimeMs += elapsed;
        stats.clean++;
        console.log(`[MONITOR] SKIPPED (bundled tooling): ${name}@${version} (${counts.join(', ')})`);

        const alert = {
          timestamp: new Date().toISOString(),
          name,
          version,
          ecosystem,
          skipped: true,
          // P7: Exclude LOW-severity findings from alert persistence
          findings: result.threats
            .filter(t => t.severity !== 'LOW')
            .map(t => ({
              rule: t.rule_id || t.type,
              severity: t.severity,
              file: t.file
            })),
          lowCount: result.threats.filter(t => t.severity === 'LOW').length
        };
        appendAlert(alert);
        updateScanStats('clean');
        recordTrainingSample(result, { name, version, ecosystem, label: 'clean', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
        return { sandboxResult: null, staticClean: true };
      } else {
        // No popularity-based skip here. The TRUSTED (popular) shortcut that used
        // to live at this point was a whitelist-by-downloads — CLAUDE.md forbids
        // FP-reducing whitelists, and the Shai-Hulud wave-2 ATO attacks of May 2026
        // proved that popular packages are precisely the prime target for ATO.
        // Downstream attenuation handles the FP load via computeReputationFactor()
        // and the graduated webhook threshold (webhook.js:83-87) — popular packages
        // need a higher static score to fire a webhook, but they remain visible in
        // the pipeline (sandbox, persisted detections, training samples) the same
        // way every other package is. The supply-chain dep-diff check that the
        // old block used as bypass logic now runs as a first-class scanner
        // (src/scanner/trusted-dep-diff.js, wired in via executor.js); its findings
        // arrive in result.threats before this point, so isSuspectClassification
        // and the reputation bypass for HIGH_CONFIDENCE_MALICE_TYPES take the
        // package straight to tier 1a + mandatory sandbox + webhook.

        const classification = isSuspectClassification(result);
        if (!classification.suspect) {
          stats.scanned++;
          const elapsed = Date.now() - startTime;
          stats.totalTimeMs += elapsed;
          stats.clean++;
          console.log(`[MONITOR] CLEAN (low-signal): ${name}@${version} (${counts.join(', ')})`);
          updateScanStats('clean');
          recordTrainingSample(result, { name, version, ecosystem, label: 'clean', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
          return { sandboxResult: null, staticClean: true };
        }

        const tier = classification.tier;

        // Tier 3: logged only, no stats.suspect increment, no sandbox
        if (tier === 3) {
          stats.scanned++;
          const elapsed = Date.now() - startTime;
          stats.totalTimeMs += elapsed;
          stats.suspectByTier.t3++;
          console.log(`[MONITOR] SUSPECT T3 (low-intent): ${name}@${version} (${counts.join(', ')})`);
          console.log(`[MONITOR] FINDINGS: ${name}@${version} → ${formatFindings(result)}`);
          updateScanStats('clean'); // T3 does not inflate suspect stats
          recordTrainingSample(result, { name, version, ecosystem, label: 'clean', tier: 3, registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
          return { sandboxResult: null, staticClean: true, tier: 3 };
        }

        // Tier 1a, 1b and Tier 2: count as suspect
        const tierKey = tier === '1a' ? 't1a' : tier === '1b' ? 't1b' : 't2';
        stats.suspectByTier[tierKey]++;
        // Legacy t1 counter: sum of t1a + t1b for backward compat in persisted stats
        if (tier === '1a' || tier === '1b') stats.suspectByTier.t1++;
        const tierLabel = tier === '1a' ? 'T1a' : tier === '1b' ? 'T1b' : 'T2';
        console.log(`[MONITOR] SUSPECT ${tierLabel}: ${name}@${version} (${counts.join(', ')})`);
        console.log(`[MONITOR] FINDINGS: ${name}@${version} → ${formatFindings(result)}`);

        // ML Phase 2: classifier filter for T1 zone (score 20-34)
        // Guard rails in classifyPackage() ensure HC types and high-score packages are never suppressed.
        // Hoisted so trySendWebhook can use ML result to prevent suppression (p >= 0.90).
        //
        // DISABLED (2026-04-08): Model has collapsed — predicts p≈0.002 for ALL inputs (always "clean"),
        // including clearly malicious patterns (lifecycle+exec+staged_payload). This suppresses real
        // threats as ml_clean (false negatives). Disabled until model is retrained on corrected JSONL
        // data with balanced labels. The classifier still runs in LOG-ONLY mode to collect data for
        // retraining validation, but its prediction is never used for filtering.
        //
        // Guards added: ecosystem === 'npm' (PyPI has no npm registry metadata),
        // npmRegistryMeta fallback fetch (ensure metadata is never null for ML features).
        let mlResult = null;
        const riskScore = result.summary.riskScore || 0;
        if ((tier === '1a' || tier === '1b') && riskScore >= 20 && riskScore < 35 && ecosystem === 'npm') {
          try {
            const { classifyPackage, isModelAvailable } = require('../ml/classifier.js');
            if (isModelAvailable()) {
              // Defensive: ensure npmRegistryMeta is fetched (should already be from line ~420,
              // but network failures can silently leave it null)
              if (!npmRegistryMeta) {
                try {
                  const { getPackageMetadata } = require('../scanner/npm-registry.js');
                  npmRegistryMeta = await getPackageMetadata(name);
                  if (!npmRegistryMeta) {
                    console.warn(`[ML] Registry metadata unavailable for ${name} — ML features will be zero-filled`);
                  }
                } catch (fetchErr) {
                  console.warn(`[ML] Registry metadata fetch failed for ${name}: ${fetchErr.message}`);
                }
              }
              const enrichedMeta = { npmRegistryMeta, fileCountTotal, hasTests, unpackedSize: meta.unpackedSize, registryMeta: meta };
              mlResult = classifyPackage(result, enrichedMeta);
              // LOG-ONLY: record ML prediction for retraining data but do NOT filter.
              // When model is retrained and validated, remove the 'true ||' guard below.
              console.log(`[MONITOR] ML LOG-ONLY: ${name}@${version} (prediction=${mlResult.prediction}, p=${mlResult.probability}, score=${riskScore})`);
              const ML_FILTER_ENABLED = false;
              if (ML_FILTER_ENABLED && mlResult.prediction === 'clean') {
                // DISABLED: model collapsed (p≈0.002 for all inputs). Re-enable after retrain.
                console.log(`[MONITOR] ML CLEAN: ${name}@${version} (p=${mlResult.probability}, score=${riskScore})`);
                stats.mlFiltered++;
                stats.scanned++;
                const elapsed = Date.now() - startTime;
                stats.totalTimeMs += elapsed;
                // Count as clean (ML-filtered), skip sandbox/webhook
                updateScanStats('ml_clean');
                recordTrainingSample(result, { name, version, ecosystem, label: 'ml_clean', tier, registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
                return { sandboxResult: null, mlFiltered: true, tier };
              }
            }
          } catch (err) {
            // Non-fatal: ML failure must never block the scan pipeline
            console.error(`[ML] Classifier error for ${name}@${version}: ${err.message}`);
          }
        }

        // Shadow model: log-only prediction for ALL score >= 20 npm packages.
        // Runs independently of classifyPackage — no effect on mlResult, webhooks,
        // or any decisions. Collects shadow validation data for the retrained model.
        if (riskScore >= 20 && ecosystem === 'npm') {
          try {
            const { isShadowModelAvailable, runShadowPrediction } = require('../ml/classifier.js');
            if (isShadowModelAvailable()) {
              const shadowMeta = { npmRegistryMeta, fileCountTotal, hasTests, unpackedSize: meta.unpackedSize, registryMeta: meta };
              runShadowPrediction(result, shadowMeta, `${name}@${version}`, riskScore);
            }
          } catch (err) {
            // Non-fatal: shadow failure must never block the pipeline
            if (err.code !== 'MODULE_NOT_FOUND') {
              console.error(`[ML-SHADOW] Error for ${name}@${version}: ${err.message}`);
            }
          }
        }

        stats.suspect++;

        // Fire-and-forget tarball archiving — never blocks the pipeline
        // Skip for fast-track packages (large boring enterprise packages — not worth archiving)
        if (meta.fastTrack) {
          console.log(`[MONITOR] FAST-TRACK SKIP: ${name}@${version} — skipping archive + LLM (static-only)`);
        } else archiveSuspectTarball(name, version, tarballUrl, {
          score: riskScore,
          priority: tierLabel,
          rulesTriggered: (result.threats || []).map(t => t.ruleId || t.type).filter(Boolean),
          llmVerdict: null // LLM runs after this point; updated by webhook if needed
        }).catch(err => {
          console.warn(`[Archive] Failed for ${name}@${version}: ${err.message}`);
        });

        // Sandbox decision based on tier + smart skip for large low-signal packages.
        // Large packages (>15MB or >80 deps) with only MEDIUM/LOW findings timeout
        // systematically (90s × 3 = INCONCLUSIVE = 0 detection). Skipping frees slots
        // for real suspects. Guard-fous: any HIGH/CRITICAL, temporal anomaly, maintainer
        // change, or dormant spike → sandbox runs regardless of size.
        const SANDBOX_SIZE_SKIP_BYTES = 15 * 1024 * 1024; // 15MB
        const SANDBOX_DEPS_SKIP = 80;
        const isLargePackage = (meta.unpackedSize || 0) > SANDBOX_SIZE_SKIP_BYTES ||
          (meta.dependencyCount || 0) > SANDBOX_DEPS_SKIP;
        const hasHighOrCriticalFinding = (result.summary.critical || 0) > 0 || (result.summary.high || 0) > 0;
        const hasTemporalSignal = (result.threats || []).some(t =>
          t.type === 'postinstall_added' || t.type === 'preinstall_added' ||
          t.type === 'install_added' || t.type === 'maintainer_change' ||
          t.type === 'dormant_spike' || t.type === 'publish_anomaly'
        );
        const skipSandboxLargePackage = (isLargePackage || meta.fastTrack) && !hasHighOrCriticalFinding && !hasTemporalSignal;

        if (skipSandboxLargePackage && meta.fastTrack) {
          console.log(`[MONITOR] FAST-TRACK: ${name}@${version} — large package static-only (${((meta.unpackedSize || 0) / 1024 / 1024).toFixed(1)}MB, no lifecycle scripts)`);
        } else if (skipSandboxLargePackage) {
          console.log(`[MONITOR] SANDBOX SKIP (large low-signal): ${name}@${version} (${((meta.unpackedSize || 0) / 1024 / 1024).toFixed(1)}MB, deps=${meta.dependencyCount || '?'}, no HIGH/CRIT, no temporal)`);
        }

        // T1a: mandatory sandbox (HC malice types, TIER1_TYPES non-LOW, lifecycle + intent compound)
        // T1b: conditional sandbox — gated by SANDBOX_SCORE_THRESHOLD (Stage 3).
        //       Previously gated at >= 25 OR queue < 20; tightened to >= 40 by
        //       default because the 25-39 band produced no decisive sandbox
        //       findings in 4 months of prod data (axon-enterprise was at 52).
        // T2:  conditional sandbox — same score gate AND queue < 50.
        let sandboxResult = null;
        const shouldSandbox = !skipSandboxLargePackage && isSandboxEnabled() && sandboxAvailable && (
          tier === '1a' ||
          (tier === '1b' && riskScore >= SANDBOX_SCORE_THRESHOLD) ||
          (tier === 2 && riskScore >= SANDBOX_SCORE_THRESHOLD && scanQueue.length < 50)
        );

        // Waste-cut: skip the sandbox (run AND defer) when re-running it yields no new
        // verdict — a memory match the webhook would suppress anyway (dominant cost:
        // restart-replay of the changes-stream backlog), or a native binary shard that
        // just hangs the install. Both detection-safe (see shouldSkipSandbox). Cheap:
        // one package.json read + a scan-memory lookup.
        let shardManifest = null;
        try {
          shardManifest = JSON.parse(fs.readFileSync(path.join(extractedDir, 'package.json'), 'utf8'));
        } catch { /* unreadable manifest → classifyNativeShard treats it as non-shard */ }
        const { isShard: isNativeShard, hasLifecycleScripts: shardHasLifecycle } =
          classifyNativeShard(name, fileCountTotal, shardManifest);
        const memEntry = loadScanMemory()[name];
        const sandboxSkip = (isSandboxEnabled() && sandboxAvailable) ? shouldSkipSandbox({
          memorySuppress: shouldSuppressByMemory(name, result).suppress,
          lastSandboxAt: memEntry && memEntry.lastSandboxAt,
          now: Date.now(),
          revalidateMs: SANDBOX_REVALIDATE_MS,
          isNativeShard,
          hasLifecycleScripts: shardHasLifecycle,
          hasHighOrCritical: hasHighOrCriticalFinding,
          hasTemporal: hasTemporalSignal
        }) : null;

        if (sandboxSkip) {
          console.log(`[MONITOR] SANDBOX SKIP (${sandboxSkip.reason}): ${name}@${version}`);
          stats.sandboxWasteSkipped = (stats.sandboxWasteSkipped || 0) + 1;
          if (sandboxSkip.action === 'skip-memory') stats.sandboxSkipMemory = (stats.sandboxSkipMemory || 0) + 1;
          else stats.sandboxSkipNative = (stats.sandboxSkipNative || 0) + 1;
        } else if (shouldSandbox) {
          try {
            const canary = isCanaryEnabled();
            const maxRuns = tier === '1a' ? undefined : 1;

            if (tier === '1a') {
              // Phase 3 (throughput decoupling): T1a no longer block-waits a scan
              // worker. The high-confidence STATIC alert still fires synchronously
              // below (trySendWebhook, with sandboxResult=null — same as the T1b/T2
              // defer paths today); the sandbox runs ASYNC on the dedicated deferred
              // slot at top priority (processed first, never evicted, keeps multi-run
              // time-bomb detection) and sends a follow-up webhook if it confirms.
              // Crash-safe: the deferred queue is persisted across restarts, unlike
              // the old in-worker await which lost the sandbox on an OOM restart.
              console.log(`[MONITOR] SANDBOX DEFER (T1a, async high-priority): ${name}@${version} (score=${riskScore})`);
              enqueueDeferred({
                name, version, ecosystem, tier, riskScore, tarballUrl,
                enqueuedAt: Date.now(),
                staticResult: result,
                npmRegistryMeta,
                retries: 0
              });
              stats.sandboxDeferred = (stats.sandboxDeferred || 0) + 1;
            } else if (tryAcquireSandboxSlot()) {
              // T1b/T2: non-blocking — slot acquired atomically, run with skipSemaphore
              const reason = tier === 2 ? ' (T2, queue low)' : ' (T1b, conditional)';
              console.log(`[MONITOR] SANDBOX${reason}: launching for ${name}@${version}${canary ? ' (canary: on)' : ''}...`);
              markSandboxed(name); // stamp before the await: an aborted/inconclusive run still spent the time
              sandboxResult = await runSandbox(name, { canary, maxRuns, skipSemaphore: true, signal });
            } else {
              // T1b/T2: all sandbox slots busy — defer instead of blocking worker
              console.log(`[MONITOR] SANDBOX DEFER (slots full): ${name}@${version} (tier=${tier}, score=${riskScore})`);
              enqueueDeferred({
                name, version, ecosystem, tier, riskScore, tarballUrl,
                enqueuedAt: Date.now(),
                staticResult: result,
                npmRegistryMeta,
                retries: 0
              });
              stats.sandboxDeferred = (stats.sandboxDeferred || 0) + 1;
            }

            if (sandboxResult) {
              console.log(`[MONITOR] SANDBOX: ${name}@${version} → score: ${sandboxResult.score}, severity: ${sandboxResult.severity}`);

              // Check for canary exfiltration findings and send dedicated alert
              const canaryFindings = (sandboxResult.findings || []).filter(f => f.type === 'canary_exfiltration');
              if (canaryFindings.length > 0) {
                console.log(`[MONITOR] CANARY EXFILTRATION: ${name}@${version} — ${canaryFindings.length} token(s) stolen!`);
                const canaryRuleId = 'canary_exfiltration';
                const previousRules = alertedPackageRules.get(name);
                const alreadyAlerted = previousRules && previousRules.has(canaryRuleId);
                if (alreadyAlerted) {
                  console.log(`[MONITOR] DEDUP: ${name} canary exfiltration (already alerted today)`);
                } else {
                  const url = getWebhookUrl();
                  if (url) {
                    const exfiltrations = canaryFindings.map(f => ({
                      token: f.detail.match(/exfiltrate (\S+)/)?.[1] || 'UNKNOWN',
                      foundIn: f.detail
                    }));
                    const payload = buildCanaryExfiltrationWebhookEmbed(name, version, exfiltrations);
                    try {
                      await sendWebhook(url, payload, { rawPayload: true });
                      console.log(`[MONITOR] Canary exfiltration webhook sent for ${name}@${version}`);
                      if (previousRules) {
                        previousRules.add(canaryRuleId);
                      } else {
                        alertedPackageRules.set(name, new Set([canaryRuleId]));
                      }
                    } catch (webhookErr) {
                      console.error(`[MONITOR] Canary webhook failed for ${name}@${version}: ${webhookErr.message}`);
                    }
                  }
                }
              }
            }
          } catch (err) {
            console.error(`[MONITOR] SANDBOX error for ${name}@${version}: ${err.message}`);
          }
        } else if (tier === '1b' && sandboxAvailable && riskScore >= SANDBOX_SCORE_THRESHOLD) {
          // Stage 3 — defer only when the score crosses the gate. Below the
          // threshold, sandbox is skipped entirely (static result is final).
          // This stops the deferred-queue from filling with low-score items
          // that would never produce decisive sandbox findings.
          console.log(`[MONITOR] SANDBOX DEFERRED (T1b, score=${riskScore}, queue ${scanQueue.length}): ${name}@${version}`);
          enqueueDeferred({
            name, version, ecosystem, tier, riskScore, tarballUrl,
            enqueuedAt: Date.now(),
            staticResult: result,
            npmRegistryMeta,
            retries: 0
          });
          stats.sandboxDeferred = (stats.sandboxDeferred || 0) + 1;
        } else if (tier === '1b' && sandboxAvailable) {
          // Below SANDBOX_SCORE_THRESHOLD — no sandbox, no defer.
          console.log(`[MONITOR] SANDBOX GATED (T1b, score=${riskScore} < ${SANDBOX_SCORE_THRESHOLD}): ${name}@${version}`);
          stats.sandboxGated = (stats.sandboxGated || 0) + 1;
        } else if (tier === '1b') {
          console.log(`[MONITOR] SANDBOX SKIPPED (T1b, no Docker): ${name}@${version}`);
        } else if (tier === 2 && sandboxAvailable && riskScore >= SANDBOX_SCORE_THRESHOLD) {
          console.log(`[MONITOR] SANDBOX DEFERRED (T2, score=${riskScore}, queue ${scanQueue.length}): ${name}@${version}`);
          enqueueDeferred({
            name, version, ecosystem, tier, riskScore, tarballUrl,
            enqueuedAt: Date.now(),
            staticResult: result,
            npmRegistryMeta,
            retries: 0
          });
          stats.sandboxDeferred = (stats.sandboxDeferred || 0) + 1;
        } else if (tier === 2 && sandboxAvailable) {
          // Below SANDBOX_SCORE_THRESHOLD — T2 was already passive; staying
          // static-only matches the existing T3 behaviour.
          console.log(`[MONITOR] SANDBOX GATED (T2, score=${riskScore} < ${SANDBOX_SCORE_THRESHOLD}): ${name}@${version}`);
          stats.sandboxGated = (stats.sandboxGated || 0) + 1;
        } else if (tier === 2) {
          console.log(`[MONITOR] SANDBOX SKIPPED (T2, no Docker): ${name}@${version}`);
        }

        stats.scanned++;
        const elapsed = Date.now() - startTime;
        stats.totalTimeMs += elapsed;
        console.log(`[MONITOR] ${name}@${version} total time: ${(elapsed / 1000).toFixed(1)}s`);

        const alert = {
          timestamp: new Date().toISOString(),
          name,
          version,
          ecosystem,
          tier,
          // P7: Exclude LOW-severity findings from alert persistence.
          // LOW findings are FP-reduced noise (bundler artifacts, config loaders, SDK patterns).
          // Storing them inflates monitor-alerts.json and obscures real threats.
          findings: result.threats
            .filter(t => t.severity !== 'LOW')
            .map(t => ({
              rule: t.rule_id || t.type,
              severity: t.severity,
              file: t.file
            })),
          lowCount: result.threats.filter(t => t.severity === 'LOW').length
        };

        if (sandboxResult && sandboxResult.score > 0) {
          alert.sandbox = {
            score: sandboxResult.score,
            severity: sandboxResult.severity,
            findings: sandboxResult.findings
          };
        }

        if (sandboxResult && sandboxResult.score === 0 && (result.summary.riskScore || 0) >= 20) {
          alert.dormant_suspect = true;
        }

        appendAlert(alert);

        const findingTypes = [...new Set(result.threats.map(t => t.type))];
        const maxSeverity = result.summary.critical > 0 ? 'CRITICAL'
          : result.summary.high > 0 ? 'HIGH'
          : result.summary.medium > 0 ? 'MEDIUM' : 'LOW';
        appendDetection(name, version, ecosystem, findingTypes, maxSeverity);
        recordTrainingSample(result, { name, version, ecosystem, label: 'suspect', tier, sandboxResult, registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });

        // Persist alert locally for ALL suspects (independent of webhook filtering)
        const alertData = buildAlertData(name, version, ecosystem, result, sandboxResult);
        persistAlert(name, version, ecosystem, alertData);

        // Reputation scoring (monitor-only, npm only)
        // Adjusts score for webhook decision without mutating persisted alert data.
        // High-confidence malice types BYPASS reputation — supply-chain compromise protection.
        // Reuses npmRegistryMeta fetched earlier (ML Phase 2a) — no duplicate HTTP call.
        let adjustedResult = result;
        if (ecosystem === 'npm' && !hasHighConfidenceThreat(result)) {
          try {
            const reputationFactor = computeReputationFactor(npmRegistryMeta);
            if (reputationFactor !== 1.0) {
              const originalScore = result.summary.riskScore || 0;
              const adjustedScore = Math.round(originalScore * reputationFactor);
              adjustedResult = {
                ...result,
                summary: { ...result.summary, riskScore: adjustedScore, reputationFactor }
              };
              console.log(`[MONITOR] REPUTATION: ${name} factor=${reputationFactor.toFixed(2)} (${originalScore} → ${adjustedScore})`);
            }
          } catch (err) {
            console.error(`[MONITOR] Reputation error for ${name}: ${err.message}`);
          }
        } else if (ecosystem === 'npm' && hasHighConfidenceThreat(result)) {
          console.log(`[MONITOR] REPUTATION BYPASS: ${name} has high-confidence threat — using raw score`);
        }

        // Record daily alert with post-reputation score for top suspects ranking.
        // AUDIT-C: carry the distinct CRITICAL/HIGH threat types so the daily report
        // can annotate MCP suspects with their signals (visual triage, no scoring change).
        if (dailyAlerts.length < MAX_DAILY_ALERTS) {
          const signals = [...new Set((result.threats || [])
            .filter(t => t.severity === 'CRITICAL' || t.severity === 'HIGH')
            .map(t => t.type))].slice(0, 6);
          dailyAlerts.push({ name, version, ecosystem, findingsCount: result.summary.total, score: adjustedResult.summary.riskScore || 0, tier, signals });
        }
        // LLM Detective: AI-powered analysis for T1a/T1b suspects
        // Skip for fast-track (large boring packages — LLM analysis adds 10-30s for no value)
        let llmResult = null;
        if (!meta.fastTrack && (tier === '1a' || tier === '1b') && (adjustedResult.summary.riskScore || 0) >= 25 && !(signal && signal.aborted)) {
          try {
            const { investigatePackage, isLlmEnabled, getLlmMode } = require('../ml/llm-detective.js');
            if (isLlmEnabled()) {
              llmResult = await investigatePackage(extractedDir, result, {
                name, version, ecosystem,
                registryMeta: meta,
                npmRegistryMeta,
                tier
              });
              if (llmResult) {
                const llmMode = getLlmMode();
                console.log(`[LLM] ${name}@${version}: verdict=${llmResult.verdict} confidence=${llmResult.confidence} mode=${llmMode}`);
                stats.llmAnalyzed = (stats.llmAnalyzed || 0) + 1;

                // Safety: never suppress packages with high-confidence threats or positive sandbox
                const hasHC = hasHighConfidenceThreat(result);
                const hasSandboxEvidence = sandboxResult && sandboxResult.score > 0;
                // Phase 3: T1a sandboxes are now deferred (async), so sandboxResult is
                // null here — the sandbox evidence that previously guarded a T1a from
                // LLM suppression hasn't run yet. Never let the LLM clear a T1a before
                // its deferred sandbox confirms; T1a is the highest-confidence tier and
                // MUST get sandbox verification (it can come via the follow-up webhook).
                if (llmMode === 'active' && llmResult.verdict === 'benign' && llmResult.confidence > 0.85
                    && !hasHC && !hasSandboxEvidence && tier !== '1a') {
                  console.log(`[LLM] SUPPRESS: ${name}@${version} cleared (benign, confidence=${llmResult.confidence})`);
                  stats.llmSuppressed = (stats.llmSuppressed || 0) + 1;
                  stats.scanned++;
                  stats.totalTimeMs += Date.now() - startTime;
                  updateScanStats('llm_benign');
                  recordTrainingSample(result, { name, version, ecosystem, label: 'llm_benign', tier, registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
                  return { sandboxResult, llmResult, tier, staticScore: result.summary.riskScore || 0 };
                }
              }
            }
          } catch (err) {
            console.error(`[LLM] Error for ${name}@${version}: ${err.message}`);
          }
        }

        await trySendWebhook(name, version, ecosystem, adjustedResult, sandboxResult, mlResult, llmResult);
        const staticScore = result.summary.riskScore || 0;
        const hasHCThreats = hasHighConfidenceThreat(result);
        const isDormant = sandboxResult && sandboxResult.score === 0 && (result.summary.riskScore || 0) >= 20;
        return { sandboxResult, llmResult, staticClean: false, tier, staticScore, hasHCThreats, isDormant };
      }
    }
  } catch (err) {
    // C2 heavy-lane: a wait-timeout is NOT a scan failure — processQueueItem
    // requeues the item (bounded by HEAVY_REQUEUE_MAX). Re-throw BEFORE any
    // error accounting: this catch otherwise swallows everything into the
    // 'scan_error' ledger path and the requeue would never happen.
    if (err && (err.code === 'HEAVY_LANE_WAIT_TIMEOUT' || err.code === 'TICKET_WAIT_TIMEOUT')) throw err;
    // Phase C: an EMERGENCY-interrupted scan is NOT a scan failure — rethrow
    // so processQueueItem (the only writer for this path) ledgers
    // 'interrupted' + spills for a bounded re-scan. Ledgering scan_error here
    // would double-count and bury the interruption as a terminal error.
    if (err && err.code === 'SCAN_INTERRUPTED') throw err;
    recordError(err, stats);
    stats.scanned++;
    stats.totalTimeMs += Date.now() - startTime;
    // Per-worker resourceLimits breach: the worker died on ITS V8 cap
    // (ERR_WORKER_OUT_OF_MEMORY) instead of blowing the process RSS. Same
    // garde-fou as static_timeout: a package that OOMs the scanner must NOT
    // count clean — inconclusive, distinct ledger source, distinct log line
    // (the live-validation metric for the limits rollout). No retry: an OOM
    // re-OOMs deterministically.
    // Reactive heap watermark (C2 volet B): the worker self-terminated before
    // blowing the process RSS. Same disposition as a resourceLimits OOM —
    // inconclusive, NOT clean, no retry (a re-scan re-explodes the same way) —
    // but a distinct ledger source so the watchdog's catch rate is measurable
    // separately from the V8 hard-cap OOMs.
    const isHeapWatermark = err && /WORKER_HEAP_WATERMARK/.test(err.message || '');
    if (isHeapWatermark) {
      console.error(`[MONITOR] WORKER_HEAP_WATERMARK: ${name}@${version} — scan worker self-terminated over the heap watermark (kept INCONCLUSIVE, not clean)`);
      stats.workerHeapWatermark = (stats.workerHeapWatermark || 0) + 1;
      updateScanStats('sandbox_inconclusive');
      try {
        appendScanLedger({ name, version, ecosystem, outcome: 'error', source: 'worker_heap_watermark' });
      } catch { /* ledger is best-effort */ }
      return { sandboxResult: null, staticClean: false };
    }
    // Per-worker resourceLimits breach: the worker died on ITS V8 cap
    // (ERR_WORKER_OUT_OF_MEMORY) instead of blowing the process RSS. Same
    // garde-fou as static_timeout: a package that OOMs the scanner must NOT
    // count clean — inconclusive, distinct ledger source, distinct log line
    // (the live-validation metric for the limits rollout). No retry: an OOM
    // re-OOMs deterministically.
    const isWorkerOom = err && (err.code === 'ERR_WORKER_OUT_OF_MEMORY' ||
      /ERR_WORKER_OUT_OF_MEMORY|reached its memory limit/i.test(err.message || ''));
    if (isWorkerOom) {
      console.error(`[MONITOR] WORKER_OOM: ${name}@${version} — scan worker hit its resourceLimits cap (kept INCONCLUSIVE, not clean)`);
      stats.workerOom = (stats.workerOom || 0) + 1;
      updateScanStats('sandbox_inconclusive');
      try {
        appendScanLedger({ name, version, ecosystem, outcome: 'error', source: 'worker_oom' });
      } catch { /* ledger is best-effort */ }
      return { sandboxResult: null, staticClean: false };
    }
    console.error(`[MONITOR] ERROR scanning ${name}@${version}: ${err.message}`);
    // Ledger the terminal failure so the scan-ledger never over-states coverage (an errored
    // package is NOT clean). Also captures EMERGENCY worker-terminate losses, whose reject
    // propagates here (CLAUDE.md "no silent caps"). Best-effort; never throws.
    try {
      appendScanLedger({ name, version, ecosystem, outcome: 'error', source: 'scan_error' });
    } catch { /* ledger is best-effort */ }
    return { sandboxResult: null, staticClean: false };
  } finally {
    // Cleanup temp dir
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

/**
 * Detect whether a package bundles a SKILL.md (Anthropic Agent Skills spec).
 * Pure observability — drives the `stats.skillMdBundled` counter, no scoring effect.
 *
 * Two-pass check: (1) inspect emitted threats for SKILL.md filenames so we catch
 * cases the scanner already touched without re-walking the tree; (2) fall back to
 * a bounded findFiles walk (maxDepth 4, maxFiles 5) for packages where no scanner
 * has flagged anything.
 *
 * @param {string|null} extractedDir - Unpacked tarball root, or null if unknown.
 * @param {Array<{file?:string}>|null} threats - Threats array from the scan result.
 * @returns {{bundled: boolean, count: number}}
 */
function detectSkillMdBundled(extractedDir, threats) {
  const fromThreats = Array.isArray(threats) && threats.some(
    t => /(?:^|[\\/])SKILL\.md$/i.test((t && t.file) || '')
  );
  if (fromThreats) return { bundled: true, count: 1 };
  if (!extractedDir) return { bundled: false, count: 0 };
  try {
    const { findFiles } = require('../utils.js');
    const found = findFiles(extractedDir, { extensions: ['SKILL.md'], maxDepth: 4, maxFiles: 5 });
    return { bundled: found.length > 0, count: found.length };
  } catch {
    return { bundled: false, count: 0 };
  }
}

function timeoutPromise(ms) {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`Scan timeout after ${ms / 1000}s`)), ms);
  });
}

// isDailyReportDue is the canonical gate in state.js (imported above), called per scan in
// processQueueItem below. Previously a local `parisHour < 8` copy here diverged from the
// daemon's `!== 8` copy; unifying in state.js removes the divergence. Still re-exported below.

/**
 * Process a single item from the scan queue.
 * Encapsulates the full per-package flow: scan -> sandbox -> reputation -> webhook.
 */
async function processQueueItem(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable) {
  // AbortController: signals the scan to stop after timeout.
  // Prevents zombie scans from continuing expensive work (HTTP, sandbox) in the background.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
  try {
    await Promise.race([
      resolveTarballAndScan(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable, controller.signal),
      new Promise((_, reject) => {
        controller.signal.addEventListener('abort', () => {
          reject(new Error(`Scan timeout after ${SCAN_TIMEOUT_MS / 1000}s`));
        }, { once: true });
      })
    ]);
  } catch (err) {
    // C2 heavy-lane: the bounded wait expired while the heavy slots were
    // saturated (typical under a spill-drain burst). Not a failure — put the
    // item back at the queue tail (natural backoff) up to HEAVY_REQUEUE_MAX
    // passes; scanPackage runs the final pass without the wait bound. Note:
    // _heavyRetries does not survive a spill (spillItems strips non-re-enqueue
    // fields) — acceptable, the spill drain runs in calm windows anyway.
    if (err && err.code === 'SCAN_INTERRUPTED') {
      // Phase C (work conservation): a protective interruption (EMERGENCY
      // worker terminate) must never silently kill coverage. Exogenous
      // interruptions ONLY — worker_oom/watermark stay no-retry ("an OOM
      // re-OOMs deterministically"). Bounded: 2 reprises, then an explicit
      // dropped/interrupted_max (never 'clean', never an infinite respill —
      // a package engineered to spike RSS gets exactly 2 extra chances).
      const key = `${item.ecosystem}/${item.name}@${item.version}`;
      recentlyScanned.delete(key); // else the drain dedups the re-scan away (F-C1)
      const { retries, giveUp } = computeInterruptDisposition(item);
      stats.interrupted = (stats.interrupted || 0) + 1;
      if (giveUp) {
        appendScanLedger({ name: item.name, version: item.version, ecosystem: item.ecosystem, outcome: 'dropped', source: 'interrupted_max' });
        console.warn(`[MONITOR] INTERRUPTED_MAX: ${item.name}@${item.version || '?'} — 3rd interruption, dropped for good (ledgered)`);
        return;
      }
      appendScanLedger({ name: item.name, version: item.version, ecosystem: item.ecosystem, outcome: 'interrupted', source: 'emergency_terminate' });
      let spilled = false;
      try {
        const sp = require('./spill.js');
        if (sp.isSpillEnabled()) {
          spilled = sp.spillItems([{ ...item, interrupted: true, interruptRetries: retries }]) === 1; // retries === item.interruptRetries (computeInterruptDisposition)
        }
      } catch { /* spill best-effort — the ledger entry stays the honest record */ }
      console.warn(`[MONITOR] INTERRUPTED: ${item.name}@${item.version || '?'} — ${spilled ? `spilled for re-scan (pass ${retries}/2, protected)` : 'ledgered only (spill disabled)'}`);
      return;
    }
    if (err && (err.code === 'HEAVY_LANE_WAIT_TIMEOUT' || err.code === 'TICKET_WAIT_TIMEOUT')) {
      const decision = computeHeavyRequeue(item);
      if (decision.requeue) {
        stats.heavyLaneRequeues = (stats.heavyLaneRequeues || 0) + 1;
        console.log(`[MONITOR] HEAVY_LANE: requeued ${item.name}@${item.version || '?'} (wait-timeout pass ${decision.retries}/${HEAVY_REQUEUE_MAX})`);
        enqueueScan(scanQueue, item, stats);
        return;
      }
      // Safety net — should be unreachable (the last pass waits unbounded).
    }
    recordError(err, stats);
    console.error(`[MONITOR] Queue error for ${item.name}: ${err.message}`);
    // IOC fallback: if scan failed for a known malicious package, send P1 alert.
    // The pre-alert was fire-and-forget; this ensures at least one webhook lands.
    if (item.isIOCMatch) {
      console.log(`[MONITOR] IOC FALLBACK: scan failed for ${item.name}@${item.version}, sending IOC alert`);
      try {
        const url = getWebhookUrl();
        if (url) {
          const payload = {
            embeds: [{
              title: '\u26a0\ufe0f IOC ALERT - Scan Failed for Known Malicious Package',
              color: 0xe74c3c,
              fields: [
                { name: 'Package', value: `${item.name}@${item.version || '?'}`, inline: true },
                { name: 'Source', value: 'IOC Database Match', inline: true },
                { name: 'Error', value: (err.message || 'Unknown error').slice(0, 200), inline: false },
                { name: 'Action', value: 'Manual investigation required.', inline: false }
              ],
              footer: { text: `MUAD'DIB IOC Fallback | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}` },
              timestamp: new Date().toISOString()
            }]
          };
          await sendWebhook(url, payload, { rawPayload: true });
        }
      } catch (webhookErr) {
        console.error(`[MONITOR] IOC fallback webhook failed: ${webhookErr.message}`);
      }
    }
  } finally {
    clearTimeout(timeoutId);
  }
  maybePersistDailyStats(stats, dailyAlerts);

  // Check daily report between each package scan (not just between poll cycles).
  // Without this, a queue of 50 packages * 3min/each = 150min delay on the report.
  if (isDailyReportDue(stats)) {
    await sendDailyReport(stats, dailyAlerts, recentlyScanned, downloadsCache);
  }
}

/**
 * Spawn a single worker that pulls from scanQueue until:
 *   - queue is empty, OR
 *   - activeWorkers exceeds targetConcurrency (soft drain on scale-down)
 *
 * Workers are fire-and-forget: they run as background promises tracked
 * in _workerPromises. Node.js is single-threaded so scanQueue.shift()
 * is atomic — no race conditions between workers.
 */
// Items currently being processed (dequeued, possibly still in download/
// extract — a superset of _liveWorkers' scan phase). Read by the daemon's
// bounded-drain shutdown (C7) to spill what a SIGKILL would otherwise lose.
const _inFlightItems = new Set();
function getInFlightItems() {
  return Array.from(_inFlightItems);
}

async function _spawnWorker(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable) {
  _activeWorkers++;
  try {
    while (scanQueue.length > 0 && _activeWorkers <= _targetConcurrency) {
      // Phase B (F-B4): during a governor freeze, do NOT dequeue — a dequeued
      // item gets downloaded+extracted before the ticket gate, so pumping
      // while frozen burns network/disk/tmpdirs on scans that cannot be
      // admitted. One pump lane stays open so the governor's liveness
      // admission (1 scan when nothing is in flight) can still flow.
      if (isGovernorFrozen() && (getGovernorState().outstandingCount > 0 || _activeWorkers > 1)) break;
      // AUDIT A2: FIFO by default; priority dequeue when MUADDIB_PRIORITY_DEQUEUE=1.
      const item = dequeueScan(scanQueue);
      if (!item) break;
      _inFlightItems.add(item);
      try {
        await processQueueItem(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable);
      } finally {
        _inFlightItems.delete(item);
      }
    }
  } finally {
    _activeWorkers--;
  }
}

/**
 * Pure spawn-count decision: how many workers to start given the target concurrency, the number
 * already active, and the queue depth. Never negative (active can exceed target during scale-down)
 * and never more than the backlog. Extracted so the adaptive worker-pool math is unit-testable
 * without spawning real (network-bound) workers.
 */
function computeWorkersToSpawn(targetConcurrency, activeWorkers, queueLength) {
  return Math.max(0, Math.min(targetConcurrency - activeWorkers, queueLength));
}

/**
 * Pure requeue decision for a heavy-lane wait-timeout (same extraction
 * rationale as computeWorkersToSpawn). Mutates item._heavyRetries; once the
 * counter passes HEAVY_REQUEUE_MAX the item is NOT requeued again — its next
 * pass through scanPackage waits unbounded instead.
 */
/**
 * Pure disposition for an interrupted scan (phase C). Mutates
 * item.interruptRetries like computeHeavyRequeue does. Bounded at 2 reprises:
 * an attacker whose package triggers a protective interruption on every scan
 * gets exactly two extra chances, then an explicit dropped/interrupted_max —
 * never an infinite respill loop, never 'clean'.
 */
function computeInterruptDisposition(item) {
  const retries = (item.interruptRetries || 0) + 1;
  item.interruptRetries = retries;
  return { retries, giveUp: retries > 2 };
}

function computeHeavyRequeue(item) {
  const retries = (item._heavyRetries || 0) + 1;
  item._heavyRetries = retries;
  return { requeue: retries <= HEAVY_REQUEUE_MAX, retries };
}

// ── RSS-aware worker admission (P1 OOM durable fix) ──
// The pressure breaker is reactive: it stops spawning at HIGH, but the workers already in
// flight overshoot RSS by ~2GB (each isolate + gVisor sandbox ~0.55GB, draining up to
// SCAN_TIMEOUT) before EMERGENCY truncates the queue + kills them. This caps the OVERSHOOT at
// the source — refuse a new spawn when current RSS + one worker's footprint would breach a
// soft ceiling (default 80% of the EMERGENCY RSS limit), leaving headroom for in-flight drain.
const RSS_SOFT_LIMIT_MB = (() => {
  const parsed = parseInt(process.env.MUADDIB_RSS_SOFT_LIMIT_MB, 10);
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  const hard = parseInt(process.env.MUADDIB_RSS_LIMIT_MB, 10);
  const base = (Number.isFinite(hard) && hard > 0) ? hard : 8500;
  return Math.round(base * 0.80);
})();
const EST_WORKER_RSS_MB = (() => {
  const parsed = parseInt(process.env.MUADDIB_EST_WORKER_RSS_MB, 10);
  return (Number.isFinite(parsed) && parsed > 0) ? parsed : 600;
})();

/**
 * Pure: how many NEW scan workers the current RSS headroom allows under the soft ceiling.
 * `currentRssBytes` already includes the active workers, so this answers "how many MORE fit".
 * Returns 0 (never negative) once RSS reaches the soft limit — existing workers are NOT killed
 * here, they drain and free memory; ensureWorkers keeps the queue alive with 1 worker if
 * nothing is running. softLimitMb / estWorkerMb are injectable for tests.
 */
function rssAdmissionCap(currentRssBytes, softLimitMb = RSS_SOFT_LIMIT_MB, estWorkerMb = EST_WORKER_RSS_MB) {
  const headroomMb = softLimitMb - (currentRssBytes / 1024 / 1024);
  if (headroomMb <= 0) return 0;
  return Math.max(0, Math.floor(headroomMb / estWorkerMb));
}

/**
 * Ensure the target number of workers are running. Non-blocking: spawns
 * missing workers as background promises. Called from the daemon main loop
 * every PROCESS_LOOP_INTERVAL (2s), and after concurrency adjustments.
 */
function ensureWorkers(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable) {
  if (scanQueue.length === 0) return;
  let toSpawn = computeWorkersToSpawn(_targetConcurrency, _activeWorkers, scanQueue.length);
  if (toSpawn <= 0) return;

  // RSS-aware admission (P1 OOM durable fix): cap NEW spawns by memory headroom so the
  // in-flight worker set can't overshoot the soft RSS ceiling. Never fully deadlock: if
  // headroom is gone AND nothing is running, allow exactly one so the queue still makes
  // forward progress (its completion frees memory). Bounds peak RSS BEFORE the reactive breaker.
  const rssNow = process.memoryUsage().rss;
  const rssCap = rssAdmissionCap(rssNow);
  if (toSpawn > rssCap) {
    if (rssCap === 0 && _activeWorkers === 0) {
      toSpawn = 1;
    } else {
      console.log(`[MONITOR] RSS admission: capping spawn ${toSpawn}->${rssCap} (rss=${Math.round(rssNow / 1024 / 1024)}MB soft=${RSS_SOFT_LIMIT_MB}MB active=${_activeWorkers})`);
      toSpawn = rssCap;
    }
  }
  if (toSpawn <= 0) return;

  console.log(`[MONITOR] Spawning ${toSpawn} worker(s) (active: ${_activeWorkers}, target: ${_targetConcurrency}, queue: ${scanQueue.length})`);
  for (let i = 0; i < toSpawn; i++) {
    const p = _spawnWorker(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable)
      .catch(err => console.error('[MONITOR] Worker error:', err.message))
      .finally(() => _workerPromises.delete(p));
    _workerPromises.add(p);
  }
}

/**
 * Wait for all active workers to finish. Used for:
 *   - Graceful shutdown (drain in-flight scans)
 *   - Tests (backward-compatible await)
 */
async function drainWorkers() {
  if (_workerPromises.size === 0) return;
  await Promise.all(_workerPromises);
}

/**
 * Backward-compatible processQueue: ensure workers + await completion.
 * Used by tests and the initial sequential scan at startup.
 * The daemon main loop uses ensureWorkers() directly (non-blocking).
 */
async function processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable) {
  if (scanQueue.length === 0) return;
  ensureWorkers(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable);
  await drainWorkers();
}

/**
 * Wrapper to resolve PyPI tarball URLs before scanning.
 * For npm packages, tarballUrl is already set from the registry response.
 * For PyPI packages, we need to fetch the JSON API to get the tarball URL.
 */
async function resolveTarballAndScan(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable, signal) {
  if (signal && signal.aborted) return;

  if (item.ecosystem === 'npm') {
    // Pre-resolve at ingestion (ingestion.js:preResolveNpmBatch) attaches
    // _npmInfo when it succeeds. Lazy path runs only when pre-resolve was
    // skipped or failed — in which case _npmInfo is absent and tarballUrl is
    // null. Either way, ATO / burst-extras / fast-track logic below runs on
    // whichever npmInfo we have, preserving full behavior.
    let npmInfo = item._npmInfo || null;
    try {
      if (!item.tarballUrl) {
        npmInfo = await getNpmLatestTarball(item.name);
        if (!npmInfo.tarball) {
          console.log(`[MONITOR] SKIP: ${item.name} — no tarball URL found on npm`);
          return;
        }
        item.tarballUrl = npmInfo.tarball;
        if (npmInfo.version) item.version = npmInfo.version;
        if (npmInfo.unpackedSize) item.unpackedSize = npmInfo.unpackedSize;
        if (npmInfo.scripts) item.registryScripts = npmInfo.scripts;
      }

      if (npmInfo) {
        // ATO signature: most-recently-published version differs from current
        // dist-tags.latest. Pattern observed in TeamPCP / @antv 2026-05-19:
        // attacker publishes 1-2 versions per package but does NOT bump the latest
        // tag. semver resolution on `npm install <pkg>@^x.y` still pulls the
        // malicious version. The mismatch is a strong ATO signal — legitimate
        // maintainers almost always move latest when publishing.
        if (npmInfo.latestTagVersion && item.version && item.version !== npmInfo.latestTagVersion) {
          item.atoSignal = true;
          console.log(`[MONITOR] ATO SIGNAL: ${item.name}@${item.version} published but dist-tags.latest=${npmInfo.latestTagVersion}`);
        }

        // Burst-publish coverage: enqueue extra versions published in the same
        // recent window. Single change event in the CouchDB feed can correspond
        // to multiple version publishes when the attacker fires several in a
        // burst (TeamPCP averaged ~2 versions per package). Without this we'd
        // only scan whichever version happened to be the most recent at resolution
        // time, racing the publish stream.
        const recents = Array.isArray(npmInfo.recentVersions) ? npmInfo.recentVersions : [];
        // Phase 2b: burst = TRUE count of versions of this name in the recent window
        // (uncapped recentWindowCount), NOT the capped extras list — so a 96-version Miasma
        // burst is distinguishable from a legit multi-version day. At/above the threshold,
        // flag the item (protects it + its extras from queue-cap eviction) and fire ONE
        // burst pre-alert per name (deduped, bounded).
        const burstCount = Number.isFinite(npmInfo.recentWindowCount) ? npmInfo.recentWindowCount : (recents.length + 1);
        const isBurst = burstCount >= BURST_PREALERT_MIN_VERSIONS;
        if (isBurst) {
          item.isBurst = true;
          // Anti-flood (notification only — the burst versions are STILL queued and scanned
          // below regardless; muting the heads-up never weakens detection):
          //  1) Established packages (mature + many versions) bursting are monorepo / CI
          //     nightly churn, not the Shai-Hulud account-takeover signal (that is a NEW /
          //     low-reputation package suddenly bursting). A real takeover of an established
          //     package is still caught by the per-version scan + the atoSignal above.
          //  2) 24h cooldown per package so a package re-bursting all day pings at most once.
          const _np = item._npmInfo || npmInfo || {};
          const _established = Number.isFinite(_np.age_days) && _np.age_days > 730 &&
            Number.isFinite(_np.version_count) && _np.version_count > 100;
          const _now = Date.now();
          const _last = _burstAlerted.get(item.name);
          const _onCooldown = _last && (_now - _last) < BURST_ALERT_COOLDOWN_MS;
          if (!_established && !_onCooldown) {
            if (_burstAlerted.size >= BURST_ALERTED_MAX) _burstAlerted.clear();
            _burstAlerted.set(item.name, _now);
            stats.burstPreAlerts = (stats.burstPreAlerts || 0) + 1;
            console.log(`[MONITOR] BURST PRE-ALERT: ${item.name} — ${burstCount} versions in the recent window`);
            sendBurstPreAlert(item.name, burstCount, item.ecosystem).catch(err => {
              console.error(`[MONITOR] burst pre-alert webhook failed for ${item.name}: ${err.message}`);
            });
          }
        }
        for (const recent of recents) {
          if (!recent || !recent.tarball || !recent.version) continue;
          const dedupeKey = `${item.name}@${recent.version}`;
          if (recentlyScanned.has(dedupeKey)) continue;
          enqueueScan(scanQueue, {
            name: item.name,
            version: recent.version,
            ecosystem: 'npm',
            tarballUrl: recent.tarball,
            unpackedSize: recent.unpackedSize || 0,
            registryScripts: recent.scripts || null,
            atoSignal: item.atoSignal === true,
            isBurst,
            isATOBurstExtra: true,
          }, stats);
        }

        // Fast-track decision: large packages (>15MB) with no lifecycle scripts and no IOC match.
        // Fast-track packages get: quick static scan (package.json + shell only), no AST,
        // no sandbox, no LLM, no archiving. Exits in ~2-3s instead of 30-300s.
        // ATO-signalled packages bypass fast-track regardless of size — we want
        // the full pipeline (AST + sandbox) on anything that smells like an ATO.
        const FAST_TRACK_SIZE_BYTES = 15 * 1024 * 1024;
        if (!item.isIOCMatch && !item.atoSignal && (item.unpackedSize || 0) > FAST_TRACK_SIZE_BYTES) {
          const scripts = item.registryScripts || {};
          if (!scripts.preinstall && !scripts.postinstall && !scripts.install) {
            item.fastTrack = true;
          }
        }

        // Free the packument-derived metadata once the per-item decisions are
        // made — keeps queue items lean (a 28k-item queue × full packument JSON
        // would be tens of MB of useless heap).
        if (item._npmInfo) delete item._npmInfo;
      }
    } catch (err) {
      console.error(`[MONITOR] ERROR resolving npm tarball for ${item.name}: ${err.message}`);
      recordError(err, stats);
      return;
    }
  }
  if (item.ecosystem === 'pypi' && !item.tarballUrl) {
    try {
      const pypiInfo = await getPyPITarballUrl(item.name, item.version || '');
      if (!pypiInfo.url) {
        // No sdist / .tar.gz / wheel — likely a legacy egg or msi-only
        // release. Clean skip: do NOT touch stats.scanned or stats.errors
        // (those would distort the Commit 1 coverage ratios). The dedicated
        // pypiSkippedNoArchive counter surfaces volume in the daily report.
        stats.pypiSkippedNoArchive = (stats.pypiSkippedNoArchive || 0) + 1;
        console.log(`[MONITOR] SKIP: ${item.name} — no tarball URL found on PyPI`);
        return;
      }
      item.tarballUrl = pypiInfo.url;
      if (pypiInfo.version) item.version = pypiInfo.version;
    } catch (err) {
      console.error(`[MONITOR] ERROR resolving PyPI tarball for ${item.name}: ${err.message}`);
      recordError(err, stats);
      return;
    }
  }

  // Deferred IOC PRE-ALERT for versioned IOCs (version now known after registry resolution).
  // Wildcard IOCs already triggered PRE-ALERT in changes stream / RSS polling.
  if (item.version && !item.isIOCMatch) {
    try {
      const iocs = loadCachedIOCs();
      const versionMatch = matchVersionedIOC(iocs, item.name, item.version);
      if (versionMatch) {
        item.isIOCMatch = true;
        console.log(`[MONITOR] IOC PRE-ALERT: ${item.name}@${item.version} — versioned IOC match`);
        stats.iocPreAlerts = (stats.iocPreAlerts || 0) + 1;
        sendIOCPreAlert(item.name, item.version).catch(err => {
          console.error(`[MONITOR] IOC pre-alert webhook failed for ${item.name}: ${err.message}`);
        });
      }
    } catch { /* IOC load failure is non-fatal */ }
  }

  // Deduplication: skip if already scanned in the last 24h
  const dedupeKey = `${item.ecosystem}/${item.name}@${item.version}`;
  if (recentlyScanned.has(dedupeKey)) {
    console.log(`[MONITOR] SKIP (already scanned): ${item.name}@${item.version}`);
    return;
  }
  recentlyScanned.add(dedupeKey);
  // FIFO eviction (P0c — bounded resource): a Set preserves insertion order, so the
  // first value is the oldest. Evicting at most one per insert pins the size at the
  // cap and prevents unbounded heap growth within an uptime (the hourly clear in
  // daemon.js pruneMemoryCaches remains a coarse backstop).
  if (recentlyScanned.size > RECENTLY_SCANNED_MAX) {
    recentlyScanned.delete(recentlyScanned.values().next().value);
  }
  // Coverage numerator: one count per unique (ecosystem, name, version) that
  // reaches a scan attempt. Excludes ATO burst extras that lose the dedup
  // race, retries, size-cap rejections — those inflate stats.scanned but
  // would distort the "% of publishes we covered" reading.
  stats.uniqueScanAttempts = (stats.uniqueScanAttempts || 0) + 1;

  // Abort check: if timeout fired during URL resolution or dedup, bail out
  if (signal && signal.aborted) return;

  // Temporal analysis: check for sudden lifecycle script changes (npm only)
  // Webhooks are deferred until after sandbox confirms the threat
  let temporalResult = null;
  let astResult = null;
  let publishResult = null;
  let maintainerResult = null;

  const TEMPORAL_LOAD_SHED_THRESHOLD = 2000;
  const skipTemporal = item.fastTrack || scanQueue.length > TEMPORAL_LOAD_SHED_THRESHOLD;
  if (item.ecosystem === 'npm' && !skipTemporal) {
    // Run all 4 temporal checks in parallel — each is independent.
    // AST diff alone consumes 5 HTTP semaphore slots per package (2 tarball downloads + 3 metadata).
    // With 16 workers that's 80 slot requests for 10 slots → workers blocked 80% of the time.
    // Load-shed when queue > 2000: temporal analysis is a luxury during catch-up.
    const [tempRes, astRes, pubRes, maintRes] = await Promise.allSettled([
      runTemporalCheck(item.name, dailyAlerts),
      runTemporalAstCheck(item.name, dailyAlerts),
      runTemporalPublishCheck(item.name, dailyAlerts),
      runTemporalMaintainerCheck(item.name, dailyAlerts)
    ]);
    temporalResult = tempRes.status === 'fulfilled' ? tempRes.value : null;
    astResult = astRes.status === 'fulfilled' ? astRes.value : null;
    publishResult = pubRes.status === 'fulfilled' ? pubRes.value : null;
    maintainerResult = maintRes.status === 'fulfilled' ? maintRes.value : null;
  } else if (skipTemporal && item.ecosystem === 'npm' && !item.fastTrack) {
    stats.temporalLoadShed = (stats.temporalLoadShed || 0) + 1; // P2.2: count the coverage degradation
    console.log(`[MONITOR] TEMPORAL LOAD-SHED: ${item.name}@${item.version} (queue=${scanQueue.length} > ${TEMPORAL_LOAD_SHED_THRESHOLD})`);
  }

  // Abort check: if timeout fired during temporal checks, skip the expensive scan
  if (signal && signal.aborted) return;

  // Stage 2 — Pass A triage. Decides whether the static scan runs all 20
  // scanners or a quick_scan subset. Defaults to full when:
  //   - env MUADDIB_TRIAGE_MODE !== 'enforce' (off | shadow | unset)
  //   - the item is fastTrack-elected (already a more aggressive subset)
  //   - any suspect signal flips triageRisk to 'full'
  // Shadow mode computes + logs the decision but still runs full — safe way
  // to observe classification share before flipping enforce.
  const triageMode = (process.env.MUADDIB_TRIAGE_MODE || 'off').toLowerCase();
  let effectiveScanMode = 'full';
  if (triageMode !== 'off' && !item.fastTrack) {
    let triageMeta = null;
    if (item.ecosystem === 'npm') {
      // Stage 2.1 — Stage 1 pre-resolve already fetched the packument and
      // (Stage 2.1) computed age_days + version_count, plus parallel-fetched
      // weekly_downloads. Read those directly to skip the second
      // registry round-trip via getPackageMetadata. Fallback to the lazy
      // metadata fetch only when _npmInfo is absent (lazy-resolve path).
      if (item._npmInfo) {
        triageMeta = {
          age_days: item._npmInfo.age_days,
          version_count: item._npmInfo.version_count,
          weekly_downloads: item._npmInfo.weekly_downloads,
        };
      } else {
        try {
          const { getPackageMetadata } = require('../scanner/npm-registry.js');
          triageMeta = await getPackageMetadata(item.name);
        } catch { /* metadata unavailable → triageRisk will see null and pick 'full' */ }
      }
    } else if (item.ecosystem === 'pypi') {
      triageMeta = item._pypiInfo || null;
    }
    const triage = triageRisk(item, triageMeta);
    item.scanMode = triage.mode;
    stats.triageQuick = (stats.triageQuick || 0) + (triage.mode === 'quick' ? 1 : 0);
    stats.triageFull = (stats.triageFull || 0) + (triage.mode === 'full' ? 1 : 0);
    console.log(`[TRIAGE] ${item.name}@${item.version || '?'}: mode=${triage.mode} reasons=[${triage.reasons.join(',') || 'none'}]`);
    if (triageMode === 'enforce') effectiveScanMode = triage.mode;
  }

  const scanResult = await scanPackage(item.name, item.version, item.ecosystem, item.tarballUrl, {
    unpackedSize: item.unpackedSize || 0,
    registryScripts: item.registryScripts || null,
    _cacheTrigger: item._cacheTrigger || null,
    fastTrack: item.fastTrack || false,
    scanMode: effectiveScanMode,
    // C2 heavy-lane: pass count set by computeHeavyRequeue — at
    // HEAVY_REQUEUE_MAX the final pass waits for its slot unbounded.
    _heavyRetries: item._heavyRetries || 0
  }, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable, signal);
  const sandboxResult = scanResult && scanResult.sandboxResult;
  const staticClean = scanResult && scanResult.staticClean;

  // FP rate tracking + ML label refinement
  if (scanResult) {
    if (!staticClean) {
      if (sandboxResult && sandboxResult.inconclusive) {
        // Sandbox timeout: cannot conclude — do NOT relabel (neither fp nor confirmed)
        updateScanStats('sandbox_inconclusive');
        console.log(`[MONITOR] SANDBOX INCONCLUSIVE (timeout): ${item.name} — keeping original label`);
      } else if (sandboxResult && sandboxResult.score === 0) {
        const hasHC = scanResult.hasHCThreats || false;
        const isDormant = scanResult.isDormant || false;
        const staticScore = scanResult.staticScore || 0;

        if (hasHC) {
          updateScanStats('sandbox_inconclusive');
          console.log(`[MONITOR] RELABEL BLOCKED (HC threats): ${item.name} — sandbox clean but has high-confidence malice types, keeping suspect label`);
        } else if (isDormant || staticScore >= 70) {
          updateScanStats('sandbox_inconclusive');
          console.log(`[MONITOR] RELABEL BLOCKED (high static): ${item.name} — static score=${staticScore}, keeping suspect label`);
        } else {
          updateScanStats('sandbox_unconfirmed');
          relabelRecords(item.name, 'unconfirmed');
        }
      } else if (sandboxResult && sandboxResult.score > 0) {
        const hasSandboxFindings = sandboxResult.findings && sandboxResult.findings.length > 0;
        if (hasSandboxFindings) {
          updateScanStats('confirmed');
          relabelRecords(item.name, 'confirmed', sandboxResult.findings.length);
        } else {
          // Sandbox score > 0 but no detailed findings = install error
          updateScanStats('sandbox_inconclusive');
          console.log(`[MONITOR] SANDBOX INCONCLUSIVE: ${item.name} score=${sandboxResult.score} but 0 findings — probable install error`);
        }
      } else {
        updateScanStats('suspect');
      }
    }
  }

  // Temporal anomaly handling: persist findings and send webhooks for CRITICAL/HIGH
  const hasSuspiciousTemporal = (temporalResult && temporalResult.suspicious)
    || (astResult && astResult.suspicious)
    || (publishResult && publishResult.suspicious)
    || (maintainerResult && maintainerResult.suspicious);

  if (hasSuspiciousTemporal) {
    // Collect all temporal findings for persistence
    const temporalFindings = [];
    if (temporalResult && temporalResult.suspicious) temporalFindings.push({ type: 'lifecycle', data: temporalResult });
    if (astResult && astResult.suspicious) temporalFindings.push({ type: 'ast_diff', data: astResult });
    if (publishResult && publishResult.suspicious) temporalFindings.push({ type: 'publish', data: publishResult });
    if (maintainerResult && maintainerResult.suspicious) temporalFindings.push({ type: 'maintainer', data: maintainerResult });

    // Always persist temporal detections
    appendTemporalDetection(item.name, item.version, temporalFindings);

    if (sandboxResult && sandboxResult.score === 0) {
      // DORMANT SUSPECT log is handled by trySendWebhook() (authoritative, uses adjusted score).
      // Only log FALSE POSITIVE here for packages that didn't reach the webhook threshold.
      const riskScore = (scanResult && scanResult.staticScore) || 0;
      if (riskScore < 20) {
        console.log(`[MONITOR] FALSE POSITIVE (sandbox clean, no alert): ${item.name}@${item.version}`);
      }
    } else if (staticClean && !sandboxResult) {
      // Temporal CRITICAL/HIGH with static clean → reclassify as SUSPECT for stats
      const temporalMaxSev = getTemporalMaxSeverity(temporalResult, astResult, publishResult, maintainerResult);
      if (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH') {
        console.log(`[MONITOR] Temporal ${temporalMaxSev} preserved despite static clean scan: ${item.name}@${item.version}`);
        console.log(`[MONITOR] SUSPECT (temporal anomaly, logged only): ${item.name}@${item.version}`);
        stats.suspect++;
        stats.clean--;
        updateScanStats('suspect');
        // Send webhook for CRITICAL/HIGH temporal findings that aren't sandbox-clean
        if (temporalResult && temporalResult.suspicious) await tryTemporalAlert(temporalResult);
        if (astResult && astResult.suspicious) await tryTemporalAstAlert(astResult);
      } else {
        console.log(`[MONITOR] FALSE POSITIVE (static clean, no alert): ${item.name}@${item.version}`);
      }
    } else {
      // Not static-clean and no sandbox / sandbox positive — send webhooks
      if (temporalResult && temporalResult.suspicious) await tryTemporalAlert(temporalResult);
      if (astResult && astResult.suspicious) await tryTemporalAstAlert(astResult);
    }
  }
}

module.exports = {
  // Constants
  SCAN_CONCURRENCY,
  SCAN_TIMEOUT_MS,
  STATIC_SCAN_TIMEOUT_MS,
  LARGE_PACKAGE_SIZE,
  FIRST_PUBLISH_SANDBOX_MAX_QUEUE,
  FIRST_PUBLISH_SANDBOX_ENABLED,
  SANDBOX_SCORE_THRESHOLD,
  computeSandboxScoreThreshold,
  SANDBOX_REVALIDATE_MS,
  KNOWN_BUNDLED_FILES,
  KNOWN_BUNDLED_PATHS,
  ML_EXCLUDED_DIRS,
  TEST_PATTERNS,
  TEST_FILE_PATTERN,
  SCAN_WORKER_PATH,

  // Adaptive concurrency
  getTargetConcurrency,
  setTargetConcurrency,
  getActiveWorkers,
  terminateAllWorkers,
  computeWorkersToSpawn,
  rssAdmissionCap,
  ensureWorkers,
  drainWorkers,

  // Functions
  isBundledToolingOnly,
  recordTrainingSample,
  countPackageFiles,
  measureJsWeight,
  computeHeavyRequeue,
  classifyNativeShard,
  shouldSkipSandbox,
  runScanInWorker,
  registerWorkerMessageHandler,
  getInFlightItems,
  computeInterruptDisposition,
  scanPackage,
  timeoutPromise,
  detectSkillMdBundled,
  isDailyReportDue,
  processQueueItem,
  processQueue,
  resolveTarballAndScan
};
