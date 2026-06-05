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
const { MAX_TARBALL_SIZE } = require('../shared/constants.js');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { scanPackageJson } = require('../scanner/package.js');
const { scanShellScripts } = require('../scanner/shell.js');
const { buildTrainingRecord } = require('../ml/feature-extractor.js');
const { appendRecord: appendTrainingRecord, relabelRecords } = require('../ml/jsonl-writer.js');

// From ./state.js
const {
  cacheTarball,
  updateScanStats,
  appendDetection,
  maybePersistDailyStats,
  appendTemporalDetection,
  tarballCacheKey,
  tarballCachePath,
  appendAlert,
  getParisHour,
  hasReportBeenSentToday,
  MAX_DAILY_ALERTS
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
  matchVersionedIOC,
  buildCanaryExfiltrationWebhookEmbed,
  getWebhookUrl,
  computeReputationFactor,
  triageRisk,
  sendDailyReport,
  alertedPackageRules,
  DAILY_REPORT_HOUR
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
const { enqueueScan } = require('./scan-queue.js');

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
// Live static-scan Worker threads — tracked so the daemon's EMERGENCY memory
// handler can terminate orphaned workers (each retains its isolate heap + parsed
// ASTs). Bounded by concurrency, so it stays tiny.
const _liveWorkers = new Set();

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
  for (const w of Array.from(_liveWorkers)) {
    try { w.terminate(); n++; } catch { /* already gone */ }
    _liveWorkers.delete(w);
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
    const worker = new Worker(SCAN_WORKER_PATH, {
      workerData: { extractedDir, scanContext: scanContext || {} }
    });
    _liveWorkers.add(worker);

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

    worker.on('message', (msg) => done(() => {
      if (msg.type === 'result') resolve(msg.data);
      else if (msg.type === 'error') reject(new Error(msg.message));
    }));

    worker.on('error', (err) => done(() => reject(err)));

    worker.on('exit', (code) => done(() => {
      if (code !== 0) reject(new Error(`Worker exited with code ${code}`));
    }));
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
        scanMode: (meta && meta.scanMode) || 'full'
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
        return { sandboxResult: null, staticClean: false };
      }
      throw staticErr;
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

    // npm registry metadata was fetched ONCE before the worker spawn (hoisted above
    // to feed scanContext.npmRegistryMeta) and is reused here for: isFirstPublishHigh-
    // Risk, ML classifier features, JSONL training records, and reputation scoring.
    // Clean packages MUST carry metadata to prevent training-data leakage (model
    // learning "metadata=0 → clean" instead of behavioral signals).

    // First-publish sandbox priority: sandbox even with 0 static findings
    // if the package is from a new/unknown maintainer without a linked repository.
    const firstPublishSandbox = isFirstPublish &&
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

        if (shouldSandbox) {
          try {
            const canary = isCanaryEnabled();
            const maxRuns = tier === '1a' ? undefined : 1;

            if (tier === '1a') {
              // T1a: mandatory sandbox — block-wait (high-confidence threats MUST get sandbox)
              console.log(`[MONITOR] SANDBOX: launching for ${name}@${version}${canary ? ' (canary: on)' : ''}...`);
              sandboxResult = await runSandbox(name, { canary, maxRuns, signal });
            } else if (tryAcquireSandboxSlot()) {
              // T1b/T2: non-blocking — slot acquired atomically, run with skipSemaphore
              const reason = tier === 2 ? ' (T2, queue low)' : ' (T1b, conditional)';
              console.log(`[MONITOR] SANDBOX${reason}: launching for ${name}@${version}${canary ? ' (canary: on)' : ''}...`);
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

        // Record daily alert with post-reputation score for top suspects ranking
        if (dailyAlerts.length < MAX_DAILY_ALERTS) {
          dailyAlerts.push({ name, version, ecosystem, findingsCount: result.summary.total, score: adjustedResult.summary.riskScore || 0, tier });
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
                if (llmMode === 'active' && llmResult.verdict === 'benign' && llmResult.confidence > 0.85
                    && !hasHC && !hasSandboxEvidence) {
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
    recordError(err, stats);
    stats.scanned++;
    stats.totalTimeMs += Date.now() - startTime;
    console.error(`[MONITOR] ERROR scanning ${name}@${version}: ${err.message}`);
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

/**
 * Helper: check if a daily report is due (Paris timezone).
 * Extracted here to avoid circular dependency with monitor.js.
 */
function isDailyReportDue(stats) {
  const parisHour = getParisHour();
  if (parisHour < DAILY_REPORT_HOUR) return false;
  return !hasReportBeenSentToday(stats);
}

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
async function _spawnWorker(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable) {
  _activeWorkers++;
  try {
    while (scanQueue.length > 0 && _activeWorkers <= _targetConcurrency) {
      const item = scanQueue.shift();
      if (!item) break;
      await processQueueItem(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable);
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
 * Ensure the target number of workers are running. Non-blocking: spawns
 * missing workers as background promises. Called from the daemon main loop
 * every PROCESS_LOOP_INTERVAL (2s), and after concurrency adjustments.
 */
function ensureWorkers(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable) {
  if (scanQueue.length === 0) return;
  const toSpawn = computeWorkersToSpawn(_targetConcurrency, _activeWorkers, scanQueue.length);
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
    scanMode: effectiveScanMode
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
  ensureWorkers,
  drainWorkers,

  // Functions
  isBundledToolingOnly,
  recordTrainingSample,
  countPackageFiles,
  runScanInWorker,
  scanPackage,
  timeoutPromise,
  detectSkillMdBundled,
  isDailyReportDue,
  processQueueItem,
  processQueue,
  resolveTarballAndScan
};
