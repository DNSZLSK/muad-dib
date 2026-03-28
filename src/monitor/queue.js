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
const { run } = require('../index.js');
const { runSandbox, isDockerAvailable } = require('../sandbox/index.js');
const { sendWebhook } = require('../webhook.js');
const { downloadToFile, extractTarGz, sanitizePackageName } = require('../shared/download.js');
const { MAX_TARBALL_SIZE } = require('../shared/constants.js');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { scanPackageJson } = require('../scanner/package.js');
const { scanShellScripts } = require('../scanner/shell.js');
const { buildTrainingRecord } = require('../ml/feature-extractor.js');
const { appendRecord: appendTrainingRecord, relabelRecords, getStats: getTrainingStats } = require('../ml/jsonl-writer.js');

// From ./state.js
const {
  cacheTarball,
  updateScanStats,
  appendDetection,
  saveScanMemory,
  maybePersistDailyStats,
  loadNpmSeq,
  saveNpmSeq,
  getParisDateString,
  appendTemporalDetection,
  atomicWriteFileSync,
  tarballCacheKey,
  tarballCachePath,
  appendAlert,
  getParisHour,
  hasReportBeenSentToday
} = require('./state.js');

// From ./classify.js
const {
  isSuspectClassification,
  hasHighConfidenceThreat,
  hasIOCMatch,
  hasTyposquat,
  hasLifecycleWithIntent,
  isSandboxEnabled,
  isCanaryEnabled,
  recordError,
  classifyError,
  formatFindings,
  evaluateCacheTrigger,
  POPULAR_THRESHOLD,
  downloadsCache: classifyDownloadsCache,
  DOWNLOADS_CACHE_TTL,
  HIGH_CONFIDENCE_MALICE_TYPES,
  IOC_MATCH_TYPES,
  TIER1_TYPES,
  hasHighOrCritical
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
  computeRiskLevel,
  sendDailyReport,
  alertedPackageRules,
  DAILY_REPORT_HOUR
} = require('./webhook.js');

// From ./temporal.js
const {
  isTemporalEnabled,
  runTemporalCheck,
  isTemporalAstEnabled,
  runTemporalAstCheck,
  isTemporalPublishEnabled,
  runTemporalPublishCheck,
  isTemporalMaintainerEnabled,
  runTemporalMaintainerCheck,
  getTemporalMaxSeverity,
  isPublishAnomalyOnly,
  tryTemporalAlert,
  tryTemporalAstAlert,
  isSafeLifecycleScript
} = require('./temporal.js');

// From ./ingestion.js (will be created — currently in monitor.js)
const { getNpmLatestTarball, getPyPITarballUrl, getWeeklyDownloads } = require('./ingestion.js');

// --- Constants ---

const SCAN_CONCURRENCY = Math.max(1, parseInt(process.env.MUADDIB_SCAN_CONCURRENCY, 10) || 5);
const SCAN_TIMEOUT_MS = 180_000; // 3 minutes per package
const STATIC_SCAN_TIMEOUT_MS = 45_000; // 45s for static analysis only
const LARGE_PACKAGE_SIZE = 10 * 1024 * 1024; // 10MB

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
 * @returns {Promise<object>} Scan result (same shape as run(_, {_capture:true}))
 */
function runScanInWorker(extractedDir, timeoutMs) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(SCAN_WORKER_PATH, {
      workerData: { extractedDir }
    });

    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        worker.terminate().then(() => {
          reject(new Error(`Static scan timeout after ${timeoutMs / 1000}s (worker terminated)`));
        }).catch(() => {
          reject(new Error(`Static scan timeout after ${timeoutMs / 1000}s (worker terminate failed)`));
        });
      }
    }, timeoutMs);

    worker.on('message', (msg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (msg.type === 'result') {
        resolve(msg.data);
      } else if (msg.type === 'error') {
        reject(new Error(msg.message));
      }
    });

    worker.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    worker.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`Worker exited with code ${code}`));
      }
    });
  });
}

// --- Package scanning ---

async function scanPackage(name, version, ecosystem, tarballUrl, registryMeta, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable) {
  const startTime = Date.now();
  const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const tmpDir = fs.mkdtempSync(path.join(tmpBase, `${sanitizePackageName(name)}-`));
  const meta = registryMeta || {};
  const cacheTrigger = meta._cacheTrigger || null;

  try {
    const tgzPath = path.join(tmpDir, 'package.tar.gz');

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
      return;
    }

    // C1: Size cap — skip full scan for large packages (>10MB unpacked).
    // Malware payloads are tiny (<1MB); 10MB has 10x safety margin.
    // Quick scan: extract + check package.json + shell scripts for lifecycle threats.
    const unpackedSize = meta.unpackedSize || 0;
    let alreadyExtracted = false;
    let extractedDir = null;

    if (unpackedSize > LARGE_PACKAGE_SIZE) {
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
          alreadyExtracted = true;
          extractedDir = extractTarGz(tgzPath, tmpDir);

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
            stats.clean++;
            updateScanStats('clean');
            return;
          }
        } catch (extractErr) {
          // Extract/quick scan failed — fallback to registry metadata check
          alreadyExtracted = false;
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
            stats.clean++;
            updateScanStats('clean');
            return;
          }
        }
      }
    }

    if (!extractedDir) {
      extractedDir = extractTarGz(tgzPath, tmpDir);
    }

    // ML Phase 2a: Count JS files and detect test presence for enriched features
    const { fileCountTotal, hasTests } = countPackageFiles(extractedDir);

    let result;
    try {
      result = await runScanInWorker(extractedDir, STATIC_SCAN_TIMEOUT_MS);
    } catch (staticErr) {
      if (/static scan timeout/i.test(staticErr.message)) {
        console.error(`[MONITOR] STATIC_TIMEOUT: ${name}@${version} — exceeded ${STATIC_SCAN_TIMEOUT_MS / 1000}s (worker terminated)`);
        recordError(staticErr, stats);
        stats.scanned++;
        stats.totalTimeMs += Date.now() - startTime;
        updateScanStats('clean');
        return { sandboxResult: null, staticClean: false };
      }
      throw staticErr;
    }

    // ML Phase 2a: Fetch npm registry metadata once for packages with findings.
    // Reused for both training records (enriched features) and reputation scoring.
    let npmRegistryMeta = null;
    if (result.summary.total > 0 && ecosystem === 'npm') {
      try {
        const { getPackageMetadata } = require('../scanner/npm-registry.js');
        npmRegistryMeta = await getPackageMetadata(name);
      } catch (err) {
        console.error(`[ML] npm registry fetch failed for ${name}: ${err.message}`);
      }
    }

    if (result.summary.total === 0) {
      stats.scanned++;
      const elapsed = Date.now() - startTime;
      stats.totalTimeMs += elapsed;
      stats.clean++;
      console.log(`[MONITOR] CLEAN: ${name}@${version} (0 findings, ${(elapsed / 1000).toFixed(1)}s)`);
      updateScanStats('clean');
      recordTrainingSample(result, { name, version, ecosystem, label: 'clean', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
      return { sandboxResult: null, staticClean: true };
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
        // Popularity pre-filter: skip sandbox for popular npm packages with only MEDIUM/LOW
        if (ecosystem === 'npm' && !hasIOCMatch(result) && !hasTyposquat(result) && !hasHighOrCritical(result)) {
          const downloads = await getWeeklyDownloads(name);
          if (downloads >= POPULAR_THRESHOLD) {
            stats.scanned++;
            const elapsed = Date.now() - startTime;
            stats.totalTimeMs += elapsed;
            stats.clean++;
            console.log(`[MONITOR] TRUSTED (popular): ${name}@${version} (${Math.round(downloads / 1000)}k downloads/week, ${counts.join(', ')})`);
            updateScanStats('clean');
            recordTrainingSample(result, { name, version, ecosystem, label: 'clean', registryMeta: meta, unpackedSize: meta.unpackedSize, npmRegistryMeta, fileCountTotal, hasTests });
            return { sandboxResult: null, staticClean: true };
          }
        }

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
        // Reduces FP webhook noise by filtering clean packages before sandbox/webhook.
        // Guard rails in classifyPackage() ensure HC types and high-score packages are never suppressed.
        // Hoisted so trySendWebhook can use ML result to prevent suppression (p >= 0.90).
        // Applies to both T1a and T1b (ML can filter both sub-tiers in the [20,35) score range).
        let mlResult = null;
        const riskScore = result.summary.riskScore || 0;
        if ((tier === '1a' || tier === '1b') && riskScore >= 20 && riskScore < 35) {
          try {
            const { classifyPackage, isModelAvailable } = require('../ml/classifier.js');
            if (isModelAvailable()) {
              const enrichedMeta = { npmRegistryMeta, fileCountTotal, hasTests, unpackedSize: meta.unpackedSize, registryMeta: meta };
              mlResult = classifyPackage(result, enrichedMeta);
              if (mlResult.prediction === 'clean') {
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
              // Not clean — proceed normally
              console.log(`[MONITOR] ML SUSPECT: ${name}@${version} (p=${mlResult.probability}, reason=${mlResult.reason})`);
            }
          } catch (err) {
            // Non-fatal: ML failure must never block the scan pipeline
            console.error(`[ML] Classifier error for ${name}@${version}: ${err.message}`);
          }
        }

        stats.suspect++;

        // Sandbox decision based on tier
        // T1a: mandatory sandbox (HC malice types, TIER1_TYPES non-LOW, lifecycle + intent compound)
        // T1b: conditional sandbox (HIGH/CRITICAL without HC type — bundler FP zone)
        //       → sandbox only if score >= 25 (significant risk) or queue pressure is low
        // T2: sandbox if queue < 50 (as before)
        let sandboxResult = null;
        const shouldSandbox = isSandboxEnabled() && sandboxAvailable && (
          tier === '1a' ||
          (tier === '1b' && (riskScore >= 25 || scanQueue.length < 20)) ||
          (tier === 2 && scanQueue.length < 50)
        );

        if (shouldSandbox) {
          try {
            const canary = isCanaryEnabled();
            const reason = tier === 2 ? ' (T2, queue low)' : tier === '1b' ? ' (T1b, conditional)' : '';
            console.log(`[MONITOR] SANDBOX${reason}: launching for ${name}@${version}${canary ? ' (canary: on)' : ''}...`);
            sandboxResult = await runSandbox(name, { canary });
            console.log(`[MONITOR] SANDBOX: ${name}@${version} → score: ${sandboxResult.score}, severity: ${sandboxResult.severity}`);

            // Check for canary exfiltration findings and send dedicated alert
            const canaryFindings = (sandboxResult.findings || []).filter(f => f.type === 'canary_exfiltration');
            if (canaryFindings.length > 0) {
              console.log(`[MONITOR] CANARY EXFILTRATION: ${name}@${version} — ${canaryFindings.length} token(s) stolen!`);
              // Dedup: skip if this package was already alerted with canary_exfiltration
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
                    // Track in dedup map
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
          } catch (err) {
            console.error(`[MONITOR] SANDBOX error for ${name}@${version}: ${err.message}`);
          }
        } else if (tier === '1b') {
          console.log(`[MONITOR] SANDBOX SKIPPED (T1b, score=${riskScore} < 25, queue ${scanQueue.length} >= 20): ${name}@${version}`);
        } else if (tier === 2) {
          console.log(`[MONITOR] SANDBOX SKIPPED (T2, queue ${scanQueue.length} >= 50): ${name}@${version}`);
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

        dailyAlerts.push({ name, version, ecosystem, findingsCount: result.summary.total, tier });
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
        await trySendWebhook(name, version, ecosystem, adjustedResult, sandboxResult, mlResult);
        const staticScore = result.summary.riskScore || 0;
        const hasHCThreats = hasHighConfidenceThreat(result);
        const isDormant = sandboxResult && sandboxResult.score === 0 && (result.summary.riskScore || 0) >= 20;
        return { sandboxResult, staticClean: false, tier, staticScore, hasHCThreats, isDormant };
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
  try {
    await Promise.race([
      resolveTarballAndScan(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable),
      timeoutPromise(SCAN_TIMEOUT_MS)
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
  }
  maybePersistDailyStats(stats, dailyAlerts);

  // Check daily report between each package scan (not just between poll cycles).
  // Without this, a queue of 50 packages * 3min/each = 150min delay on the report.
  if (isDailyReportDue(stats)) {
    await sendDailyReport(stats, dailyAlerts, recentlyScanned, downloadsCache);
  }
}

/**
 * Worker-pool consumer for the scan queue.
 * Runs up to SCAN_CONCURRENCY scans in parallel. Each worker pulls from the
 * shared scanQueue until it's empty. Node.js is single-threaded so
 * scanQueue.shift() is atomic — no race conditions between workers.
 */
async function processQueue(scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable) {
  if (scanQueue.length === 0) return;

  if (SCAN_CONCURRENCY > 1 && scanQueue.length > 1) {
    console.log(`[MONITOR] Processing ${scanQueue.length} queued packages (concurrency: ${SCAN_CONCURRENCY})`);
  }

  async function worker() {
    while (scanQueue.length > 0) {
      const item = scanQueue.shift();
      await processQueueItem(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable);
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(SCAN_CONCURRENCY, scanQueue.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
}

/**
 * Wrapper to resolve PyPI tarball URLs before scanning.
 * For npm packages, tarballUrl is already set from the registry response.
 * For PyPI packages, we need to fetch the JSON API to get the tarball URL.
 */
async function resolveTarballAndScan(item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable) {
  if (item.ecosystem === 'npm' && !item.tarballUrl) {
    try {
      const npmInfo = await getNpmLatestTarball(item.name);
      if (!npmInfo.tarball) {
        console.log(`[MONITOR] SKIP: ${item.name} — no tarball URL found on npm`);
        return;
      }
      item.tarballUrl = npmInfo.tarball;
      if (npmInfo.version) item.version = npmInfo.version;
      if (npmInfo.unpackedSize) item.unpackedSize = npmInfo.unpackedSize;
      if (npmInfo.scripts) item.registryScripts = npmInfo.scripts;
    } catch (err) {
      console.error(`[MONITOR] ERROR resolving npm tarball for ${item.name}: ${err.message}`);
      recordError(err, stats);
      return;
    }
  }
  if (item.ecosystem === 'pypi' && !item.tarballUrl) {
    try {
      const pypiInfo = await getPyPITarballUrl(item.name);
      if (!pypiInfo.url) {
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

  // Temporal analysis: check for sudden lifecycle script changes (npm only)
  // Webhooks are deferred until after sandbox confirms the threat
  let temporalResult = null;
  let astResult = null;
  let publishResult = null;
  let maintainerResult = null;

  if (item.ecosystem === 'npm') {
    // Run all 4 temporal checks in parallel — each is independent.
    // With metadata cache (temporal-analysis.js), the 4 modules share 1 HTTP request.
    const [tempRes, astRes, pubRes, maintRes] = await Promise.allSettled([
      runTemporalCheck(item.name),
      runTemporalAstCheck(item.name),
      runTemporalPublishCheck(item.name),
      runTemporalMaintainerCheck(item.name)
    ]);
    temporalResult = tempRes.status === 'fulfilled' ? tempRes.value : null;
    astResult = astRes.status === 'fulfilled' ? astRes.value : null;
    publishResult = pubRes.status === 'fulfilled' ? pubRes.value : null;
    maintainerResult = maintRes.status === 'fulfilled' ? maintRes.value : null;
  }

  const scanResult = await scanPackage(item.name, item.version, item.ecosystem, item.tarballUrl, {
    unpackedSize: item.unpackedSize || 0,
    registryScripts: item.registryScripts || null,
    _cacheTrigger: item._cacheTrigger || null
  }, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable);
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
  KNOWN_BUNDLED_FILES,
  KNOWN_BUNDLED_PATHS,
  ML_EXCLUDED_DIRS,
  TEST_PATTERNS,
  TEST_FILE_PATTERN,
  SCAN_WORKER_PATH,

  // Functions
  isBundledToolingOnly,
  recordTrainingSample,
  countPackageFiles,
  runScanInWorker,
  scanPackage,
  timeoutPromise,
  isDailyReportDue,
  processQueueItem,
  processQueue,
  resolveTarballAndScan
};
