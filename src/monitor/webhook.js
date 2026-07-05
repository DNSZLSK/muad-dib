/**
 * monitor/webhook.js — Webhook/Discord/alert-related functions extracted from monitor.js
 *
 * Contains: webhook decision logic, Discord embed builders, alert persistence,
 * daily report generation, scope grouping, and all related helpers.
 */

const fs = require('fs');
const path = require('path');

const { sendWebhook } = require('../webhook.js');
const { sendIngest, isIngestConfigured } = require('../integrations/api-ingest.js');
const {
  atomicWriteFileSync,
  ALERTS_LOG_DIR,
  DAILY_REPORTS_LOG_DIR,
  getParisDateString,
  getParisHour,
  DAILY_REPORT_HOUR,
  loadScanStats,
  loadDetections,
  saveLastDailyReportDate,
  resetDailyStats,
  reconcileDailyHeadline,
  captureScanStatsBaseline,
  saveScanMemory,
  shouldSuppressByMemory,
  recordScanMemory,
  saveState,
  loadStateRaw,
  getScansSinceLastMemoryPersist,
  setScansSinceLastMemoryPersist,
  computeLedgerRollup,
  loadLastDailyReportTs
} = require('./state.js');
const {
  HIGH_CONFIDENCE_MALICE_TYPES,
  hasIOCMatch,
  hasHighOrCritical,
  formatErrorBreakdown
} = require('./classify.js');

// --- Mutable state ---

// Webhook dedup: track alerted packages by name -> Set<rule_ids> (cleared with daily report).
// If a new version triggers the same rules, skip the webhook. If new rules appear, let it through.
const alertedPackageRules = new Map();
const ALERTED_PACKAGES_MAX = 5_000; // single source of truth for the alerted-packages cap (daemon.js imports this for pruneMemoryCaches)

// Scope grouping: buffer scoped npm packages for grouped webhooks (monorepo noise reduction).
// @scope -> { packages[], timer, maxScore, ecosystem }
const SCOPE_GROUP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const pendingGrouped = new Map();

// --- Alert Priority Triage (C2) ---
// P1 IMMEDIATE: requires human action within minutes (confirmed malicious)
// P2 REVIEW: requires human investigation within hours
// P3 MONITOR: informational, low urgency
const HIGH_INTENT_TYPES = new Set([
  'suspicious_dataflow', 'dangerous_call_eval', 'dangerous_call_function',
  'env_access', 'staged_payload', 'dynamic_require', 'dangerous_exec',
  'remote_code_load', 'obfuscation_detected'
]);

// DAILY_REPORT_HOUR (=8) is imported from state.js (single source of truth) and
// re-exported below for back-compat (monitor.js / tests import it via webhook).

// --- Webhook alerting ---

function getWebhookUrl() {
  return process.env.MUADDIB_WEBHOOK_URL || null;
}

/**
 * Get the webhook score threshold based on reputation factor.
 * Established packages (low factor) require higher scores to trigger alerts,
 * reducing noise from well-known packages with benign FP patterns.
 *
 * @param {number} reputationFactor - Package reputation factor from computeReputationFactor()
 * @returns {number} Threshold: 35 (very established), 25 (established), 20 (new/unknown)
 */
function getWebhookThreshold(reputationFactor) {
  if (reputationFactor <= 0.5) return 35;   // very established — high bar
  if (reputationFactor <= 0.8) return 25;   // established — moderate bar
  return 20;                                 // new/unknown — default bar
}

function shouldSendWebhook(result, sandboxResult, mlResult) {
  if (!getWebhookUrl()) return false;

  const staticScore = (result && result.summary) ? (result.summary.riskScore || 0) : 0;
  const sandboxScore = (sandboxResult && sandboxResult.score !== undefined) ? sandboxResult.score : -1;
  const sandboxRan = sandboxScore >= 0;

  // Graduated threshold: use reputationFactor if available, else default (20)
  const reputationFactor = (result && result.summary && result.summary.reputationFactor !== undefined)
    ? result.summary.reputationFactor : 1.0;
  const threshold = getWebhookThreshold(reputationFactor);

  // 1. IOC match — ALWAYS send, regardless of sandbox result.
  // IOC matches are highest-confidence (225K+ known malicious packages).
  // Sandbox can miss time-bombs, env-specific, browser-only payloads.
  if (hasIOCMatch(result)) return true;

  // 1b. ML malicious with high probability — prevent suppression.
  // ML1 saw enough signals to classify as malicious (p >= 0.90).
  // Sandbox clean doesn't disprove ML (time bombs, env checks, targeted).
  // Guard: require ≥1 HIGH/CRITICAL finding. ALL-LOW = expert FP system overrides ML.
  if (mlResult && mlResult.prediction !== 'clean' && mlResult.probability >= 0.90
      && hasHighOrCritical(result)) return true;

  // 2. Real sandbox detection (> 30) — always send
  if (sandboxScore > 30) return true;

  // 3. Sandbox clean (0) or timeout noise (1-15): suppress unless static is strong.
  // Dormant malware can be statically suspicious but dynamically clean.
  // Threshold graduated by reputation — established packages need higher static score.
  // hasHighOrCritical() guards against FP (benign score with only MEDIUM/LOW won't pass).
  if (sandboxRan && sandboxScore <= 15) {
    return staticScore >= threshold && hasHighOrCritical(result);
  }

  // 4. Sandbox moderate (16-30): send if static corroborates
  if (sandboxRan && sandboxScore > 15 && sandboxScore <= 30) {
    return staticScore >= threshold && hasHighOrCritical(result);
  }

  // 5. No sandbox: static-only thresholds
  if (staticScore >= threshold && hasHighOrCritical(result)) return true;

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

/**
 * Build the registry web link for a package, ecosystem-aware. Mirrors the link
 * logic in ghsa-poller.js so pre-alerts point at the correct registry instead of
 * always npmjs.com (PyPI IOC pre-alerts previously mislinked to npm).
 */
function registryLink(ecosystem, name) {
  if (ecosystem === 'pypi') return `https://pypi.org/project/${encodeURIComponent(name)}/`;
  if (ecosystem === 'crates') return `https://crates.io/crates/${encodeURIComponent(name)}`;
  return `https://www.npmjs.com/package/${encodeURIComponent(name)}`;
}

/**
 * Layer 1: Build the IOC pre-alert embed (pure \u2014 no network). Exported for tests.
 * @param {string} name - Package name matching IOC database
 * @param {string} [version] - Version if known
 * @param {string} [ecosystem='npm'] - 'npm' | 'pypi' (link target)
 */
function buildIOCPreAlertEmbed(name, version, ecosystem = 'npm') {
  const versionStr = version ? `@${version}` : '';
  return {
    embeds: [{
      title: '\u26a0\ufe0f IOC PRE-ALERT \u2014 Known Malicious Package',
      color: 0xe74c3c,
      fields: [
        { name: 'Package', value: `[${ecosystem}/${name}${versionStr}](${registryLink(ecosystem, name)})`, inline: true },
        { name: 'Source', value: 'IOC Database Match', inline: true },
        { name: 'Detection', value: 'Changes stream pre-scan', inline: true },
        { name: 'Status', value: 'Full scan queued \u2014 this is an early warning. Package may be unpublished before scan completes.', inline: false }
      ],
      footer: {
        text: `MUAD'DIB IOC Pre-Alert | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Layer 1: Send immediate IOC pre-alert webhook when a known malicious package
 * appears in the changes stream, BEFORE tarball download. Safety net for packages
 * that get unpublished before scanning completes.
 * @param {string} name - Package name matching IOC database
 * @param {string} [version] - Version if known (from CouchDB doc)
 * @param {string} [ecosystem='npm'] - 'npm' | 'pypi'
 */
async function sendIOCPreAlert(name, version, ecosystem = 'npm') {
  const url = getWebhookUrl();
  if (!url) return;
  await sendWebhook(url, buildIOCPreAlertEmbed(name, version, ecosystem), { rawPayload: true });
}

/**
 * Layer 1b: Build the campaign pre-alert embed (pure \u2014 no network). Exported for tests.
 * @param {string} name - Package name that matched the campaign pattern
 * @param {string} campaign - Short campaign label (e.g. 'did-NNNN')
 * @param {string} [ecosystem='npm'] - 'npm' | 'pypi' (link target)
 */
function buildCampaignPreAlertEmbed(name, campaign, ecosystem = 'npm') {
  return {
    embeds: [{
      title: '\u26a0\ufe0f CAMPAIGN PRE-ALERT \u2014 Suspected Active Campaign',
      color: 0xe67e22,
      fields: [
        { name: 'Package', value: `[${ecosystem}/${name}](${registryLink(ecosystem, name)})`, inline: true },
        { name: 'Source', value: `Name pattern: ${campaign}`, inline: true },
        { name: 'Detection', value: 'Changes stream pre-scan', inline: true },
        { name: 'Status', value: 'Suspected campaign publication \u2014 not yet confirmed malicious. Full scan queued; treat as suspect until verdict lands.', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Campaign Pre-Alert | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Layer 1b: Send a campaign pre-alert webhook when a package name matches an
 * active-campaign pattern (e.g. `did-NNNN`). Fires BEFORE tarball download \u2014 IOC
 * lists lag the campaign by hours to days, so name-pattern watch is the only
 * real-time signal while the campaign is in flight.
 * @param {string} name - Package name that matched the campaign pattern
 * @param {string} campaign - Short campaign label (e.g. 'did-NNNN')
 * @param {string} [ecosystem='npm'] - 'npm' | 'pypi'
 */
async function sendCampaignPreAlert(name, campaign, ecosystem = 'npm') {
  const url = getWebhookUrl();
  if (!url) return;
  await sendWebhook(url, buildCampaignPreAlertEmbed(name, campaign, ecosystem), { rawPayload: true });
}

/**
 * Layer 1c: Build the burst pre-alert embed (pure — no network). Exported for tests.
 * Fires when ≥K versions of one package land in a short window (account-takeover /
 * "Miasma" burst-publish). Amber to distinguish from IOC (red) and campaign (orange).
 * @param {string} name - Package name
 * @param {number} count - Number of versions seen in the burst window
 * @param {string} [ecosystem='npm'] - 'npm' | 'pypi' | 'crates' (link target)
 */
function buildBurstPreAlertEmbed(name, count, ecosystem = 'npm') {
  return {
    embeds: [{
      title: '⚠️ BURST PRE-ALERT — Rapid Multi-Version Publish',
      color: 0xf39c12,
      fields: [
        { name: 'Package', value: `[${ecosystem}/${name}](${registryLink(ecosystem, name)})`, inline: true },
        { name: 'Versions', value: `${count} in a short window`, inline: true },
        { name: 'Detection', value: 'Burst-publish (possible ATO / Miasma)', inline: true },
        { name: 'Status', value: 'Multiple versions published rapidly — every version queued for scan and protected from queue-cap eviction. Treat as suspect until verdicts land.', inline: false }
      ],
      footer: {
        text: `MUAD'DIB Burst Pre-Alert | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Burst pre-alert Discord toggle — OFF by default. Measured 2026-07: the burst
 * heads-up fires ~700×/day and is anti-correlated with real kills/incidents, so it is
 * pure #alerts noise. This gates ONLY the Discord POST in sendBurstPreAlert(): the
 * burst versions are still queued + scanned (queue.js), and the `[MONITOR] BURST
 * PRE-ALERT` console.log + the `stats.burstPreAlerts` counter (used by the daily
 * summary) are emitted BEFORE the send at the call site, so they are unaffected.
 * Opt back in with MUADDIB_BURST_PREALERT_WEBHOOK=1 (also accepts true/yes/on).
 * Read at call time so a restart re-toggles it without a code change (and tests can flip it).
 */
function burstPreAlertWebhookEnabled() {
  const v = (process.env.MUADDIB_BURST_PREALERT_WEBHOOK || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Layer 1c: Send a burst pre-alert webhook. Fire-and-forget; callers dedupe per
 * name/window so a burst pings once, not once per version. Discord POST is muted by
 * default — see burstPreAlertWebhookEnabled(). Scoped to this sender only; the shared
 * sendWebhook() and every other alert type (IOC/campaign pre-alerts, scan results,
 * DEGRADED, daily report) are untouched.
 */
async function sendBurstPreAlert(name, count, ecosystem = 'npm') {
  if (!burstPreAlertWebhookEnabled()) return;
  const url = getWebhookUrl();
  if (!url) return;
  await sendWebhook(url, buildBurstPreAlertEmbed(name, count, ecosystem), { rawPayload: true });
}

/**
 * Check if a specific package@version matches a versioned IOC entry.
 * Returns the matching IOC entry or null.
 * Wildcard IOCs are NOT checked here (use wildcardPackages.has() separately).
 */
function matchVersionedIOC(iocs, name, version) {
  if (!version || !iocs.packagesMap) return null;
  const entries = iocs.packagesMap.get(name);
  if (!entries) return null;
  return entries.find(e => e.version === version) || null;
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
 * Clamped to [0.10, 1.5].
 *
 * @param {Object|null} metadata - Registry metadata from getPackageMetadata()
 * @returns {number} factor in [0.10, 1.5]
 */
function computeReputationFactor(metadata) {
  if (!metadata) return 1.0;
  let factor = 1.0;

  // Age signal (mutually exclusive branches)
  const ageDays = metadata.age_days;
  if (ageDays !== null && ageDays !== undefined) {
    if (ageDays > 1825) factor -= 0.5;       // 5+ years — highly established
    else if (ageDays > 730) factor -= 0.3;
    else if (ageDays > 365) factor -= 0.15;
    else if (ageDays < 7) factor += 0.3;
    else if (ageDays < 30) factor += 0.2;
  }

  // Version count signal (mutually exclusive)
  const versionCount = metadata.version_count || 0;
  if (versionCount > 200) factor -= 0.3;     // 200+ versions — mature project
  else if (versionCount > 50) factor -= 0.2;
  else if (versionCount > 20) factor -= 0.1;
  else if (versionCount === 1) factor += 0.2;
  else if (versionCount <= 2) factor += 0.15;

  // Downloads signal
  const downloads = metadata.weekly_downloads || 0;
  if (downloads > 1000000) factor -= 0.4;    // 1M+ weekly — top-tier package
  else if (downloads > 100000) factor -= 0.2;
  else if (downloads > 50000) factor -= 0.1;
  else if (downloads < 10) factor += 0.15;
  else if (downloads < 100) factor += 0.1;

  return Math.max(0.10, Math.min(1.5, factor));
}

/**
 * True if the package declares an install-time lifecycle script that executes
 * code on `npm install`. These hooks are the principal vehicle for malicious
 * payloads (preinstall / postinstall / install). PyPI's setup.py equivalent is
 * handled separately via `meta.has_setup_py` in triageRisk.
 *
 * Reads from both `item.registryScripts` (set by changes-stream docMeta when
 * available) and `item._npmInfo.scripts` (set by Stage 1's preResolveNpmBatch).
 *
 * @param {Object} item - queue item
 * @returns {boolean}
 */
function hasDangerousLifecycle(item) {
  if (!item) return false;
  const direct = item.registryScripts;
  if (direct && (direct.preinstall || direct.postinstall || direct.install)) return true;
  const stashed = item._npmInfo && item._npmInfo.scripts;
  if (stashed && (stashed.preinstall || stashed.postinstall || stashed.install)) return true;
  return false;
}

/**
 * Pass A triage: choose between full pipeline (20 scanners) and quick_scan
 * subset for a queued package. Default is `quick`; any suspect signal flips
 * to `full`. Used by the monitor only — CLI scans default to full elsewhere.
 *
 * Tiers (any reason → full):
 *   T0  IOC match / ATO signal / install-time lifecycle → known or high-prob threat
 *   T1  No registry metadata available → cannot establish trust, default safe
 *   T2  (npm) computeReputationFactor(meta) >= 1.0 → composite signal of new /
 *       low-download / few-versions package, subsumes individual checks
 *   T3  (PyPI) direct age < 30d or version_count < 5 → PyPI has no download
 *       stats, so we cannot reuse the npm composite; use the direct fields the
 *       PyPI JSON API exposes.
 *
 * Returning the reasons list (not just the mode) makes shadow-mode logs
 * actionable for tuning.
 *
 * @param {Object} item - queue item
 * @param {Object|null} meta - registry metadata {age_days, version_count, weekly_downloads, has_setup_py?}
 * @returns {{mode: 'full'|'quick', reasons: string[]}}
 */
function triageRisk(item, meta) {
  const reasons = [];
  const ecosystem = (item && item.ecosystem) || null;

  if (item && item.isIOCMatch) reasons.push('ioc_match');
  if (item && item.atoSignal)  reasons.push('ato_signal');
  if (hasDangerousLifecycle(item)) reasons.push('lifecycle_scripts');

  if (!meta) {
    reasons.push('no_metadata');
  } else if (ecosystem === 'npm') {
    const factor = computeReputationFactor(meta);
    if (factor >= 1.2) reasons.push(`reputation_factor=${factor.toFixed(2)}`);
  } else if (ecosystem === 'pypi') {
    // PyPI has no weekly_downloads source today, so we cannot reuse
    // computeReputationFactor as-is. Use direct signals instead.
    if ((meta.age_days || 0) < 30) reasons.push('pypi_age<30d');
    if ((meta.version_count || 0) < 5) reasons.push('pypi_version_count<5');
    if (meta.has_setup_py === true) reasons.push('pypi_setup_py');
  }

  return { mode: reasons.length ? 'full' : 'quick', reasons };
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
      // delivered=false until the webhook confirms — markReportDelivered() flips it
      // after a successful send. The boot redelivery path keys off this (AUDIT 3).
      delivered: false,
      deliveredAt: null,
      embed: reportPayload,
      metrics: rawMetrics
    };
    atomicWriteFileSync(filePath, JSON.stringify(data, null, 2));
    console.log(`[MONITOR] Daily report persisted to ${filePath}`);
  } catch (err) {
    console.error(`[MONITOR] Failed to persist daily report: ${err.message}`);
  }
}

// --- AUDIT 3: persisted-report redelivery (resend + boot recovery) ---

/** List persisted daily-report dates (YYYY-MM-DD), sorted ascending. */
function listPersistedReportDates() {
  try {
    return fs.readdirSync(DAILY_REPORTS_LOG_DIR)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.json$/.test(f))
      .map(f => f.slice(0, -5))
      .sort();
  } catch { return []; }
}

/**
 * Load a persisted daily report by date (default: latest). Returns
 * { date, filePath, data } or null if none / unreadable.
 */
function loadPersistedReport(date) {
  let d = date;
  if (!d) {
    const all = listPersistedReportDates();
    if (all.length === 0) return null;
    d = all[all.length - 1];
  }
  const filePath = path.join(DAILY_REPORTS_LOG_DIR, `${d}.json`);
  try {
    return { date: d, filePath, data: JSON.parse(fs.readFileSync(filePath, 'utf8')) };
  } catch { return null; }
}

/** Mark a persisted report file as delivered (idempotent, best-effort). */
function markReportDelivered(filePath, data) {
  try {
    data.delivered = true;
    data.deliveredAt = new Date().toISOString();
    atomicWriteFileSync(filePath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[MONITOR] Failed to mark report delivered: ${err.message}`);
  }
}

/**
 * Resend a persisted daily report's EXACT embed to the webhook — faithful
 * redelivery, no stats reconstruction. Used by `report --resend [date]` and the
 * boot redelivery path. Returns { sent, message, date }.
 */
async function resendDailyReport(date) {
  const url = getWebhookUrl();
  if (!url) return { sent: false, message: 'MUADDIB_WEBHOOK_URL not configured' };
  const report = loadPersistedReport(date);
  if (!report) {
    return { sent: false, message: date ? `No persisted report for ${date}` : 'No persisted reports found' };
  }
  const payload = report.data && report.data.embed;
  if (!payload) return { sent: false, message: `Report ${report.date} has no embed payload`, date: report.date };
  try {
    await sendWebhook(url, payload, { rawPayload: true });
  } catch (err) {
    return { sent: false, message: `Webhook failed: ${err.message}`, date: report.date };
  }
  markReportDelivered(report.filePath, report.data);
  return { sent: true, message: `Daily report ${report.date} resent`, date: report.date };
}

/**
 * Boot redelivery: if the most recent persisted report was never confirmed
 * delivered (last webhook failed — e.g. the 2026-06-10 DNS blip) AND a webhook URL
 * is configured, attempt exactly one resend. Best-effort; never throws. Reports
 * with delivered === undefined (written before this feature) are treated as
 * delivered, so upgrading never spams historical reports.
 */
async function redeliverPendingReportOnBoot() {
  try {
    const report = loadPersistedReport(null); // latest
    if (!report) return { attempted: false, reason: 'no_reports' };
    if (report.data.delivered !== false) return { attempted: false, reason: 'already_delivered_or_legacy' };
    if (!getWebhookUrl()) return { attempted: false, reason: 'no_webhook_url' };
    console.log(`[MONITOR] Last daily report (${report.date}) was not delivered — attempting boot redelivery...`);
    const res = await resendDailyReport(report.date);
    console.log(`[MONITOR] Boot redelivery of ${report.date}: ${res.sent ? 'sent' : 'failed — ' + res.message}`);
    return { attempted: true, sent: res.sent, date: report.date };
  } catch (err) {
    console.error(`[MONITOR] Boot redelivery error (non-fatal): ${err.message}`);
    return { attempted: false, reason: 'error' };
  }
}

function computeAlertPriority(result, sandboxResult) {
  const threats = (result && result.threats) || [];
  const score = (result && result.summary) ? (result.summary.riskScore || 0) : 0;

  // P1: IOC match
  if (threats.some(t => t.type === 'known_malicious_package' || t.type === 'ioc_match' || t.type === 'shai_hulud_marker')) {
    return { level: 'P1', reason: 'ioc_match' };
  }

  // P1: High-confidence malice type (non-LOW)
  if (threats.some(t => HIGH_CONFIDENCE_MALICE_TYPES.has(t.type) && t.severity !== 'LOW')) {
    return { level: 'P1', reason: 'high_confidence_type' };
  }

  // P1: Sandbox detection
  if (sandboxResult && sandboxResult.score > 30) {
    return { level: 'P1', reason: 'sandbox_detection' };
  }

  // P1: Canary exfiltration
  if (threats.some(t => t.type === 'sandbox_canary_exfiltration')) {
    return { level: 'P1', reason: 'canary_exfiltration' };
  }

  // P2: High score
  if (score >= 50) {
    return { level: 'P2', reason: 'high_score' };
  }

  // P2: Compound detection present
  if (threats.some(t => t.compound === true)) {
    return { level: 'P2', reason: 'compound_detection' };
  }

  // P2: lifecycle_script + high-intent type (non-LOW)
  const hasLifecycle = threats.some(t => t.type === 'lifecycle_script');
  if (hasLifecycle) {
    const hasHighIntent = threats.some(t =>
      HIGH_INTENT_TYPES.has(t.type) && t.severity !== 'LOW'
    );
    if (hasHighIntent) {
      return { level: 'P2', reason: 'lifecycle_plus_intent' };
    }
  }

  // P3: Everything else
  return { level: 'P3', reason: 'default' };
}

function buildAlertData(name, version, ecosystem, result, sandboxResult, llmResult) {
  const priority = computeAlertPriority(result, sandboxResult);
  const webhookData = {
    target: `${ecosystem}/${name}@${version}`,
    timestamp: new Date().toISOString(),
    ecosystem,
    priority,
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
  if (llmResult && llmResult.verdict) {
    webhookData.llm = {
      verdict: llmResult.verdict,
      confidence: llmResult.confidence,
      investigation_steps: (llmResult.investigation_steps || []).slice(0, 5),
      reasoning: (llmResult.reasoning || '').slice(0, 200),
      attack_type: llmResult.attack_type || null,
      iocs_found: (llmResult.iocs_found || []).slice(0, 5),
      mode: llmResult.mode || 'shadow'
    };
  }
  return webhookData;
}

async function trySendWebhook(name, version, ecosystem, result, sandboxResult, mlResult, llmResult) {
  if (!shouldSendWebhook(result, sandboxResult, mlResult)) {
    if (mlResult && mlResult.prediction !== 'clean' && mlResult.probability >= 0.90
        && !hasHighOrCritical(result)) {
      console.log(`[MONITOR] ML DEFERRED (all LOW): ${name}@${version} (ML p=${mlResult.probability.toFixed(3)})`);
    } else if (sandboxResult && sandboxResult.score === 0) {
      console.log(`[MONITOR] SUPPRESSED (sandbox clean, low static): ${name}@${version}`);
    }
    return;
  }

  if (sandboxResult && sandboxResult.score === 0) {
    const staticScore = (result && result.summary) ? (result.summary.riskScore || 0) : 0;
    console.log(`[MONITOR] DORMANT SUSPECT: ${name}@${version} (static score: ${staticScore}, sandbox clean — possible evasive malware)`);
  }

  // C3: Scan memory — cross-session webhook dedup (before daily dedup).
  // Suppresses webhook if previous scan produced equivalent results (same types, similar score).
  // Always records the current scan for future comparisons.
  const currentScore = (result && result.summary) ? (result.summary.riskScore || 0) : 0;
  const currentTypes = [...new Set((result.threats || []).map(t => t.type))];
  const currentHCTypes = [...new Set(
    (result.threats || [])
      .filter(t => HIGH_CONFIDENCE_MALICE_TYPES.has(t.type) && t.severity !== 'LOW')
      .map(t => t.type)
  )];

  const memoryCheck = shouldSuppressByMemory(name, result);
  // Always record current scan (updates timestamp + fingerprint for future checks)
  recordScanMemory(name, currentScore, currentTypes, currentHCTypes);

  // Push to muad-api dashboard. Fires for every alert that passes shouldSendWebhook,
  // independent of Discord dedup. The API's ON CONFLICT DO UPDATE absorbs duplicates;
  // dedup downstream is a Discord noise filter, not a data filter.
  if (isIngestConfigured()) {
    sendIngest(name, version, result).catch(() => {});
  }

  // Persist periodically (throttled to every 10 scans to avoid disk I/O overhead)
  let scansSinceLastMemoryPersist = getScansSinceLastMemoryPersist();
  scansSinceLastMemoryPersist++;
  setScansSinceLastMemoryPersist(scansSinceLastMemoryPersist);
  if (scansSinceLastMemoryPersist >= 10) {
    saveScanMemory();
    setScansSinceLastMemoryPersist(0);
  }

  if (memoryCheck.suppress) {
    console.log(`[MONITOR] MEMORY SUPPRESSED: ${name}@${version} (${memoryCheck.reason})`);
    return;
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
    // FIFO size cap (bounded resource): evict the oldest tracked package when over
    // the cap. A Map preserves insertion order, so the first key is the oldest.
    if (alertedPackageRules.size > ALERTED_PACKAGES_MAX) {
      alertedPackageRules.delete(alertedPackageRules.keys().next().value);
    }
  }

  // Scope grouping: buffer scoped npm packages for grouped webhook
  const scope = extractScope(name);
  if (scope && ecosystem === 'npm') {
    bufferScopedWebhook(scope, name, version, ecosystem, result, sandboxResult, llmResult);
    return;
  }

  // Non-scoped: send immediately (existing behavior)
  const url = getWebhookUrl();
  const webhookData = buildAlertData(name, version, ecosystem, result, sandboxResult, llmResult);
  try {
    await sendWebhook(url, webhookData);
    console.log(`[MONITOR] Webhook sent for ${name}@${version}`);
  } catch (err) {
    console.error(`[MONITOR] Webhook failed for ${name}@${version}: ${err.message}`);
  }
}

/**
 * Extract the npm scope from a package name, e.g. '@scope/pkg' -> '@scope'.
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
function bufferScopedWebhook(scope, name, version, ecosystem, result, sandboxResult, llmResult) {
  const entry = {
    name, version,
    score: (result && result.summary) ? (result.summary.riskScore || 0) : 0,
    threats: result.threats || [],
    sandboxResult,
    llmResult: llmResult || null
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
    const critical = pkg.threats.filter(t => t.severity === 'CRITICAL').length;
    const high = pkg.threats.filter(t => t.severity === 'HIGH').length;
    const medium = pkg.threats.filter(t => t.severity === 'MEDIUM').length;
    const low = pkg.threats.filter(t => t.severity === 'LOW').length;
    const result = {
      threats: pkg.threats,
      summary: { riskScore: pkg.score, critical, high, medium, low, total: pkg.threats.length }
    };
    const webhookData = buildAlertData(pkg.name, pkg.version, group.ecosystem, result, pkg.sandboxResult, pkg.llmResult);
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

/**
 * Build the daily report Discord embed.
 * @param {Object} stats - In-memory stats object (scanned, clean, suspect, errors, errorsByType, totalTimeMs, suspectByTier, mlFiltered)
 * @param {Array} dailyAlerts - In-memory daily alerts array
 */
/**
 * Load yesterday's persisted report metrics for J-1 comparison.
 * @returns {Object|null} yesterday's raw metrics or null if unavailable
 */
function loadYesterdayMetrics() {
  try {
    // Use Paris timezone to match persistDailyReport() which uses getParisDateString()
    const todayParis = getParisDateString(); // YYYY-MM-DD in Europe/Paris
    const [y, m, d] = todayParis.split('-').map(Number);
    const yesterday = new Date(y, m - 1, d);
    yesterday.setDate(yesterday.getDate() - 1);
    const yStr = yesterday.toISOString().slice(0, 10);
    const filePath = path.join(DAILY_REPORTS_LOG_DIR, `${yStr}.json`);
    if (!fs.existsSync(filePath)) return null;
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return data.metrics || null;
  } catch {
    return null;
  }
}

/**
 * Format a delta with sign: "+1200" or "-50" or "=0"
 */
function formatDelta(current, previous) {
  const d = current - previous;
  if (d > 0) return `+${d}`;
  if (d < 0) return `${d}`;
  return '=0';
}

// Phase 0b: fallback window for the daily report's ledger section when no
// last-report timestamp exists yet (first report ever / pre-upgrade stamp file).
// Normal operation derives the window from lastReportTs instead (8h→8h Paris,
// restart-proof). Env-tunable.
const LEDGER_ROLLUP_WINDOW_MS = (() => {
  const v = parseInt(process.env.MUADDIB_LEDGER_ROLLUP_WINDOW_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 24 * 60 * 60 * 1000;
})();

// Hard ceiling on the report window. A multi-day daemon outage would otherwise make
// the next report's window (and the rollup's distinct-key sets) span the whole gap;
// clamp to 48h and flag it so the report stays honest about the truncation.
const LEDGER_ROLLUP_MAX_WINDOW_MS = 48 * 60 * 60 * 1000;

/**
 * Compute the per-scan ledger rollup for the daily-report window. The window is
 * [last report send → now] (8h→8h Paris semantics, exact across restarts) when the
 * lastReportTs stamp exists, else the fixed fallback window. Best-effort: a rollup
 * failure (corrupt ledger, I/O) must NEVER break the daily report, so this swallows
 * errors and returns null. Also returns null when the ledger is empty so the report
 * omits the section instead of showing a noise row of zeros.
 */
function safeLedgerRollup() {
  try {
    const now = Date.now();
    let sinceMs = now - LEDGER_ROLLUP_WINDOW_MS;
    let windowClamped = false;
    let windowSource = 'fallback_24h';
    const lastTs = loadLastDailyReportTs();
    if (lastTs) {
      const p = Date.parse(lastTs);
      // Guard against clock skew (stamp in the future) — fall back to 24h.
      if (!Number.isNaN(p) && p <= now) {
        if (p < now - LEDGER_ROLLUP_MAX_WINDOW_MS) {
          sinceMs = now - LEDGER_ROLLUP_MAX_WINDOW_MS;
          windowClamped = true;
        } else {
          sinceMs = p;
        }
        windowSource = 'last_report';
      }
    }
    // Ledger source resolved at CALL time (not module load) so tests can point the
    // rollup at a synthetic/empty ledger after the module graph is already loaded.
    // Unset env → computeLedgerRollup falls back to its SCAN_LEDGER_FILE default.
    const fileOverride = process.env.MUADDIB_SCAN_LEDGER_FILE;
    const rollup = computeLedgerRollup(sinceMs, fileOverride ? { file: fileOverride } : {});
    if (rollup && rollup.total > 0) {
      rollup.windowClamped = windowClamped;
      rollup.windowSource = windowSource;
      return rollup;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Format the ledger rollup as a Discord embed field, or null to omit it (no data).
 * Surfaces operational scan coverage: scanned, alert rate (NOT a TPR — see
 * computeLedgerRollup's HONEST METRIC NOTE), the dropped/vanished coverage holes,
 * and a per-ecosystem split. Compact, well under Discord's 1024-char field limit.
 */
function formatLedgerField(rollup) {
  if (!rollup || rollup.total <= 0) return null;
  const pct = rollup.alertRate != null ? (rollup.alertRate * 100).toFixed(2) : '0.00';
  // All counts here are name@version scan EVENTS (NOT distinct package names — that
  // ratio is the headline's "Noms uniques"). alertRate = suspect+confirmed / scanned
  // (NOT a TPR — see computeLedgerRollup's HONEST METRIC NOTE).
  const lines = [`Scans: ${rollup.scanned} events · alertés ${rollup.alerted} (${pct}%)`];
  if (rollup.dropped > 0) {
    const bo = rollup.byOutcome || {};
    const spill = bo.spilled || 0;
    const evicted = (bo.dropped || 0) + (bo.interrupted || 0);
    const vanishedNote = rollup.exactVanished ? `${rollup.vanished}` : `≥${rollup.vanished}`;
    // Honest split (2026-06-20): the aggregate `dropped` folds RECOVERABLE spill (disk
    // waiting list, drains later) with HARD evictions (queue-cap / killed, gone). byOutcome
    // keeps them distinct so the report stops reading a drain backlog as permanent loss.
    // `vanished` is the distinct name@version subset never (re)scanned in-window — still
    // version-granular and still includes not-yet-drained spill, so NOT a removal count.
    lines.push(`Non scannés: ${rollup.dropped} events — spill ${spill} (récup.) + ${evicted} évincés · ${vanishedNote} name@ver jamais (re)scannés`);
  }
  const ecos = Object.keys(rollup.byEcosystem)
    .sort((a, b) => rollup.byEcosystem[b].total - rollup.byEcosystem[a].total);
  if (ecos.length > 0) {
    lines.push(ecos.slice(0, 4).map(e => `${e} ${rollup.byEcosystem[e].total}`).join(' · '));
  }
  const label = rollup.windowSource === 'last_report'
    ? `Ledger (since last report${rollup.windowClamped ? ', clamped 48h' : ''})`
    : 'Ledger (24h)';
  return { name: label, value: lines.join('\n'), inline: false };
}

// AUDIT-C: MCP self-identity by package name (matches the F9/F15 MCP_NAME_RE family in
// feature-extractor.js — kept local to avoid importing the ML module into the embed path).
const _MCP_TRIAGE_NAME_RE = /(?:^|[/_-])mcp(?:[_-]|$)|mcp[_-](?:server|init|bridge|installer|memory|plugin|core|router|host|client|gateway|relay|stdio|transport|orchestrator)/i;

/**
 * Triage tag for a daily-report top-suspect. Returns ' 🔌 [MCP: sig1, sig2]' when the
 * package self-identifies as an MCP server/installer, else ''. Signals come from the
 * alert's recorded CRITICAL/HIGH threat types (AUDIT-C). Presentation only.
 */
function mcpTriageTag(a) {
  const name = (a && (a.name || a.package)) || '';
  if (!_MCP_TRIAGE_NAME_RE.test(name)) return '';
  const sigs = Array.isArray(a.signals) ? a.signals.slice(0, 3) : [];
  return sigs.length ? ` 🔌 [MCP: ${sigs.join(', ')}]` : ' 🔌 [MCP]';
}

/**
 * Stability field for the daily report. The spill segment (spilled / drained /
 * backlog size) only appears when the disk waiting list is enabled — backlog
 * size is THE convergence signal of the spill rollout (must oscillate around
 * 0 across days; monotonic growth = drain capacity too low, raise concurrency).
 * Best-effort: a spill read failure must never break the report.
 */
function _stabilityFieldValue(stats) {
  let v = `Restarts (24h): ${stats.restartsToday || 0} | Temporal load-shed: ${stats.temporalLoadShed || 0} | Queue hard-drops: ${stats.queueHardDrops || 0}`;
  try {
    const { isSpillEnabled, getBacklogSize } = require('./spill.js');
    if (isSpillEnabled()) {
      v += `\nSpill: ${stats.spilled || 0} spilled | ${stats.spillDrained || 0} drained | backlog ${getBacklogSize()}`;
      if (stats.workerOom) v += ` | worker OOM: ${stats.workerOom}`;
    } else if (stats.workerOom) {
      v += ` | worker OOM: ${stats.workerOom}`;
    }
  } catch { /* best-effort */ }
  return v;
}

// Phase D: currently-active degradation states for the daily report. The
// registry lives in the daemon process (same instance); CLI callers that
// build a report without it just show the em-dash.
function _degradationsFieldValue() {
  try {
    const active = require('./degradation.js').getActiveDegradations();
    return active.length > 0 ? `⚠️ ${active.join(', ')}` : '—';
  } catch { return '—'; }
}

function buildDailyReportEmbed(stats, dailyAlerts, ledgerRollup) {
  // Use in-memory stats (accumulated since last reset, restored from disk on restart)
  // instead of disk-based daily entries which can undercount due to UTC/Paris date mismatch
  const { top3: diskTop3 } = buildReportFromDisk();

  // --- Phase 0b: per-scan ledger rollup (resolved early so the headline can use it) ---
  // Caller may pass a precomputed rollup (sendDailyReport does, to persist the same
  // numbers it displays); undefined → compute here; explicit null → omit the section.
  const ledger = ledgerRollup !== undefined ? ledgerRollup : safeLedgerRollup();

  // HEADLINE BOUNDARY — scanned/clean/suspect come from the ledger window
  // [last report → now] when available: window-exact and restart-proof, unlike the
  // in-memory counters (reset-restore cycles can under-count after a restart storm).
  // Everything NOT in the ledger (errorsByType breakdown, changes-stream/publish-event
  // counts, pypi*, avg scan time) stays on the in-memory counters + daily-stats.json:
  // best-effort since the last reset, may under-count after a restart.
  const headline = (ledger && ledger.headline && ledger.headline.scanned > 0) ? ledger.headline : null;
  const hScanned = headline ? headline.scanned : stats.scanned;
  const hClean = headline ? headline.clean : stats.clean;
  const hSuspect = headline ? headline.suspect : stats.suspect;

  // Prefer in-memory dailyAlerts for top suspects (richer data), fallback to disk
  const top3 = dailyAlerts.length > 0
    ? dailyAlerts.slice().sort((a, b) => (b.score || 0) - (a.score || 0) || b.findingsCount - a.findingsCount).slice(0, 3)
    : diskTop3;

  const top3Text = top3.length > 0
    ? top3.map((a, i) => {
        const name = a.ecosystem ? `${a.ecosystem}/${a.name || a.package}` : (a.name || a.package);
        const version = a.version || 'N/A';
        const count = a.findingsCount || (a.findings ? a.findings.length : 0);
        const scoreText = a.score != null ? `score ${a.score}, ` : '';
        // AUDIT-C: annotate MCP suspects (identity + signals) for visual triage — MCP
        // servers score high but are statically ambiguous vs MCP-malware (see AUDIT 2).
        // Pure presentation, no scoring change.
        return `${i + 1}. **${name}@${version}** — ${scoreText}${count} finding(s)${mcpTriageTag(a)}`;
      }).join('\n')
    : 'None';

  // Avg scan time from in-memory stats (totalTimeMs is not ledgerized — best-effort)
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';

  // --- 3 sections, une unité chacune (refonte 2026-06-20) ---
  // Le 2026-06-18 a étiqueté les unités ; ce passage les SÉPARE en champs distincts pour
  // qu'un humain lise « combien vu / combien scanné / combien couvert » en 5 secondes,
  // sans empiler trois unités dans un seul champ "Coverage" (le piège des comparaisons
  // inter-unités absurdes, cf daily-reports-analysis.md) :
  //   • Flux     → events bruts du changes-stream (1 pkg × N versions = N events)
  //   • Scanned  → packages traités (events terminés, fenêtre ledger) + avg + catch-up
  //   • Coverage → noms de paquets DISTINCTS scannés/vus (version-collapsed, ≤100%)
  const attempted = stats.uniqueScanAttempts || 0;
  const npmPub = stats.npmPublishEventsSeen || 0;
  const pypiPub = stats.pypiChangelogPackages || 0;
  const published = npmPub + pypiPub;
  const catchupSkipped = (stats.npmCatchupSkippedSeqs || 0) + (stats.pypiCatchupSkippedEvents || 0);

  // Flux: raw stream events seen — NOT distinct packages, NOT scans.
  const fluxText = `${published} events vus · npm ${npmPub} · pypi ${pypiPub}`;

  // Scanned: packages actually processed. Prefers the ledger headline window (restart-proof)
  // over the in-memory counter; `compteur` exposes the raw stats.scanned when it exceeds the
  // deduped headline (retries/burst). Catch-up skip = events the catch-up fast-forwarded.
  const opsQualifier = headline ? ' (events terminés)' : '';
  const rawCounter = (headline && typeof stats.scanned === 'number' && stats.scanned > hScanned)
    ? ` · compteur ${stats.scanned} (retries/burst)`
    : '';
  let scannedText = `${hScanned}${opsQualifier}${rawCounter} · ${avg}s/pkg`;
  if (catchupSkipped > 0) scannedText += ` · Catch-up skip: ${catchupSkipped}`;

  // Coverage: distinct package NAMES scanned vs seen (version-collapsed, bounded ≤100%,
  // immune to version-spam). A low % is usually a throughput symptom (the drain floods the
  // window with backlog names), NOT a detection miss — the `non couverts` gap is mostly
  // spill awaiting drain, split spill-vs-evicted in the Ops/Ledger field. Fallback to the
  // raw event ratio only when the ledger is unavailable (first boot / empty ledger).
  let coverageText;
  if (ledger && ledger.distinctPackages > 0 && ledger.distinctCoverage != null) {
    const pct = (ledger.distinctCoverage * 100).toFixed(0);
    const approx = ledger.exactVanished === false ? '~' : '';
    const gap = ledger.distinctPackages - ledger.distinctScanned;
    coverageText = `Noms uniques: ${ledger.distinctScanned}/${ledger.distinctPackages} (${approx}${pct}%)`;
    if (gap > 0) coverageText += ` · ${gap} non couverts (backlog/drain)`;
  } else if (published > 0) {
    const coverageRatio = (attempted / published * 100).toFixed(0);
    coverageText = `${attempted}/${published} (${coverageRatio}%)`;
  } else {
    coverageText = `${attempted} attempted`;
  }

  // --- Timeouts ---
  const staticTimeouts = (stats.errorsByType && stats.errorsByType.static_timeout) || 0;
  const httpTimeouts = (stats.errorsByType && stats.errorsByType.timeout) || 0;
  const timeoutPct = stats.scanned > 0 ? (staticTimeouts / stats.scanned * 100) : 0;
  const timeoutWarning = timeoutPct > 15 ? ' \u26a0\ufe0f' : '';
  const timeoutText = `Static: ${staticTimeouts}/${stats.scanned} (${timeoutPct.toFixed(1)}%)${timeoutWarning}\nHTTP: ${httpTimeouts}`;

  // --- J-1 trends ---
  const yesterday = loadYesterdayMetrics();
  let trendsText = 'No data (first day or missing)';
  if (yesterday) {
    const dScanned = formatDelta(hScanned, yesterday.scanned || 0);
    const dSuspect = formatDelta(hSuspect, yesterday.suspect || 0);
    const dErrors = formatDelta(stats.errors, yesterday.errors || 0);
    trendsText = `${dScanned} scanned, ${dSuspect} suspects, ${dErrors} errors`;
  }

  // --- ML stats ---
  let mlText;
  try {
    const { isModelAvailable } = require('../ml/classifier.js');
    if (isModelAvailable()) {
      mlText = stats.mlFiltered > 0 ? `${stats.mlFiltered} filtered` : '0 filtered';
    } else {
      mlText = 'No model loaded';
    }
  } catch {
    mlText = 'No model loaded';
  }

  // --- LLM Detective stats ---
  let llmText;
  try {
    const { isLlmEnabled, getStats: getLlmStats } = require('../ml/llm-detective.js');
    if (isLlmEnabled()) {
      const ls = getLlmStats();
      llmText = `${ls.analyzed} analyzed (${ls.malicious} mal, ${ls.benign} ben, ${ls.uncertain} unc, ${ls.errors} err)`;
      if ((stats.llmSuppressed || 0) > 0) {
        llmText += ` | ${stats.llmSuppressed} suppressed`;
      }
    } else {
      llmText = 'Disabled';
    }
  } catch {
    llmText = 'Not loaded';
  }

  // --- System health ---
  const uptimeSec = Math.floor(process.uptime());
  const uptimeH = Math.floor(uptimeSec / 3600);
  const uptimeM = Math.floor((uptimeSec % 3600) / 60);
  const heapMB = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(0);
  let jsonlInfo = '';
  try {
    const { getStats: getTrainingStats } = require('../ml/jsonl-writer.js');
    const jStats = getTrainingStats();
    jsonlInfo = ` | JSONL: ${jStats.recordCount} records (${jStats.fileSizeMB}MB)`;
  } catch { /* non-fatal */ }
  const healthText = `Up ${uptimeH}h${uptimeM}m | Heap ${heapMB}MB${jsonlInfo}`;

  // --- Phase 0b: per-scan ledger rollup (operational coverage) ---
  // `ledger` was resolved above (Coverage uses it). explicit null → omit the section.
  const ledgerField = formatLedgerField(ledger);

  const now = new Date();
  const readableTime = now.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    embeds: [{
      title: '\uD83D\uDCCA MUAD\'DIB Daily Report',
      color: 0x3498db,
      fields: [
        { name: 'Flux', value: fluxText, inline: false },
        { name: 'Scanned', value: scannedText, inline: true },
        { name: 'Clean', value: `${hClean}`, inline: true },
        { name: 'Suspects', value: `${hSuspect}`, inline: true },
        { name: 'Errors', value: formatErrorBreakdown(stats.errors, stats.errorsByType), inline: true },
        { name: 'Coverage', value: coverageText, inline: true },
        { name: 'Timeouts', value: timeoutText, inline: true },
        { name: 'vs Yesterday', value: trendsText, inline: false },
        { name: 'ML', value: mlText, inline: true },
        { name: 'LLM Detective', value: llmText, inline: true },
        { name: 'Top Suspects', value: top3Text, inline: false }
      ],
      footer: {
        // Headline-source annotation: 'ledger' = window-exact [last report → now]
        // (completed/deduped scans), 'counters' = in-memory fallback (ledger
        // unavailable — pre-upgrade behavior).
        text: `MUAD'DIB - Daily summary | headline: ${headline ? 'ledger — completed/deduped, exact 24h window' : 'counters (in-memory fallback)'} | ${readableTime}`
      },
      timestamp: now.toISOString()
    }, {
      // --- Embed 2: Ops / system state (kept OUT of the daily headline) ---
      // Operator feedback: a daily that mixes 24h outcome with multi-day system state
      // reads as failure when it isn't. Each line here carries its own clock:
      //   • Ledger      → 24h window, in name@version scan EVENTS (NOT package names —
      //                   the name ratio is the headline's "Noms uniques"). `dropped` folds
      //                   in recoverable spill (backlog awaiting drain) + queue-cap evictions
      //                   + burst-extras; `vanished` is the distinct name@version subset never
      //                   (re)scanned in-window — also version-granular, and it too still
      //                   includes not-yet-drained spill, so neither is a registry-removal count.
      //   • Stability   → cumulative since the 08:00 reset (backlog = point-in-time depth
      //                   of the persistent spill file, the one snapshot in this field).
      //   • Degradations / System → instantaneous snapshot (degradations have no TTL: if
      //                   shown, the condition is active right now, not earlier in the window).
      title: '⚙️ Ops / état système',
      color: 0x95a5a6,
      description: 'Ledger = fenêtre 24h en events name@version (pas des noms de paquets — voir « Coverage » dans le headline) · « Non scannés » sépare spill récupérable (drainable) et évincés (perdus) · Stability = cumulé depuis 08:00 (backlog = instantané) · Degradations/System = instantané',
      fields: [
        ...((stats.sandboxDeferred || stats.deferredProcessed || stats.deferredExpired)
          ? [{ name: 'Deferred Sandbox', value: `Enqueued: ${stats.sandboxDeferred || 0} | Processed: ${stats.deferredProcessed || 0} | Expired: ${stats.deferredExpired || 0}`, inline: false }]
          : []),
        { name: 'Stability (cumulé depuis 08:00)', value: _stabilityFieldValue(stats), inline: false },
        { name: 'Degradations (actif maintenant)', value: _degradationsFieldValue(), inline: false },
        ...(ledgerField ? [ledgerField] : []),
        { name: 'System', value: healthText, inline: false }
      ],
      timestamp: now.toISOString()
    }]
  };
}

/**
 * Send the daily report webhook and reset counters.
 * @param {Object} stats - In-memory stats object (mutable — counters will be reset)
 * @param {Array} dailyAlerts - In-memory daily alerts array (will be cleared)
 * @param {Set} recentlyScanned - In-memory recently scanned set (will be cleared)
 * @param {Map} downloadsCache - In-memory downloads cache (will be cleared)
 */
async function sendDailyReport(stats, dailyAlerts, recentlyScanned, downloadsCache) {
  // Dead-zone guard (defense in depth): never send or stamp before the 08:00 Paris window.
  // The scheduled gate (isDailyReportDue) already excludes 00:00–07:59, but an ungated /
  // manual / test caller firing at e.g. 00:43 would otherwise write-ahead the NEW day's date
  // (below) and suppress that day's real report. This makes the early stamp impossible.
  if (getParisHour() < DAILY_REPORT_HOUR) {
    console.log(`[MONITOR] Daily report suppressed: before ${DAILY_REPORT_HOUR}:00 Paris (hour=${getParisHour()})`);
    return;
  }
  // Phase 0b: compute the ledger rollup ONCE so the embed shows exactly the numbers
  // we persist (no double-scan, no drift between Discord and the on-disk metrics).
  // Resolved BEFORE the empty-skip and the reconcile: when the ledger headline is
  // available it IS the published number (window [last report → now], restart-proof),
  // and the counter-based machinery below only runs as fallback.
  const ledgerRollup = safeLedgerRollup();
  const headline = (ledgerRollup && ledgerRollup.headline && ledgerRollup.headline.scanned > 0)
    ? ledgerRollup.headline : null;

  if (!headline) {
    // Crash-safe FALLBACK headline: a restart-storm around report time can zero the
    // in-memory counter (the monitor OOM-restarts ~10×/day). Floor scanned/clean/suspect
    // at the durable scan-stats delta so we never publish "5" when ~44k were really
    // scanned. Not applied when the ledger headline is used — that one is window-exact.
    reconcileDailyHeadline(stats);
  }

  // Never send an empty report (0 scanned — restart with no work done)
  const publishedScanned = headline ? headline.scanned : stats.scanned;
  if (publishedScanned === 0) {
    console.log('[MONITOR] Daily report skipped (0 packages scanned)');
    return;
  }

  // Write-ahead: mark today's report as sent BEFORE the webhook HTTP request.
  // If the process is killed (SIGKILL) during sendWebhook, the date is already
  // recorded on disk and prevents duplicate reports on next startup. The same
  // write-ahead stamps lastReportTs = start of the next report's ledger window.
  const today = getParisDateString();
  stats.lastDailyReportDate = today;
  // Persist the monotonic scan-stats counter as the baseline for the NEXT report's
  // delta. Written before the (now last) webhook so a mid-send kill can't double-count.
  saveLastDailyReportDate(today, captureScanStatsBaseline());
  // Observability: the success path previously logged nothing, which made the late-fire bug
  // invisible in the journal. Log the stamped date + the actual Paris hour (an on-time 08:00
  // fire vs a catch-up at hour 14 are now distinguishable) + the headline count + source.
  console.log(`[MONITOR] Daily report firing for ${today} (hour=${getParisHour()} Paris, scanned=${publishedScanned}, headline=${headline ? 'ledger' : 'counters'})`);

  const payload = buildDailyReportEmbed(stats, dailyAlerts, ledgerRollup);

  // Persist locally with full raw metrics (independent of webhook — enables trend analysis).
  // Headline (scanned/clean/suspect/byTier) follows the same source as the embed: ledger
  // window when available, in-memory counters otherwise. headlineSource records which.
  persistDailyReport(payload, {
    headlineSource: headline ? 'ledger' : 'counters',
    scanned: publishedScanned,
    clean: headline ? headline.clean : stats.clean,
    suspect: headline ? headline.suspect : stats.suspect,
    errors: stats.errors,
    errorsByType: { ...stats.errorsByType },
    avgScanTimeMs: stats.scanned > 0 ? Math.round(stats.totalTimeMs / stats.scanned) : 0,
    suspectByTier: headline ? { ...headline.byTier } : { ...stats.suspectByTier },
    mlFiltered: stats.mlFiltered || 0,
    llmAnalyzed: stats.llmAnalyzed || 0,
    llmSuppressed: stats.llmSuppressed || 0,
    sandboxDeferred: stats.sandboxDeferred || 0,
    deferredProcessed: stats.deferredProcessed || 0,
    deferredExpired: stats.deferredExpired || 0,
    changesStreamPackages: stats.changesStreamPackages || 0,
    // Honest version-collapsed coverage (AUDIT 4): top-level mirror of the
    // ledger fields so trend analysis can read them without descending into
    // metrics.ledger. null when the ledger window was empty.
    distinctPackages: ledgerRollup ? (ledgerRollup.distinctPackages ?? null) : null,
    distinctScanned: ledgerRollup ? (ledgerRollup.distinctScanned ?? null) : null,
    distinctCoverage: ledgerRollup ? (ledgerRollup.distinctCoverage ?? null) : null,
    restartsToday: stats.restartsToday || 0,
    temporalLoadShed: stats.temporalLoadShed || 0,
    queueHardDrops: stats.queueHardDrops || 0,
    ledger: ledgerRollup || null,
    topSuspects: dailyAlerts.slice().sort((a, b) => (b.score || 0) - (a.score || 0) || b.findingsCount - a.findingsCount).slice(0, 10)
  });

  // Reset daily counters
  stats.scanned = 0;
  stats.clean = 0;
  stats.suspect = 0;
  stats.suspectByTier.t1 = 0;
  stats.suspectByTier.t1a = 0;
  stats.suspectByTier.t1b = 0;
  stats.suspectByTier.t2 = 0;
  stats.suspectByTier.t3 = 0;
  stats.errors = 0;
  stats.errorsByType.too_large = 0;
  stats.errorsByType.tar_failed = 0;
  stats.errorsByType.archive_failed = 0;
  stats.errorsByType.unsupported_format = 0;
  stats.errorsByType.http_error = 0;
  stats.errorsByType.timeout = 0;
  stats.errorsByType.static_timeout = 0;
  stats.errorsByType.other = 0;
  stats.totalTimeMs = 0;
  stats.mlFiltered = 0;
  stats.llmAnalyzed = 0;
  stats.llmSuppressed = 0;
  stats.sandboxDeferred = 0;
  stats.deferredProcessed = 0;
  stats.deferredExpired = 0;
  // Reset LLM detective internal stats
  try { require('../ml/llm-detective.js').resetStats(); } catch {}
  stats.changesStreamPackages = 0;
  stats.uniqueScanAttempts = 0;
  stats.npmPublishEventsSeen = 0;
  stats.pypiChangelogPackages = 0;
  stats.pypiChangelogEvents = 0;
  stats.npmCatchupSkippedSeqs = 0;
  stats.npmCatchupSkips = 0;
  stats.pypiCatchupSkippedEvents = 0;
  stats.pypiCatchupSkips = 0;
  stats.pypiWheelsScanned = 0;
  stats.pypiSkippedNoArchive = 0;
  stats.temporalLoadShed = 0;
  stats.queueHardDrops = 0;
  stats.rssFallbackCount = 0;
  dailyAlerts.length = 0;
  recentlyScanned.clear();
  alertedPackageRules.clear();
  // Flush and clear pending scope groups on daily reset
  for (const [, group] of pendingGrouped) {
    clearTimeout(group.timer);
  }
  pendingGrouped.clear();
  downloadsCache.clear();
  // Reset the durable daily-stats counter. Done BEFORE the (now last) webhook so a
  // SIGKILL during the send can't leave the counter un-reset (which would double-count
  // into the next day's report). loadDailyStats() treats the absent file as zeros.
  resetDailyStats();
  // C3: Flush scan memory to disk on daily reset (ensures no data loss)
  saveScanMemory();

  // Send webhook LAST (best-effort). The reset + baseline above are already durable,
  // so a kill during the send loses only the Discord ping — never the accounting.
  const url = getWebhookUrl();
  if (url) {
    try {
      await sendWebhook(url, payload, { rawPayload: true });
      console.log('[MONITOR] Daily report sent');
      // Confirm delivery on the just-persisted file so boot redelivery won't resend it.
      const persisted = loadPersistedReport(today);
      if (persisted) markReportDelivered(persisted.filePath, persisted.data);
    } catch (err) {
      // Webhook failed (DNS/network/5xx after retries). The report stays on disk with
      // delivered=false → it will be redelivered on the next daemon boot (AUDIT 3).
      console.error(`[MONITOR] Daily report webhook failed: ${err.message} — left undelivered for boot redelivery`);
    }
  } else {
    console.log('[MONITOR] Daily report persisted locally (no webhook URL configured)');
  }
}

// --- CLI report helpers (muaddib report --now / --status) ---

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
async function sendReportNow(stats) {
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

  // Update lastDailyReportDate on disk — but ONLY at/after 08:00 Paris. A manual report run
  // before 08:00 is a deliberate operator override (we still SEND it), but it must NOT stamp
  // today's date: hasReportBeenSentToday() keys off the Paris calendar date, so an early
  // stamp would suppress that day's scheduled 08:00 report (the exact failure we're fixing).
  if (getParisHour() >= DAILY_REPORT_HOUR) {
    const today = getParisDateString();
    const stateRaw = loadStateRaw();
    const state = {
      npmLastPackage: stateRaw.npmLastPackage || '',
      pypiLastPackage: stateRaw.pypiLastPackage || ''
    };
    stats.lastDailyReportDate = today;
    saveState(state, stats);
    saveLastDailyReportDate(today);
  } else {
    console.log(`[MONITOR] Manual report sent; not stamping (before ${DAILY_REPORT_HOUR}:00 Paris — the scheduled report will still fire today)`);
  }

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

module.exports = {
  // Mutable state
  alertedPackageRules,
  SCOPE_GROUP_WINDOW_MS,
  pendingGrouped,

  // Constants
  HIGH_INTENT_TYPES,
  DAILY_REPORT_HOUR,
  ALERTED_PACKAGES_MAX,

  // Functions
  getWebhookUrl,
  getWebhookThreshold,
  shouldSendWebhook,
  buildMonitorWebhookPayload,
  registryLink,
  buildIOCPreAlertEmbed,
  sendIOCPreAlert,
  buildCampaignPreAlertEmbed,
  sendCampaignPreAlert,
  buildBurstPreAlertEmbed,
  sendBurstPreAlert,
  burstPreAlertWebhookEnabled,
  matchVersionedIOC,
  computeRiskLevel,
  computeRiskScore,
  computeReputationFactor,
  hasDangerousLifecycle,
  triageRisk,
  persistAlert,
  persistDailyReport,
  listPersistedReportDates,
  loadPersistedReport,
  markReportDelivered,
  resendDailyReport,
  redeliverPendingReportOnBoot,
  computeAlertPriority,
  buildAlertData,
  trySendWebhook,
  extractScope,
  bufferScopedWebhook,
  flushScopeGroup,
  buildTemporalWebhookEmbed,
  buildTemporalAstWebhookEmbed,
  buildPublishAnomalyWebhookEmbed,
  buildMaintainerChangeWebhookEmbed,
  buildCanaryExfiltrationWebhookEmbed,
  buildDailyReportEmbed,
  formatLedgerField,
  sendDailyReport,
  buildReportFromDisk,
  buildReportEmbedFromDisk,
  sendReportNow,
  getReportStatus,
  loadYesterdayMetrics,
  formatDelta
};
