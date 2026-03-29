/**
 * monitor/webhook.js — Webhook/Discord/alert-related functions extracted from monitor.js
 *
 * Contains: webhook decision logic, Discord embed builders, alert persistence,
 * daily report generation, scope grouping, and all related helpers.
 */

const fs = require('fs');
const path = require('path');

const { sendWebhook } = require('../webhook.js');
const {
  atomicWriteFileSync,
  ALERTS_LOG_DIR,
  DAILY_REPORTS_LOG_DIR,
  getParisDateString,
  getParisHour,
  loadScanStats,
  loadDetections,
  loadLastDailyReportDate,
  saveLastDailyReportDate,
  saveDailyStats,
  resetDailyStats,
  saveScanMemory,
  shouldSuppressByMemory,
  recordScanMemory,
  loadState,
  saveState,
  loadStateRaw,
  getScansSinceLastMemoryPersist,
  setScansSinceLastMemoryPersist,
  STATE_FILE
} = require('./state.js');
const {
  HIGH_CONFIDENCE_MALICE_TYPES,
  hasIOCMatch,
  hasHighOrCritical,
  hasHighConfidenceThreat,
  hasTyposquat,
  hasLifecycleWithIntent,
  isSuspectClassification,
  formatErrorBreakdown
} = require('./classify.js');

// --- Mutable state ---

// Webhook dedup: track alerted packages by name -> Set<rule_ids> (cleared with daily report).
// If a new version triggers the same rules, skip the webhook. If new rules appear, let it through.
const alertedPackageRules = new Map();

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

const DAILY_REPORT_HOUR = 8; // 08:00 Paris time (Europe/Paris)

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
 * Layer 1: Send immediate IOC pre-alert webhook when a known malicious package
 * appears in the changes stream, BEFORE tarball download.
 * Safety net for packages that get unpublished before scanning completes.
 * @param {string} name - Package name matching IOC database
 * @param {string} [version] - Version if known (from CouchDB doc)
 */
async function sendIOCPreAlert(name, version) {
  const url = getWebhookUrl();
  if (!url) return;

  const npmLink = `https://www.npmjs.com/package/${encodeURIComponent(name)}`;
  const versionStr = version ? `@${version}` : '';

  const payload = {
    embeds: [{
      title: '\u26a0\ufe0f IOC PRE-ALERT \u2014 Known Malicious Package',
      color: 0xe74c3c,
      fields: [
        { name: 'Package', value: `[${name}${versionStr}](${npmLink})`, inline: true },
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

  await sendWebhook(url, payload, { rawPayload: true });
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

function buildDailyReportEmbed(stats, dailyAlerts) {
  // Use in-memory stats (accumulated since last reset, restored from disk on restart)
  // instead of disk-based daily entries which can undercount due to UTC/Paris date mismatch
  const { top3: diskTop3 } = buildReportFromDisk();

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

  // Avg scan time from in-memory stats
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';

  // --- Coverage estimation ---
  // changesStreamPackages = total versions seen from npm changes stream (≈ published today)
  const published = stats.changesStreamPackages || 0;
  const coverageText = published > 0
    ? `${stats.scanned}/${published} (${(stats.scanned / published * 100).toFixed(0)}%)`
    : `${stats.scanned} scanned`;

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
    const dScanned = formatDelta(stats.scanned, yesterday.scanned || 0);
    const dSuspect = formatDelta(stats.suspect, yesterday.suspect || 0);
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

  const now = new Date();
  const readableTime = now.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    embeds: [{
      title: '\uD83D\uDCCA MUAD\'DIB Daily Report',
      color: 0x3498db,
      fields: [
        { name: 'Coverage', value: coverageText, inline: true },
        { name: 'Clean', value: `${stats.clean}`, inline: true },
        { name: 'Suspects', value: `${stats.suspect}`, inline: true },
        { name: 'Errors', value: formatErrorBreakdown(stats.errors, stats.errorsByType), inline: true },
        { name: 'Avg Scan Time', value: `${avg}s/pkg`, inline: true },
        { name: 'Timeouts', value: timeoutText, inline: true },
        { name: 'vs Yesterday', value: trendsText, inline: false },
        { name: 'ML', value: mlText, inline: true },
        { name: 'LLM Detective', value: llmText, inline: true },
        { name: 'Top Suspects', value: top3Text, inline: false },
        { name: 'System', value: healthText, inline: false }
      ],
      footer: {
        text: `MUAD'DIB - Daily summary | ${readableTime}`
      },
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

  const payload = buildDailyReportEmbed(stats, dailyAlerts);

  // Persist locally with full raw metrics (independent of webhook — enables trend analysis)
  persistDailyReport(payload, {
    scanned: stats.scanned,
    clean: stats.clean,
    suspect: stats.suspect,
    errors: stats.errors,
    errorsByType: { ...stats.errorsByType },
    avgScanTimeMs: stats.scanned > 0 ? Math.round(stats.totalTimeMs / stats.scanned) : 0,
    suspectByTier: { ...stats.suspectByTier },
    mlFiltered: stats.mlFiltered || 0,
    llmAnalyzed: stats.llmAnalyzed || 0,
    llmSuppressed: stats.llmSuppressed || 0,
    changesStreamPackages: stats.changesStreamPackages || 0,
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
  stats.suspectByTier.t1a = 0;
  stats.suspectByTier.t1b = 0;
  stats.suspectByTier.t2 = 0;
  stats.suspectByTier.t3 = 0;
  stats.errors = 0;
  stats.errorsByType.too_large = 0;
  stats.errorsByType.tar_failed = 0;
  stats.errorsByType.http_error = 0;
  stats.errorsByType.timeout = 0;
  stats.errorsByType.static_timeout = 0;
  stats.errorsByType.other = 0;
  stats.totalTimeMs = 0;
  stats.mlFiltered = 0;
  stats.llmAnalyzed = 0;
  stats.llmSuppressed = 0;
  // Reset LLM detective internal stats
  try { require('../ml/llm-detective.js').resetStats(); } catch {}
  stats.changesStreamPackages = 0;
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
  resetDailyStats();
  // C3: Flush scan memory to disk on daily reset (ensures no data loss)
  saveScanMemory();
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

  // Update lastDailyReportDate on disk
  const today = getParisDateString();
  const stateRaw = loadStateRaw();
  const state = {
    npmLastPackage: stateRaw.npmLastPackage || '',
    pypiLastPackage: stateRaw.pypiLastPackage || ''
  };
  stats.lastDailyReportDate = today;
  saveState(state, stats);
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

module.exports = {
  // Mutable state
  alertedPackageRules,
  SCOPE_GROUP_WINDOW_MS,
  pendingGrouped,

  // Constants
  HIGH_INTENT_TYPES,
  DAILY_REPORT_HOUR,

  // Functions
  getWebhookUrl,
  getWebhookThreshold,
  shouldSendWebhook,
  buildMonitorWebhookPayload,
  sendIOCPreAlert,
  matchVersionedIOC,
  computeRiskLevel,
  computeRiskScore,
  computeReputationFactor,
  persistAlert,
  persistDailyReport,
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
  sendDailyReport,
  buildReportFromDisk,
  buildReportEmbedFromDisk,
  sendReportNow,
  getReportStatus,
  loadYesterdayMetrics,
  formatDelta
};
