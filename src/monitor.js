const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { run } = require('./index.js');
const { runSandbox, isDockerAvailable } = require('./sandbox.js');
const { sendWebhook } = require('./webhook.js');
const { detectSuddenLifecycleChange } = require('./temporal-analysis.js');
const { detectSuddenAstChanges } = require('./temporal-ast-diff.js');
const { detectPublishAnomaly } = require('./publish-anomaly.js');
const { detectMaintainerChange } = require('./maintainer-change.js');
const { downloadToFile, extractTarGz, sanitizePackageName } = require('./shared/download.js');
const { MAX_TARBALL_SIZE } = require('./shared/constants.js');

const STATE_FILE = path.join(__dirname, '..', 'data', 'monitor-state.json');
const ALERTS_FILE = path.join(__dirname, '..', 'data', 'monitor-alerts.json');
const DETECTIONS_FILE = path.join(__dirname, '..', 'data', 'detections.json');
const SCAN_STATS_FILE = path.join(__dirname, '..', 'data', 'scan-stats.json');
const POLL_INTERVAL = 60_000;
const SCAN_TIMEOUT_MS = 180_000; // 3 minutes per package

// --- Stats counters ---

const stats = {
  scanned: 0,
  clean: 0,
  suspect: 0,
  errors: 0,
  totalTimeMs: 0,
  lastReportTime: Date.now(),
  lastDailyReportDate: null // YYYY-MM-DD (Paris) of last daily report sent
};

// Track daily suspects for the daily report (name, version, ecosystem, findingsCount)
const dailyAlerts = [];

// Deduplication: track recently scanned packages (cleared every 24h with daily report)
const recentlyScanned = new Set();

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

let verboseMode = false;

function isVerboseMode() {
  if (verboseMode) return true;
  const env = process.env.MUADDIB_MONITOR_VERBOSE;
  return env !== undefined && env.toLowerCase() === 'true';
}

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

// --- Webhook alerting ---

function getWebhookUrl() {
  return process.env.MUADDIB_WEBHOOK_URL || null;
}

function shouldSendWebhook(result, sandboxResult) {
  if (!getWebhookUrl()) return false;

  // If sandbox ran, it is the final arbiter
  if (sandboxResult && sandboxResult.score !== undefined) {
    return sandboxResult.score > 0;
  }

  // No sandbox — only send webhook for confirmed IOC matches
  // (known_malicious_package, known_malicious_hash, pypi_malicious_package, etc.)
  if (hasIOCMatch(result)) return true;

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
  if (summary.critical > 0) return 'CRITICAL';
  if (summary.high > 0) return 'HIGH';
  if (summary.medium > 0) return 'MEDIUM';
  if (summary.low > 0) return 'LOW';
  return 'CLEAN';
}

function computeRiskScore(summary) {
  const raw = (summary.critical || 0) * 25
            + (summary.high || 0) * 15
            + (summary.medium || 0) * 5
            + (summary.low || 0) * 1;
  return Math.min(raw, 100);
}

async function trySendWebhook(name, version, ecosystem, result, sandboxResult) {
  if (!shouldSendWebhook(result, sandboxResult)) {
    if (sandboxResult && sandboxResult.score === 0) {
      console.log(`[MONITOR] FALSE POSITIVE (sandbox clean): ${name}@${version}`);
    }
    return;
  }
  const url = getWebhookUrl();
  const payload = buildMonitorWebhookPayload(name, version, ecosystem, result, sandboxResult);
  const webhookData = {
    target: `${ecosystem}/${name}@${version}`,
    timestamp: payload.timestamp,
    ecosystem,
    summary: {
      ...result.summary,
      riskLevel: computeRiskLevel(result.summary),
      riskScore: computeRiskScore(result.summary)
    },
    threats: result.threats
  };
  if (sandboxResult && sandboxResult.score > 0) {
    webhookData.sandbox = {
      score: sandboxResult.score,
      severity: sandboxResult.severity
    };
  }
  try {
    await sendWebhook(url, webhookData);
    console.log(`[MONITOR] Webhook sent for ${name}@${version}`);
  } catch (err) {
    console.error(`[MONITOR] Webhook failed for ${name}@${version}: ${err.message}`);
  }
}

// --- Temporal analysis integration ---

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

async function tryTemporalAlert(temporalResult) {
  // Temporal anomalies are logged only — no webhook unless --verbose
  console.log(`[MONITOR] ANOMALY (logged only): temporal lifecycle change for ${temporalResult.packageName}`);
  if (!isVerboseMode()) return;

  const url = getWebhookUrl();
  if (!url) return;

  const payload = buildTemporalWebhookEmbed(temporalResult);
  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log(`[MONITOR] Temporal webhook sent for ${temporalResult.packageName} (verbose mode)`);
  } catch (err) {
    console.error(`[MONITOR] Temporal webhook failed for ${temporalResult.packageName}: ${err.message}`);
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

async function tryTemporalAstAlert(astResult) {
  // AST anomalies are logged only — no webhook unless --verbose
  console.log(`[MONITOR] ANOMALY (logged only): AST change for ${astResult.packageName}`);
  if (!isVerboseMode()) return;

  const url = getWebhookUrl();
  if (!url) return;

  const payload = buildTemporalAstWebhookEmbed(astResult);
  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log(`[MONITOR] Temporal AST webhook sent for ${astResult.packageName} (verbose mode)`);
  } catch (err) {
    console.error(`[MONITOR] Temporal AST webhook failed for ${astResult.packageName}: ${err.message}`);
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

async function tryTemporalPublishAlert(publishResult) {
  // Publish anomalies are logged only — no webhook unless --verbose
  console.log(`[MONITOR] ANOMALY (logged only): publish frequency for ${publishResult.packageName}`);
  if (!isVerboseMode()) return;

  const url = getWebhookUrl();
  if (!url) return;

  const payload = buildPublishAnomalyWebhookEmbed(publishResult);
  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log(`[MONITOR] Publish anomaly webhook sent for ${publishResult.packageName} (verbose mode)`);
  } catch (err) {
    console.error(`[MONITOR] Publish anomaly webhook failed for ${publishResult.packageName}: ${err.message}`);
  }
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

async function tryTemporalMaintainerAlert(maintainerResult) {
  // Maintainer changes are logged only — no webhook unless --verbose
  console.log(`[MONITOR] ANOMALY (logged only): maintainer change for ${maintainerResult.packageName}`);
  if (!isVerboseMode()) return;

  const url = getWebhookUrl();
  if (!url) return;

  const payload = buildMaintainerChangeWebhookEmbed(maintainerResult);
  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log(`[MONITOR] Maintainer change webhook sent for ${maintainerResult.packageName} (verbose mode)`);
  } catch (err) {
    console.error(`[MONITOR] Maintainer change webhook failed for ${maintainerResult.packageName}: ${err.message}`);
  }
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
    fs.writeFileSync(STATE_FILE, JSON.stringify(persistedState, null, 2), 'utf8');
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
    fs.writeFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2), 'utf8');
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
    fs.writeFileSync(DETECTIONS_FILE, JSON.stringify(data, null, 2), 'utf8');
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
    const dir = path.dirname(SCAN_STATS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`[MONITOR] Failed to save scan stats: ${err.message}`);
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
          findings: result.threats.map(t => ({
            rule: t.rule_id || t.type,
            severity: t.severity,
            file: t.file
          }))
        };
        appendAlert(alert);
        updateScanStats('clean');
        return { sandboxResult: null, staticClean: true };
      } else {
        stats.suspect++;
        console.log(`[MONITOR] SUSPECT: ${name}@${version} (${counts.join(', ')})`);

        // Sandbox: run dynamic analysis on HIGH/CRITICAL findings
        let sandboxResult = null;
        if (hasHighOrCritical(result) && isSandboxEnabled() && sandboxAvailable) {
          try {
            const canary = isCanaryEnabled();
            console.log(`[MONITOR] SANDBOX: launching for ${name}@${version}${canary ? ' (canary: on)' : ''}...`);
            sandboxResult = await runSandbox(name, { canary });
            console.log(`[MONITOR] SANDBOX: ${name}@${version} → score: ${sandboxResult.score}, severity: ${sandboxResult.severity}`);

            // Check for canary exfiltration findings and send dedicated alert
            const canaryFindings = (sandboxResult.findings || []).filter(f => f.type === 'canary_exfiltration');
            if (canaryFindings.length > 0) {
              console.log(`[MONITOR] CANARY EXFILTRATION: ${name}@${version} — ${canaryFindings.length} token(s) stolen!`);
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
                } catch (webhookErr) {
                  console.error(`[MONITOR] Canary webhook failed for ${name}@${version}: ${webhookErr.message}`);
                }
              }
            }
          } catch (err) {
            console.error(`[MONITOR] SANDBOX error for ${name}@${version}: ${err.message}`);
          }
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
          findings: result.threats.map(t => ({
            rule: t.rule_id || t.type,
            severity: t.severity,
            file: t.file
          }))
        };

        if (sandboxResult && sandboxResult.score > 0) {
          alert.sandbox = {
            score: sandboxResult.score,
            severity: sandboxResult.severity,
            findings: sandboxResult.findings
          };
        }

        appendAlert(alert);

        const findingTypes = [...new Set(result.threats.map(t => t.type))];
        const maxSeverity = result.summary.critical > 0 ? 'CRITICAL'
          : result.summary.high > 0 ? 'HIGH'
          : result.summary.medium > 0 ? 'MEDIUM' : 'LOW';
        appendDetection(name, version, ecosystem, findingTypes, maxSeverity);

        dailyAlerts.push({ name, version, ecosystem, findingsCount: result.summary.total });
        await trySendWebhook(name, version, ecosystem, result, sandboxResult);
        return { sandboxResult, staticClean: false };
      }
    }
  } catch (err) {
    stats.errors++;
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
      stats.errors++;
      console.error(`[MONITOR] Queue error for ${item.name}: ${err.message}`);
    }
  }
}

// --- Stats reporting ---

function reportStats() {
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';
  console.log(`[MONITOR] Stats: ${stats.scanned} scanned, ${stats.clean} clean, ${stats.suspect} suspect, ${stats.errors} error${stats.errors !== 1 ? 's' : ''}, avg ${avg}s/pkg`);
  stats.lastReportTime = Date.now();
}

const DAILY_REPORT_HOUR = 8; // 08:00 Paris time (Europe/Paris)

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
 * Check if the daily report is due: Paris hour matches DAILY_REPORT_HOUR
 * and we haven't already sent one today.
 */
function isDailyReportDue() {
  const parisHour = getParisHour();
  if (parisHour !== DAILY_REPORT_HOUR) return false;
  const today = getParisDateString();
  return stats.lastDailyReportDate !== today;
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
        { name: 'Errors', value: `${stats.errors}`, inline: true },
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
  const url = getWebhookUrl();
  if (!url) return;

  const payload = buildDailyReportEmbed();
  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log('[MONITOR] Daily report sent');
  } catch (err) {
    console.error(`[MONITOR] Daily report webhook failed: ${err.message}`);
  }

  // Reset daily counters
  stats.scanned = 0;
  stats.clean = 0;
  stats.suspect = 0;
  stats.errors = 0;
  stats.totalTimeMs = 0;
  dailyAlerts.length = 0;
  recentlyScanned.clear();
  stats.lastDailyReportDate = getParisDateString();
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

  // If no report ever sent (null), include ALL daily entries (first report = full history).
  // After first send, lastDailyReportDate is set and subsequent reports show delta only.
  const sinceDays = lastDate
    ? scanData.daily.filter(d => d.date > lastDate)
    : scanData.daily;

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
    : detections.detections;

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
  const stateRaw = loadStateRaw();
  const state = {
    npmLastPackage: stateRaw.npmLastPackage || '',
    pypiLastPackage: stateRaw.pypiLastPackage || ''
  };
  stats.lastDailyReportDate = getParisDateString();
  saveState(state);

  return { sent: true, message: 'Daily report sent' };
}

/**
 * Get report status for `muaddib report --status`.
 */
function getReportStatus() {
  const stateRaw = loadStateRaw();
  const lastDate = stateRaw.lastDailyReportDate || null;

  // Count packages scanned since last report (all history if never sent)
  const scanData = loadScanStats();
  const sinceDays = lastDate
    ? scanData.daily.filter(d => d.date > lastDate)
    : scanData.daily;

  let scannedSince = 0;
  for (const d of sinceDays) {
    scannedSince += d.scanned || 0;
  }

  // Compute next report time
  const today = getParisDateString();
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
  const url = 'https://registry.npmjs.org/-/rss?descending=true&limit=50';

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
    return 0;
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
    return 0;
  }
}

// --- Main loop ---

async function startMonitor(options) {
  if (options && options.verbose) {
    setVerboseMode(true);
  }

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
  if (isVerboseMode()) {
    console.log('[MONITOR] Verbose mode ON — ALL anomalies sent as webhooks (temporal, publish, maintainer, AST)');
  } else {
    console.log('[MONITOR] Strict webhook mode — only IOC matches, sandbox confirmations, and canary exfiltrations trigger webhooks');
    console.log('[MONITOR]   Temporal/publish/maintainer anomalies are logged but NOT sent as webhooks');
    console.log('[MONITOR]   Use --verbose to send all anomalies as webhooks');
  }

  const state = loadState();
  console.log(`[MONITOR] State loaded — npm last: ${state.npmLastPackage || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}`);
  console.log(`[MONITOR] Polling every ${POLL_INTERVAL / 1000}s. Ctrl+C to stop.\n`);

  let running = true;

  // SIGINT: send pending daily report, save state and exit
  process.on('SIGINT', async () => {
    console.log('\n[MONITOR] Stopping — sending pending daily report...');
    if (stats.scanned > 0) {
      await sendDailyReport();
    }
    saveState(state);
    reportStats();
    console.log('[MONITOR] State saved. Bye!');
    running = false;
    process.exit(0);
  });

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

  console.log(`[MONITOR] Found ${npmCount} npm + ${pypiCount} PyPI new packages`);
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
      stats.errors++;
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
      stats.errors++;
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

  // Send temporal webhooks only if the package is confirmed suspicious
  const hasSuspiciousTemporal = (temporalResult && temporalResult.suspicious)
    || (astResult && astResult.suspicious)
    || (publishResult && publishResult.suspicious)
    || (maintainerResult && maintainerResult.suspicious);

  if (hasSuspiciousTemporal) {
    // Sandbox ran and package is CLEAN → suppress temporal webhooks
    if (sandboxResult && sandboxResult.score === 0) {
      console.log(`[MONITOR] FALSE POSITIVE (sandbox clean, no alert): ${item.name}@${item.version}`);
    // Static scan is CLEAN (0 findings) and no sandbox ran → suppress temporal webhooks
    } else if (staticClean && !sandboxResult) {
      console.log(`[MONITOR] FALSE POSITIVE (static clean, no alert): ${item.name}@${item.version}`);
    // publish_anomaly alone → no webhook (too noisy, not actionable alone)
    } else if (isPublishAnomalyOnly(temporalResult, astResult, publishResult, maintainerResult)) {
      console.log(`[MONITOR] PUBLISH ANOMALY (alone, no alert): ${item.name}@${item.version}`);
    } else {
      // Sandbox confirmed threat (score > 0) OR static scan found threats → send webhooks
      if (temporalResult && temporalResult.suspicious) await tryTemporalAlert(temporalResult);
      if (astResult && astResult.suspicious) await tryTemporalAstAlert(astResult);
      if (publishResult && publishResult.suspicious) await tryTemporalPublishAlert(publishResult);
      if (maintainerResult && maintainerResult.suspicious) await tryTemporalMaintainerAlert(maintainerResult);
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
  trySendWebhook,
  computeRiskLevel,
  computeRiskScore,
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
  isPublishAnomalyOnly,
  isVerboseMode,
  setVerboseMode,
  hasIOCMatch,
  IOC_MATCH_TYPES,
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
  getReportStatus
};

// Standalone entry point: node src/monitor.js
if (require.main === module) {
  startMonitor().catch(err => {
    console.error('[MONITOR] Fatal error:', err.message);
    process.exit(1);
  });
}
