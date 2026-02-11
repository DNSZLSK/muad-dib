const { scanPackageJson } = require('./scanner/package.js');
const { scanShellScripts } = require('./scanner/shell.js');
const { analyzeAST } = require('./scanner/ast.js');
const { detectObfuscation } = require('./scanner/obfuscation.js');
const { scanDependencies } = require('./scanner/dependencies.js');
const { scanHashes } = require('./scanner/hash.js');
const { analyzeDataFlow } = require('./scanner/dataflow.js');
const { getPlaybook } = require('./response/playbooks.js');
const { getRule, PARANOID_RULES } = require('./rules/index.js');
const { saveReport } = require('./report.js');
const { saveSARIF } = require('./sarif.js');
const { scanTyposquatting, findPyPITyposquatMatch } = require('./scanner/typosquat.js');
const { sendWebhook } = require('./webhook.js');
const fs = require('fs');
const path = require('path');
const { scanGitHubActions } = require('./scanner/github-actions.js');
const { detectPythonProject, normalizePythonName } = require('./scanner/python.js');
const { loadCachedIOCs } = require('./ioc/updater.js');

// ============================================
// SCORING CONSTANTS
// ============================================
// Severity weights for risk score calculation (0-100)
// These values determine the impact of each threat type on the final score.
// Example: 4 CRITICAL threats = 100 (max score), 10 HIGH threats = 100
const SEVERITY_WEIGHTS = {
  // CRITICAL: Threats with immediate impact (active malware, data exfiltration)
  // High weight because a single critical threat justifies immediate action
  CRITICAL: 25,

  // HIGH: Serious threats (dangerous code, known malicious dependencies)
  // 10 HIGH threats reach the maximum score
  HIGH: 10,

  // MEDIUM: Potential threats (suspicious patterns, light obfuscation)
  // Moderate impact, requires investigation but not necessarily malicious
  MEDIUM: 3,

  // LOW: Informational findings, minimal impact on risk score
  LOW: 1
};

// Thresholds for determining the overall risk level
const RISK_THRESHOLDS = {
  CRITICAL: 75,  // >= 75: Immediate action required
  HIGH: 50,      // >= 50: Priority investigation
  MEDIUM: 25     // >= 25: Monitor
  // < 25 && > 0: LOW
  // === 0: SAFE
};

// Maximum score (capped)
const MAX_RISK_SCORE = 100;

// Paranoid mode scanner
function scanParanoid(targetPath) {
  const threats = [];

  function scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');

      // Ignore URLs (they often contain patterns like .git)
      const contentWithoutUrls = content.replace(/https?:\/\/[^\s"']+/g, '');

      for (const [, rule] of Object.entries(PARANOID_RULES)) {
        for (const pattern of rule.patterns) {
          if (contentWithoutUrls.includes(pattern)) {
            threats.push({
              type: rule.id,
              severity: rule.severity.toUpperCase(),
              message: `${rule.message}: "${pattern}"`,
              file: path.relative(targetPath, filePath),
              mitre: rule.mitre
            });
          }
        }
      }
    } catch {
      // Ignore read errors
    }
  }

  function walkDir(dir) {
    const excluded = ['node_modules', '.git', 'test', 'tests', 'src', 'vscode-extension', '.muaddib-cache', 'data', 'iocs', 'docker'];
    try {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        // Use lstatSync to avoid following symlinks
        const stat = fs.lstatSync(fullPath);

        if (stat.isSymbolicLink()) continue;

        if (stat.isDirectory()) {
          if (!excluded.includes(file)) {
            walkDir(fullPath);
          }
        } else if (file.endsWith('.js') || file.endsWith('.json') || file.endsWith('.sh')) {
          scanFile(fullPath);
        }
      }
    } catch {
      // Ignore walk errors
    }
  }

  walkDir(targetPath);
  return threats;
}

/**
 * Match detected Python dependencies against PyPI IOCs.
 * @param {Array<{name: string, version: string, file: string}>} deps
 * @param {string} targetPath
 * @returns {Array} threats
 */
function matchPythonIOCs(deps, targetPath) {
  if (deps.length === 0) return [];

  const iocs = loadCachedIOCs();
  const threats = [];

  for (const dep of deps) {
    const name = normalizePythonName(dep.name);
    let malicious = null;

    // Check wildcard (all versions malicious)
    if (iocs.pypiWildcardPackages && iocs.pypiWildcardPackages.has(name)) {
      const pkgList = iocs.pypiPackagesMap.get(name);
      malicious = pkgList ? pkgList.find(p => p.version === '*') : { name, version: '*', severity: 'critical' };
    }
    // Check specific version via Map
    else if (iocs.pypiPackagesMap && iocs.pypiPackagesMap.has(name)) {
      const pkgList = iocs.pypiPackagesMap.get(name);
      const cleanVersion = dep.version.replace(/^(==|>=|<=|~=|!=|>|<)/, '');
      malicious = pkgList.find(p => p.version === cleanVersion || p.version === dep.version || p.version === '*');
    }
    // Fallback: linear search
    else if (!iocs.pypiPackagesMap && iocs.pypi_packages) {
      malicious = iocs.pypi_packages.find(p => {
        if (normalizePythonName(p.name) !== name) return false;
        if (p.version === '*') return true;
        const cleanVersion = dep.version.replace(/^(==|>=|<=|~=|!=|>|<)/, '');
        return p.version === cleanVersion || p.version === dep.version;
      });
    }

    if (malicious) {
      const severity = (malicious.severity || 'critical').toUpperCase();
      const relFile = path.relative(targetPath, dep.file) || dep.file;
      threats.push({
        type: 'pypi_malicious_package',
        severity: severity,
        message: `Malicious PyPI package: ${dep.name}@${malicious.version} (source: ${malicious.source || 'OSV'})`,
        file: relFile
      });
    }
  }

  return threats;
}

/**
 * Check Python dependencies for PyPI typosquatting (Levenshtein only, no API).
 * @param {Array<{name: string, version: string, file: string}>} deps
 * @param {string} targetPath
 * @returns {Array} threats
 */
function checkPyPITyposquatting(deps, targetPath) {
  const threats = [];

  for (const dep of deps) {
    const match = findPyPITyposquatMatch(dep.name);
    if (match) {
      const relFile = path.relative(targetPath, dep.file) || dep.file;
      threats.push({
        type: 'pypi_typosquat_detected',
        severity: 'HIGH',
        message: `PyPI package "${dep.name}" resembles "${match.original}" (${match.type}, distance: ${match.distance})`,
        file: relFile
      });
    }
  }

  return threats;
}

async function run(targetPath, options = {}) {
  // Detect Python project (synchronous, fast file reads)
  const pythonDeps = detectPythonProject(targetPath);

  // Parallel execution of all independent scanners
  const [
    packageThreats,
    shellThreats,
    astThreats,
    obfuscationThreats,
    dependencyThreats,
    hashThreats,
    dataflowThreats,
    typosquatThreats,
    ghActionsThreats,
    pythonThreats,
    pypiTyposquatThreats
  ] = await Promise.all([
    scanPackageJson(targetPath),
    scanShellScripts(targetPath),
    analyzeAST(targetPath),
    Promise.resolve(detectObfuscation(targetPath)),
    scanDependencies(targetPath),
    scanHashes(targetPath),
    analyzeDataFlow(targetPath),
    scanTyposquatting(targetPath),
    Promise.resolve(scanGitHubActions(targetPath)),
    Promise.resolve(matchPythonIOCs(pythonDeps, targetPath)),
    Promise.resolve(checkPyPITyposquatting(pythonDeps, targetPath))
  ]);

  const threats = [
    ...packageThreats,
    ...shellThreats,
    ...astThreats,
    ...obfuscationThreats,
    ...dependencyThreats,
    ...hashThreats,
    ...dataflowThreats,
    ...typosquatThreats,
    ...ghActionsThreats,
    ...pythonThreats,
    ...pypiTyposquatThreats
  ];

  // Paranoid mode
  if (options.paranoid) {
    console.log('[PARANOID] Ultra-strict mode enabled\n');
    const paranoidThreats = scanParanoid(targetPath);
    threats.push(...paranoidThreats);
  }

  // Sandbox integration
  let sandboxData = null;
  if (options.sandboxResult && options.sandboxResult.findings) {
    const sr = options.sandboxResult;
    const pkg = sr.raw_report?.package || 'unknown';
    sandboxData = {
      package: pkg,
      score: sr.score,
      severity: sr.severity,
      findings: sr.findings,
      network: sr.raw_report?.network || null
    };
    for (const f of sr.findings) {
      threats.push({
        type: 'sandbox_' + f.type,
        severity: f.severity,
        message: f.detail,
        file: `[SANDBOX] ${pkg}`
      });
    }
  }

  // Deduplicate: same file + same type + same message = show once with count
  const deduped = [];
  const seen = new Map();
  for (const t of threats) {
    const key = `${t.file}::${t.type}::${t.message}`;
    if (seen.has(key)) {
      seen.get(key).count++;
    } else {
      const entry = { ...t, count: 1 };
      seen.set(key, entry);
      deduped.push(entry);
    }
  }

  // Enrich each threat with rules
  const enrichedThreats = deduped.map(t => {
    const rule = getRule(t.type);
    return {
      ...t,
      rule_id: rule.id || t.type,
      rule_name: rule.name || t.type,
      confidence: rule.confidence || 'medium',
      references: rule.references || [],
      mitre: t.mitre || rule.mitre,
      playbook: getPlaybook(t.type)
    };
  });

  // Calculate risk score (0-100) using deduplicated threats
  const criticalCount = deduped.filter(t => t.severity === 'CRITICAL').length;
  const highCount = deduped.filter(t => t.severity === 'HIGH').length;
  const mediumCount = deduped.filter(t => t.severity === 'MEDIUM').length;
  const lowCount = deduped.filter(t => t.severity === 'LOW').length;

  let riskScore = 0;
  riskScore += criticalCount * SEVERITY_WEIGHTS.CRITICAL;
  riskScore += highCount * SEVERITY_WEIGHTS.HIGH;
  riskScore += mediumCount * SEVERITY_WEIGHTS.MEDIUM;
  riskScore += lowCount * SEVERITY_WEIGHTS.LOW;
  riskScore = Math.min(MAX_RISK_SCORE, riskScore);

  const riskLevel = riskScore >= RISK_THRESHOLDS.CRITICAL ? 'CRITICAL'
                  : riskScore >= RISK_THRESHOLDS.HIGH ? 'HIGH'
                  : riskScore >= RISK_THRESHOLDS.MEDIUM ? 'MEDIUM'
                  : riskScore > 0 ? 'LOW'
                  : 'SAFE';

  // Python scan metadata
  const pythonInfo = pythonDeps.length > 0 ? {
    dependencies: pythonDeps.length,
    files: [...new Set(pythonDeps.map(d => path.relative(targetPath, d.file) || d.file))],
    threats: pythonThreats.length + pypiTyposquatThreats.length
  } : null;

  const result = {
    target: targetPath,
    timestamp: new Date().toISOString(),
    threats: enrichedThreats,
    python: pythonInfo,
    summary: {
      total: deduped.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      riskScore: riskScore,
      riskLevel: riskLevel
    },
    sandbox: sandboxData
  };

  // JSON output
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  }
  // HTML output
  else if (options.html) {
    saveReport(result, options.html);
    console.log(`[OK] HTML report generated: ${options.html}`);
  }
  // SARIF output
  else if (options.sarif) {
    saveSARIF(result, options.sarif);
    console.log(`[OK] SARIF report generated: ${options.sarif}`);
  }
  // Explain output
  else if (options.explain) {
    console.log(`\n[MUADDIB] Scanning ${targetPath}\n`);

    if (pythonInfo) {
      console.log(`[PYTHON] ${pythonInfo.dependencies} dependencies detected (${pythonInfo.files.join(', ')})`);
      if (pythonInfo.threats > 0) {
        console.log(`[PYTHON] ${pythonInfo.threats} malicious PyPI package(s) found!\n`);
      } else {
        console.log(`[PYTHON] No known malicious PyPI packages.\n`);
      }
    }

    if (enrichedThreats.length === 0) {
      console.log('[OK] No threats detected.\n');
    } else {
      console.log(`[ALERT] ${enrichedThreats.length} threat(s) detected:\n`);
      enrichedThreats.forEach((t, i) => {
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const countStr = t.count > 1 ? ` (x${t.count})` : '';
        console.log(`  ${i + 1}. [${t.severity}] ${t.rule_name}${countStr}`);
        console.log(`     Rule ID:    ${t.rule_id}`);
        console.log(`     File:       ${t.file}`);
        if (t.line) console.log(`     Line:       ${t.line}`);
        console.log(`     Confidence: ${t.confidence}`);
        console.log(`     Message:    ${t.message}`);
        if (t.mitre) console.log(`     MITRE:      ${t.mitre} (https://attack.mitre.org/techniques/${t.mitre.replace('.', '/')})`);
        if (t.references && t.references.length > 0) {
          console.log(`     References:`);
          t.references.forEach(ref => console.log(`       - ${ref}`));
        }
        console.log(`     Playbook:   ${t.playbook}`);
        console.log('');
      });
    }

    // Sandbox section (explain)
    if (sandboxData) {
      console.log(`\n[SANDBOX] Dynamic analysis — ${sandboxData.package}`);
      console.log(`  Score:    ${sandboxData.score}/100`);
      console.log(`  Severity: ${sandboxData.severity}`);
      if (sandboxData.findings.length === 0) {
        console.log('  No suspicious behavior detected.\n');
      } else {
        console.log(`  ${sandboxData.findings.length} finding(s):`);
        sandboxData.findings.forEach(f => {
          console.log(`    [${f.severity}] ${f.type}: ${f.detail}`);
        });
        console.log('');
      }
    }
  }
  // Normal output
  else {
    console.log(`\n[MUADDIB] Scanning ${targetPath}\n`);

    const scoreBar = '█'.repeat(Math.floor(result.summary.riskScore / 5)) + '░'.repeat(20 - Math.floor(result.summary.riskScore / 5));
    console.log(`[SCORE] ${result.summary.riskScore}/100 [${scoreBar}] ${result.summary.riskLevel}\n`);

    if (pythonInfo) {
      console.log(`[PYTHON] ${pythonInfo.dependencies} dependencies detected (${pythonInfo.files.join(', ')})`);
      if (pythonInfo.threats > 0) {
        console.log(`[PYTHON] ${pythonInfo.threats} malicious PyPI package(s) found!\n`);
      } else {
        console.log(`[PYTHON] No known malicious PyPI packages.\n`);
      }
    }

    if (deduped.length === 0) {
      console.log('[OK] No threats detected.\n');
    } else {
      console.log(`[ALERT] ${deduped.length} threat(s) detected:\n`);
      deduped.forEach((t, i) => {
        const countStr = t.count > 1 ? ` (x${t.count})` : '';
        console.log(`  ${i + 1}. [${t.severity}] ${t.type}${countStr}`);
        console.log(`     ${t.message}`);
        console.log(`     File: ${t.file}\n`);
      });

      console.log('[RESPONSE] Recommendations:\n');
      deduped.forEach(t => {
        const playbook = getPlaybook(t.type);
        if (playbook) {
          console.log(`  -> ${playbook}\n`);
        }
      });
    }

    // Sandbox section (normal)
    if (sandboxData) {
      console.log(`[SANDBOX] Dynamic analysis — ${sandboxData.package}`);
      console.log(`  Score:    ${sandboxData.score}/100`);
      console.log(`  Severity: ${sandboxData.severity}`);
      if (sandboxData.findings.length === 0) {
        console.log('  No suspicious behavior detected.\n');
      } else {
        console.log(`  ${sandboxData.findings.length} finding(s):`);
        sandboxData.findings.forEach(f => {
          console.log(`    [${f.severity}] ${f.type}: ${f.detail}`);
        });
        console.log('');
      }
    }
  }

  // Send webhook if configured
  if (options.webhook && threats.length > 0) {
    try {
      await sendWebhook(options.webhook, result);
      console.log(`[OK] Alert sent to webhook`);
    } catch (err) {
      console.log(`[WARN] Webhook send failed: ${err.message}`);
    }
  }

  // Calculate exit code based on fail level
  const failLevel = options.failLevel || 'high';
  const severityLevels = {
    critical: ['CRITICAL'],
    high: ['CRITICAL', 'HIGH'],
    medium: ['CRITICAL', 'HIGH', 'MEDIUM'],
    low: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  };
  
  const levelsToCheck = severityLevels[failLevel] || severityLevels.high;
  const failingThreats = deduped.filter(t => levelsToCheck.includes(t.severity));

  return failingThreats.length;
}

module.exports = { run };