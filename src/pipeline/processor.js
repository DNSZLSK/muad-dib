const fs = require('fs');
const path = require('path');
const { getRule } = require('../rules/index.js');
const { getPlaybook } = require('../response/playbooks.js');
const { computeReachableFiles } = require('../scanner/reachability.js');
const { applyFPReductions, applyCompoundBoosts, calculateRiskScore, getSeverityWeights } = require('../scoring.js');
const { buildIntentPairs } = require('../intent-graph.js');
const { debugLog } = require('../utils.js');

/**
 * Process raw threats: sandbox integration, dedup, compounds, FP reductions,
 * intent analysis, enrichment, and scoring.
 * @param {Array} threats - Raw threats array (mutated: sandbox threats pushed)
 * @param {string} targetPath - Directory being scanned
 * @param {object} options - CLI options
 * @param {Array} pythonDeps - Detected Python dependencies
 * @param {string[]} warnings - Warnings array
 * @returns {Promise<{result: object, deduped: Array, enrichedThreats: Array, sandboxData: object|null, pythonInfo: object|null, breakdown: Array, mostSuspiciousFile: string|null, maxFileScore: number, packageScore: number, globalRiskScore: number, scannerErrors: Array}>}
 */
async function process(threats, targetPath, options, pythonDeps, warnings, scannerErrors) {
  // Auto-sandbox: trigger sandbox analysis when static scan detects threats.
  // Preliminary score estimate: count CRITICAL/HIGH threats as a quick heuristic.
  // Only when --auto-sandbox flag is set, no explicit sandboxResult, and Docker available.
  if (options.autoSandbox && !options.sandboxResult) {
    const critCount = threats.filter(t => t.severity === 'CRITICAL').length;
    const highCount = threats.filter(t => t.severity === 'HIGH').length;
    const prelimScore = Math.min(100, critCount * 25 + highCount * 10);
    if (prelimScore >= 20) {
      try {
        const { isDockerAvailable, buildSandboxImage, runSandbox } = require('../sandbox/index.js');
        if (isDockerAvailable()) {
          console.log(`\n[AUTO-SANDBOX] Preliminary score ~${prelimScore} >= 20 — triggering sandbox analysis...`);
          const built = await buildSandboxImage();
          if (built) {
            const sbResult = await runSandbox(targetPath, { local: true, strict: false });
            if (sbResult && Array.isArray(sbResult.findings)) {
              options.sandboxResult = sbResult;
            }
          }
        } else {
          debugLog('[AUTO-SANDBOX] Docker not available — skipping sandbox');
        }
      } catch (e) {
        debugLog('[AUTO-SANDBOX] Error:', e && e.message);
        // Graceful fallback — sandbox is best-effort
      }
    }
  }

  // Sandbox integration
  let sandboxData = null;
  if (options.sandboxResult && Array.isArray(options.sandboxResult.findings)) {
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

  // Reachability analysis: determine which files are reachable from entry points
  let reachableFiles = null;
  if (!options.noReachability) {
    try {
      const reachability = computeReachableFiles(targetPath);
      if (!reachability.skipped) {
        reachableFiles = reachability.reachableFiles;
      }
    } catch (e) {
      debugLog('[REACHABILITY] error:', e?.message);
      // Graceful fallback — treat all files as reachable
    }
  }

  // Read package name and dependencies for FP reduction heuristics
  let packageName = null;
  let packageDeps = null;
  try {
    const pkgPath = path.join(targetPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      packageName = pkgData.name || null;
      packageDeps = pkgData.dependencies || null;
    }
  } catch { /* graceful fallback */ }

  // Cross-scanner compound: detached_process + suspicious_dataflow in same file
  // Catches cases where credential flow is detected by dataflow scanner, not AST scanner
  {
    const DIST_RE = /(?:^|[/\\])(?:dist|build|out|output)[/\\]|\.min\.js$|\.bundle\.js$/i;
    const fileMap = Object.create(null);
    for (const t of deduped) {
      if (t.file) {
        if (!fileMap[t.file]) fileMap[t.file] = [];
        fileMap[t.file].push(t);
      }
    }
    for (const file of Object.keys(fileMap)) {
      // Skip dist/build files — bundler aggregation creates coincidental co-occurrence
      // of detached_process + suspicious_dataflow. Real DPRK attacks target root files.
      if (DIST_RE.test(file)) continue;
      const fileThreats = fileMap[file];
      const hasDetached = fileThreats.some(t => t.type === 'detached_process');
      const hasCredFlow = fileThreats.some(t => t.type === 'suspicious_dataflow');
      const alreadyCompound = fileThreats.some(t => t.type === 'detached_credential_exfil');
      if (hasDetached && hasCredFlow && !alreadyCompound) {
        deduped.push({
          type: 'detached_credential_exfil',
          severity: 'CRITICAL',
          message: 'Detached process + credential dataflow — background exfiltration (cross-scanner compound).',
          file,
          count: 1
        });
      }
    }
  }

  // Audit v3 B6: lifecycle_file_exec compound — lifecycle script referencing a local JS file
  // that contains HIGH/CRITICAL threats is a strong indicator of install-time malware.
  {
    const lifecycleThreats = deduped.filter(t => t.type === 'lifecycle_script' && t.file === 'package.json');
    if (lifecycleThreats.length > 0) {
      // Extract referenced JS files from lifecycle script messages
      // Pattern: "node xxx.js", "node ./xxx.js", "node lib/setup.js"
      const NODE_FILE_RE = /\bnode\s+(?:\.\/)?([^\s"';&|]+\.(?:js|mjs|cjs))\b/;
      const referencedFiles = new Set();
      for (const lt of lifecycleThreats) {
        const match = lt.message && NODE_FILE_RE.exec(lt.message);
        if (match) referencedFiles.add(match[1]);
      }
      // Also check raw package.json scripts for file references
      try {
        const pkgPath = path.join(targetPath, 'package.json');
        if (fs.existsSync(pkgPath)) {
          const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
          const scripts = pkgData.scripts || {};
          const LIFECYCLE_NAMES = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall', 'prepare'];
          for (const name of LIFECYCLE_NAMES) {
            if (scripts[name]) {
              const m = NODE_FILE_RE.exec(scripts[name]);
              if (m) referencedFiles.add(m[1]);
            }
          }
        }
      } catch { /* ignore */ }

      if (referencedFiles.size > 0) {
        // Check if any referenced file has HIGH/CRITICAL threats
        const HIGH_SEV = new Set(['HIGH', 'CRITICAL']);
        for (const refFile of referencedFiles) {
          const normalizedRef = refFile.replace(/\\/g, '/');
          const fileThreats = deduped.filter(t =>
            t.file && t.file.replace(/\\/g, '/') === normalizedRef &&
            HIGH_SEV.has(t.severity)
          );
          if (fileThreats.length > 0) {
            const threatTypes = [...new Set(fileThreats.map(t => t.type))].join(', ');
            deduped.push({
              type: 'lifecycle_file_exec',
              severity: 'CRITICAL',
              message: `Lifecycle script executes ${refFile} which contains ${fileThreats.length} HIGH/CRITICAL threat(s): ${threatTypes}`,
              file: 'package.json',
              count: 1,
              compound: true
            });
            break; // One compound per package is enough
          }
        }
      }
    }
  }

  // FP reduction: legitimate frameworks produce high volumes of certain threat types.
  // A malware package typically has 1-3 occurrences, not dozens.
  applyFPReductions(deduped, reachableFiles, packageName, packageDeps);

  // Compound scoring: inject synthetic CRITICAL threats when co-occurring types
  // indicate unambiguous malice. Applied AFTER FP reductions to recover signals
  // that were individually downgraded (count-based, dist, reachability).
  applyCompoundBoosts(deduped);

  // Intent coherence analysis: detect source→sink pairs within files
  // Pass targetPath for destination-aware SDK pattern detection
  const intentResult = buildIntentPairs(deduped, targetPath);
  // Add intent threats to deduped before enrichment so they get rules/playbooks
  if (intentResult.intentThreats) {
    for (const it of intentResult.intentThreats) {
      // Respect reachability: downgrade intent threats in unreachable files
      if (reachableFiles && reachableFiles.size > 0 && it.file) {
        const normalizedFile = it.file.replace(/\\/g, '/');
        if (!reachableFiles.has(normalizedFile)) {
          it.severity = 'LOW';
          it.unreachable = true;
        }
      }
      deduped.push(it);
    }
  }

  // Enrich each threat with rules
  const enrichedThreats = deduped.map(t => {
    const rule = getRule(t.type);
    const confFactor = { high: 1.0, medium: 0.85, low: 0.6 }[rule.confidence] || 1.0;
    const points = Math.round((getSeverityWeights()[t.severity] || 0) * confFactor);
    return {
      ...t,
      rule_id: rule.id || t.type,
      rule_name: rule.name || t.type,
      confidence: rule.confidence || 'medium',
      references: rule.references || [],
      mitre: t.mitre || rule.mitre,
      playbook: getPlaybook(t.type),
      points
    };
  });

  // Build score breakdown sorted by impact (descending)
  const breakdown = enrichedThreats
    .map(t => ({ rule: t.rule_id, type: t.type, points: t.points, reason: t.message }))
    .sort((a, b) => b.points - a.points);

  // Per-file max scoring (v2.2.11) with intent graph bonus
  const {
    riskScore, riskLevel, globalRiskScore,
    maxFileScore, packageScore, intentBonus, mostSuspiciousFile, fileScores,
    criticalCount, highCount, mediumCount, lowCount
  } = calculateRiskScore(deduped, intentResult);

  // Python scan metadata
  const pythonInfo = pythonDeps.length > 0 ? {
    dependencies: pythonDeps.length,
    files: [...new Set(pythonDeps.map(d => path.relative(targetPath, d.file) || d.file))],
    threats: threats.filter(t => t.type === 'pypi_malicious_package' || t.type === 'pypi_typosquat_detected').length
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
      riskScore,
      riskLevel,
      globalRiskScore,
      maxFileScore,
      packageScore,
      mostSuspiciousFile,
      fileScores,
      breakdown
    },
    sandbox: sandboxData,
    warnings: warnings.length > 0 ? warnings : undefined,
    scannerErrors: scannerErrors.length > 0 ? scannerErrors : undefined
  };

  return {
    result,
    deduped,
    enrichedThreats,
    sandboxData,
    pythonInfo,
    breakdown,
    mostSuspiciousFile,
    maxFileScore,
    packageScore,
    globalRiskScore
  };
}

module.exports = { process };
