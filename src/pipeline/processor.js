const fs = require('fs');
const path = require('path');
const { getRule } = require('../rules/index.js');
const { getPlaybook } = require('../response/playbooks.js');
const { computeReachableFiles, computeReachableFunctions } = require('../scanner/reachability.js');
const { applyFPReductions, applyCompoundBoosts, calculateRiskScore, getSeverityWeights, applyContextualFPCaps, applySingleFireCriticalFloor, applyReputationFactor, applyMatureStableCap, applySandboxVerdict, applyDeltaMultiplier } = require('../scoring.js');
const { loadPriorVersionSignatures, computeSignatures, saveCachedSignatures } = require('../scoring/delta-multiplier.js');
const { annotateConfidenceTiers, tierAtLeast } = require('../rules/confidence-tiers.js');
const { buildIntentPairs } = require('../intent-graph.js');
const { debugLog } = require('../utils.js');
const { getPackageMetadata } = require('../scanner/npm-registry.js');

// Auto-sandbox compound trigger : optional out-of-tree dependency. Lazy-load
// it so the pipeline still works when the file is absent (some dev machines
// have it untracked, CI does not). When missing, evaluateSandboxTrigger
// degrades to a no-op {shouldRun:false} so the auto-sandbox branch skips.
let _sandboxTriggerCache = null;
function evaluateSandboxTrigger(threats, prelimScore) {
  if (_sandboxTriggerCache === null) {
    try {
      _sandboxTriggerCache = require('../sandbox/compound-triggers.js').evaluateSandboxTrigger;
    } catch {
      _sandboxTriggerCache = () => ({ shouldRun: false });
    }
  }
  return _sandboxTriggerCache(threats, prelimScore);
}

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
  // Auto-sandbox: surgical trigger only when a sandbox-friendly compound
  // matches AND the preliminary score is in the borderline window [15, 35].
  // See src/sandbox/compound-triggers.js for the 6 compounds and rationale.
  // Score < 15 = clean, no need to run; score > 35 = already definitive,
  // no second-tier verdict needed. The verdict is then applied below via
  // applySandboxVerdict (floor at 75/60 for malicious, -8 for clean).
  if (options.autoSandbox && !options.sandboxResult) {
    const critCount = threats.filter(t => t.severity === 'CRITICAL').length;
    const highCount = threats.filter(t => t.severity === 'HIGH').length;
    const prelimScore = Math.min(100, critCount * 25 + highCount * 10);
    const sandboxTrigger = evaluateSandboxTrigger(threats, prelimScore);
    if (sandboxTrigger.shouldRun) {
      try {
        const { isDockerAvailable, buildSandboxImage, runSandbox } = require('../sandbox/index.js');
        if (isDockerAvailable()) {
          console.log(`\n[AUTO-SANDBOX] Compound "${sandboxTrigger.compound}" matched (score ~${prelimScore}) - triggering sandbox analysis...`);
          const built = await buildSandboxImage();
          if (built) {
            const sbResult = await runSandbox(targetPath, {
              local: true,
              strict: false,
              compound: sandboxTrigger.compound,
              watchpoints: sandboxTrigger.watchpoints
            });
            if (sbResult && Array.isArray(sbResult.findings)) {
              if (sbResult.meta) {
                sbResult.meta.compound = sandboxTrigger.compound;
                sbResult.meta.watchpoints = sandboxTrigger.watchpoints;
              } else {
                sbResult.meta = { compound: sandboxTrigger.compound, watchpoints: sandboxTrigger.watchpoints };
              }
              options.sandboxResult = sbResult;
            }
          }
        } else {
          debugLog('[AUTO-SANDBOX] Docker not available - skipping sandbox');
        }
      } catch (e) {
        debugLog('[AUTO-SANDBOX] Error:', e && e.message);
      }
    } else {
      debugLog('[AUTO-SANDBOX] No compound matched (score ~' + prelimScore + ') - ' + sandboxTrigger.reason);
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
  let reachableFunctions = null; // FPR plan C2 : intra-file fn-level reachability
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
    // FPR plan C2 : function-level reachability. Default ON since v2.11.9 after
    // measuring -2.0 pp FPR (curated 11.4% -> 9.4%) with zero TPR/ADR regression
    // on the full evaluation corpus (1054 packages). Opt-out via
    // MUADDIB_FN_REACHABILITY=0. Activated only when file-level reachability
    // succeeded (otherwise no entry-point context to seed from).
    if (reachableFiles && globalThis.process.env.MUADDIB_FN_REACHABILITY !== '0') {
      try {
        reachableFunctions = computeReachableFunctions(targetPath, reachableFiles);
      } catch (e) {
        debugLog('[FN-REACHABILITY] error:', e?.message);
        reachableFunctions = null;
      }
    }
  }

  // Read package name and dependencies for FP reduction heuristics
  let packageName = null;
  let packageDeps = null;
  let packageVersion = null;
  let _pkgMeta = null; // v2.10.97: full pkg metadata for contextual FP caps
  try {
    const pkgPath = path.join(targetPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      packageName = pkgData.name || null;
      packageDeps = pkgData.dependencies || null;
      packageVersion = (typeof pkgData.version === 'string') ? pkgData.version : null;
      _pkgMeta = {
        name: pkgData.name,
        version: packageVersion,
        scripts: pkgData.scripts || {},
        description: pkgData.description || '',
        homepage: pkgData.homepage || (typeof pkgData.repository === 'string' ? pkgData.repository : (pkgData.repository && pkgData.repository.url) || ''),
        dependencies: pkgData.dependencies,
        devDependencies: pkgData.devDependencies,
      };
    }
  } catch { /* graceful fallback */ }

  // FPR plan Chantier 4 + 5 wiring : fetch npm registry packument and attach
  // it as _pkgMeta.npmRegistryMeta so applyReputationFactor, applyMatureStable-
  // Cap, and applyDeltaMultiplier can fire. getPackageMetadata has an in-
  // process cache, so repeated scans of the same package hit the cache and
  // never re-fetch. Network failure / unknown package -> returns null and all
  // downstream functions degrade gracefully.
  //
  // Default ON since v2.11.9. To skip the fetch entirely (air-gap, offline CI,
  // perf-critical batch), set MUADDIB_NO_REGISTRY_FETCH=1 — this disables the
  // 3 metadata-dependent gates (METADATA_FACTOR, MATURE_CAP, DELTA_MODE) in
  // one shot. Individual gates can still be turned off via their own =0 flag.
  if (
    packageName &&
    _pkgMeta &&
    globalThis.process.env.MUADDIB_NO_REGISTRY_FETCH !== '1' &&
    (
      globalThis.process.env.MUADDIB_METADATA_FACTOR !== '0' ||
      globalThis.process.env.MUADDIB_MATURE_CAP !== '0' ||
      globalThis.process.env.MUADDIB_DELTA_MODE !== '0'
    )
  ) {
    try {
      const meta = await getPackageMetadata(packageName);
      if (meta) {
        // Attach the scanned version so applyMatureStableCap can require
        // scan_version === latest_version. Without this gate, scanning a
        // historical compromised version (e.g. eslint-scope 3.7.2, chalk
        // 5.6.1) would inherit the live registry's "stable" reputation and
        // mask the attack.
        meta.scan_version = packageVersion;
        _pkgMeta.npmRegistryMeta = meta;
      }
    } catch (err) {
      debugLog('[REGISTRY-META] fetch failed for ' + packageName + ': ' + err.message);
    }
  }

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
  applyFPReductions(deduped, reachableFiles, packageName, packageDeps, reachableFunctions);

  // FPR plan Chantier 3 - delta-aware decay. Threats present in the last 3
  // published versions (and not HC/IOC) decay to LOW. Default ON since v2.11.9.
  // Opt-out: MUADDIB_DELTA_MODE=0 (or set MUADDIB_NO_REGISTRY_FETCH=1 to skip
  // the registry fetch upstream). No-op when registry meta is absent (CLI
  // scans on private packages, offline, or unknown package).
  let _deltaResult = null;
  if (
    packageName && packageVersion &&
    _pkgMeta && _pkgMeta.npmRegistryMeta &&
    globalThis.process.env.MUADDIB_DELTA_MODE !== '0'
  ) {
    try {
      const packument = _pkgMeta.npmRegistryMeta.packument || _pkgMeta.npmRegistryMeta;
      const priorSigs = loadPriorVersionSignatures(packageName, packageVersion, packument);
      _deltaResult = applyDeltaMultiplier(deduped, priorSigs);
    } catch (e) {
      debugLog('[DELTA] error:', e?.message);
      _deltaResult = null;
    }
  }

  // Compound scoring: inject synthetic CRITICAL threats when co-occurring types
  // indicate unambiguous malice. Applied AFTER FP reductions to recover signals
  // that were individually downgraded (count-based, dist, reachability, delta).
  applyCompoundBoosts(deduped, targetPath);

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

  // FPR plan Chantier 6 - tag every threat with its confidence tier so the
  // CLI / JSON / SARIF formatters can filter to verified+high by default and
  // evaluate.js can report a "FPR perceived" headline alongside "FPR all".
  // Annotation reads severity AFTER all FP reductions, so reductions trail
  // (count_threshold, unreachable, delta_stable, ...) influences the tier.
  annotateConfidenceTiers(deduped);

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
      confidenceTier: t.confidenceTier || 'medium',
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

  // v2.10.96: stat each file that carries a threat and expose sizes on the
  // scan result. Used by ML cluster-FP features (bundle_without_install_scripts)
  // to replace the bundle-path-shape proxy with a real ">100KB" check.
  // Cost: one statSync per unique threatened file (typically <30); same
  // operation already runs elsewhere in the pipeline (executor.js:251).
  const fileSizes = {};
  for (const rel of Object.keys(fileScores)) {
    if (!rel || rel === '(unknown)' || rel.startsWith('[SANDBOX]')) continue;
    try {
      const abs = path.isAbsolute(rel) ? rel : path.join(targetPath, rel);
      const st = fs.statSync(abs);
      if (st.isFile()) fileSizes[rel] = st.size;
    } catch {
      // File removed between scan and stat, or unreadable: skip silently.
    }
  }

  // Python scan metadata
  const pythonInfo = pythonDeps.length > 0 ? {
    dependencies: pythonDeps.length,
    files: [...new Set(pythonDeps.map(d => path.relative(targetPath, d.file) || d.file))],
    threats: threats.filter(t => t.type === 'pypi_malicious_package' || t.type === 'pypi_typosquat_detected').length
  } : null;

  // FPR plan Chantier 6 - tier counts let downstream metrics report FPR
  // perceived (verified + high) alongside FPR all. The CLI reads these to
  // decide whether to print a finding by default vs hide behind --show-low.
  const tierCounts = { verified: 0, high: 0, medium: 0, low: 0 };
  for (const t of deduped) {
    const tier = t.confidenceTier || 'medium';
    if (tierCounts[tier] !== undefined) tierCounts[tier]++;
  }
  const perceivedFlagged = tierCounts.verified + tierCounts.high;

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
      fileSizes,
      breakdown,
      // C6 : confidence tier rollup
      tierCounts,
      perceivedFlagged
    },
    sandbox: sandboxData,
    warnings: warnings.length > 0 ? warnings : undefined,
    scannerErrors: scannerErrors.length > 0 ? scannerErrors : undefined
  };

  // v2.10.97: contextual FP post-filter — deterministic score caps for
  // packages matching well-known FP clusters (100% precision, 302 human labels).
  const fpCaps = applyContextualFPCaps(result, _pkgMeta);
  if (fpCaps.length > 0) {
    debugLog('[FP-CAP] ' + (packageName || targetPath) + ': ' +
      fpCaps.map(c => c.feature + (c.cap > 0 ? '→MAX' + c.cap : '→suppress')).join(', ') +
      ' → score=' + result.summary.riskScore);
  }

  // FPR plan Chantier 5 : mature stable cap — caps mature, well-owned, high-
  // traffic packages at MEDIUM unless an HC type or IOC is present. Sits
  // BETWEEN the contextual caps (which it composes with) and the single-fire
  // floor (which can override on hard signals). Default ON since v2.11.9.
  // Opt-out: MUADDIB_MATURE_CAP=0. No-op when registry meta is absent.
  if (globalThis.process.env.MUADDIB_MATURE_CAP !== '0') {
    const matureCap = applyMatureStableCap(result, _pkgMeta && _pkgMeta.npmRegistryMeta);
    if (matureCap && matureCap.applied) {
      debugLog('[MATURE-CAP] ' + (packageName || targetPath) + ': ' +
        matureCap.oldScore + ' -> ' + matureCap.newScore + ' (' +
        Object.entries(matureCap.reasons).map(([k, v]) => k + '=' + v).join(', ') + ')');
    }
  }

  // Hybrid v3 Phase 1: single-fire critical floor — applied AFTER contextual
  // caps so a deterministic IOC match (known_malicious_hash, lifecycle_shell_pipe…)
  // stays CRITICAL even if the package also matches a benign FP cluster.
  const sfTriggers = applySingleFireCriticalFloor(result);
  if (sfTriggers.length > 0) {
    debugLog('[SF-FLOOR] ' + (packageName || targetPath) + ': ' +
      sfTriggers.map(t => t.type + '/' + t.severity).join(', ') +
      ' → score=' + result.summary.riskScore);
  }

  // Hybrid v3 Phase 4: metadata-first reputation factor — multiplies the score
  // by a factor in [0.10, 1.5] derived from npm registry signals. Applied LAST
  // so all severity logic completes first; the factor is the final, package-
  // wide context filter. Default ON since v2.11.9. Opt-out:
  // MUADDIB_METADATA_FACTOR=0. No-op when metadata is absent (CLI scans on
  // unknown package, offline, MUADDIB_NO_REGISTRY_FETCH=1).
  // NOTE: this module's exported function is named `process`, which shadows
  // the global `process` inside its body. Use globalThis.process.env to reach
  // the real environment.
  if (globalThis.process.env.MUADDIB_METADATA_FACTOR !== '0') {
    const repAdjust = applyReputationFactor(result, _pkgMeta && _pkgMeta.npmRegistryMeta);
    if (repAdjust) {
      debugLog('[META-FACTOR] ' + (packageName || targetPath) + ': factor=' +
        repAdjust.factor.toFixed(2) + ' (' + repAdjust.oldScore + ' → ' + repAdjust.newScore + ')');
    }
  }

  // Sandbox verdict: meta-layer applied after every other scoring step.
  // MALICIOUS_CONFIRMED floors the score at 75 (any honey READ correlated
  // outbound, or critical preload signal). MALICIOUS_CHAIN floors at 60
  // (>=2 high preload signals). CLEAN_HIGH_CONFIDENCE applies a -8 delta when
  // the sandbox completed cleanly with no fingerprint detected. INCONCLUSIVE
  // leaves the score unchanged with a warning attached.
  if (options.sandboxResult) {
    const verdict = applySandboxVerdict(result, options.sandboxResult);
    if (verdict) {
      debugLog('[SANDBOX-VERDICT] ' + (packageName || targetPath) + ': ' +
        verdict.verdict + ' ' + verdict.oldScore + ' -> ' + verdict.newScore +
        (verdict.signals.length > 0 ? ' [' + verdict.signals.slice(0, 3).join(', ') + ']' : ''));
    }
  }

  // FPR plan Chantier 3 : persist this version's signature set so future scans
  // (or future versions) can use it as a baseline for delta decay. Best-effort
  // and idempotent ; cache misses on read are silent so a missed write never
  // blocks scoring. Write whenever delta-mode is enabled (default ON) AND we
  // have a concrete package@version pair.
  if (
    globalThis.process.env.MUADDIB_DELTA_MODE !== '0' &&
    packageName && packageVersion
  ) {
    try {
      const sigs = computeSignatures(deduped);
      saveCachedSignatures(packageName, packageVersion, sigs);
      debugLog('[DELTA] cached ' + sigs.size + ' signatures for ' + packageName + '@' + packageVersion);
    } catch (e) {
      debugLog('[DELTA] cache write failed:', e?.message);
    }
  }

  if (_deltaResult && _deltaResult.downgraded > 0) {
    debugLog('[DELTA] ' + (packageName || targetPath) + ': ' +
      _deltaResult.downgraded + ' threats decayed to LOW (baseline=' +
      _deltaResult.baselineSize + ', new=' + _deltaResult.newThreats + ')');
  }

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
