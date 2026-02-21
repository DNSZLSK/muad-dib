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
const { ensureIOCs } = require('./ioc/bootstrap.js');
const { scanEntropy } = require('./scanner/entropy.js');
const { scanAIConfig } = require('./scanner/ai-config.js');
const { deobfuscate } = require('./scanner/deobfuscate.js');
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows } = require('./scanner/module-graph.js');
const { detectSuddenLifecycleChange } = require('./temporal-analysis.js');
const { detectSuddenAstChanges } = require('./temporal-ast-diff.js');
const { detectPublishAnomaly } = require('./publish-anomaly.js');
const { detectMaintainerChange } = require('./maintainer-change.js');
const { setExtraExcludes, getExtraExcludes, Spinner } = require('./utils.js');

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

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Cap MEDIUM prototype_hook contribution (frameworks like Restify have 50+ extensions)
const PROTO_HOOK_MEDIUM_CAP = 15;

// ============================================
// PER-FILE MAX SCORING (v2.2.11)
// ============================================
// Threat types classified as package-level (not tied to a specific source file).
// These are added to the package score, not grouped by file.
const PACKAGE_LEVEL_TYPES = new Set([
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified',
  'known_malicious_package', 'typosquat_detected',
  'shai_hulud_marker', 'suspicious_file',
  'pypi_malicious_package', 'pypi_typosquat_detected',
  'dangerous_api_added_critical', 'dangerous_api_added_high', 'dangerous_api_added_medium',
  'publish_burst', 'publish_dormant_spike', 'publish_rapid_succession',
  'maintainer_new_suspicious', 'maintainer_sole_change',
  'sandbox_network_activity', 'sandbox_file_changes', 'sandbox_process_spawns',
  'sandbox_canary_exfiltration'
]);

/**
 * Classify a threat as package-level or file-level.
 * Package-level: metadata findings (package.json, node_modules, sandbox)
 * File-level: code-level findings in specific source files
 */
function isPackageLevelThreat(threat) {
  if (PACKAGE_LEVEL_TYPES.has(threat.type)) return true;
  if (threat.file === 'package.json') return true;
  if (threat.file && (threat.file.startsWith('node_modules/') || threat.file.startsWith('node_modules\\'))) return true;
  if (threat.file && threat.file.startsWith('[SANDBOX]')) return true;
  return false;
}

/**
 * Compute a risk score for a group of threats using standard weights.
 * Handles prototype_hook MEDIUM cap per group.
 * @param {Array} threats - array of threat objects (after FP reductions)
 * @returns {number} score 0-100
 */
function computeGroupScore(threats) {
  const criticalCount = threats.filter(t => t.severity === 'CRITICAL').length;
  const highCount = threats.filter(t => t.severity === 'HIGH').length;
  const mediumCount = threats.filter(t => t.severity === 'MEDIUM').length;
  const lowCount = threats.filter(t => t.severity === 'LOW').length;

  const mediumProtoHookCount = threats.filter(
    t => t.type === 'prototype_hook' && t.severity === 'MEDIUM'
  ).length;
  const protoHookPoints = Math.min(mediumProtoHookCount * SEVERITY_WEIGHTS.MEDIUM, PROTO_HOOK_MEDIUM_CAP);
  const otherMediumCount = mediumCount - mediumProtoHookCount;

  let score = 0;
  score += criticalCount * SEVERITY_WEIGHTS.CRITICAL;
  score += highCount * SEVERITY_WEIGHTS.HIGH;
  score += otherMediumCount * SEVERITY_WEIGHTS.MEDIUM;
  score += protoHookPoints;
  score += lowCount * SEVERITY_WEIGHTS.LOW;
  return Math.min(MAX_RISK_SCORE, score);
}

// ============================================
// FP REDUCTION POST-PROCESSING
// ============================================
// Legitimate frameworks produce high volumes of certain threat types that
// malware never does. This function downgrades severity when the count
// exceeds thresholds only seen in legitimate codebases.
const FP_COUNT_THRESHOLDS = {
  dynamic_require: { maxCount: 10, from: 'HIGH', to: 'LOW' },
  dangerous_call_function: { maxCount: 5, from: 'MEDIUM', to: 'LOW' },
  require_cache_poison: { maxCount: 3, from: 'CRITICAL', to: 'LOW' },
  suspicious_dataflow: { maxCount: 5, to: 'LOW' },
  obfuscation_detected: { maxCount: 3, to: 'LOW' }
};

// Custom class prototypes that HTTP frameworks legitimately extend.
// Distinguished from dangerous core Node.js prototype hooks.
const FRAMEWORK_PROTOTYPES = ['Request', 'Response', 'App', 'Router'];
const FRAMEWORK_PROTO_RE = new RegExp(
  '^(' + FRAMEWORK_PROTOTYPES.join('|') + ')\\.prototype\\.'
);

function applyFPReductions(threats) {
  // Count occurrences of each threat type (package-level, across all files)
  const typeCounts = {};
  for (const t of threats) {
    typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
  }

  for (const t of threats) {
    // Count-based downgrade: if a threat type appears too many times,
    // it's a framework/plugin system, not malware
    const rule = FP_COUNT_THRESHOLDS[t.type];
    if (rule && typeCounts[t.type] > rule.maxCount && (!rule.from || t.severity === rule.from)) {
      t.severity = rule.to;
    }

    // Prototype hook: framework class prototypes → MEDIUM
    // Core Node.js prototypes (http.IncomingMessage, net.Socket) stay CRITICAL
    // Browser/native APIs (globalThis.fetch, XMLHttpRequest) stay HIGH
    if (t.type === 'prototype_hook' && t.severity === 'HIGH' &&
        FRAMEWORK_PROTO_RE.test(t.message)) {
      t.severity = 'MEDIUM';
    }
  }
}

// Paranoid mode scanner
function scanParanoid(targetPath) {
  const threats = [];

  function scanFile(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) return;
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

  function walkDir(dir, depth) {
    if (depth > 50) return; // Max depth guard (IDX-06)
    const excluded = ['node_modules', '.git', '.muaddib-cache', ...getExtraExcludes()];
    try {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        // Use lstatSync to avoid following symlinks
        const stat = fs.lstatSync(fullPath);

        if (stat.isSymbolicLink()) continue;

        if (stat.isDirectory()) {
          const rel = path.relative(targetPath, fullPath).replace(/\\/g, '/');
          const isExcluded = excluded.includes(file) ||
            excluded.some(ex => rel === ex || rel.startsWith(ex + '/'));
          if (!isExcluded) {
            walkDir(fullPath, depth + 1);
          }
        } else if (file.endsWith('.js') || file.endsWith('.json') || file.endsWith('.sh')) {
          scanFile(fullPath);
        }
      }
    } catch {
      // Ignore walk errors
    }
  }

  walkDir(targetPath, 0);
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
  // Ensure IOCs are downloaded (first run only, graceful failure)
  await ensureIOCs();

  // Apply --exclude dirs for this scan
  if (options.exclude && options.exclude.length > 0) {
    setExtraExcludes(options.exclude, targetPath);
  }

  // Detect Python project (synchronous, fast file reads)
  const pythonDeps = detectPythonProject(targetPath);

  // Show spinner during scan (TTY only; piped/CI output keeps static message)
  const useTTYSpinner = !options._capture && process.stdout.isTTY;
  let spinner = null;
  if (useTTYSpinner) {
    spinner = new Spinner();
    spinner.start(`[MUADDIB] Scanning ${targetPath}...`);
  }

  // Deobfuscation pre-processor (pass to AST/dataflow scanners unless disabled)
  const deobfuscateFn = options.noDeobfuscate ? null : deobfuscate;

  // Cross-file module graph analysis (before individual scanners)
  let crossFileFlows = [];
  if (!options.noModuleGraph) {
    try {
      const graph = buildModuleGraph(targetPath);
      const tainted = annotateTaintedExports(graph, targetPath);
      crossFileFlows = detectCrossFileFlows(graph, tainted, targetPath);
    } catch {
      // Graceful fallback — module graph is best-effort
    }
  }

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
    pypiTyposquatThreats,
    entropyThreats,
    aiConfigThreats
  ] = await Promise.all([
    scanPackageJson(targetPath),
    scanShellScripts(targetPath),
    analyzeAST(targetPath, { deobfuscate: deobfuscateFn }),
    Promise.resolve(detectObfuscation(targetPath)),
    scanDependencies(targetPath),
    scanHashes(targetPath),
    analyzeDataFlow(targetPath, { deobfuscate: deobfuscateFn }),
    scanTyposquatting(targetPath),
    Promise.resolve(scanGitHubActions(targetPath)),
    Promise.resolve(matchPythonIOCs(pythonDeps, targetPath)),
    Promise.resolve(checkPyPITyposquatting(pythonDeps, targetPath)),
    Promise.resolve(scanEntropy(targetPath, { entropyThreshold: options.entropyThreshold || undefined })),
    Promise.resolve(scanAIConfig(targetPath))
  ]);

  // Stop spinner now that scanning is complete
  if (spinner) {
    spinner.succeed(`[MUADDIB] Scanned ${targetPath}`);
  }

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
    ...pypiTyposquatThreats,
    ...entropyThreats,
    ...aiConfigThreats,
    ...crossFileFlows.map(f => ({
      type: f.type,
      severity: f.severity,
      message: `Cross-file dataflow: ${f.source} in ${f.sourceFile} → ${f.sink} in ${f.sinkFile}`,
      file: f.sinkFile
    }))
  ];

  // Paranoid mode
  if (options.paranoid) {
    console.log('[PARANOID] Ultra-strict mode enabled\n');
    const paranoidThreats = scanParanoid(targetPath);
    threats.push(...paranoidThreats);
  }

  // Temporal analysis (--temporal flag, off by default)
  if (options.temporal) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL] Analyzing lifecycle script changes (this makes network requests)...\n');
    }
    const nodeModulesPath = path.join(targetPath, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      const pkgNames = [];
      try {
        const items = fs.readdirSync(nodeModulesPath);
        for (const item of items) {
          if (item.startsWith('.')) continue;
          const itemPath = path.join(nodeModulesPath, item);
          try {
            const stat = fs.lstatSync(itemPath);
            if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
            if (item.startsWith('@')) {
              const scopedItems = fs.readdirSync(itemPath);
              for (const si of scopedItems) {
                const sp = path.join(itemPath, si);
                const ss = fs.lstatSync(sp);
                if (!ss.isSymbolicLink() && ss.isDirectory()) {
                  pkgNames.push(`${item}/${si}`);
                }
              }
            } else {
              pkgNames.push(item);
            }
          } catch { /* skip unreadable */ }
        }
      } catch { /* no node_modules readable */ }

      const TEMPORAL_CONCURRENCY = 5;
      for (let i = 0; i < pkgNames.length; i += TEMPORAL_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + TEMPORAL_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectSuddenLifecycleChange(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const f of det.findings) {
            const isCriticalScript = ['preinstall', 'install', 'postinstall'].includes(f.script);
            const threatType = f.type === 'lifecycle_added'
              ? (isCriticalScript ? 'lifecycle_added_critical' : 'lifecycle_added_high')
              : 'lifecycle_modified';
            threats.push({
              type: threatType,
              severity: f.severity,
              message: `Package "${det.packageName}" v${det.latestVersion} ${f.type === 'lifecycle_added' ? 'added' : 'modified'} ${f.script} script (not in v${det.previousVersion}). Script: "${f.type === 'lifecycle_modified' ? f.newValue : f.value}"`,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
      }
    }
  }

  // Temporal AST analysis (--temporal-ast or --temporal-full flag, off by default)
  if (options.temporalAst) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL-AST] Analyzing dangerous API changes (this downloads tarballs)...\n');
    }
    const nodeModulesPath = path.join(targetPath, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      const pkgNames = [];
      try {
        const items = fs.readdirSync(nodeModulesPath);
        for (const item of items) {
          if (item.startsWith('.')) continue;
          const itemPath = path.join(nodeModulesPath, item);
          try {
            const stat = fs.lstatSync(itemPath);
            if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
            if (item.startsWith('@')) {
              const scopedItems = fs.readdirSync(itemPath);
              for (const si of scopedItems) {
                const sp = path.join(itemPath, si);
                const ss = fs.lstatSync(sp);
                if (!ss.isSymbolicLink() && ss.isDirectory()) {
                  pkgNames.push(`${item}/${si}`);
                }
              }
            } else {
              pkgNames.push(item);
            }
          } catch { /* skip unreadable */ }
        }
      } catch { /* no node_modules readable */ }

      const AST_CONCURRENCY = 3;
      for (let i = 0; i < pkgNames.length; i += AST_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + AST_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectSuddenAstChanges(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const f of det.findings) {
            const threatType = f.severity === 'CRITICAL' ? 'dangerous_api_added_critical'
              : f.severity === 'HIGH' ? 'dangerous_api_added_high'
              : 'dangerous_api_added_medium';
            threats.push({
              type: threatType,
              severity: f.severity,
              message: `Package "${det.packageName}" v${det.latestVersion} now uses ${f.pattern} (not in v${det.previousVersion})`,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
      }
    }
  }

  // Temporal publish frequency analysis (--temporal-publish or --temporal-full flag, off by default)
  if (options.temporalPublish) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL-PUBLISH] Analyzing publish frequency anomalies (this makes network requests)...\n');
    }
    const nodeModulesPath = path.join(targetPath, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      const pkgNames = [];
      try {
        const items = fs.readdirSync(nodeModulesPath);
        for (const item of items) {
          if (item.startsWith('.')) continue;
          const itemPath = path.join(nodeModulesPath, item);
          try {
            const stat = fs.lstatSync(itemPath);
            if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
            if (item.startsWith('@')) {
              const scopedItems = fs.readdirSync(itemPath);
              for (const si of scopedItems) {
                const sp = path.join(itemPath, si);
                const ss = fs.lstatSync(sp);
                if (!ss.isSymbolicLink() && ss.isDirectory()) {
                  pkgNames.push(`${item}/${si}`);
                }
              }
            } else {
              pkgNames.push(item);
            }
          } catch { /* skip unreadable */ }
        }
      } catch { /* no node_modules readable */ }

      const PUBLISH_CONCURRENCY = 5;
      for (let i = 0; i < pkgNames.length; i += PUBLISH_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + PUBLISH_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectPublishAnomaly(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const a of det.anomalies) {
            threats.push({
              type: a.type,
              severity: a.severity,
              message: a.description,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
      }
    }
  }

  // Temporal maintainer change analysis (--temporal-maintainer or --temporal-full flag, off by default)
  if (options.temporalMaintainer) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL-MAINTAINER] Analyzing maintainer changes (this makes network requests)...\n');
    }
    const nodeModulesPath = path.join(targetPath, 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      const pkgNames = [];
      try {
        const items = fs.readdirSync(nodeModulesPath);
        for (const item of items) {
          if (item.startsWith('.')) continue;
          const itemPath = path.join(nodeModulesPath, item);
          try {
            const stat = fs.lstatSync(itemPath);
            if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
            if (item.startsWith('@')) {
              const scopedItems = fs.readdirSync(itemPath);
              for (const si of scopedItems) {
                const sp = path.join(itemPath, si);
                const ss = fs.lstatSync(sp);
                if (!ss.isSymbolicLink() && ss.isDirectory()) {
                  pkgNames.push(`${item}/${si}`);
                }
              }
            } else {
              pkgNames.push(item);
            }
          } catch { /* skip unreadable */ }
        }
      } catch { /* no node_modules readable */ }

      const MAINTAINER_CONCURRENCY = 5;
      for (let i = 0; i < pkgNames.length; i += MAINTAINER_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + MAINTAINER_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectMaintainerChange(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const f of det.findings) {
            threats.push({
              type: f.type,
              severity: f.severity,
              message: f.description,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
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

  // FP reduction: legitimate frameworks produce high volumes of certain threat types.
  // A malware package typically has 1-3 occurrences, not dozens.
  applyFPReductions(deduped);

  // Enrich each threat with rules
  const enrichedThreats = deduped.map(t => {
    const rule = getRule(t.type);
    const points = SEVERITY_WEIGHTS[t.severity] || 0;
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

  // ============================================
  // PER-FILE MAX SCORING (v2.2.11)
  // ============================================

  // 1. Separate deduped threats into package-level and file-level
  const packageLevelThreats = [];
  const fileLevelThreats = [];
  for (const t of deduped) {
    if (isPackageLevelThreat(t)) {
      packageLevelThreats.push(t);
    } else {
      fileLevelThreats.push(t);
    }
  }

  // 2. Group file-level threats by file
  const fileGroups = new Map();
  for (const t of fileLevelThreats) {
    const key = t.file || '(unknown)';
    if (!fileGroups.has(key)) fileGroups.set(key, []);
    fileGroups.get(key).push(t);
  }

  // 3. Compute per-file scores and find the most suspicious file
  let maxFileScore = 0;
  let mostSuspiciousFile = null;
  const fileScores = {};
  for (const [file, fileThreats] of fileGroups) {
    const score = computeGroupScore(fileThreats);
    fileScores[file] = score;
    if (score > maxFileScore) {
      maxFileScore = score;
      mostSuspiciousFile = file;
    }
  }

  // 4. Compute package-level score (typosquat, lifecycle, dependency IOC, etc.)
  const packageScore = computeGroupScore(packageLevelThreats);

  // 5. Final score = max file score + package-level score, capped at 100
  const riskScore = Math.min(MAX_RISK_SCORE, maxFileScore + packageScore);

  // 6. Old global score for comparison (sum of ALL findings)
  const globalRiskScore = computeGroupScore(deduped);

  // 7. Severity counts (global, for summary display)
  const criticalCount = deduped.filter(t => t.severity === 'CRITICAL').length;
  const highCount = deduped.filter(t => t.severity === 'HIGH').length;
  const mediumCount = deduped.filter(t => t.severity === 'MEDIUM').length;
  const lowCount = deduped.filter(t => t.severity === 'LOW').length;

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
      riskScore,
      riskLevel,
      globalRiskScore,
      maxFileScore,
      packageScore,
      mostSuspiciousFile,
      fileScores,
      breakdown
    },
    sandbox: sandboxData
  };

  // _capture mode: return result directly without printing (used by diff.js)
  if (options._capture) {
    setExtraExcludes([]);
    return result;
  }

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
    if (!spinner) console.log(`\n[MUADDIB] Scanning ${targetPath}\n`);
    else console.log('');

    const explainScoreBar = '█'.repeat(Math.floor(result.summary.riskScore / 5)) + '░'.repeat(20 - Math.floor(result.summary.riskScore / 5));
    console.log(`[SCORE] ${result.summary.riskScore}/100 [${explainScoreBar}] ${result.summary.riskLevel}`);
    if (mostSuspiciousFile) {
      console.log(`        Max file: ${mostSuspiciousFile} (${maxFileScore} pts)`);
      if (packageScore > 0) {
        console.log(`        Package-level: +${packageScore} pts`);
      }
    }
    console.log('');

    if (options.breakdown && breakdown.length > 0) {
      console.log('[BREAKDOWN] Score contributors:');
      for (const entry of breakdown) {
        const pts = String(entry.points).padStart(2);
        console.log(`  +${pts}  ${entry.reason} (${entry.rule})`);
      }
      if (globalRiskScore !== riskScore) {
        console.log('  ----');
        console.log(`  Global sum: ${globalRiskScore}, Per-file max: ${riskScore}`);
      }
      console.log('');
    }

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
    if (!spinner) console.log(`\n[MUADDIB] Scanning ${targetPath}\n`);
    else console.log('');

    const scoreBar = '█'.repeat(Math.floor(result.summary.riskScore / 5)) + '░'.repeat(20 - Math.floor(result.summary.riskScore / 5));
    console.log(`[SCORE] ${result.summary.riskScore}/100 [${scoreBar}] ${result.summary.riskLevel}`);
    if (mostSuspiciousFile) {
      console.log(`        Max file: ${mostSuspiciousFile} (${maxFileScore} pts)`);
      if (packageScore > 0) {
        console.log(`        Package-level: +${packageScore} pts`);
      }
    }
    console.log('');

    if (options.breakdown && breakdown.length > 0) {
      console.log('[BREAKDOWN] Score contributors:');
      for (const entry of breakdown) {
        const pts = String(entry.points).padStart(2);
        console.log(`  +${pts}  ${entry.reason} (${entry.rule})`);
      }
      if (globalRiskScore !== riskScore) {
        console.log('  ----');
        console.log(`  Global sum: ${globalRiskScore}, Per-file max: ${riskScore}`);
      }
      console.log('');
    }

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
        console.log(`     File: ${t.file}`);
        const playbook = getPlaybook(t.type);
        if (playbook) {
          console.log(`     \u2192 ${playbook}`);
        }
        console.log('');
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
  if (options.webhook && enrichedThreats.length > 0) {
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

  // Clear runtime excludes
  setExtraExcludes([]);

  return Math.min(failingThreats.length, 125);
}

module.exports = { run, isPackageLevelThreat, computeGroupScore };