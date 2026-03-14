const { scanPackageJson } = require('./scanner/package.js');
const { scanShellScripts } = require('./scanner/shell.js');
const { analyzeAST } = require('./scanner/ast.js');
const { detectObfuscation } = require('./scanner/obfuscation.js');
const { scanDependencies } = require('./scanner/dependencies.js');
const { scanHashes } = require('./scanner/hash.js');
const { analyzeDataFlow } = require('./scanner/dataflow.js');
const { getPlaybook } = require('./response/playbooks.js');
const { getRule, PARANOID_RULES } = require('./rules/index.js');
const { scanTyposquatting, findPyPITyposquatMatch } = require('./scanner/typosquat.js');
let sendWebhook;
try {
  sendWebhook = require('./webhook.js').sendWebhook;
} catch {
  sendWebhook = async () => {}; // no-op quand webhook.js absent (npm package)
}
const fs = require('fs');
const path = require('path');
const { scanGitHubActions } = require('./scanner/github-actions.js');
const { detectPythonProject, normalizePythonName } = require('./scanner/python.js');
const { loadCachedIOCs, checkIOCStaleness } = require('./ioc/updater.js');
const { ensureIOCs } = require('./ioc/bootstrap.js');
const { scanEntropy } = require('./scanner/entropy.js');
const { scanAIConfig } = require('./scanner/ai-config.js');
const { deobfuscate } = require('./scanner/deobfuscate.js');
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows, annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows } = require('./scanner/module-graph.js');
const { computeReachableFiles } = require('./scanner/reachability.js');
const { runTemporalAnalyses } = require('./temporal-runner.js');
const { formatOutput } = require('./output-formatter.js');
const { setExtraExcludes, getExtraExcludes, Spinner, listInstalledPackages, clearFileListCache, debugLog } = require('./utils.js');
const { SEVERITY_WEIGHTS, RISK_THRESHOLDS, MAX_RISK_SCORE, isPackageLevelThreat, computeGroupScore, applyFPReductions, calculateRiskScore } = require('./scoring.js');
const { buildIntentPairs } = require('./intent-graph.js');

const { MAX_FILE_SIZE, safeParse } = require('./shared/constants.js');
const walk = require('acorn-walk');

// Paranoid mode scanner
function scanParanoid(targetPath) {
  const threats = [];

  // AST-based paranoid detection patterns
  const PARANOID_AST_DETECTORS = {
    network_access: {
      callNames: new Set(['fetch', 'axios']),
      memberPatterns: [
        { obj: 'http', prop: 'request' }, { obj: 'http', prop: 'get' },
        { obj: 'https', prop: 'request' }, { obj: 'https', prop: 'get' },
        { obj: 'net', prop: 'connect' }
      ],
      newNames: new Set(['XMLHttpRequest'])
    },
    sensitive_file_access: {
      sensitiveStrings: ['.env', '.npmrc', '.ssh', '.git', 'id_rsa', 'credentials', 'secrets']
    },
    dynamic_execution: {
      callNames: new Set(['eval']),
      newNames: new Set(['Function']),
      memberPatterns: [
        { obj: 'vm', prop: 'runInContext' }, { obj: 'vm', prop: 'runInNewContext' },
        { obj: 'vm', prop: 'runInThisContext' }
      ]
    },
    subprocess: {
      callNames: new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync']),
      memberPatterns: [
        { obj: 'child_process', prop: 'exec' }, { obj: 'child_process', prop: 'execSync' },
        { obj: 'child_process', prop: 'spawn' }, { obj: 'child_process', prop: 'fork' }
      ]
    },
    env_access: {
      memberPatterns: [{ obj: 'process', prop: 'env' }]
    }
  };

  function scanFileAST(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) return;
      const content = fs.readFileSync(filePath, 'utf8');
      const relFile = path.relative(targetPath, filePath);

      const ast = safeParse(content);
      if (!ast) {
        // Parse failed — fall back to content matching for this file
        scanFileContent(filePath, content, relFile);
        return;
      }

      const found = new Set(); // deduplicate: one finding per rule per file

      // v2.6.5: Track aliases of eval, Function, require for bypass detection
      // e.g., const e = eval; e(code) — or — const F = Function; new F(code)
      const ALIAS_TARGETS = new Set(['eval', 'Function', 'require']);
      const aliases = new Map(); // aliasName → originalName

      walk.simple(ast, {
        VariableDeclarator(node) {
          // const e = eval / const F = Function / const r = require
          if (node.id?.type === 'Identifier' && node.init?.type === 'Identifier' &&
              ALIAS_TARGETS.has(node.init.name)) {
            aliases.set(node.id.name, node.init.name);
          }
        },
        CallExpression(node) {
          // Direct calls: eval(), exec(), fetch(), etc.
          if (node.callee.type === 'Identifier') {
            // Resolve alias to original name if applicable
            const name = aliases.get(node.callee.name) || node.callee.name;
            for (const [ruleKey, detector] of Object.entries(PARANOID_AST_DETECTORS)) {
              if (detector.callNames && detector.callNames.has(name) && !found.has(ruleKey)) {
                found.add(ruleKey);
                const rule = PARANOID_RULES[ruleKey];
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "${node.callee.name}"${aliases.has(node.callee.name) ? ` (alias of ${name})` : ''}`,
                  file: relFile, mitre: rule.mitre
                });
              }
            }
          }
          // Member calls: http.request(), child_process.exec(), etc.
          if (node.callee.type === 'MemberExpression' &&
              node.callee.object?.type === 'Identifier' &&
              node.callee.property?.type === 'Identifier') {
            const obj = node.callee.object.name;
            const prop = node.callee.property.name;
            for (const [ruleKey, detector] of Object.entries(PARANOID_AST_DETECTORS)) {
              if (detector.memberPatterns &&
                  detector.memberPatterns.some(m => m.obj === obj && m.prop === prop) &&
                  !found.has(ruleKey)) {
                found.add(ruleKey);
                const rule = PARANOID_RULES[ruleKey];
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "${obj}.${prop}"`, file: relFile, mitre: rule.mitre
                });
              }
            }
          }
        },
        NewExpression(node) {
          if (node.callee.type === 'Identifier') {
            // Resolve alias: const F = Function; new F(code)
            const name = aliases.get(node.callee.name) || node.callee.name;
            for (const [ruleKey, detector] of Object.entries(PARANOID_AST_DETECTORS)) {
              if (detector.newNames && detector.newNames.has(name) && !found.has(ruleKey)) {
                found.add(ruleKey);
                const rule = PARANOID_RULES[ruleKey];
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "new ${node.callee.name}"${aliases.has(node.callee.name) ? ` (alias of ${name})` : ''}`,
                  file: relFile, mitre: rule.mitre
                });
              }
            }
          }
        },
        MemberExpression(node) {
          // process.env access
          if (node.object?.type === 'Identifier' && node.object.name === 'process' &&
              node.property?.type === 'Identifier' && node.property.name === 'env' &&
              !found.has('env_access')) {
            found.add('env_access');
            const rule = PARANOID_RULES.env_access;
            threats.push({
              type: rule.id, severity: rule.severity.toUpperCase(),
              message: `${rule.message}: "process.env"`, file: relFile, mitre: rule.mitre
            });
          }
        },
        Literal(node) {
          // Sensitive file string literals
          if (typeof node.value === 'string' && !found.has('sensitive_file_access')) {
            const detector = PARANOID_AST_DETECTORS.sensitive_file_access;
            for (const s of detector.sensitiveStrings) {
              if (node.value.includes(s)) {
                found.add('sensitive_file_access');
                const rule = PARANOID_RULES.sensitive_file_access;
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "${s}"`, file: relFile, mitre: rule.mitre
                });
                break;
              }
            }
          }
        }
      });
    } catch {
      // Ignore read/parse errors
    }
  }

  // Content-based fallback for non-JS files or parse failures
  function scanFileContent(filePath, content, relFile) {
    const contentWithoutUrls = content.replace(/https?:\/\/[^\s"']+/g, '');
    for (const [, rule] of Object.entries(PARANOID_RULES)) {
      for (const pattern of rule.patterns) {
        if (contentWithoutUrls.includes(pattern)) {
          threats.push({
            type: rule.id, severity: rule.severity.toUpperCase(),
            message: `${rule.message}: "${pattern}"`, file: relFile, mitre: rule.mitre
          });
        }
      }
    }
  }

  function scanFile(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) return;
      const ext = path.extname(filePath);
      if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
        scanFileAST(filePath);
      } else {
        const content = fs.readFileSync(filePath, 'utf8');
        const relFile = path.relative(targetPath, filePath);
        scanFileContent(filePath, content, relFile);
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
        } else if (file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs') ||
                   file.endsWith('.json') || file.endsWith('.sh')) {
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
  // Validate targetPath exists and is a directory
  if (!targetPath || !fs.existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }
  if (!fs.statSync(targetPath).isDirectory()) {
    throw new Error(`Target path is not a directory: ${targetPath}`);
  }

  // Ensure IOCs are downloaded (first run only, graceful failure)
  await ensureIOCs();

  // Check IOC freshness — warn if database is older than 30 days
  const iocStalenessWarning = checkIOCStaleness(30);

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

  // Helper: yield to event loop so spinner can animate between sync operations
  const yieldThen = (fn) => new Promise(resolve => setImmediate(() => resolve(fn())));

  // Cross-file module graph analysis (before individual scanners)
  // Wrapped in yieldThen to unblock spinner animation
  // Bounded: 5s timeout to prevent DoS on large/adversarial packages
  const MODULE_GRAPH_TIMEOUT_MS = 5000;
  const warnings = [];
  if (iocStalenessWarning) warnings.push(iocStalenessWarning);
  let crossFileFlows = [];
  if (!options.noModuleGraph) {
    const moduleGraphWork = async () => {
      const graph = await yieldThen(() => buildModuleGraph(targetPath));
      if (Object.keys(graph).length === 0) {
        // buildModuleGraph returns empty when MAX_GRAPH_NODES exceeded
        warnings.push('Module graph skipped: package exceeds 100 files limit');
      }
      const tainted = await yieldThen(() => annotateTaintedExports(graph, targetPath));
      const sinkAnnotations = await yieldThen(() => annotateSinkExports(graph, targetPath));
      crossFileFlows = await yieldThen(() => detectCrossFileFlows(graph, tainted, sinkAnnotations, targetPath));
      // Callback-based cross-file flow detection
      const callbackFlows = await yieldThen(() => detectCallbackCrossFileFlows(graph, tainted, sinkAnnotations, targetPath));
      crossFileFlows = crossFileFlows.concat(callbackFlows);
      // EventEmitter cross-module flow detection
      const emitterFlows = await yieldThen(() => detectEventEmitterFlows(graph, tainted, sinkAnnotations, targetPath));
      crossFileFlows = crossFileFlows.concat(emitterFlows);
    };
    let graphTimerId;
    const timeout = new Promise((_, reject) => {
      graphTimerId = setTimeout(() => reject(new Error('Module graph timeout')), MODULE_GRAPH_TIMEOUT_MS);
    });
    try {
      await Promise.race([moduleGraphWork(), timeout]);
    } catch (e) {
      // Graceful fallback — module graph is best-effort
      debugLog('[MODULE-GRAPH] Error:', e && e.message);
      if (e && e.message === 'Module graph timeout') {
        warnings.push(`Module graph analysis timed out (${MODULE_GRAPH_TIMEOUT_MS / 1000}s) — cross-file flows may be incomplete`);
      }
    } finally {
      clearTimeout(graphTimerId);
    }
  }

  // Sequential execution of scanners with event loop yields between each.
  // All scanners (even "async" ones) are effectively synchronous (readFileSync, readdirSync).
  // Running them via yieldThen ensures the spinner animates between each scanner.
  // Uses Promise.allSettled so one scanner crash doesn't kill the entire scan.
  const SCANNER_NAMES = [
    'scanPackageJson', 'scanShellScripts', 'analyzeAST', 'detectObfuscation',
    'scanDependencies', 'scanHashes', 'analyzeDataFlow', 'scanTyposquatting',
    'scanGitHubActions', 'matchPythonIOCs', 'checkPyPITyposquatting',
    'scanEntropy', 'scanAIConfig'
  ];

  const settledResults = await Promise.allSettled([
    yieldThen(() => scanPackageJson(targetPath)),
    yieldThen(() => scanShellScripts(targetPath)),
    yieldThen(() => analyzeAST(targetPath, { deobfuscate: deobfuscateFn })),
    yieldThen(() => detectObfuscation(targetPath)),
    yieldThen(() => scanDependencies(targetPath)),
    yieldThen(() => scanHashes(targetPath)),
    yieldThen(() => analyzeDataFlow(targetPath, { deobfuscate: deobfuscateFn })),
    yieldThen(() => scanTyposquatting(targetPath)),
    yieldThen(() => scanGitHubActions(targetPath)),
    yieldThen(() => matchPythonIOCs(pythonDeps, targetPath)),
    yieldThen(() => checkPyPITyposquatting(pythonDeps, targetPath)),
    yieldThen(() => scanEntropy(targetPath, { entropyThreshold: options.entropyThreshold || undefined })),
    yieldThen(() => scanAIConfig(targetPath))
  ]);

  // Extract results: use empty array for rejected scanners, log errors
  const scannerErrors = [];
  const scanResult = settledResults.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    scannerErrors.push({ scanner: SCANNER_NAMES[i], error: r.reason });
    console.error(`[WARN] Scanner ${SCANNER_NAMES[i]} failed: ${r.reason?.message || r.reason}`);
    return [];
  });

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
  ] = scanResult;

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
    ...crossFileFlows.filter(f => f && f.sourceFile && f.sinkFile).map(f => ({
      type: f.type,
      severity: f.severity,
      message: `Cross-file dataflow: ${f.source} in ${f.sourceFile} → ${f.sink} in ${f.sinkFile}`,
      file: f.sinkFile
    }))
  ];

  // Paranoid mode
  if (options.paranoid) {
    if (!options.json) {
      console.log('[PARANOID] Ultra-strict mode enabled\n');
    }
    const paranoidThreats = scanParanoid(targetPath);
    threats.push(...paranoidThreats);
  }

  // Temporal analyses (--temporal, --temporal-ast, --temporal-publish, --temporal-maintainer)
  if (options.temporal || options.temporalAst || options.temporalPublish || options.temporalMaintainer) {
    const pkgNames = listInstalledPackages(targetPath);
    const temporalThreats = await runTemporalAnalyses(targetPath, options, pkgNames);
    threats.push(...temporalThreats);
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
    } catch {
      // Graceful fallback — treat all files as reachable
    }
  }

  // Read package name for benign package whitelist
  let packageName = null;
  try {
    const pkgPath = path.join(targetPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      packageName = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).name || null;
    }
  } catch { /* graceful fallback */ }

  // FP reduction: legitimate frameworks produce high volumes of certain threat types.
  // A malware package typically has 1-3 occurrences, not dozens.
  applyFPReductions(deduped, reachableFiles, packageName);

  // Intent coherence analysis: detect source→sink pairs across files
  const intentResult = buildIntentPairs(deduped);
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
    threats: pythonThreats.length + pypiTyposquatThreats.length
  } : null;

  // Track deobfuscation failures
  // (deobfuscate returns {deobfuscatedThreats, failures} but failures aren't surfaced)
  // We detect this via scannerErrors for now

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

  // _capture mode: return result directly without printing (used by diff.js)
  if (options._capture) {
    setExtraExcludes([]);
    clearFileListCache();
    return result;
  }

  formatOutput(result, options, {
    spinner, sandboxData, mostSuspiciousFile, maxFileScore,
    packageScore, globalRiskScore, deduped, enrichedThreats,
    pythonInfo, breakdown, targetPath
  });

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

  // Clear runtime state
  setExtraExcludes([]);
  clearFileListCache();

  return Math.min(failingThreats.length, 125);
}

module.exports = { run, isPackageLevelThreat, computeGroupScore };