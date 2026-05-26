const fs = require('fs');
const path = require('path');
const { scanPackageJson } = require('../scanner/package.js');
const { scanShellScripts } = require('../scanner/shell.js');
const { analyzeAST } = require('../scanner/ast.js');
const { detectObfuscation } = require('../scanner/obfuscation.js');
const { scanDependencies } = require('../scanner/dependencies.js');
const { scanHashes } = require('../scanner/hash.js');
const { scanIocStrings } = require('../scanner/ioc-strings.js');
const { scanAntiForensic } = require('../scanner/anti-forensic.js');
const { scanStubPackage } = require('../scanner/stub-package.js');
const { scanMonorepo } = require('../scanner/monorepo.js');
const { scanTrustedDepDiff } = require('../scanner/trusted-dep-diff.js');
const { analyzeDataFlow } = require('../scanner/dataflow.js');
const { scanTyposquatting, findPyPITyposquatMatch } = require('../scanner/typosquat.js');
const { scanGitHubActions } = require('../scanner/github-actions.js');
const { scanEntropy } = require('../scanner/entropy.js');
const { scanAIConfig } = require('../scanner/ai-config.js');
const { deobfuscate } = require('../scanner/deobfuscate.js');
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows, annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows } = require('../scanner/module-graph');
const { loadCachedIOCs, checkIOCStaleness } = require('../ioc/updater.js');
const { detectPythonProject, normalizePythonName } = require('../scanner/python.js');
const { scanPythonSource } = require('../scanner/python-source.js');
const { initPythonParser, scanPythonAST } = require('../scanner/python-ast.js');
const { Spinner, listInstalledPackages, wasFilesCapped, getOverflowFiles, debugLog } = require('../utils.js');
const { getMaxFileSize } = require('../shared/constants.js');
const { scanParanoid } = require('../scanner/paranoid.js');
const { runTemporalAnalyses } = require('../temporal-runner.js');

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

/**
 * Execute all scanners and collect threats.
 * @param {string} targetPath - Directory to scan
 * @param {object} options - CLI options
 * @param {Array} pythonDeps - Detected Python dependencies
 * @param {string[]} warnings - Warnings array (mutated: may push module graph warnings)
 * @returns {Promise<{threats: Array, scannerErrors: Array}>}
 */
async function execute(targetPath, options, pythonDeps, warnings) {
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
  // Yield to the event loop before running `fn`. Without the try/catch the
  // exception escapes the setImmediate callback as an uncaught exception
  // (Node's setImmediate handler is outside any await/promise frame) and
  // crashes the process — which is what was killing evaluate on benigns that
  // hit a corner-case in detect-cross-file.js. Now sync throws become
  // promise rejections, picked up by the surrounding try/catch.
  const yieldThen = (fn) => new Promise((resolve, reject) =>
    setImmediate(() => { try { resolve(fn()); } catch (e) { reject(e); } })
  );

  // Cross-file module graph analysis (before individual scanners)
  // Bounded: 5s timeout to prevent DoS on large/adversarial packages
  const MODULE_GRAPH_TIMEOUT_MS = 5000;
  let crossFileFlows = [];
  // Threats ABOUT the module graph (audit DF-C1): truncation when the package
  // exceeds MAX_GRAPH_NODES. Separate from crossFileFlows because the latter
  // gets filtered/reshaped (line ~316 requires sourceFile && sinkFile).
  const moduleGraphThreats = [];
  if (!options.noModuleGraph) {
    const moduleGraphWork = async () => {
      const graphMeta = {};
      const graph = await yieldThen(() => buildModuleGraph(targetPath, graphMeta));
      if (graphMeta.truncated) {
        warnings.push(`Module graph skipped: ${graphMeta.fileCount} files exceeds MAX_GRAPH_NODES (${graphMeta.maxNodes})`);
        moduleGraphThreats.push({
          type: 'large_package_graph_truncated',
          severity: 'MEDIUM',
          message: `Cross-file analysis désactivée : ${graphMeta.fileCount} fichiers dépassent la limite (${graphMeta.maxNodes}). Risque de blind spot sur monorepo / large package — auditer les sous-modules manuellement.`,
          file: 'package.json',
          line: 0,
          fileCount: graphMeta.fileCount,
          maxNodes: graphMeta.maxNodes
        });
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

  // Pre-analysis stage: init the tree-sitter Python parser (async WASM load).
  // Same pattern as the module-graph block above — runs once before the
  // parallel scanner batch. If init fails (web-tree-sitter missing, WASM
  // corrupted, etc.), the PYAST scanner silently returns [] downstream;
  // we never block the whole scan on this.
  try {
    await initPythonParser();
  } catch (e) {
    debugLog('[PYAST-INIT] failed (continuing without Python AST scanner):', e && e.message);
  }

  // Sequential execution of scanners with event loop yields between each.
  // All scanners (even "async" ones) are effectively synchronous (readFileSync, readdirSync).
  // Running them via yieldThen ensures the spinner animates between each scanner.
  // Uses Promise.allSettled so one scanner crash doesn't kill the entire scan.
  //
  // Per-scanner timeout (ANSSI audit m2): prevents DoS via adversarial packages
  // with deep nesting or pathological AST structures. Heavy scanners (AST, dataflow,
  // entropy) get individual timeouts; lightweight scanners run without timeout.
  const SCANNER_TIMEOUT_MS = 45000; // 45s per heavy scanner

  function withTimeout(fn, name) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        debugLog(`[TIMEOUT] Scanner ${name} exceeded ${SCANNER_TIMEOUT_MS / 1000}s — returning partial results`);
        resolve([]);
      }, SCANNER_TIMEOUT_MS);
      yieldThen(fn).then(result => { clearTimeout(timer); resolve(result); })
        .catch(err => { clearTimeout(timer); reject(err); });
    });
  }

  const SCANNER_NAMES = [
    'scanPackageJson', 'scanShellScripts', 'analyzeAST', 'detectObfuscation',
    'scanDependencies', 'scanHashes', 'analyzeDataFlow', 'scanTyposquatting',
    'scanGitHubActions', 'matchPythonIOCs', 'checkPyPITyposquatting',
    'scanEntropy', 'scanAIConfig', 'scanIocStrings', 'scanAntiForensic',
    'scanStubPackage', 'scanMonorepo', 'scanTrustedDepDiff', 'scanPythonSource',
    'scanPythonAST'
  ];

  const settledResults = await Promise.allSettled([
    yieldThen(() => scanPackageJson(targetPath)),
    yieldThen(() => scanShellScripts(targetPath)),
    withTimeout(() => analyzeAST(targetPath, { deobfuscate: deobfuscateFn }), 'analyzeAST'),
    yieldThen(() => detectObfuscation(targetPath)),
    yieldThen(() => scanDependencies(targetPath)),
    yieldThen(() => scanHashes(targetPath)),
    withTimeout(() => analyzeDataFlow(targetPath, { deobfuscate: deobfuscateFn }), 'analyzeDataFlow'),
    yieldThen(() => scanTyposquatting(targetPath)),
    yieldThen(() => scanGitHubActions(targetPath)),
    yieldThen(() => matchPythonIOCs(pythonDeps, targetPath)),
    yieldThen(() => checkPyPITyposquatting(pythonDeps, targetPath)),
    withTimeout(() => scanEntropy(targetPath, { entropyThreshold: options.entropyThreshold || undefined }), 'scanEntropy'),
    yieldThen(() => scanAIConfig(targetPath)),
    yieldThen(() => scanIocStrings(targetPath)),
    withTimeout(() => scanAntiForensic(targetPath), 'scanAntiForensic'),
    yieldThen(() => scanStubPackage(targetPath)),
    yieldThen(() => scanMonorepo(targetPath)),
    // Opt-in scanner — short-circuits to [] unless options.trustedDepDiff or
    // options.monitorMode is set. CLI runs without flags pay no cost (no I/O).
    // Wrapped in withTimeout as defense in depth: scanner has its own 10s + 5s × N
    // internal timeouts, but a registry slowdown with many added deps could exceed
    // the static-scan budget without this cap.
    withTimeout(() => scanTrustedDepDiff(targetPath, options), 'scanTrustedDepDiff'),
    // PYSRC-001..008 (v2.11.25, TrapDoor PyPI gap). Detect import-time RCE
    // in __init__.py / setup.py / top-level .py files. Runs always — not gated
    // on detectPythonProject() because an attacker can ship a malicious __init__.py
    // without a requirements.txt. Walker is cheap (just a depth-1 readdir).
    yieldThen(() => scanPythonSource(targetPath)),
    // PYAST-001..008 (v2.11.42+, npm/PyPI parity Phase 1). Full Python CST
    // analysis via tree-sitter-python WASM. Scope-aware module-level detection
    // of cmdclass override, exec, subprocess shell=True, pickle.loads,
    // __import__ dangerous, entry_points. Parser init happens at pre-analysis
    // stage above; this call is sync from the caller's POV.
    yieldThen(() => scanPythonAST(targetPath))
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
    aiConfigThreats,
    iocStringThreats,
    antiForensicThreats,
    stubPackageThreats,
    monorepoThreats,
    trustedDepDiffThreats,
    pythonSourceThreats,
    pythonAstThreats
  ] = scanResult;

  // Emit warning if file count cap was hit + quick-scan overflow files
  const quickScanThreats = [];
  if (wasFilesCapped()) {
    warnings.push('File count cap reached (500 files) — overflow files scanned in quick-scan mode (lifecycle + child_process only).');
    const overflowFiles = getOverflowFiles();
    // v2.10.73 P3: Quick-scan is a DEGRADED regex-based pass — no AST, no scope
    // tracking. It cannot distinguish exec() at module top-level (CRITICAL) from
    // exec() inside an exported route handler (LOW runtime). Audit forensique v2.10.72:
    // 18+ fires AST-007 sur rsshub/dist-lib/*.mjs where spawn() lives inside exported
    // route handlers. Default severity is now MEDIUM (downgraded from HIGH). Module._load
    // remains CRITICAL — very rare outside of malware. Threats are flagged `degraded:true`
    // so scoring.js excludes them from max_file_score (see applyFPReductions).
    const QUICK_SCAN_PATTERNS = [
      { re: /\brequire\s*\(\s*['"]child_process['"]\s*\)/, type: 'dangerous_exec', severity: 'MEDIUM', label: 'require("child_process")' },
      { re: /\brequire\s*\(\s*['"]node:child_process['"]\s*\)/, type: 'dangerous_exec', severity: 'MEDIUM', label: 'require("node:child_process")' },
      { re: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/, type: 'dangerous_exec', severity: 'MEDIUM', label: 'exec/spawn call' },
      { re: /\bprocess\.mainModule\b/, type: 'dynamic_require', severity: 'MEDIUM', label: 'process.mainModule' },
      { re: /\bModule\._load\b/, type: 'module_load_bypass', severity: 'CRITICAL', label: 'Module._load' }
    ];
    // v2.11.11: Tooling path detection for quick-scan. Files in standard monorepo
    // tooling directories (scripts/, test/, examples/, .github/, compiler/) carry
    // much lower signal than root/src files — build/CI/test scripts legitimately
    // use child_process. Downgrade non-CRITICAL findings to LOW in these paths.
    // Module._load remains CRITICAL — it is never legitimate in tooling scripts.
    const TOOLING_PATH_RE = /(?:^|[/\\])(?:scripts|test|tests|__tests__|spec|examples|fixtures|compiler[/\\]scripts|\.github)[/\\]/i;
    for (const filePath of overflowFiles) {
      try {
        const stat = fs.statSync(filePath);
        if (stat.size > getMaxFileSize()) continue;
        const content = fs.readFileSync(filePath, 'utf8');
        const relFile = path.relative(targetPath, filePath);
        const isToolingPath = TOOLING_PATH_RE.test(relFile);
        for (const pat of QUICK_SCAN_PATTERNS) {
          if (pat.re.test(content)) {
            // Downgrade non-CRITICAL findings in tooling paths to LOW
            const severity = (isToolingPath && pat.severity !== 'CRITICAL') ? 'LOW' : pat.severity;
            quickScanThreats.push({
              type: pat.type,
              severity,
              message: `[quick-scan] ${pat.label} detected in overflow file.`,
              file: relFile,
              degraded: true,  // P3: regex-only detection, no semantic context
              quickScan: true
            });
          }
        }
      } catch { /* skip unreadable files */ }
    }
    if (quickScanThreats.length > 0) {
      debugLog(`Quick-scan found ${quickScanThreats.length} threats in ${overflowFiles.length} overflow files`);
    }
  }

  // Stop spinner now that scanning is complete
  if (spinner) {
    spinner.succeed(`[MUADDIB] Scanned ${targetPath}`);
  }

  const threats = [
    ...packageThreats,
    ...shellThreats,
    ...astThreats,
    ...quickScanThreats,
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
    ...iocStringThreats,
    ...antiForensicThreats,
    ...stubPackageThreats,
    ...monorepoThreats,
    ...trustedDepDiffThreats,
    ...pythonSourceThreats,
    ...pythonAstThreats,
    ...crossFileFlows.filter(f => f && f.sourceFile && f.sinkFile).map(f => ({
      type: f.type,
      severity: f.severity,
      message: `Cross-file dataflow: ${f.source} in ${f.sourceFile} → ${f.sink} in ${f.sinkFile}`,
      file: f.sinkFile
    })),
    ...moduleGraphThreats
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

  return { threats, scannerErrors };
}

module.exports = { execute, matchPythonIOCs, checkPyPITyposquatting };
