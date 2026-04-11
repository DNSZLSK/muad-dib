const fs = require('fs');
const path = require('path');
const { scanPackageJson } = require('../scanner/package.js');
const { scanShellScripts } = require('../scanner/shell.js');
const { analyzeAST } = require('../scanner/ast.js');
const { detectObfuscation } = require('../scanner/obfuscation.js');
const { scanDependencies } = require('../scanner/dependencies.js');
const { scanHashes } = require('../scanner/hash.js');
const { analyzeDataFlow } = require('../scanner/dataflow.js');
const { scanTyposquatting, findPyPITyposquatMatch } = require('../scanner/typosquat.js');
const { scanGitHubActions } = require('../scanner/github-actions.js');
const { scanEntropy } = require('../scanner/entropy.js');
const { scanAIConfig } = require('../scanner/ai-config.js');
const { deobfuscate } = require('../scanner/deobfuscate.js');
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows, annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows } = require('../scanner/module-graph');
const { loadCachedIOCs, checkIOCStaleness } = require('../ioc/updater.js');
const { detectPythonProject, normalizePythonName } = require('../scanner/python.js');
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
  const yieldThen = (fn) => new Promise(resolve => setImmediate(() => resolve(fn())));

  // Cross-file module graph analysis (before individual scanners)
  // Bounded: 5s timeout to prevent DoS on large/adversarial packages
  const MODULE_GRAPH_TIMEOUT_MS = 5000;
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
    'scanEntropy', 'scanAIConfig'
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

  // Emit warning if file count cap was hit + quick-scan overflow files
  const quickScanThreats = [];
  if (wasFilesCapped()) {
    warnings.push('File count cap reached (500 files) — overflow files scanned in quick-scan mode (lifecycle + child_process only).');
    const overflowFiles = getOverflowFiles();
    const QUICK_SCAN_PATTERNS = [
      { re: /\brequire\s*\(\s*['"]child_process['"]\s*\)/, type: 'dangerous_exec', severity: 'HIGH', label: 'require("child_process")' },
      { re: /\brequire\s*\(\s*['"]node:child_process['"]\s*\)/, type: 'dangerous_exec', severity: 'HIGH', label: 'require("node:child_process")' },
      { re: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/, type: 'dangerous_exec', severity: 'HIGH', label: 'exec/spawn call' },
      { re: /\bprocess\.mainModule\b/, type: 'dynamic_require', severity: 'HIGH', label: 'process.mainModule' },
      { re: /\bModule\._load\b/, type: 'module_load_bypass', severity: 'CRITICAL', label: 'Module._load' }
    ];
    for (const filePath of overflowFiles) {
      try {
        const stat = fs.statSync(filePath);
        if (stat.size > getMaxFileSize()) continue;
        const content = fs.readFileSync(filePath, 'utf8');
        const relFile = path.relative(targetPath, filePath);
        for (const pat of QUICK_SCAN_PATTERNS) {
          if (pat.re.test(content)) {
            quickScanThreats.push({
              type: pat.type,
              severity: pat.severity,
              message: `[quick-scan] ${pat.label} detected in overflow file.`,
              file: relFile
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

  return { threats, scannerErrors };
}

module.exports = { execute, matchPythonIOCs, checkPyPITyposquatting };
