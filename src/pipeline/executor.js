/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

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
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows, filterFirstPartyNetworkFlows, annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows, runWithWorkBudget, MAX_FLOWS } = require('../scanner/module-graph');
const { markIncomplete, resetCompleteness } = require('../shared/completeness.js');
const { loadCachedIOCs } = require('../ioc/updater.js');
// Below this many npm IOC entries the database is considered absent: the YAML built-ins alone
// hold a few dozen; a full database holds about 250 000.
const MIN_LOADED_IOC_PACKAGES = 1000;
// Per heavy scanner, in source characters analyzed (architecture lot 2). Measured 2026-11-15
// on 50 npm packages (40 random + the 10 largest of a 395-package random sample): at most
// 16.8 MB of analyzable source (vuetify, pro-design-vue, 2 000-file cap reached), 0.7 to
// 3.9 s per MB for AST + dataflow. 32 Mi is about twice the largest benign package.
const DEFAULT_SCANNER_WORK_BUDGET = 32 * 1024 * 1024;
// Module-graph analysis, in source characters read by its six steps together (each step
// reads the graph's files again, the direct-flow steps twice). Measured 2026-11-15 on the
// same 50 packages: at most 22.6 Mi (@emotion-icons/crypto, 944 files, about 4 s; it flipped
// between COMPLETE and INCONCLUSIVE under the former 5 s clock), next 18.8 Mi; 5 to 10 Mi
// per second. 32 Mi is about 1.4 times the largest benign package.
const DEFAULT_MODULE_GRAPH_WORK_BUDGET = 32 * 1024 * 1024;
const { normalizePythonName } = require('../scanner/python.js');
const { scanPythonSource } = require('../scanner/python-source.js');
const { initPythonParser, scanPythonAST } = require('../scanner/python-ast.js');
const { scanAntiScannerInjection } = require('../scanner/anti-scanner-injection.js');
const { scanBinarySource } = require('../scanner/binary-source.js');
const { Spinner, listInstalledPackages, wasFilesCapped, getOverflowFiles, debugLog, getMaxScanFiles } = require('../utils.js');
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

const SCANNER_NAMES = [
  'scanPackageJson', 'scanShellScripts', 'analyzeAST', 'detectObfuscation',
  'scanDependencies', 'scanHashes', 'analyzeDataFlow', 'scanTyposquatting',
  'scanGitHubActions', 'matchPythonIOCs', 'checkPyPITyposquatting',
  'scanEntropy', 'scanAIConfig', 'scanIocStrings', 'scanAntiForensic',
  'scanStubPackage', 'scanMonorepo', 'scanTrustedDepDiff', 'scanPythonSource',
  'scanPythonAST', 'scanAntiScannerInjection', 'scanBinarySource'
];

// Stage 2 quick_scan subset (monitor-only, set via options.scanMode='quick'
// by queue.js when MUADDIB_TRIAGE_MODE=enforce). The subset keeps the heavy
// detectors that anchor TPR on the 96-sample GT (analyzeAST covers 70/96,
// analyzeDataFlow covers 31/96 — non-negotiable), the cheap high-signal
// lifecycle/IOC scanners, and the Python detectors (PyPI samples need them;
// npm exit immediately on a depth-1 readdir, so the cost is negligible).
// Excluded: scanAntiForensic (45s timeout, never the unique trigger on GT),
// scanHashes (cheap but GT samples are rebuilt — hashes drift), scanAIConfig,
// scanStubPackage, scanMonorepo, scanTrustedDepDiff (opt-in registry diff),
// checkPyPITyposquatting (subsumed by scanTyposquatting for npm; PyPI
// typosquats already get full via triage signals). CLI mode and shadow mode
// never set scanMode so the default branch runs all 20 scanners — fully
// backwards-compatible.
// Module-level + exported so tests assert THIS set, not a copy (audit 2026-07:
// triage-gt.test.js compared two hand-maintained replicas of it).
const QUICK_SCAN_ALLOWLIST = new Set([
  'scanPackageJson',
  'scanShellScripts',
  'analyzeAST',
  'detectObfuscation',
  'scanDependencies',
  'analyzeDataFlow',
  'scanTyposquatting',
  'scanGitHubActions',
  'matchPythonIOCs',
  'scanEntropy',
  'scanIocStrings',
  'scanPythonSource',
  'scanPythonAST',
  'scanAIConfig',
  'scanAntiScannerInjection',
  'scanBinarySource'
]);

async function execute(targetPath, options, pythonDeps, warnings) {
  // Show spinner during scan (TTY only; piped/CI output keeps static message)
  const useTTYSpinner = !options._capture && process.stdout.isTTY;
  let spinner = null;
  if (useTTYSpinner) {
    spinner = new Spinner();
    spinner.start(`[MUADDIB] Scanning ${targetPath}...`);
  }

  // try/finally guarantees the spinner's setInterval is always cleared. A scanner
  // throwing before the succeed() below would otherwise leave it animating AND keep
  // the event loop alive (process hang). _stop() is idempotent.
  try {

  // Fresh incompleteness record for this scan (resetAll() also clears it at the
  // end; this guards direct execute() callers that never reach resetAll()).
  resetCompleteness();

  // No IOC database = known-malicious package detection did not run: the scan is INCONCLUSIVE
  // (lot 1 contract), never SAFE. Measured 2026-11-14: a fresh npm install of 2.12.2 scored a
  // flatmap-stream@0.1.1 dependency 0 because the database download had been a 404 for months.
  // Checked here, after the reset above (initialize() runs before it).
  {
    let iocPackageCount = 0;
    try {
      const iocs = loadCachedIOCs();
      iocPackageCount = (iocs.packagesMap ? iocs.packagesMap.size : 0) + (iocs.wildcardPackages ? iocs.wildcardPackages.size : 0);
    } catch { /* unreadable database counts as absent */ }
    if (iocPackageCount < MIN_LOADED_IOC_PACKAGES) {
      markIncomplete('iocs', 'database-unavailable', { limit: MIN_LOADED_IOC_PACKAGES, observed: iocPackageCount });
    }
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

  // Cross-file module graph analysis (before individual scanners).
  // Bounded by a work budget in source characters read (architecture lot 2), not a clock:
  // the 5 s wall-clock budget it replaces flipped borderline packages between COMPLETE and
  // INCONCLUSIVE from one run to the next. Env-tunable (non-negative integer) so the
  // exhaustion path is testable. Strict parse: an empty or malformed value
  // (`MUADDIB_MODULE_GRAPH_WORK_BUDGET=` in a CI config) must not become Number('') === 0,
  // which would skip cross-file analysis on every scan.
  const rawGraphBudget = process.env.MUADDIB_MODULE_GRAPH_WORK_BUDGET;
  const MODULE_GRAPH_WORK_BUDGET = typeof rawGraphBudget === 'string' && /^\d+$/.test(rawGraphBudget.trim())
    ? parseInt(rawGraphBudget.trim(), 10) : DEFAULT_MODULE_GRAPH_WORK_BUDGET;
  let crossFileFlows = [];
  // Threats ABOUT the module graph (audit DF-C1): truncation when the package
  // exceeds MAX_GRAPH_NODES. Separate from crossFileFlows because the latter
  // gets filtered/reshaped (line ~316 requires sourceFile && sinkFile).
  const moduleGraphThreats = [];
  if (!options.noModuleGraph) {
    // Incompleteness contract (architecture lot 1): the graph result is published
    // exactly once, by this function, after its last step. The previous
    // Promise.race let the losing work keep running and mutate crossFileFlows
    // after the scan had moved on, so the verdict depended on which step was
    // reached (28 -> 10 or 10 -> 28, audit 2026-09-29). Every step is synchronous and
    // reads its files through parseFile, which charges the budget: once it is spent,
    // the step skips its remaining files and the next steps are skipped; the flows
    // already produced still go through the destination filter, and the analysis is
    // marked INCONCLUSIVE. Same input, same budget, same result on any machine.
    const graphBudget = { limit: MODULE_GRAPH_WORK_BUDGET, used: 0, exhausted: false };
    const step = (fn) => yieldThen(() => runWithWorkBudget(graphBudget, fn));
    const overBudget = () => graphBudget.exhausted;
    const moduleGraphWork = async () => {
      let direct = [];
      let indirect = [];
      const graphMeta = {};
      const graph = await step(() => buildModuleGraph(targetPath, graphMeta));
      if (graphMeta.truncated) {
        warnings.push(`Module graph skipped: ${graphMeta.fileCount} files exceeds MAX_GRAPH_NODES (${graphMeta.maxNodes})`);
        moduleGraphThreats.push({
          type: 'large_package_graph_truncated',
          severity: 'MEDIUM',
          message: `Cross-file analysis disabled: ${graphMeta.fileCount} files exceed the limit (${graphMeta.maxNodes}). Risk of a blind spot on a monorepo / large package — audit the sub-modules manually.`,
          file: 'package.json',
          line: 0,
          fileCount: graphMeta.fileCount,
          maxNodes: graphMeta.maxNodes
        });
      }
      // A step that throws stops the remaining steps but keeps the flows already
      // produced (they still go through the filter below): a crash is reported
      // as INCONCLUSIVE, never as an empty, complete result.
      try {
        run: {
          if (overBudget()) break run;
          const tainted = await step(() => annotateTaintedExports(graph, targetPath));
          if (overBudget()) break run;
          const sinkAnnotations = await step(() => annotateSinkExports(graph, targetPath));
          if (overBudget()) break run;
          direct = await step(() => detectCrossFileFlows(graph, tainted, sinkAnnotations, targetPath));
          if (overBudget()) break run;
          // Callback-based cross-file flow detection
          indirect = indirect.concat(await step(() => detectCallbackCrossFileFlows(graph, tainted, sinkAnnotations, targetPath)));
          if (overBudget()) break run;
          // EventEmitter cross-module flow detection
          indirect = indirect.concat(await step(() => detectEventEmitterFlows(graph, tainted, sinkAnnotations, targetPath)));
        }
      } catch (e) {
        debugLog('[MODULE-GRAPH] Error:', e && e.message);
        markIncomplete('moduleGraph', 'error');
      }
      // FP gate (segment A): drop cross_file_dataflow flows whose network sink targets
      // only first-party/local/provider destinations — legit SDK calls, not exfil.
      // Suspicious/unknown/public-IP destinations and exec sinks are kept (ecto stays).
      // Runs on whatever was produced, even after a timeout: an unfiltered candidate
      // must never be published. The MAX_FLOWS quota applies AFTER the filter so
      // filtered decoys cannot consume it.
      direct = filterFirstPartyNetworkFlows(direct, targetPath);
      // More flows than the quota survive the filter: the surplus is not published, so
      // the analysis cannot claim to be complete. Measured 2026-11-13 on the 3 242-package
      // corpus sample: the maximum is 5 flows after the filter, so this marks no package there.
      if (direct.length > MAX_FLOWS) {
        markIncomplete('moduleGraph', 'flow-limit', { limit: MAX_FLOWS, observed: direct.length });
        direct = direct.slice(0, MAX_FLOWS);
      }
      indirect = filterFirstPartyNetworkFlows(indirect, targetPath);
      return direct.concat(indirect);
    };
    try {
      crossFileFlows = await moduleGraphWork();
    } catch (e) {
      // buildModuleGraph or the filter threw: nothing reliable to publish.
      debugLog('[MODULE-GRAPH] Error:', e && e.message);
      markIncomplete('moduleGraph', 'error');
      crossFileFlows = [];
    }
    debugLog(`[MODULE-GRAPH] work ${graphBudget.used} / ${MODULE_GRAPH_WORK_BUDGET} chars`);
    if (graphBudget.exhausted) {
      markIncomplete('moduleGraph', 'work-budget', { limit: MODULE_GRAPH_WORK_BUDGET, observed: graphBudget.used });
      warnings.push(`Module graph analysis stopped at its work budget (${MODULE_GRAPH_WORK_BUDGET} source characters): cross-file flows may be incomplete`);
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
  // Per-scanner work budget (ANSSI audit m2, architecture lot 2): prevents DoS via
  // adversarial packages with many large files. Heavy scanners (AST, dataflow, entropy,
  // anti-forensic) are synchronous, so a timer can never interrupt them: each one counts the
  // source characters it analyzes and, past the budget, stops before the next file, returns
  // the findings already made (executed files first) and marks itself INCONCLUSIVE. A count,
  // not a clock, so the verdict does not depend on the machine. The hard wall-clock bound is
  // one level up: hard-timeout.js for the CLI, the terminated scan worker for the monitor.
  // Strict parse, as for the graph budget.
  const rawWorkBudget = process.env.MUADDIB_SCANNER_WORK_BUDGET;
  const SCANNER_WORK_BUDGET = typeof rawWorkBudget === 'string' && /^\d+$/.test(rawWorkBudget.trim())
    ? parseInt(rawWorkBudget.trim(), 10) : DEFAULT_SCANNER_WORK_BUDGET;
  const SCANNER_TIMEOUT_MS = 45000; // scanTrustedDepDiff only (registry I/O)

  function withBudget(fn) {
    return yieldThen(() => fn({ byteBudget: SCANNER_WORK_BUDGET }));
  }

  // Real timer, for the one scanner that awaits I/O (registry fetches). Started when the
  // scanner starts, not when the batch is built: the synchronous scanners before it would
  // otherwise consume its budget.
  function withTimeout(fn, name) {
    return yieldThen(() => new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        // Incompleteness contract: a timed-out scanner is never reported as a clean result.
        debugLog(`[TIMEOUT] Scanner ${name} exceeded ${SCANNER_TIMEOUT_MS / 1000}s`);
        markIncomplete(name, 'timeout', { limit: SCANNER_TIMEOUT_MS });
        resolve([]);
      }, SCANNER_TIMEOUT_MS);
      Promise.resolve().then(fn).then(result => { clearTimeout(timer); resolve(result); })
        .catch(err => { clearTimeout(timer); reject(err); });
    }));
  }

  const isQuick = options.scanMode === 'quick';
  function ifEnabled(name, fn) {
    if (isQuick && !QUICK_SCAN_ALLOWLIST.has(name)) return Promise.resolve([]);
    return fn();
  }
  if (isQuick) {
    const skipped = SCANNER_NAMES.filter(n => !QUICK_SCAN_ALLOWLIST.has(n));
    debugLog(`[EXECUTOR] scanMode=quick — skipping ${skipped.length} scanners: ${skipped.join(', ')}`);
  }

  const settledResults = await Promise.allSettled([
    ifEnabled('scanPackageJson', () => yieldThen(() => scanPackageJson(targetPath))),
    ifEnabled('scanShellScripts', () => yieldThen(() => scanShellScripts(targetPath))),
    ifEnabled('analyzeAST', () => withBudget(budget => analyzeAST(targetPath, { deobfuscate: deobfuscateFn, ...budget }))),
    ifEnabled('detectObfuscation', () => yieldThen(() => detectObfuscation(targetPath))),
    ifEnabled('scanDependencies', () => yieldThen(() => scanDependencies(targetPath))),
    ifEnabled('scanHashes', () => yieldThen(() => scanHashes(targetPath))),
    ifEnabled('analyzeDataFlow', () => withBudget(budget => analyzeDataFlow(targetPath, { deobfuscate: deobfuscateFn, ...budget }))),
    ifEnabled('scanTyposquatting', () => yieldThen(() => scanTyposquatting(targetPath))),
    ifEnabled('scanGitHubActions', () => yieldThen(() => scanGitHubActions(targetPath))),
    ifEnabled('matchPythonIOCs', () => yieldThen(() => matchPythonIOCs(pythonDeps, targetPath))),
    ifEnabled('checkPyPITyposquatting', () => yieldThen(() => checkPyPITyposquatting(pythonDeps, targetPath))),
    ifEnabled('scanEntropy', () => withBudget(budget => scanEntropy(targetPath, { entropyThreshold: options.entropyThreshold || undefined, ...budget }))),
    ifEnabled('scanAIConfig', () => yieldThen(() => scanAIConfig(targetPath))),
    ifEnabled('scanIocStrings', () => yieldThen(() => scanIocStrings(targetPath))),
    ifEnabled('scanAntiForensic', () => withBudget(budget => scanAntiForensic(targetPath, budget))),
    ifEnabled('scanStubPackage', () => yieldThen(() => scanStubPackage(targetPath))),
    ifEnabled('scanMonorepo', () => yieldThen(() => scanMonorepo(targetPath))),
    // Opt-in scanner — short-circuits to [] unless options.trustedDepDiff or
    // options.monitorMode is set. CLI runs without flags pay no cost (no I/O).
    // Wrapped in withTimeout as defense in depth: scanner has its own 10s + 5s × N
    // internal timeouts, but a registry slowdown with many added deps could exceed
    // the static-scan budget without this cap.
    ifEnabled('scanTrustedDepDiff', () => withTimeout(() => scanTrustedDepDiff(targetPath, options), 'scanTrustedDepDiff')),
    // PYSRC-001..008 (v2.11.25, TrapDoor PyPI gap). Detect import-time RCE
    // in __init__.py / setup.py / top-level .py files. Runs always — not gated
    // on detectPythonProject() because an attacker can ship a malicious __init__.py
    // without a requirements.txt. Walker is cheap (just a depth-1 readdir).
    ifEnabled('scanPythonSource', () => yieldThen(() => scanPythonSource(targetPath))),
    // PYAST-001..008 (v2.11.42+, npm/PyPI parity Phase 1). Full Python CST
    // analysis via tree-sitter-python WASM. Scope-aware module-level detection
    // of cmdclass override, exec, subprocess shell=True, pickle.loads,
    // __import__ dangerous, entry_points. Parser init happens at pre-analysis
    // stage above; this call is sync from the caller's POV.
    ifEnabled('scanPythonAST', () => yieldThen(() => scanPythonAST(targetPath))),
    // ASI-001..004 (chantier 2026-06-20). Anti-scanner prompt injection in source text
    // (comments/strings). Regex-only, cheap; the attack lives in root entry files.
    ifEnabled('scanAntiScannerInjection', () => yieldThen(() => scanAntiScannerInjection(targetPath))),
    // BINSRC-001 (Layer 2): binary masquerading as a .js/.ts source file. Scans dist/build/out
    // (which the other text scanners exclude) reading an 8 KB prefix — catches multi-MB carriers.
    ifEnabled('scanBinarySource', () => yieldThen(() => scanBinarySource(targetPath)))
  ]);

  // Extract results: use empty array for rejected scanners, log errors
  const scannerErrors = [];
  const scanResult = settledResults.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const message = String((r.reason && r.reason.message) || r.reason);
    // `error` stays the raw reason (an Error serializes to {} in JSON); `message` is readable.
    scannerErrors.push({ scanner: SCANNER_NAMES[i], error: r.reason, message });
    console.error(`[WARN] Scanner ${SCANNER_NAMES[i]} failed: ${message}`);
    // Incompleteness contract: a crashed scanner contributed nothing, so the scan cannot be
    // COMPLETE. A one-line package.json value that crashed scanPackageJson hid a
    // `postinstall: curl | sh` (score 75 -> 0, reported SAFE) before this mark.
    markIncomplete(SCANNER_NAMES[i], 'error');
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
    pythonAstThreats,
    antiScannerThreats,
    binarySourceThreats
  ] = scanResult;

  // A partial archive extraction (tar refused members, see download.js) means part of the
  // package was never on disk: the scan is INCONCLUSIVE under the lot 1 contract, not only
  // a LOW finding.
  if (Array.isArray(options.extractionFindings) &&
      options.extractionFindings.some(t => t && t.type === 'archive_partial_extraction')) {
    markIncomplete('extraction', 'partial-archive');
  }

  // Emit warning if file count cap was hit + quick-scan overflow files
  const quickScanThreats = [];
  if (wasFilesCapped()) {
    markIncomplete('files', 'file-cap', { limit: getMaxScanFiles() });
    warnings.push(`File count cap reached (${getMaxScanFiles()} files) — overflow files scanned in quick-scan mode (lifecycle + child_process only).`);
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
    ...antiScannerThreats,
    ...binarySourceThreats,
    ...crossFileFlows.filter(f => f && f.sourceFile && f.sinkFile).map(f => ({
      type: f.type,
      severity: f.severity,
      message: `Cross-file dataflow: ${f.source} in ${f.sourceFile} → ${f.sink} in ${f.sinkFile}`,
      file: f.sinkFile
    })),
    ...moduleGraphThreats,
    // Archive-level findings from the caller's extraction (monitor/evaluate): a partial tar
    // extraction and the members tar refused. Only these two types are accepted.
    ...(Array.isArray(options.extractionFindings) ? options.extractionFindings : [])
      .filter(t => t && (t.type === 'archive_hostile_member' || t.type === 'archive_partial_extraction'))
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
  } finally {
    if (spinner) spinner._stop();
  }
}

module.exports = { execute, matchPythonIOCs, checkPyPITyposquatting, QUICK_SCAN_ALLOWLIST, SCANNER_NAMES };
