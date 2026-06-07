#!/usr/bin/env node
/**
 * scripts/regression-check.js
 *
 * Compares the latest two metrics/v{version}.json snapshots and fails (exit 1)
 * if any FPR metric regressed by more than the threshold, or if TPR/ADR
 * dropped beyond tolerance.
 *
 * Drives Chantier 8 of the FPR improvement plan : protect the gains from
 * chantiers 1-7 against silent regressions (CLAUDE.md interdictions :
 * "pas de regression silencieuse").
 *
 * Usage :
 *   node scripts/regression-check.js                                # latest vs second-latest
 *   node scripts/regression-check.js --current path1 --baseline path2
 *   node scripts/regression-check.js --fpr-tolerance 0.005          # default 0.5pt
 *   node scripts/regression-check.js --tpr-tolerance 0.005          # default 0.5pt
 *   node scripts/regression-check.js --adr-tolerance 0.005          # default 0.5pt
 *   node scripts/regression-check.js --json
 *
 * Exit codes :
 *   0 - no regression beyond tolerance
 *   1 - regression detected (one or more metrics worsened)
 *   2 - usage / file error
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const METRICS_DIR = path.join(ROOT, 'metrics');

// Default tolerances : 0.5 percentage point absolute
const DEFAULT_FPR_TOLERANCE = 0.005;
const DEFAULT_TPR_TOLERANCE = 0.005;
const DEFAULT_ADR_TOLERANCE = 0.005;

function parseArgs(argv) {
  const args = {
    current: null,
    baseline: null,
    fprTolerance: DEFAULT_FPR_TOLERANCE,
    tprTolerance: DEFAULT_TPR_TOLERANCE,
    adrTolerance: DEFAULT_ADR_TOLERANCE,
    json: false
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--current') args.current = argv[++i];
    else if (a === '--baseline') args.baseline = argv[++i];
    else if (a === '--fpr-tolerance') args.fprTolerance = parseFloat(argv[++i]);
    else if (a === '--tpr-tolerance') args.tprTolerance = parseFloat(argv[++i]);
    else if (a === '--adr-tolerance') args.adrTolerance = parseFloat(argv[++i]);
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node scripts/regression-check.js [--current path] [--baseline path] [--fpr-tolerance N] [--tpr-tolerance N] [--adr-tolerance N] [--json]');
      process.exit(0);
    }
  }
  return args;
}

/**
 * Sort metrics filenames by semver descending. Returns absolute paths.
 */
function listMetricsDescending() {
  if (!fs.existsSync(METRICS_DIR)) return [];
  const files = fs.readdirSync(METRICS_DIR).filter(f => /^v[\d.]+\.json$/.test(f));
  files.sort((a, b) => {
    const va = a.slice(1, -5).split('.').map(Number);
    const vb = b.slice(1, -5).split('.').map(Number);
    for (let i = 0; i < Math.max(va.length, vb.length); i++) {
      const x = va[i] || 0;
      const y = vb[i] || 0;
      if (x !== y) return y - x;
    }
    return 0;
  });
  return files.map(f => path.join(METRICS_DIR, f));
}

function loadMetrics(filepath) {
  if (!fs.existsSync(filepath)) {
    throw new Error(`Metrics file not found : ${filepath}`);
  }
  return JSON.parse(fs.readFileSync(filepath, 'utf8'));
}

function getRate(node) {
  if (!node || typeof node !== 'object') return null;
  if (typeof node.fpr === 'number') return { rate: node.fpr, flagged: node.flagged, scanned: node.scanned };
  if (typeof node.tpr === 'number') return { rate: node.tpr, detected: node.detected, total: node.total };
  if (typeof node.adr === 'number') return { rate: node.adr, detected: node.detected, available: node.available };
  return null;
}

/**
 * Check a metric for regression. A regression is a worsening:
 *   - FPR going up beyond tolerance
 *   - TPR / ADR going down beyond tolerance
 *
 * Returns { regressed, delta, currentRate, baselineRate }.
 */
function checkMetric(label, currentNode, baselineNode, tolerance, direction) {
  const cur = getRate(currentNode);
  const base = getRate(baselineNode);
  if (!cur || !base) {
    return { label, status: 'missing', regressed: false };
  }
  const delta = cur.rate - base.rate;
  let regressed = false;
  if (direction === 'lower-is-better') {
    regressed = delta > tolerance;
  } else if (direction === 'higher-is-better') {
    regressed = -delta > tolerance;
  }
  return {
    label,
    status: 'compared',
    regressed,
    delta,
    deltaPct: delta * 100,
    currentRate: cur.rate,
    baselineRate: base.rate,
    direction,
    tolerance
  };
}

function findNewClusters(currentReport, baselineReport, topN) {
  const cur = (currentReport.fpClusters && currentReport.fpClusters.topClusters) || [];
  const base = (baselineReport.fpClusters && baselineReport.fpClusters.topClusters) || [];
  if (cur.length === 0) return [];
  const baseKeys = new Set(base.map(c => c.key));
  const fresh = cur.filter(c => !baseKeys.has(c.key));
  fresh.sort((a, b) => b.count - a.count);
  return fresh.slice(0, topN);
}

function fmtPct(n) {
  if (typeof n !== 'number') return 'n/a';
  return (n * 100).toFixed(2) + '%';
}

function fmtDelta(n) {
  if (typeof n !== 'number') return 'n/a';
  const sign = n > 0 ? '+' : '';
  return `${sign}${(n * 100).toFixed(2)}pt`;
}

function main() {
  const args = parseArgs(process.argv);

  let currentPath = args.current;
  let baselinePath = args.baseline;
  if (!currentPath || !baselinePath) {
    const all = listMetricsDescending();
    if (all.length < 2) {
      // Not an error : a fresh repo or first-time PR has 0 or 1 metric file
      // and there is nothing to regress against. CI must stay green so the
      // workflow can still gate future PRs once a baseline exists.
      console.log(`Regression check skipped : ${all.length} metrics file(s) found, need at least 2 for comparison.`);
      console.log('First metric snapshot becomes the baseline ; subsequent commits will be checked against it.');
      process.exit(0);
    }
    if (!currentPath) currentPath = all[0];
    if (!baselinePath) baselinePath = all[1];
  }

  let currentReport, baselineReport;
  try {
    currentReport = loadMetrics(currentPath);
    baselineReport = loadMetrics(baselinePath);
  } catch (err) {
    console.error(err.message);
    process.exit(2);
  }

  const checks = [
    checkMetric('FPR rules curated', currentReport.benign, baselineReport.benign, args.fprTolerance, 'lower-is-better'),
    checkMetric('FPR random npm', currentReport.benignRandom, baselineReport.benignRandom, args.fprTolerance, 'lower-is-better'),
    checkMetric('FPR after ML', currentReport.fprAfterML, baselineReport.fprAfterML, args.fprTolerance, 'lower-is-better'),
    checkMetric('FPR PyPI benign', currentReport.benignPyPI, baselineReport.benignPyPI, args.fprTolerance, 'lower-is-better'),
    checkMetric('TPR ground truth', currentReport.groundTruth, baselineReport.groundTruth, args.tprTolerance, 'higher-is-better'),
    checkMetric('ADR adversarial', currentReport.adversarial, baselineReport.adversarial, args.adrTolerance, 'higher-is-better')
  ];

  const regressions = checks.filter(c => c.regressed);
  const newClusters = findNewClusters(currentReport, baselineReport, 5);

  // Phase 0b: operational coverage from the per-scan ledger. INFORMATIONAL ONLY — it
  // never enters `regressions` and never changes the exit code. The ledger is a
  // prod-runtime artifact (absent on CI → null) and operational coverage legitimately
  // drifts day to day, so it is a dashboard trend, not a hard gate ("Dashboard, pas
  // gate CI dur"). Rétro-compatible: older snapshots simply have no `operational` node.
  const operational = {
    current: currentReport.operational || null,
    baseline: baselineReport.operational || null
  };

  if (args.json) {
    console.log(JSON.stringify({
      currentVersion: currentReport.version,
      baselineVersion: baselineReport.version,
      currentPath: path.relative(ROOT, currentPath),
      baselinePath: path.relative(ROOT, baselinePath),
      checks,
      regressions,
      newClusters,
      operational,
      pass: regressions.length === 0
    }, null, 2));
    process.exit(regressions.length === 0 ? 0 : 1);
  }

  console.log(`\n  Regression check : v${currentReport.version} vs v${baselineReport.version}\n`);

  for (const c of checks) {
    if (c.status === 'missing') {
      console.log(`    [SKIP] ${c.label.padEnd(22)} : missing in one of the snapshots`);
      continue;
    }
    const status = c.regressed ? 'REGRESSION' : 'ok';
    const dir = c.direction === 'lower-is-better' ? '⇣' : '⇡';
    console.log(`    [${status.padEnd(10)}] ${c.label.padEnd(22)} : ${fmtPct(c.baselineRate)} ${dir} ${fmtPct(c.currentRate)} (${fmtDelta(c.delta)}, tol ${(c.tolerance * 100).toFixed(2)}pt)`);
  }

  if (newClusters.length > 0) {
    console.log(`\n  Top ${newClusters.length} new FP cluster(s) (vs baseline) :`);
    for (const c of newClusters) {
      console.log(`    [${c.count}x] ${c.rule_type} on ${c.file_pattern} ${c.is_bundle ? '(bundle)' : '(src)'} - ${c.distinct_packages} pkg(s)`);
    }
  }

  // Operational coverage (ledger) — informational, never gates CI (see note above).
  const opHas = (o) => o && typeof o.total === 'number' && o.total > 0;
  console.log(`\n  Operational coverage (ledger, informational — not gated) :`);
  if (!opHas(operational.current) && !opHas(operational.baseline)) {
    console.log('    [SKIP] no ledger rollup in either snapshot');
  } else {
    const num = (o, k) => (o && typeof o[k] === 'number') ? String(o[k]) : 'n/a';
    const rate = (o) => (o && o.alertRate != null) ? (o.alertRate * 100).toFixed(2) + '%' : 'n/a';
    console.log(`    scanned    : ${num(operational.baseline, 'scanned')} -> ${num(operational.current, 'scanned')}`);
    console.log(`    alert rate : ${rate(operational.baseline)} -> ${rate(operational.current)}  (NOT a TPR — needs GHSA cross-ref, Phase 5)`);
    console.log(`    dropped    : ${num(operational.baseline, 'dropped')} -> ${num(operational.current, 'dropped')}  (vanished ${num(operational.baseline, 'vanished')} -> ${num(operational.current, 'vanished')})`);
  }

  if (regressions.length === 0) {
    console.log(`\n  PASS : no regression beyond tolerance.\n`);
    process.exit(0);
  } else {
    console.log(`\n  FAIL : ${regressions.length} regression(s) detected.\n`);
    for (const r of regressions) {
      console.log(`    -> ${r.label} : ${fmtDelta(r.delta)} (current ${fmtPct(r.currentRate)}, baseline ${fmtPct(r.baselineRate)})`);
    }
    console.log('');
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { listMetricsDescending, checkMetric, findNewClusters };
