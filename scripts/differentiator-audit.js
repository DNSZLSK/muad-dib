#!/usr/bin/env node
/**
 * scripts/differentiator-audit.js — quantify MUAD'DIB's commercial differentiator.
 *
 * The only sellable signal in a threat-intel feed is what MUAD'DIB finds BY ITS OWN
 * HEURISTICS (AST / dataflow / entropy / compound) that the public feeds (GHSA/OSV)
 * either DON'T have, or that we saw FIRST. This script measures exactly that and
 * nothing else — it deliberately EXCLUDES two non-differentiators:
 *
 *   - ioc-only detections — a suspect whose findings are ALL ingested-IOC matches
 *     (known_malicious_package / _hash, pypi_malicious_package, shai_hulud_*). Those
 *     are downstream of OSV/OSM/GHSA: we only "found" them because we ingested their
 *     IOC. Zero differentiation value. (IOC type list sourced from classify.js so it
 *     never drifts.)
 *   - tied-or-behind — heuristic detections that landed AT/AFTER the public advisory.
 *     We re-detected known malware; no lead.
 *
 * What's left is the product:
 *   - net-new  — heuristic detection of a package that is NOT in the GHSA malware set.
 *   - ahead    — heuristic detection whose first_seen_at precedes the GHSA advisory's
 *                published_at → lead_time_hours = published_at − first_seen_at.
 *
 * HEADLINE = netNew + ahead (heuristic). Lead-time is reported as a MEDIAN (robust to
 * the long tail). Both numbers are conservative:
 *   - first_seen_at is bounded below by when our monitor started existing (we cannot
 *     have seen a package before the detections ledger did), so lead is never inflated;
 *   - GHSA published_at is advisory-publication time, not first-malware-appearance, so
 *     the true lead is if anything LARGER than reported.
 *
 * Data source: data/detections.jsonl (override with MUADDIB_DETECTIONS_FILE or --file
 * to run against an exported prod copy). Denominator: GHSA type=malware for npm+pypi
 * via ghsa-poller (needs GITHUB_TOKEN for the full paginated list).
 *
 * Read-only by default. --write backfills advisory_at + lead_time_hours into the
 * detections file so `muaddib detections --stats` shows a real lead-time.
 *
 * Usage:
 *   node scripts/differentiator-audit.js                    # window = earliest detection
 *   node scripts/differentiator-audit.js --all              # no window
 *   node scripts/differentiator-audit.js --since 2026-06-01T00:00:00Z
 *   node scripts/differentiator-audit.js --file /path/to/detections.jsonl
 *   node scripts/differentiator-audit.js --json
 *   node scripts/differentiator-audit.js --write            # backfill the ledger
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPORT_FILE = path.join(ROOT, 'data', 'differentiator-audit.json');

/**
 * PURE core. Classify every detection against the GHSA published-at map.
 * Kept dependency-free (iocTypes injected) so it is unit-testable in isolation.
 *
 * @param {Array<{package:string,version?:string,ecosystem?:string,first_seen_at?:string,findings?:string[],severity?:string}>} detections
 * @param {Map<string,string>} ghsaMap   key "eco/name" -> earliest published_at ISO
 * @param {Set<string>} iocTypes         finding types that mean "ingested-IOC match"
 * @param {{sinceMs?:number|null}} [opts]
 */
function classifyDifferentiator(detections, ghsaMap, iocTypes, opts = {}) {
  const since = (opts.sinceMs === undefined) ? null : opts.sinceMs;
  const ioc = iocTypes || new Set();
  const gh = ghsaMap || new Map();

  const buckets = { netNew: [], ahead: [], tiedOrBehind: [], iocOnly: [], skipped: [] };
  const byEcosystem = Object.create(null);
  const leadHours = [];
  const seen = new Set();
  let total = 0;

  for (const d of (detections || [])) {
    if (!d || !d.package) continue;
    const eco = d.ecosystem || 'unknown';
    const dedupKey = `${eco}/${d.package}@${d.version || '?'}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const firstMs = d.first_seen_at ? Date.parse(d.first_seen_at) : NaN;
    if (since !== null && (Number.isNaN(firstMs) || firstMs < since)) {
      buckets.skipped.push(dedupKey);
      continue;
    }
    total++;

    let node = byEcosystem[eco];
    if (!node) node = byEcosystem[eco] = { total: 0, netNew: 0, ahead: 0, tiedOrBehind: 0, iocOnly: 0 };
    node.total++;

    const findings = Array.isArray(d.findings) ? d.findings : [];
    const rec = {
      key: dedupKey, name: d.package, version: d.version || null, ecosystem: eco,
      findings, severity: d.severity || null, first_seen_at: d.first_seen_at || null
    };

    // ioc-only: has findings AND every finding is an ingested-IOC type → downstream, excluded.
    if (findings.length > 0 && findings.every(t => ioc.has(t))) {
      buckets.iocOnly.push(rec); node.iocOnly++;
      continue;
    }

    const pub = gh.get(`${eco}/${d.package}`);
    if (!pub) { buckets.netNew.push(rec); node.netNew++; continue; }

    const pubMs = Date.parse(pub);
    rec.advisory_at = pub;
    if (!Number.isNaN(firstMs) && !Number.isNaN(pubMs) && firstMs < pubMs) {
      const lead = (pubMs - firstMs) / 3_600_000;
      rec.lead_time_hours = lead;
      buckets.ahead.push(rec); node.ahead++;
      leadHours.push(lead);
    } else {
      buckets.tiedOrBehind.push(rec); node.tiedOrBehind++;
    }
  }

  const differentiatorCount = buckets.netNew.length + buckets.ahead.length;
  return {
    total,
    differentiatorCount,
    counts: {
      netNew: buckets.netNew.length,
      ahead: buckets.ahead.length,
      tiedOrBehind: buckets.tiedOrBehind.length,
      iocOnly: buckets.iocOnly.length,
      skipped: buckets.skipped.length
    },
    leadTime: leadStats(leadHours),
    byEcosystem,
    buckets
  };
}

/** Median + min/max/count over an array of hours. Returns null when empty. */
function leadStats(hours) {
  if (!hours || hours.length === 0) return null;
  const sorted = [...hours].sort((a, b) => a - b);
  const n = sorted.length;
  const mid = Math.floor(n / 2);
  const median = (n % 2 === 0) ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  let sum = 0;
  for (const h of sorted) sum += h;
  return { count: n, median, avg: sum / n, min: sorted[0], max: sorted[n - 1] };
}

/** Build "eco/name" -> earliest published_at from GHSA rows. */
function buildGhsaMap(rows) {
  const m = new Map();
  for (const r of (rows || [])) {
    if (!r || !r.name || r.withdrawn) continue;
    if (!r.published_at) continue;
    const k = `${r.ecosystem || 'unknown'}/${r.name}`;
    const prev = m.get(k);
    if (!prev || Date.parse(r.published_at) < Date.parse(prev)) m.set(k, r.published_at);
  }
  return m;
}

function earliestDetectionTs(detections) {
  let min = null;
  for (const d of (detections || [])) {
    if (d && d.first_seen_at) {
      const t = Date.parse(d.first_seen_at);
      if (!Number.isNaN(t) && (min === null || t < min)) min = t;
    }
  }
  return min;
}

function parseArgs(argv) {
  const a = { json: false, all: false, since: null, file: null, write: false, maxPages: 30, top: 20 };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--json') a.json = true;
    else if (argv[i] === '--all') a.all = true;
    else if (argv[i] === '--write') a.write = true;
    else if (argv[i] === '--since') a.since = argv[++i];
    else if (argv[i] === '--file') a.file = argv[++i];
    else if (argv[i] === '--max-pages') a.maxPages = parseInt(argv[++i], 10) || 30;
    else if (argv[i] === '--top') a.top = parseInt(argv[++i], 10) || 20;
  }
  return a;
}

function fmtH(n) { return (typeof n === 'number') ? n.toFixed(1) + 'h' : 'n/a'; }

/**
 * Backfill advisory_at + lead_time_hours into the detections JSONL. Best-effort,
 * atomic (tmp+rename). Only touches lines that matched a GHSA advisory.
 */
function backfillDetections(filePath, buckets) {
  const patch = new Map(); // "eco/name@version" -> { advisory_at, lead_time_hours }
  for (const r of [...buckets.ahead, ...buckets.tiedOrBehind]) {
    patch.set(r.key, { advisory_at: r.advisory_at || null, lead_time_hours: (r.lead_time_hours != null ? r.lead_time_hours : null) });
  }
  if (patch.size === 0) return 0;
  if (!fs.existsSync(filePath)) return 0;

  const raw = fs.readFileSync(filePath, 'utf8');
  const out = [];
  let patched = 0;
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    let e;
    try { e = JSON.parse(line); } catch { out.push(line); continue; }
    const key = `${e.ecosystem || 'unknown'}/${e.package}@${e.version || '?'}`;
    const p = patch.get(key);
    if (p) { e.advisory_at = p.advisory_at; e.lead_time_hours = p.lead_time_hours; patched++; }
    out.push(JSON.stringify(e));
  }
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, out.length ? out.join('\n') + '\n' : '', 'utf8');
  fs.renameSync(tmp, filePath);
  return patched;
}

async function main() {
  const args = parseArgs(process.argv);

  // Point loadDetections at an exported copy before requiring state.js (constant is
  // resolved once at module load). Deferred require mirrors coverage-audit.js.
  if (args.file) process.env.MUADDIB_DETECTIONS_FILE = args.file;
  const { loadDetections } = require('../src/monitor/state.js');
  const { fetchAllGhsaMalware } = require('../src/ioc/ghsa-poller.js');
  const { IOC_MATCH_TYPES } = require('../src/monitor/classify.js');

  const detections = loadDetections().detections || [];

  let sinceMs = null;
  if (!args.all) sinceMs = args.since ? Date.parse(args.since) : earliestDetectionTs(detections);

  // Denominator: GHSA malware for npm + pypi.
  const ghsaRows = [];
  for (const eco of ['npm', 'pypi']) {
    try {
      const rows = await fetchAllGhsaMalware(eco, { maxPages: args.maxPages });
      for (const r of rows) ghsaRows.push(r);
    } catch (err) {
      console.error(`[differentiator-audit] GHSA fetch ${eco} failed: ${err.message}`);
    }
  }
  const ghsaMap = buildGhsaMap(ghsaRows);

  const result = classifyDifferentiator(detections, ghsaMap, IOC_MATCH_TYPES, { sinceMs });
  const windowStr = sinceMs !== null ? new Date(sinceMs).toISOString() : '(all history)';

  const report = {
    generatedAt: new Date().toISOString(),
    window: windowStr,
    detectionsFile: process.env.MUADDIB_DETECTIONS_FILE || path.join('data', 'detections.jsonl'),
    detectionsTotal: detections.length,
    ghsaDenominator: ghsaMap.size,
    total: result.total,
    differentiatorCount: result.differentiatorCount,
    counts: result.counts,
    leadTime: result.leadTime,
    byEcosystem: result.byEcosystem,
    // top net-new heuristic catches — the list that "proves" the feed
    topNetNew: result.buckets.netNew
      .slice(0, args.top)
      .map(r => ({ key: r.key, severity: r.severity, findings: r.findings }))
  };

  try {
    if (!fs.existsSync(path.dirname(REPORT_FILE))) fs.mkdirSync(path.dirname(REPORT_FILE), { recursive: true });
    fs.writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));
  } catch (err) { console.error(`[differentiator-audit] persist failed: ${err.message}`); }

  if (args.write) {
    const target = process.env.MUADDIB_DETECTIONS_FILE || path.join(ROOT, 'data', 'detections.jsonl');
    try {
      const patched = backfillDetections(target, result.buckets);
      console.error(`[differentiator-audit] backfilled advisory_at/lead_time_hours on ${patched} detection(s) in ${path.relative(ROOT, target)}`);
    } catch (err) { console.error(`[differentiator-audit] backfill failed: ${err.message}`); }
  }

  if (args.json) { console.log(JSON.stringify(report, null, 2)); return 0; }

  const c = result.counts;
  console.log(`\n  MUAD'DIB differentiator audit`);
  console.log(`  window: detections first_seen since ${windowStr}  |  detections: ${detections.length}, GHSA malware denom: ${ghsaMap.size}\n`);
  console.log(`  DIFFERENTIATOR : ${result.differentiatorCount}   ← headline (heuristic net-new + ahead of GHSA)`);
  console.log(`    net-new       : ${c.netNew}   (heuristic catch, NOT in GHSA malware — independent detection)`);
  console.log(`    ahead         : ${c.ahead}   (heuristic catch BEFORE the GHSA advisory)`);
  if (result.leadTime) {
    console.log(`      lead time   : median ${fmtH(result.leadTime.median)} · avg ${fmtH(result.leadTime.avg)} · min ${fmtH(result.leadTime.min)} · max ${fmtH(result.leadTime.max)} (${result.leadTime.count})`);
  }
  console.log(`    tied/behind   : ${c.tiedOrBehind}   (heuristic, but at/after the advisory — no lead, downstream value)`);
  console.log(`    ioc-only      : ${c.iocOnly}   (ingested-IOC match only — downstream of public feeds, EXCLUDED from value)`);
  if (c.skipped) console.log(`    skipped       : ${c.skipped}   (first_seen before the window)`);
  console.log('');
  for (const [eco, n] of Object.entries(result.byEcosystem)) {
    console.log(`    ${eco.padEnd(5)} : ${n.netNew} net-new · ${n.ahead} ahead · ${n.tiedOrBehind} tied/behind · ${n.iocOnly} ioc-only  (of ${n.total})`);
  }
  if (report.topNetNew.length) {
    console.log(`\n  Top net-new heuristic catches (the feed's proof, written to ${path.relative(ROOT, REPORT_FILE)}):`);
    for (const r of report.topNetNew) console.log(`    - [${r.severity}] ${r.key} — ${r.findings.join(', ')}`);
  }
  console.log('');
  return 0;
}

if (require.main === module) {
  main().then(code => process.exit(code || 0)).catch(err => { console.error(err); process.exit(2); });
}

module.exports = { classifyDifferentiator, leadStats, buildGhsaMap, earliestDetectionTs, backfillDetections };
