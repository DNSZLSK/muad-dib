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
 *     (known_malicious_package / _hash, pypi_malicious_package, dependency_ioc_match,
 *     shai_hulud_*). Those are downstream of OSV/OSM/GHSA. Zero differentiation value.
 *   - tied-or-behind — heuristic detections that landed AT/AFTER the public advisory.
 *
 * What's left is the product:
 *   - net-new  — heuristic detection of a package NOT in the GHSA malware set.
 *   - ahead    — heuristic detection whose first_seen precedes the GHSA advisory's
 *                published_at → lead_time_hours = published_at − first_seen.
 *
 * ── SOURCE (the important lever) ────────────────────────────────────────────
 * detections.jsonl is a ROLLING BUFFER, not a window: MAX_DETECTIONS=10_000
 * (state.js) compacted to the most-recent 10k. At ~350 detections/h on the VPS
 * that is ~28h of retention — you cannot measure a multi-week differentiator from
 * it, ever. So the DEFAULT source is the scan-ledger (scan-ledger.jsonl, cap
 * 500_000) filtered to outcome ∈ {suspect, confirmed}, deduped to the EARLIEST
 * suspect per package. That spans weeks and carries score/tier/types for the gate.
 *   --source ledger      (default) real window from scan-ledger.jsonl
 *   --source detections  the rolling 10k buffer (only if you also want --write backfill)
 *
 * ── CONFIDENCE GATE (what makes the number sellable) ────────────────────────
 * Raw suspect output is dominated by heuristic FALSE POSITIVES (minified-bundle
 * patterns on legit packages — prototype_pollution / high_entropy_string /
 * credential_regex_harvest). A feed publishes only the high-confidence subset.
 * The gate (all provided flags AND-combined; ledger source carries score/tier):
 *   --min-score N        keep detections with riskScore >= N
 *   --min-tier  1a|1b|2|3 keep detections at/above this suspect tier
 *   --high-confidence    keep only detections with a HIGH_CONFIDENCE_MALICE_TYPES finding
 * With no gate flags the raw (noisy) number is reported, as before.
 *
 * Lead-time is a MEDIAN (robust to the tail) and conservative: first_seen is bounded
 * below by when the ledger started; GHSA published_at is advisory-publication time
 * (≥ first-malware-appearance), so true lead is if anything larger than reported.
 *
 * Read-only. --write (detections source only) backfills advisory_at + lead_time_hours
 * into detections.jsonl so `muaddib detections --stats` shows a real lead-time.
 *
 * Usage:
 *   node scripts/differentiator-audit.js                              # ledger, no gate
 *   node scripts/differentiator-audit.js --high-confidence            # publishable subset
 *   node scripts/differentiator-audit.js --min-tier 1a --min-score 50
 *   node scripts/differentiator-audit.js --source detections --write  # backfill the buffer
 *   node scripts/differentiator-audit.js --since 2026-06-01T00:00:00Z --json
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPORT_FILE = path.join(ROOT, 'data', 'differentiator-audit.json');

// Ledger outcomes that count as "we raised it" (mirrors coverage-audit ALERT_OUTCOMES).
const ALERT_OUTCOMES = new Set(['suspect', 'confirmed']);

// Suspect-tier ordering for --min-tier. 1a is the highest-confidence tier.
const TIER_RANK = { '1a': 4, '1': 4, '1b': 3, '2': 2, '3': 1 };
function tierRank(t) { return TIER_RANK[String(t)] || 0; }

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
function maxSeverity(a, b) {
  return (SEV_RANK[b] || 0) > (SEV_RANK[a] || 0) ? b : (a || b || null);
}

/**
 * PURE core. Classify every detection against the GHSA published-at map, after an
 * optional confidence gate. Dependency-free (iocTypes + gate.hcTypes injected).
 *
 * @param {Array<{package:string,version?:string,ecosystem?:string,first_seen_at?:string,findings?:string[],severity?:string,score?:number,tier?:string}>} detections
 * @param {Map<string,string>} ghsaMap   key "eco/name" -> earliest published_at ISO
 * @param {Set<string>} iocTypes         finding types meaning "ingested-IOC match"
 * @param {{sinceMs?:number|null, gate?:{minScore?:number,minTier?:string,highConfidence?:boolean,hcTypes?:Set<string>}}} [opts]
 */
function classifyDifferentiator(detections, ghsaMap, iocTypes, opts = {}) {
  const since = (opts.sinceMs === undefined) ? null : opts.sinceMs;
  const gate = opts.gate || null;
  const ioc = iocTypes || new Set();
  const gh = ghsaMap || new Map();

  const buckets = { netNew: [], ahead: [], tiedOrBehind: [], iocOnly: [], gatedOut: [], skipped: [] };
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

    // Confidence gate — a detection the feed would NOT publish is set aside, never
    // counted toward the differentiator. Applied before classification so the headline
    // reflects only the publishable subset.
    if (gate && !passesGate(d, gate)) {
      buckets.gatedOut.push(dedupKey);
      continue;
    }

    total++;
    let node = byEcosystem[eco];
    if (!node) node = byEcosystem[eco] = { total: 0, netNew: 0, ahead: 0, tiedOrBehind: 0, iocOnly: 0 };
    node.total++;

    const findings = Array.isArray(d.findings) ? d.findings : [];
    const rec = {
      key: dedupKey, name: d.package, version: d.version || null, ecosystem: eco,
      findings, severity: d.severity || null, score: (typeof d.score === 'number' ? d.score : null),
      tier: d.tier || null, first_seen_at: d.first_seen_at || null
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
      gatedOut: buckets.gatedOut.length,
      skipped: buckets.skipped.length
    },
    leadTime: leadStats(leadHours),
    byEcosystem,
    buckets
  };
}

/** Does a detection clear the confidence gate? All provided criteria must hold. */
function passesGate(d, gate) {
  if (!gate) return true;
  if (gate.minScore != null) {
    if (!(typeof d.score === 'number' && d.score >= gate.minScore)) return false;
  }
  if (gate.minTier != null) {
    if (tierRank(d.tier) < tierRank(gate.minTier)) return false;
  }
  if (gate.highConfidence) {
    const hc = gate.hcTypes || new Set();
    const findings = Array.isArray(d.findings) ? d.findings : [];
    if (!findings.some(t => hc.has(t))) return false;
  }
  return true;
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

/**
 * Reduce raw scan-ledger entries (many per package, one per scan) to one
 * detection-shaped record per package: the EARLIEST suspect/confirmed as first_seen,
 * the union of finding types, the max score, and the best (highest) tier/severity.
 * PURE. This is the source that gives a real multi-week window.
 */
function detectionsFromLedger(ledgerEntries) {
  const byKey = new Map();
  for (const e of (ledgerEntries || [])) {
    if (!e || !e.name || !ALERT_OUTCOMES.has(e.outcome)) continue;
    const eco = e.ecosystem || 'unknown';
    const key = `${eco}/${e.name}`;
    const tsMs = e.ts ? Date.parse(e.ts) : NaN;
    let rec = byKey.get(key);
    if (!rec) {
      rec = {
        package: e.name, version: e.version || null, ecosystem: eco,
        first_seen_at: e.ts || null, _firstMs: tsMs, findings: new Set(),
        score: (typeof e.score === 'number' ? e.score : null),
        tier: e.tier || null, severity: e.maxSeverity || null
      };
      byKey.set(key, rec);
    } else {
      if (!Number.isNaN(tsMs) && (Number.isNaN(rec._firstMs) || tsMs < rec._firstMs)) {
        rec._firstMs = tsMs; rec.first_seen_at = e.ts; rec.version = e.version || rec.version;
      }
      if (typeof e.score === 'number' && (rec.score == null || e.score > rec.score)) rec.score = e.score;
      if (tierRank(e.tier) > tierRank(rec.tier)) rec.tier = e.tier;
      rec.severity = maxSeverity(rec.severity, e.maxSeverity);
    }
    for (const t of (e.types || [])) rec.findings.add(t);
  }
  const out = [];
  for (const rec of byKey.values()) {
    rec.findings = [...rec.findings];
    delete rec._firstMs;
    out.push(rec);
  }
  return out;
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

function earliestTs(records, field) {
  let min = null;
  for (const r of (records || [])) {
    const v = r && r[field];
    if (v) { const t = Date.parse(v); if (!Number.isNaN(t) && (min === null || t < min)) min = t; }
  }
  return min;
}

function parseArgs(argv) {
  const a = {
    json: false, all: false, since: null, file: null, write: false,
    maxPages: 30, top: 20, source: 'ledger',
    minScore: null, minTier: null, highConfidence: false
  };
  for (let i = 2; i < argv.length; i++) {
    const v = argv[i];
    if (v === '--json') a.json = true;
    else if (v === '--all') a.all = true;
    else if (v === '--write') a.write = true;
    else if (v === '--high-confidence') a.highConfidence = true;
    else if (v === '--since') a.since = argv[++i];
    else if (v === '--file') a.file = argv[++i];
    else if (v === '--source') a.source = argv[++i];
    else if (v === '--min-score') a.minScore = parseFloat(argv[++i]);
    else if (v === '--min-tier') a.minTier = argv[++i];
    else if (v === '--max-pages') a.maxPages = parseInt(argv[++i], 10) || 30;
    else if (v === '--top') a.top = parseInt(argv[++i], 10) || 20;
  }
  return a;
}

function fmtH(n) { return (typeof n === 'number') ? n.toFixed(1) + 'h' : 'n/a'; }

/**
 * Backfill advisory_at + lead_time_hours into the detections JSONL. Best-effort,
 * atomic (tmp+rename). Only touches lines that matched a GHSA advisory.
 */
function backfillDetections(filePath, buckets) {
  const patch = new Map();
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

  if (args.file) process.env.MUADDIB_DETECTIONS_FILE = args.file;
  const { loadDetections, loadScanLedger } = require('../src/monitor/state.js');
  const { fetchAllGhsaMalware } = require('../src/ioc/ghsa-poller.js');
  const { IOC_MATCH_TYPES, HIGH_CONFIDENCE_MALICE_TYPES } = require('../src/monitor/classify.js');

  // Source selection. Ledger (default) = real window; detections = rolling 10k buffer.
  let records;
  if (args.source === 'detections') {
    records = loadDetections().detections || [];
  } else {
    records = detectionsFromLedger(loadScanLedger());
  }

  let sinceMs = null;
  if (!args.all) sinceMs = args.since ? Date.parse(args.since) : earliestTs(records, 'first_seen_at');

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

  // IOC exclusion set: classify.js runtime set + dependency_ioc_match (an IOC type the
  // monitor emits — see ml-retrain has_ioc_match — but that is not in the runtime set).
  // Extended locally so we never mutate the production IOC_MATCH_TYPES.
  const iocTypes = new Set([...IOC_MATCH_TYPES, 'dependency_ioc_match']);

  const gateOn = (args.minScore != null && !Number.isNaN(args.minScore)) || args.minTier != null || args.highConfidence;
  const gate = gateOn ? {
    minScore: (args.minScore != null && !Number.isNaN(args.minScore)) ? args.minScore : null,
    minTier: args.minTier || null,
    highConfidence: !!args.highConfidence,
    hcTypes: HIGH_CONFIDENCE_MALICE_TYPES
  } : null;

  const result = classifyDifferentiator(records, ghsaMap, iocTypes, { sinceMs, gate });
  const windowStr = sinceMs !== null ? new Date(sinceMs).toISOString() : '(all history)';
  const gateStr = gate
    ? [gate.minScore != null ? `score>=${gate.minScore}` : null, gate.minTier ? `tier>=${gate.minTier}` : null, gate.highConfidence ? 'high-confidence' : null].filter(Boolean).join(' & ')
    : 'none (raw)';

  const report = {
    generatedAt: new Date().toISOString(),
    source: args.source,
    window: windowStr,
    gate: gateStr,
    recordsConsidered: records.length,
    ghsaDenominator: ghsaMap.size,
    total: result.total,
    differentiatorCount: result.differentiatorCount,
    counts: result.counts,
    leadTime: result.leadTime,
    byEcosystem: result.byEcosystem,
    topNetNew: result.buckets.netNew
      .slice(0, args.top)
      .map(r => ({ key: r.key, severity: r.severity, score: r.score, tier: r.tier, findings: r.findings }))
  };

  try {
    if (!fs.existsSync(path.dirname(REPORT_FILE))) fs.mkdirSync(path.dirname(REPORT_FILE), { recursive: true });
    fs.writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));
  } catch (err) { console.error(`[differentiator-audit] persist failed: ${err.message}`); }

  if (args.write) {
    if (args.source !== 'detections') {
      console.error('[differentiator-audit] --write is only valid with --source detections (it backfills detections.jsonl). Skipped.');
    } else {
      const target = process.env.MUADDIB_DETECTIONS_FILE || path.join(ROOT, 'data', 'detections.jsonl');
      try {
        const patched = backfillDetections(target, result.buckets);
        console.error(`[differentiator-audit] backfilled advisory_at/lead_time_hours on ${patched} detection(s) in ${path.relative(ROOT, target)}`);
      } catch (err) { console.error(`[differentiator-audit] backfill failed: ${err.message}`); }
    }
  }

  if (args.json) { console.log(JSON.stringify(report, null, 2)); return 0; }

  const c = result.counts;
  console.log(`\n  MUAD'DIB differentiator audit`);
  console.log(`  source: ${args.source}  |  gate: ${gateStr}  |  window: first_seen since ${windowStr}`);
  console.log(`  records: ${records.length}, GHSA malware denom: ${ghsaMap.size}\n`);
  console.log(`  DIFFERENTIATOR : ${result.differentiatorCount}   ← headline (heuristic net-new + ahead of GHSA, after gate)`);
  console.log(`    net-new       : ${c.netNew}   (heuristic catch, NOT in GHSA malware — independent detection)`);
  console.log(`    ahead         : ${c.ahead}   (heuristic catch BEFORE the GHSA advisory)`);
  if (result.leadTime) {
    console.log(`      lead time   : median ${fmtH(result.leadTime.median)} · avg ${fmtH(result.leadTime.avg)} · min ${fmtH(result.leadTime.min)} · max ${fmtH(result.leadTime.max)} (${result.leadTime.count})`);
  }
  console.log(`    tied/behind   : ${c.tiedOrBehind}   (heuristic, at/after the advisory — no lead)`);
  console.log(`    ioc-only      : ${c.iocOnly}   (ingested-IOC match only — downstream, EXCLUDED)`);
  if (gate) console.log(`    gated-out     : ${c.gatedOut}   (below the confidence gate — not what the feed would publish)`);
  if (c.skipped) console.log(`    skipped       : ${c.skipped}   (first_seen before the window)`);
  console.log('');
  for (const [eco, n] of Object.entries(result.byEcosystem)) {
    console.log(`    ${eco.padEnd(5)} : ${n.netNew} net-new · ${n.ahead} ahead · ${n.tiedOrBehind} tied/behind · ${n.iocOnly} ioc-only  (of ${n.total})`);
  }
  if (report.topNetNew.length) {
    console.log(`\n  Top net-new heuristic catches (written to ${path.relative(ROOT, REPORT_FILE)}):`);
    for (const r of report.topNetNew) {
      const meta = [r.severity, r.tier ? `tier ${r.tier}` : null, r.score != null ? `score ${r.score}` : null].filter(Boolean).join(' ');
      console.log(`    - [${meta}] ${r.key} — ${r.findings.join(', ')}`);
    }
  }
  console.log('');
  return 0;
}

if (require.main === module) {
  main().then(code => process.exit(code || 0)).catch(err => { console.error(err); process.exit(2); });
}

module.exports = {
  classifyDifferentiator, passesGate, leadStats, buildGhsaMap,
  detectionsFromLedger, tierRank, maxSeverity, earliestTs, backfillDetections
};
