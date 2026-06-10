'use strict';

// muaddib fpr-live — honest operational alert-rate / FPR report, computed entirely
// from data already on disk (no corpus, no re-download):
//   - data/scan-stats.json   : lifetime cumulative counters + per-day history
//   - data/scan-ledger.jsonl : recent rolling window with per-package detail
//                              (outcome, score, firing-rule `types[]`, ecosystem)
//
// HONEST METRIC NOTE: `alertRate = alerted / scanned` is NOT the curated FPR (1.10%
// on famous packages with reputation suppression). On the live firehose, which is
// dominated by new / low-reputation packages, alertRate is the operational reality
// and — because confirmed malware is a vanishingly small fraction of alerts — it is
// a tight UPPER BOUND on the true FPR. Turning it into a precise FPR needs the
// alerts triaged into TP/FP (independent adjudication). We report it as what it is,
// never dressed up.

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const { computeLedgerRollup, SCAN_LEDGER_FILE } = require('../monitor/state.js');

const SCAN_STATS_FILE = path.join(__dirname, '..', '..', 'data', 'scan-stats.json');
const OUT_FILE = path.join(__dirname, '..', '..', 'data', 'fpr-live.json');

function _pct(n, d) {
  if (!d || d <= 0) return null;
  return n / d;
}
function _fmtPct(r) {
  return r === null || r === undefined ? 'N/A' : (r * 100).toFixed(2) + '%';
}

function _loadScanStats() {
  try {
    return JSON.parse(fs.readFileSync(SCAN_STATS_FILE, 'utf8'));
  } catch {
    return null;
  }
}

// Streaming pass over the ledger for the two dimensions computeLedgerRollup does not
// carry: score buckets and the firing-rule histogram. Bounded memory (readline, plus
// a rule map whose key-count is bounded by the rule catalogue ~260).
async function _ledgerDetail(ledgerFile) {
  const buckets = { '20-29': 0, '30-49': 0, '50-74': 0, '75-100': 0 };
  const ruleCounts = Object.create(null);
  let alertsScored = 0;
  let alertsUnscored = 0;

  if (!fs.existsSync(ledgerFile)) {
    return { buckets, topRules: [], alertsScored, alertsUnscored, available: false };
  }

  const rl = readline.createInterface({
    input: fs.createReadStream(ledgerFile, { encoding: 'utf8' }),
    crlfDelay: Infinity
  });

  for await (const line of rl) {
    if (!line) continue;
    let e;
    try { e = JSON.parse(line); } catch { continue; }
    if (!e || e.outcome === 'dropped') continue;
    // An "alert" is a suspect/confirmed outcome — the same numerator as alertRate.
    if (e.outcome !== 'suspect' && e.outcome !== 'confirmed') continue;

    const score = typeof e.score === 'number' ? e.score : null;
    if (score === null) {
      alertsUnscored++;
    } else {
      alertsScored++;
      if (score >= 75) buckets['75-100']++;
      else if (score >= 50) buckets['50-74']++;
      else if (score >= 30) buckets['30-49']++;
      else if (score >= 20) buckets['20-29']++;
      // scores < 20 with a suspect outcome are anomalies; ignore for the FP buckets.
    }
    if (Array.isArray(e.types)) {
      for (const t of e.types) ruleCounts[t] = (ruleCounts[t] || 0) + 1;
    }
  }

  const topRules = Object.entries(ruleCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([type, count]) => ({ type, count }));

  return { buckets, topRules, alertsScored, alertsUnscored, available: true };
}

// Pure builder (no I/O side effects beyond reading) — returns the full report object.
async function buildFprLiveReport(opts = {}) {
  const ledgerFile = opts.ledgerFile || SCAN_LEDGER_FILE;
  const stats = _loadScanStats();

  // 1. Lifetime + daily trend, from scan-stats.json cumulative counters.
  let lifetime = null;
  let trend = [];
  if (stats && stats.stats) {
    const s = stats.stats;
    lifetime = {
      total_scanned: s.total_scanned || 0,
      suspect: s.suspect || 0,
      confirmed_malicious: s.confirmed_malicious || 0,
      // alertRate ≈ FPR upper bound: of everything scanned, the fraction flagged.
      alertRate: _pct(s.suspect || 0, s.total_scanned || 0)
    };
    const days = Array.isArray(stats.daily) ? stats.daily : [];
    const window = typeof opts.trendDays === 'number' ? opts.trendDays : 14;
    trend = days.slice(-window).map(d => ({
      date: d.date,
      scanned: d.scanned || 0,
      suspect: d.suspect || 0,
      confirmed: d.confirmed || 0,
      alertRate: _pct(d.suspect || 0, d.scanned || 0)
    }));
  }

  // 2. Recent rolling window detail, from the ledger.
  const rollup = computeLedgerRollup(opts.since || null, { file: ledgerFile });
  const detail = await _ledgerDetail(ledgerFile);

  return {
    generatedAt: rollup.generatedAt,
    note: 'alertRate is the operational alert load (alerted/scanned). It is an UPPER BOUND on FPR — not the curated 1.10%. Precise FPR requires alert triage (TP/FP labelling).',
    lifetime,
    trend,
    recentWindow: {
      windowStart: rollup.windowStart,
      windowEnd: rollup.windowEnd,
      scanned: rollup.scanned,
      dropped: rollup.dropped,
      alerted: rollup.alerted,
      alertRate: rollup.alertRate,
      byEcosystem: rollup.byEcosystem,
      scoreBuckets: detail.buckets,
      alertsScored: detail.alertsScored,
      alertsUnscored: detail.alertsUnscored,
      topFiringRules: detail.topRules
    }
  };
}

function _printReport(r) {
  console.log('\n  MUAD\'DIB — Operational FPR / Alert-Rate (live)\n');
  console.log('  ' + r.note + '\n');

  if (r.lifetime) {
    const l = r.lifetime;
    console.log('  Lifetime (scan-stats.json cumulative)');
    console.log('  ' + '-'.repeat(58));
    console.log(`  Total scanned:        ${l.total_scanned.toLocaleString()}`);
    console.log(`  Flagged (suspect ≥20): ${l.suspect.toLocaleString()}`);
    console.log(`  Confirmed malware:    ${l.confirmed_malicious.toLocaleString()}`);
    console.log(`  Alert rate (≈FPR↑):   ${_fmtPct(l.alertRate)}`);
    console.log('');
  }

  if (r.trend && r.trend.length) {
    console.log('  Daily trend (alert rate)');
    console.log('  ' + '-'.repeat(58));
    console.log('  Date         Scanned  Suspect  Confirmed  AlertRate');
    for (const d of r.trend) {
      console.log(
        `  ${d.date}   ${String(d.scanned).padStart(6)}   ${String(d.suspect).padStart(6)}   ` +
        `${String(d.confirmed).padStart(8)}   ${_fmtPct(d.alertRate).padStart(8)}`
      );
    }
    console.log('');
  }

  const w = r.recentWindow;
  console.log('  Recent window detail (scan-ledger.jsonl)');
  console.log('  ' + '-'.repeat(58));
  console.log(`  Window:        ${w.windowStart || 'n/a'} → ${w.windowEnd || 'n/a'}`);
  console.log(`  Scanned:       ${w.scanned.toLocaleString()}  (dropped: ${w.dropped.toLocaleString()})`);
  console.log(`  Alerted:       ${w.alerted.toLocaleString()}   Alert rate: ${_fmtPct(w.alertRate)}`);
  console.log('');
  console.log('  By ecosystem:');
  for (const [eco, n] of Object.entries(w.byEcosystem)) {
    const ar = _pct(n.alerted, n.scanned);
    console.log(`    ${eco.padEnd(8)} scanned=${String(n.scanned).padStart(6)}  alerted=${String(n.alerted).padStart(6)}  rate=${_fmtPct(ar)}`);
  }
  console.log('');
  console.log('  Alert score distribution:');
  for (const [b, n] of Object.entries(w.scoreBuckets)) {
    console.log(`    ${b.padEnd(7)} ${String(n).padStart(6)}`);
  }
  if (w.alertsUnscored) console.log(`    (unscored alerts: ${w.alertsUnscored})`);
  console.log('');
  console.log('  Top firing rules on alerts (the FP-load drivers):');
  for (const r2 of w.topFiringRules) {
    console.log(`    ${String(r2.count).padStart(6)}  ${r2.type}`);
  }
  console.log('');
}

async function runFprLive(opts = {}) {
  const report = await buildFprLiveReport(opts);

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    _printReport(report);
  }

  // Persist for trend tracking / future anomaly detection (best-effort).
  try {
    fs.writeFileSync(OUT_FILE, JSON.stringify(report, null, 2));
  } catch (e) {
    if (!opts.json) console.log('  [warn] could not persist fpr-live.json: ' + e.message);
  }

  return report;
}

module.exports = { runFprLive, buildFprLiveReport };
