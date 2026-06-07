#!/usr/bin/env node
/**
 * scripts/coverage-audit.js — Phase 5 capstone: continuous operational-coverage audit.
 *
 * Cross-references the authoritative GHSA malware denominator against what the monitor
 * actually did (scan-ledger from Phase 0a/0b) and what it caught (tarball-archive), to
 * produce the HONEST GHSA-denominated operational TPR — the real "105/429" number the
 * whole coverage plan exists to move. Every GHSA malware package is classified:
 *
 *   alerted      — we flagged it (ledger outcome suspect/confirmed, or it's in the archive)
 *   scannedClean — we SCANNED it but returned clean  → a detection MISS (false negative)
 *   dropped      — only ever queue-cap-evicted / ghsa_gone → a throughput/coverage hole
 *   neverSeen    — never appeared in the ledger at all → an ingestion gap
 *
 * operationalTPR = alerted / total.
 *
 * FAIR WINDOW: the scan-ledger only exists since Phase 0a deployed, while GHSA malware
 * goes back years. Counting 2022 malware against a days-old ledger would be dishonest, so
 * by default the denominator is scoped to advisories PUBLISHED since the earliest ledger
 * entry (override with --since <ISO> or --all). The window is printed alongside the number.
 *
 * The scannedClean misses are the highest-value GT candidates (known malware we let
 * through). They are written to data/gt-proposals.json as ADVISORY only — GT promotion is
 * human-gated (CLAUDE.md), never auto-applied to tests/ground-truth/attacks.json.
 *
 * Usage:
 *   node scripts/coverage-audit.js                 # window = ledger start
 *   node scripts/coverage-audit.js --all           # no window (all GHSA history)
 *   node scripts/coverage-audit.js --since 2026-06-01T00:00:00Z
 *   node scripts/coverage-audit.js --json
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ARCHIVE_DIR = process.env.MUADDIB_ARCHIVE_DIR || path.join(ROOT, 'archive');
const GT_PROPOSALS_FILE = path.join(ROOT, 'data', 'gt-proposals.json');
const COVERAGE_REPORT_FILE = path.join(ROOT, 'data', 'coverage-audit.json');

// Ledger outcomes that count as "we raised it" vs "we scanned and cleared it".
const ALERT_OUTCOMES = new Set(['suspect', 'confirmed']);
const CLEAN_OUTCOMES = new Set([
  'clean', 'clean_low_signal', 'clean_tooling', 'ml_clean', 'llm_benign',
  'sandbox_inconclusive', 'sandbox_unconfirmed', 'size_skip', 'static_timeout'
]);

/**
 * PURE core. Classify every denominator package against the ledger + archive.
 * @param {Array<{ecosystem:string,name:string}>} denomRows - GHSA malware (deduped upstream or here)
 * @param {Array<{ecosystem:string,name:string,outcome:string}>} ledgerEntries
 * @param {Set<string>} archivedNames - package names present in the tarball-archive (detected)
 */
function classifyCoverage(denomRows, ledgerEntries, archivedNames) {
  const led = new Map(); // "eco/name" -> Set<outcome>
  for (const e of (ledgerEntries || [])) {
    if (!e || !e.name) continue;
    const k = `${e.ecosystem || 'unknown'}/${e.name}`;
    let s = led.get(k);
    if (!s) { s = new Set(); led.set(k, s); }
    s.add(e.outcome || 'clean');
  }
  const archived = archivedNames || new Set();

  const byEcosystem = Object.create(null);
  const misses = { scannedClean: [], neverSeen: [] };
  let total = 0, alerted = 0, scannedClean = 0, dropped = 0, neverSeen = 0;
  const seen = new Set();

  for (const r of (denomRows || [])) {
    if (!r || !r.name) continue;
    const eco = r.ecosystem || 'unknown';
    const key = `${eco}/${r.name}`;
    if (seen.has(key)) continue; // dedup (a package can appear in multiple advisories)
    seen.add(key);
    total++;
    let node = byEcosystem[eco];
    if (!node) node = byEcosystem[eco] = { total: 0, alerted: 0, scannedClean: 0, dropped: 0, neverSeen: 0 };
    node.total++;

    const outcomes = led.get(key);
    const outArr = outcomes ? [...outcomes] : [];
    let cls;
    if (archived.has(r.name) || outArr.some(o => ALERT_OUTCOMES.has(o))) cls = 'alerted';
    else if (outArr.some(o => CLEAN_OUTCOMES.has(o))) cls = 'scannedClean';
    else if (outcomes && outcomes.has('dropped')) cls = 'dropped';
    else cls = 'neverSeen';

    if (cls === 'alerted') { alerted++; node.alerted++; }
    else if (cls === 'scannedClean') { scannedClean++; node.scannedClean++; misses.scannedClean.push(key); }
    else if (cls === 'dropped') { dropped++; node.dropped++; }
    else { neverSeen++; node.neverSeen++; misses.neverSeen.push(key); }
  }

  return {
    total, alerted, scannedClean, dropped, neverSeen,
    operationalTPR: total > 0 ? alerted / total : null,
    byEcosystem, misses
  };
}

/** Read the tarball-archive and return the Set of package names we archived (= detected). */
function loadArchivedNames(archiveDir = ARCHIVE_DIR) {
  const names = new Set();
  let dayDirs;
  try { dayDirs = fs.readdirSync(archiveDir, { withFileTypes: true }); } catch { return names; }
  for (const d of dayDirs) {
    if (!d.isDirectory()) continue;
    let files;
    try { files = fs.readdirSync(path.join(archiveDir, d.name)); } catch { continue; }
    for (const f of files) {
      if (!f.endsWith('.json')) continue;
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(archiveDir, d.name, f), 'utf8'));
        const n = meta && (meta.package || meta.name);
        if (n) names.add(n);
      } catch { /* skip unreadable */ }
    }
  }
  return names;
}

function earliestLedgerTs(ledgerEntries) {
  let min = null;
  for (const e of ledgerEntries) {
    if (e && e.ts) { const t = Date.parse(e.ts); if (!Number.isNaN(t) && (min === null || t < min)) min = t; }
  }
  return min;
}

function parseArgs(argv) {
  const a = { json: false, all: false, since: null, maxPages: 30 };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--json') a.json = true;
    else if (argv[i] === '--all') a.all = true;
    else if (argv[i] === '--since') a.since = argv[++i];
    else if (argv[i] === '--max-pages') a.maxPages = parseInt(argv[++i], 10) || 30;
  }
  return a;
}

function fmtPct(n) { return typeof n === 'number' ? (n * 100).toFixed(1) + '%' : 'n/a'; }

async function main() {
  const args = parseArgs(process.argv);
  const { loadScanLedger } = require('../src/monitor/state.js');
  const { fetchAllGhsaMalware } = require('../src/ioc/ghsa-poller.js');

  const ledger = loadScanLedger();
  let sinceMs = null;
  if (!args.all) {
    sinceMs = args.since ? Date.parse(args.since) : earliestLedgerTs(ledger);
  }

  // Denominator: full GHSA malware list (npm + pypi), withdrawn excluded, window-scoped.
  const denom = [];
  for (const eco of ['npm', 'pypi']) {
    let rows;
    try { rows = await fetchAllGhsaMalware(eco, { maxPages: args.maxPages }); }
    catch (err) { console.error(`[coverage-audit] GHSA fetch ${eco} failed: ${err.message}`); continue; }
    for (const r of rows) {
      if (r.withdrawn) continue; // a retracted advisory is not "should have caught"
      if (sinceMs !== null) {
        const pub = r.published_at ? Date.parse(r.published_at) : NaN;
        if (Number.isNaN(pub) || pub < sinceMs) continue;
      }
      denom.push({ ecosystem: r.ecosystem, name: r.name });
    }
  }

  const archived = loadArchivedNames();
  const result = classifyCoverage(denom, ledger, archived);
  const windowStr = sinceMs !== null ? new Date(sinceMs).toISOString() : '(all history)';

  // Persist the report + the human-gated GT proposals (scannedClean = known malware we missed).
  const report = {
    generatedAt: new Date().toISOString(),
    window: windowStr,
    ledgerEntries: ledger.length,
    archivedNames: archived.size,
    ...result
  };
  try {
    if (!fs.existsSync(path.dirname(COVERAGE_REPORT_FILE))) fs.mkdirSync(path.dirname(COVERAGE_REPORT_FILE), { recursive: true });
    fs.writeFileSync(COVERAGE_REPORT_FILE, JSON.stringify(report, null, 2));
    fs.writeFileSync(GT_PROPOSALS_FILE, JSON.stringify({
      generatedAt: report.generatedAt, window: windowStr,
      note: 'ADVISORY ONLY — GT promotion is human-gated. Review each before adding to tests/ground-truth/attacks.json.',
      candidates: result.misses.scannedClean
    }, null, 2));
  } catch (err) { console.error(`[coverage-audit] persist failed: ${err.message}`); }

  if (args.json) { console.log(JSON.stringify(report, null, 2)); return 0; }

  console.log(`\n  Operational coverage audit (GHSA-denominated)`);
  console.log(`  window: advisories published since ${windowStr}  |  ledger: ${ledger.length} entries, archive: ${archived.size} names\n`);
  console.log(`  Operational TPR : ${result.alerted}/${result.total}  ${fmtPct(result.operationalTPR)}   ← headline (alerted / GHSA malware in window)`);
  console.log(`    alerted       : ${result.alerted}   (ledger suspect/confirmed or archived)`);
  console.log(`    scanned-clean : ${result.scannedClean}   ← MISSES (we scanned a known-malware pkg and cleared it)`);
  console.log(`    dropped       : ${result.dropped}   (queue-cap / ghsa_gone, never scanned)`);
  console.log(`    never-seen    : ${result.neverSeen}   (ingestion never processed it in-window)`);
  for (const [eco, n] of Object.entries(result.byEcosystem)) {
    console.log(`    ${eco.padEnd(5)} : ${n.alerted}/${n.total} alerted · ${n.scannedClean} miss · ${n.dropped} dropped · ${n.neverSeen} never-seen`);
  }
  if (result.misses.scannedClean.length) {
    console.log(`\n  Top detection misses (scanned-clean — GT candidates, written to ${path.relative(ROOT, GT_PROPOSALS_FILE)}):`);
    for (const m of result.misses.scannedClean.slice(0, 15)) console.log(`    - ${m}`);
    console.log(`  ${result.misses.scannedClean.length} candidate(s) total — HUMAN-GATED, not auto-added to ground truth.`);
  }
  console.log('');
  return 0;
}

if (require.main === module) {
  main().then(code => process.exit(code || 0)).catch(err => { console.error(err); process.exit(2); });
}

module.exports = { classifyCoverage, loadArchivedNames, earliestLedgerTs };
