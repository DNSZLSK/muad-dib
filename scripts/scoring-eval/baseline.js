#!/usr/bin/env node
'use strict';

// Scoring baseline harness for Hybrid v3 refactor.
//
// Merges three labeled corpora into one baseline:
//   1. evaluate-scan-cache.json — 917 pkgs with full threats[] (severity-aware)
//   2. fp-extended-results.json — 1969 pkgs with types[] + verdict (no severity)
//   3. dedup-fp-new.txt / fp-week-04-18-names.txt / dedup-malware-{new,dup}.txt —
//      explicit name@version labels from manual review (canonical label source)
//
// For each unique package: prefer cache (full severity), fall back to extended.
// Label resolution priority: explicit-malware > explicit-fp > extended-verdict >
//   inferred-from-path (benign-tarballs => fp; ground-truth/adversarial/holdout => mw).
//
// Phase 1 validation: count FP false-lifts that the candidate
// SINGLE_FIRE_CRITICAL_TYPES would cause if a CRITICAL floor was applied.
// Iterate the candidate set + MIN_SEVERITY until fpFalseLifts == 0.

const fs = require('fs');
const path = require('path');

const ARGS = process.argv.slice(2);
function arg(name, def) {
  const i = ARGS.indexOf(`--${name}`);
  return i >= 0 ? ARGS[i + 1] : def;
}
function flag(name) { return ARGS.includes(`--${name}`); }
const REPLAY = flag('replay');

const CACHE_DIR = arg('cache', path.resolve(__dirname, '../../../muad-dib/.muaddib-cache'));
const DATA_DIR = arg('data', path.resolve(__dirname, '../../../muad-dib/data'));
const TAG = arg('tag', 'master');
const OUT = path.resolve(__dirname, `../../.muaddib-cache/scoring-baseline-${TAG}.json`);

// --- Phase 1 candidate set: types that should single-fire to CRITICAL floor.
// Refined against 2508-pkg corpus (744 cache + 1588 fp-extended).
//
// Empirical verdicts:
//   cross_file_dataflow      26fp / 13mw  REJECTED (67% precision)
//   reverse_shell            16fp /  3mw  REJECTED (16% precision)
//   module_load_bypass        4fp /  1mw  REJECTED (20% precision)
//   newsletter_auto_follow    1fp /  1mw  REJECTED (50% precision)
//   lifecycle_shell_pipe      0fp /  1mw  KEEP (100% in corpus, "curl|sh")
//   known_malicious_hash       no fires    KEEP (deterministic IOC equality)
//   known_malicious_package    no fires    KEEP (deterministic IOC equality)
//   pypi_malicious_package     no fires    KEEP (deterministic IOC equality)
//   shai_hulud_marker          no fires    KEEP (deterministic IOC marker)
//   crypto_address_swap        no fires    DROP (no validation evidence)
//   curl_exec                  no fires    DROP (no validation evidence)
//   require_process_mainmodule no fires    DROP (no validation evidence)
const SINGLE_FIRE_CRITICAL_CANDIDATES = new Set([
  'lifecycle_shell_pipe',
  'known_malicious_hash',
  'known_malicious_package',
  'pypi_malicious_package',
  'shai_hulud_marker'
]);

const MIN_SEVERITY = arg('min-severity', 'HIGH');
const SEV_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const FLOOR_CRITICAL = 75;

function readLines(p) {
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').split('\n').map(s => s.trim()).filter(Boolean);
}

// --- Explicit label maps. Key shape: name@version (lowercased), and bare name as fallback.
const explicitFP = new Set();
const explicitMW = new Set();
function addLabelTo(set, lst, _src) {
  for (const k of lst) {
    set.add(k.toLowerCase());
    const at = k.lastIndexOf('@');
    if (at > 0) set.add(k.slice(0, at).toLowerCase()); // bare name fallback
  }
}
addLabelTo(explicitFP, readLines(path.join(CACHE_DIR, 'dedup-fp-new.txt')), 'dedup-fp-new');
addLabelTo(explicitFP, readLines(path.join(CACHE_DIR, 'dedup-fp-dup.txt')), 'dedup-fp-dup');
addLabelTo(explicitFP, readLines(path.join(CACHE_DIR, 'fp-week-04-18-names.txt')), 'fp-week-04-18');
addLabelTo(explicitMW, readLines(path.join(CACHE_DIR, 'dedup-malware-new.txt')), 'dedup-malware-new');
addLabelTo(explicitMW, readLines(path.join(CACHE_DIR, 'dedup-malware-dup.txt')), 'dedup-malware-dup');
console.log(`Explicit labels: fp=${explicitFP.size} mw=${explicitMW.size}`);

// --- Source A: evaluate-scan-cache.json (full threats with severity)
const cachePath = path.join(CACHE_DIR, 'evaluate-scan-cache.json');
if (!fs.existsSync(cachePath)) { console.error(`MISSING cache: ${cachePath}`); process.exit(1); }
const cache = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
console.log(`evaluate-scan-cache fingerprint=${cache.fingerprint} packages=${Object.keys(cache.results).length}`);

// --- Source B: fp-extended-results.json (types + verdict, no severity)
const extPath = path.join(DATA_DIR, 'fp-extended-results.json');
const extended = fs.existsSync(extPath) ? JSON.parse(fs.readFileSync(extPath, 'utf8')) : [];
console.log(`fp-extended-results: ${extended.length} packages`);

// --- Inference helpers.
function inferLabelFromPath(cacheKey) {
  const k = cacheKey.toLowerCase().replace(/\\/g, '/');
  if (k.includes('benign-random-tarballs')) return 'fp';
  if (k.includes('benign-tarballs')) return 'fp';
  if (k.includes('benign-pypi')) return 'fp';
  if (k.includes('benign-training-tarballs')) return 'fp';
  if (k.includes('ground-truth')) return 'mw';
  if (k.includes('adversarial')) return 'mw';
  if (k.includes('holdout')) return 'mw';
  return null;
}
function decanonicalize(dirName) {
  // "_assaabloy_gw-group-footer_25.0.2" -> "@assaabloy/gw-group-footer@25.0.2"
  // "express_4.18.0" -> "express@4.18.0" (heuristic on last underscore-version)
  if (dirName.startsWith('_')) {
    const stripped = dirName.slice(1);
    // "_scope_name_ver" — assume scope is first segment, name second, ver everything after the next _
    const i = stripped.indexOf('_');
    if (i < 0) return dirName;
    const scope = stripped.slice(0, i);
    const rest = stripped.slice(i + 1);
    const verMatch = rest.match(/^(.+?)_(\d.*)$/);
    if (verMatch) return `@${scope}/${verMatch[1]}@${verMatch[2]}`;
    return `@${scope}/${rest}`;
  }
  const verMatch = dirName.match(/^(.+?)_(\d.*)$/);
  if (verMatch) return `${verMatch[1]}@${verMatch[2]}`;
  return dirName;
}

// --- Build merged corpus, keyed by canonical pkg name (lowercased).
// Each row: { pkg, label, source, types[], severities{type:rank}, oldScore, fromCache }
const corpus = new Map();

function addRow(pkg, row) {
  const key = pkg.toLowerCase();
  const existing = corpus.get(key);
  if (!existing || (row.fromCache && !existing.fromCache)) corpus.set(key, row);
}

function resolveLabel(pkg, fallback) {
  const lower = pkg.toLowerCase();
  if (explicitMW.has(lower)) return 'mw';
  const at = lower.lastIndexOf('@');
  if (at > 0 && explicitMW.has(lower.slice(0, at))) return 'mw';
  if (explicitFP.has(lower)) return 'fp';
  if (at > 0 && explicitFP.has(lower.slice(0, at))) return 'fp';
  return fallback;
}

// REPLAY mode: import the live scoring module so we can re-aggregate cached
// threats with the current src/scoring.js logic (incl. MUADDIB_DECAY=1).
let liveScoring = null;
if (REPLAY) {
  liveScoring = require('../../src/scoring.js');
  console.log(`REPLAY mode ON. MUADDIB_DECAY=${process.env.MUADDIB_DECAY || '0'}`);
}

// Pass A: evaluate-scan-cache rows.
for (const [cacheKey, entry] of Object.entries(cache.results)) {
  if (!entry || !entry.summary || !entry.threats) continue;
  const segs = cacheKey.split(/[\\/]/);
  const tail = segs[segs.length - 1] === 'package' ? segs[segs.length - 2] : segs[segs.length - 1];
  const pkgName = decanonicalize(tail);
  const inferred = inferLabelFromPath(cacheKey);
  const label = resolveLabel(pkgName, inferred);
  if (!label) continue;
  const threats = entry.threats;
  const types = [...new Set(threats.map(t => t.type))];
  const severities = {};
  for (const t of threats) {
    const r = SEV_RANK[t.severity] ?? 0;
    if ((severities[t.type] ?? -1) < r) severities[t.type] = r;
  }
  let replayScore = null;
  if (REPLAY && liveScoring) {
    try {
      // Phase 3 needs replacedByCompound tags on constituents — re-running
      // applyCompoundBoosts is idempotent for compound emission (skipped if
      // already present) but always re-tags constituents (added in v3 Phase 3).
      // Clone threats to avoid corpus pollution across packages.
      const replayThreats = threats.map(t => ({ ...t }));
      liveScoring.applyCompoundBoosts(replayThreats);
      const replayResult = liveScoring.calculateRiskScore(replayThreats);
      replayScore = replayResult.riskScore;
    } catch (e) {
      replayScore = -1; // mark error
    }
  }
  addRow(pkgName, {
    pkg: pkgName, label, source: inferred ? `cache:${inferred}` : 'cache:explicit',
    cacheKey, types, severities, oldScore: entry.summary.riskScore || 0,
    replayScore, fromCache: true
  });
}

// Pass B: fp-extended-results rows (types only, no severity).
for (const r of extended) {
  if (!r.pkg) continue;
  let label = null;
  if (r.verdict === 'FP') label = 'fp';
  else if (r.verdict === 'REVIEW' || r.verdict === 'SUSPICIOUS') continue; // ambiguous
  // Explicit labels override fp-extended verdict
  label = resolveLabel(r.pkg, label);
  if (!label) continue;
  const types = r.types || [];
  // No severity available — record max known rank as null
  const severities = {};
  for (const t of types) severities[t] = null;
  addRow(r.pkg, {
    pkg: r.pkg, label, source: `extended:${r.verdict}`,
    cacheKey: null, types, severities, oldScore: r.score || 0,
    replayScore: null, // no full threats array in fp-extended
    fromCache: false
  });
}

console.log(`Merged corpus: ${corpus.size} packages`);

// --- Phase 1 simulation.
const minRank = SEV_RANK[MIN_SEVERITY];
function singleFireHits(row) {
  const hits = [];
  for (const t of row.types) {
    if (!SINGLE_FIRE_CRITICAL_CANDIDATES.has(t)) continue;
    const sev = row.severities[t];
    if (sev === null) {
      // No severity info (fp-extended). Conservative: assume satisfies threshold.
      hits.push({ type: t, severity: '?', conservative: true });
    } else if (sev >= minRank) {
      hits.push({ type: t, severity: Object.keys(SEV_RANK).find(k => SEV_RANK[k] === sev), conservative: false });
    }
  }
  return hits;
}

const rows = [];
for (const row of corpus.values()) {
  const hits = singleFireHits(row);
  // Phase 1 floor projection on top of either oldScore (cached, no replay)
  // or replayScore (live re-aggregation, e.g. with MUADDIB_DECAY=1).
  const baseScore = REPLAY && row.replayScore != null && row.replayScore >= 0
    ? row.replayScore
    : row.oldScore;
  const newScore = hits.length > 0 ? Math.max(baseScore, FLOOR_CRITICAL) : baseScore;
  rows.push({
    pkg: row.pkg, label: row.label, source: row.source, fromCache: row.fromCache,
    oldScore: row.oldScore,
    replayScore: row.replayScore,
    newScore, delta: newScore - row.oldScore,
    crossesCritical: row.oldScore < FLOOR_CRITICAL && newScore >= FLOOR_CRITICAL,
    droppedCritical: row.oldScore >= FLOOR_CRITICAL && newScore < FLOOR_CRITICAL,
    types: row.types, hits
  });
}

const fpRows = rows.filter(r => r.label === 'fp');
const mwRows = rows.filter(r => r.label === 'mw');

// --- Per-type stats among single-fire candidates.
const typeStats = {};
for (const t of SINGLE_FIRE_CRITICAL_CANDIDATES) typeStats[t] = { fp: 0, mw: 0, fpConservative: 0, mwConservative: 0 };
for (const r of rows) {
  for (const h of r.hits) {
    typeStats[h.type][r.label]++;
    if (h.conservative) typeStats[h.type][r.label + 'Conservative']++;
  }
}

const summary = {
  tag: TAG,
  generated: new Date().toISOString(),
  config: {
    minSeverity: MIN_SEVERITY,
    floor: FLOOR_CRITICAL,
    candidateTypes: [...SINGLE_FIRE_CRITICAL_CANDIDATES].sort()
  },
  totals: {
    corpus: corpus.size, fpRows: fpRows.length, mwRows: mwRows.length,
    fpFromCache: fpRows.filter(r => r.fromCache).length,
    fpFromExtended: fpRows.filter(r => !r.fromCache).length,
    mwFromCache: mwRows.filter(r => r.fromCache).length,
    mwFromExtended: mwRows.filter(r => !r.fromCache).length
  },
  baseline: {
    fpAtOrAboveCritical: fpRows.filter(r => r.oldScore >= FLOOR_CRITICAL).length,
    mwAtOrAboveCritical: mwRows.filter(r => r.oldScore >= FLOOR_CRITICAL).length,
    mwBelowCritical: mwRows.filter(r => r.oldScore < FLOOR_CRITICAL).length
  },
  replay: REPLAY ? (() => {
    const cached = rows.filter(r => r.replayScore != null && r.replayScore >= 0);
    const fpCached = cached.filter(r => r.label === 'fp');
    const mwCached = cached.filter(r => r.label === 'mw');
    return {
      decayEnv: process.env.MUADDIB_DECAY || '0',
      replayed: cached.length,
      fpReplayed: fpCached.length,
      mwReplayed: mwCached.length,
      fpAtOrAboveCriticalReplay: fpCached.filter(r => r.replayScore >= FLOOR_CRITICAL).length,
      mwAtOrAboveCriticalReplay: mwCached.filter(r => r.replayScore >= FLOOR_CRITICAL).length,
      mwTierDrops: mwCached.filter(r => r.oldScore >= FLOOR_CRITICAL && r.replayScore < FLOOR_CRITICAL).length,
      fpTierDrops: fpCached.filter(r => r.oldScore >= FLOOR_CRITICAL && r.replayScore < FLOOR_CRITICAL).length,
      mwTierGains: mwCached.filter(r => r.oldScore < FLOOR_CRITICAL && r.replayScore >= FLOOR_CRITICAL).length,
      fpTierGains: fpCached.filter(r => r.oldScore < FLOOR_CRITICAL && r.replayScore >= FLOOR_CRITICAL).length,
      mwTierDropDetails: mwCached.filter(r => r.oldScore >= FLOOR_CRITICAL && r.replayScore < FLOOR_CRITICAL)
        .slice(0, 50)
        .map(r => ({ pkg: r.pkg, source: r.source, oldScore: r.oldScore, replayScore: r.replayScore })),
      fpTierDropDetails: fpCached.filter(r => r.oldScore >= FLOOR_CRITICAL && r.replayScore < FLOOR_CRITICAL)
        .slice(0, 50)
        .map(r => ({ pkg: r.pkg, source: r.source, oldScore: r.oldScore, replayScore: r.replayScore }))
    };
  })() : null,
  phase1Projection: {
    fpFalseLifts: fpRows.filter(r => r.crossesCritical).length,
    mwRecoveries: mwRows.filter(r => r.crossesCritical).length,
    fpRowsFiringSingleFire: fpRows.filter(r => r.hits.length > 0).length,
    mwRowsFiringSingleFire: mwRows.filter(r => r.hits.length > 0).length
  },
  fpFalseLiftDetails: fpRows.filter(r => r.crossesCritical)
    .map(r => ({ pkg: r.pkg, source: r.source, oldScore: r.oldScore, hits: r.hits.map(h => `${h.type}/${h.severity}`) })),
  mwRecoveryDetails: mwRows.filter(r => r.crossesCritical)
    .map(r => ({ pkg: r.pkg, source: r.source, oldScore: r.oldScore, hits: r.hits.map(h => `${h.type}/${h.severity}`) })),
  typeStats: Object.fromEntries(
    Object.entries(typeStats)
      .filter(([_, v]) => v.fp + v.mw > 0)
      .sort((a, b) => (b[1].fp + b[1].mw) - (a[1].fp + a[1].mw))
  )
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify({ summary, rows }, null, 2));
console.log(`\nWrote ${OUT}\n`);
console.log(JSON.stringify(summary, null, 2));
