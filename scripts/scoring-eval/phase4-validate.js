#!/usr/bin/env node
'use strict';

// Phase 4 validation: applies the reputation factor (lifted into scoring.js)
// to every row in ml-training-curated-benign.jsonl + ml-training-datadog.jsonl
// and measures tier shifts at 75/50/25.
//
// Source-as-label only — never reads the in-file `label` field (C1
// contamination concern per project memory). curated-benign = fp,
// datadog = mw.

const fs = require('fs');
const path = require('path');
const { applyReputationFactor } = require('../../src/scoring.js');

const DATA_DIR = path.resolve(__dirname, '../../../muad-dib/data');
const FP_FILE = path.join(DATA_DIR, 'ml-training-curated-benign.jsonl');
const MW_FILE = path.join(DATA_DIR, 'ml-training-datadog.jsonl');
const OUT = path.resolve(__dirname, '../../.muaddib-cache/scoring-baseline-phase4.json');

const FLOOR_CRITICAL = 75;

function readJsonl(p) {
  if (!fs.existsSync(p)) {
    console.error(`MISSING ${p}`);
    return [];
  }
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
  const out = [];
  for (const ln of lines) {
    try { out.push(JSON.parse(ln)); } catch { /* skip malformed */ }
  }
  return out;
}

function evaluate(label, rows) {
  const out = [];
  for (const r of rows) {
    const oldScore = r.score || 0;
    const meta = {
      age_days: r.package_age_days,
      version_count: r.version_count,
      weekly_downloads: r.weekly_downloads,
      has_repository: r.has_repository,
      author_package_count: r.author_package_count
    };
    const result = { summary: { riskScore: oldScore, riskLevel: oldScore >= 75 ? 'CRITICAL' : 'HIGH', reputationFactor: 1.0 } };
    const adjust = applyReputationFactor(result, meta);
    const newScore = result.summary.riskScore;
    out.push({
      pkg: `${r.name}@${r.version}`,
      label,
      oldScore,
      newScore,
      delta: newScore - oldScore,
      factor: adjust ? adjust.factor : 1.0,
      crossesCritical: oldScore < FLOOR_CRITICAL && newScore >= FLOOR_CRITICAL,
      droppedCritical: oldScore >= FLOOR_CRITICAL && newScore < FLOOR_CRITICAL,
      meta
    });
  }
  return out;
}

const fpRows = evaluate('fp', readJsonl(FP_FILE));
const mwRows = evaluate('mw', readJsonl(MW_FILE));
const all = [...fpRows, ...mwRows];

function tierStats(rows) {
  return {
    n: rows.length,
    oldAtCrit: rows.filter(r => r.oldScore >= 75).length,
    newAtCrit: rows.filter(r => r.newScore >= 75).length,
    oldAtHigh: rows.filter(r => r.oldScore >= 50).length,
    newAtHigh: rows.filter(r => r.newScore >= 50).length,
    oldAtMed: rows.filter(r => r.oldScore >= 25).length,
    newAtMed: rows.filter(r => r.newScore >= 25).length,
    droppedFromCrit: rows.filter(r => r.droppedCritical).length,
    crossedToCrit: rows.filter(r => r.crossesCritical).length,
    sumDelta: rows.reduce((s, r) => s + r.delta, 0),
    avgFactor: (rows.reduce((s, r) => s + r.factor, 0) / Math.max(1, rows.length)).toFixed(3)
  };
}

const summary = {
  generated: new Date().toISOString(),
  fp: tierStats(fpRows),
  mw: tierStats(mwRows),
  fpDropFromCriticalSamples: fpRows.filter(r => r.droppedCritical).slice(0, 15)
    .map(r => ({ pkg: r.pkg, oldScore: r.oldScore, newScore: r.newScore, factor: r.factor })),
  mwDropFromCriticalSamples: mwRows.filter(r => r.droppedCritical).slice(0, 15)
    .map(r => ({ pkg: r.pkg, oldScore: r.oldScore, newScore: r.newScore, factor: r.factor })),
  mwCrossedToCriticalSamples: mwRows.filter(r => r.crossesCritical).slice(0, 5)
    .map(r => ({ pkg: r.pkg, oldScore: r.oldScore, newScore: r.newScore, factor: r.factor }))
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify({ summary, rows: all }, null, 2));
console.log(JSON.stringify(summary, null, 2));
