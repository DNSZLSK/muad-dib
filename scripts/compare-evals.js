#!/usr/bin/env node
'use strict';

/**
 * Compare two `muaddib evaluate --json` outputs and print the delta.
 * Usage:
 *   node scripts/compare-evals.js metrics/v2.11.4.json metrics/v2.11.8-eval-2026-05-10.json
 */

const fs = require('fs');
const path = require('path');

function load(p) {
  if (!fs.existsSync(p)) {
    console.error('[ERR] missing file: ' + p);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function pct(n, total) {
  if (!total) return 'N/A';
  return ((n / total) * 100).toFixed(2) + '%';
}

function fmt(rate) {
  if (rate === undefined || rate === null) return 'N/A';
  return (rate * 100).toFixed(2) + '%';
}

function delta(a, b) {
  if (a === undefined || b === undefined) return '';
  const d = (b - a) * 100;
  if (Math.abs(d) < 0.01) return '  (=)';
  const sign = d > 0 ? '+' : '';
  return '  (' + sign + d.toFixed(2) + ' pp)';
}

const baselinePath = process.argv[2] || 'metrics/v2.11.4.json';
const targetPath = process.argv[3];
if (!targetPath) {
  console.error('Usage: node scripts/compare-evals.js <baseline.json> <target.json>');
  process.exit(1);
}

const a = load(baselinePath);
const b = load(targetPath);

const name = (j, fallback) => j.version || fallback;

console.log('Compared : ' + name(a, baselinePath) + '  -->  ' + name(b, targetPath));
console.log('Dates    : ' + (a.date || '-') + '  -->  ' + (b.date || '-'));
console.log('');

const rows = [];

function pick(j, key) {
  if (!j) return undefined;
  if (j[key] && typeof j[key] === 'object' && 'fpr' in j[key]) return j[key];
  return j[key];
}

if (a.groundTruth && b.groundTruth) {
  rows.push(['TPR@3', a.groundTruth.tpr, b.groundTruth.tpr,
    a.groundTruth.detected + '/' + a.groundTruth.total,
    b.groundTruth.detected + '/' + b.groundTruth.total]);
  rows.push(['TPR@20', a.groundTruth.tprAt20, b.groundTruth.tprAt20,
    a.groundTruth.detectedAt20 + '/' + a.groundTruth.total,
    b.groundTruth.detectedAt20 + '/' + b.groundTruth.total]);
}

if (a.benign && b.benign) {
  rows.push(['FPR curated', a.benign.fpr, b.benign.fpr,
    a.benign.flagged + '/' + a.benign.scanned,
    b.benign.flagged + '/' + b.benign.scanned]);
}
if (a.benignAfterML && b.benignAfterML) {
  rows.push(['FPR after ML', a.benignAfterML.fpr, b.benignAfterML.fpr, '', '']);
}
if (a.benignRandom && b.benignRandom) {
  rows.push(['FPR random', a.benignRandom.fpr, b.benignRandom.fpr,
    a.benignRandom.flagged + '/' + a.benignRandom.scanned,
    b.benignRandom.flagged + '/' + b.benignRandom.scanned]);
}
if (a.benignPyPI && b.benignPyPI) {
  rows.push(['FPR PyPI', a.benignPyPI.fpr, b.benignPyPI.fpr,
    a.benignPyPI.flagged + '/' + a.benignPyPI.scanned,
    b.benignPyPI.flagged + '/' + b.benignPyPI.scanned]);
}
if (a.adversarial && b.adversarial) {
  rows.push(['ADR', a.adversarial.adr, b.adversarial.adr,
    a.adversarial.detected + '/' + a.adversarial.total,
    b.adversarial.detected + '/' + b.adversarial.total]);
}

console.log('| Metric        | Baseline | Target   | Delta        | Baseline detail | Target detail |');
console.log('|---------------|----------|----------|--------------|-----------------|---------------|');
for (const r of rows) {
  const [m, av, bv, ad, bd] = r;
  console.log('| ' + m.padEnd(13) + ' | ' + fmt(av).padEnd(8) + ' | ' + fmt(bv).padEnd(8) + ' |' + delta(av, bv).padEnd(13) + ' | ' + (ad || '').padEnd(15) + ' | ' + (bd || '').padEnd(13) + ' |');
}

// Highlight regressions / improvements
console.log('');
console.log('Verdict :');
function judge(label, a_, b_, lowerIsBetter) {
  if (a_ === undefined || b_ === undefined) return;
  const d = b_ - a_;
  if (Math.abs(d) < 0.0001) { console.log('  ' + label + ' : unchanged'); return; }
  const isImprove = lowerIsBetter ? d < 0 : d > 0;
  const tag = isImprove ? 'IMPROVE' : 'REGRESS';
  console.log('  ' + tag + ' on ' + label + ' (' + (d > 0 ? '+' : '') + (d * 100).toFixed(2) + ' pp)');
}
if (a.groundTruth && b.groundTruth) {
  judge('TPR@3', a.groundTruth.tpr, b.groundTruth.tpr, false);
  judge('TPR@20', a.groundTruth.tprAt20, b.groundTruth.tprAt20, false);
}
if (a.benign && b.benign) judge('FPR curated', a.benign.fpr, b.benign.fpr, true);
if (a.benignRandom && b.benignRandom) judge('FPR random', a.benignRandom.fpr, b.benignRandom.fpr, true);
if (a.adversarial && b.adversarial) judge('ADR', a.adversarial.adr, b.adversarial.adr, false);
