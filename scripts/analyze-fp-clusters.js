#!/usr/bin/env node
/**
 * scripts/analyze-fp-clusters.js
 *
 * Reads the latest metrics/v{version}.json (or one passed as --metrics) and
 * renders a markdown report of the dominant false-positive clusters.
 *
 * Drives Chantier 1 of the FPR improvement plan (mai 2026) : surface the
 * dominant FP buckets so subsequent chantiers (call-graph reachability,
 * delta scanning, mature gate, etc.) can target the right detections.
 *
 * Usage :
 *   node scripts/analyze-fp-clusters.js                       # latest version
 *   node scripts/analyze-fp-clusters.js --metrics path.json   # specific file
 *   node scripts/analyze-fp-clusters.js --top 20              # top 20 clusters
 *   node scripts/analyze-fp-clusters.js --out report.md       # write to file
 *   node scripts/analyze-fp-clusters.js --json                # JSON output
 *
 * Output sections :
 *   - Overview (total FP, unique clusters, schema)
 *   - Top N clusters with severity / corpus distribution + examples
 *   - Significant clusters (>= 5% of total FPs) flagged for action
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const METRICS_DIR = path.join(ROOT, 'metrics');
const SIGNIFICANT_THRESHOLD = 0.05; // 5% of total FPs => actionable

function parseArgs(argv) {
  const args = { metrics: null, top: 10, out: null, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--metrics') args.metrics = argv[++i];
    else if (a === '--top') args.top = parseInt(argv[++i], 10) || 10;
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node scripts/analyze-fp-clusters.js [--metrics path] [--top N] [--out path] [--json]');
      process.exit(0);
    }
  }
  return args;
}

function findLatestMetrics() {
  if (!fs.existsSync(METRICS_DIR)) return null;
  const files = fs.readdirSync(METRICS_DIR).filter(f => /^v[\d.]+\.json$/.test(f));
  if (files.length === 0) return null;
  // Sort semver-ish
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
  return path.join(METRICS_DIR, files[0]);
}

function pct(n, total) {
  if (!total) return '0.0%';
  return ((n / total) * 100).toFixed(1) + '%';
}

function renderMarkdown(report, fpClusters, args) {
  const lines = [];
  lines.push(`# FP cluster report - muad-dib v${report.version || '?'}`);
  lines.push('');
  lines.push(`Generated : ${new Date().toISOString()}`);
  lines.push(`Source metrics : ${report.date || '?'}`);
  lines.push('');

  if (!fpClusters) {
    lines.push('No `fpClusters` section found in metrics file. Re-run `npm run eval` with the updated `evaluate.js` to populate it.');
    return lines.join('\n');
  }

  // FPR headlines
  const benign = report.benign || {};
  const benignRandom = report.benignRandom || {};
  const fprAfterML = report.fprAfterML || {};
  lines.push('## FPR baseline');
  lines.push('');
  lines.push('| Metric | Flagged / Scanned | Rate |');
  lines.push('|---|---|---|');
  if (benign.scanned !== undefined) {
    lines.push(`| FPR rules curated | ${benign.flagged}/${benign.scanned} | ${pct(benign.flagged, benign.scanned)} |`);
  }
  if (benignRandom.scanned !== undefined) {
    lines.push(`| FPR random npm | ${benignRandom.flagged}/${benignRandom.scanned} | ${pct(benignRandom.flagged, benignRandom.scanned)} |`);
  }
  if (fprAfterML.scanned !== undefined) {
    lines.push(`| FPR after ML | ${fprAfterML.flagged}/${fprAfterML.scanned} | ${pct(fprAfterML.flagged, fprAfterML.scanned)} |`);
  }
  lines.push('');

  // Cluster overview
  lines.push('## Cluster overview');
  lines.push('');
  lines.push(`- Total FP threats observed : **${fpClusters.totalFps}**`);
  lines.push(`- Distinct clusters : **${fpClusters.totalUniqueClusters}**`);
  lines.push(`- Schema version : ${fpClusters.schema_version}`);
  lines.push('');

  const total = fpClusters.totalFps || 1;
  const significant = (fpClusters.topClusters || []).filter(c => c.count / total >= SIGNIFICANT_THRESHOLD);

  if (significant.length > 0) {
    lines.push(`## Significant clusters (>= ${(SIGNIFICANT_THRESHOLD * 100).toFixed(0)}% of FPs)`);
    lines.push('');
    lines.push('Each of these clusters drives enough FP volume that closing it would shift one or more headline metrics. Use them as the entry list for chantiers 2-7 (reachability, delta, mature gate, compound tightening).');
    lines.push('');
    for (const c of significant) {
      lines.push(`### \`${c.rule_type}\` on \`${c.file_pattern}\` ${c.is_bundle ? '(bundle)' : '(src)'}`);
      lines.push('');
      lines.push(`- Count : **${c.count}** (${pct(c.count, total)} of all FPs)`);
      lines.push(`- Distinct packages : ${c.distinct_packages}`);
      const sevLine = Object.entries(c.severity_distribution).filter(([, v]) => v > 0).map(([k, v]) => `${k}=${v}`).join(', ');
      if (sevLine) lines.push(`- Severity distribution : ${sevLine}`);
      const corpLine = Object.entries(c.corpus_distribution).filter(([, v]) => v > 0).map(([k, v]) => `${k}=${v}`).join(', ');
      if (corpLine) lines.push(`- Corpus distribution : ${corpLine}`);
      if (c.examples && c.examples.length > 0) {
        lines.push('- Examples :');
        for (const ex of c.examples) {
          lines.push(`  - \`${ex.package}\` -> ${ex.file || '<no-file>'} [${ex.severity}]`);
        }
      }
      lines.push('');
    }
  }

  // Full top N
  const topN = (fpClusters.topClusters || []).slice(0, args.top);
  lines.push(`## Top ${topN.length} clusters`);
  lines.push('');
  lines.push('| Rank | Type | File pattern | Bundle | Count | Pkgs | Severity |');
  lines.push('|---|---|---|---|---|---|---|');
  for (let i = 0; i < topN.length; i++) {
    const c = topN[i];
    const sev = Object.entries(c.severity_distribution).filter(([, v]) => v > 0).map(([k, v]) => `${k.charAt(0)}=${v}`).join(' ');
    lines.push(`| ${i + 1} | \`${c.rule_type}\` | \`${c.file_pattern}\` | ${c.is_bundle ? 'yes' : 'no'} | ${c.count} | ${c.distinct_packages} | ${sev} |`);
  }
  lines.push('');

  // Coverage summary
  if (significant.length === 0) {
    lines.push('## Action');
    lines.push('');
    lines.push('No single cluster crosses the 5% threshold. FPs are spread broadly - consider working on systemic levers (call-graph reachability C2, delta scanning C3, mature gate C5) before targeting individual rules.');
    lines.push('');
  } else {
    const sigSum = significant.reduce((s, c) => s + c.count, 0);
    lines.push('## Action');
    lines.push('');
    lines.push(`The ${significant.length} significant cluster(s) account for **${pct(sigSum, total)}** of all FP threats. Closing them is the highest-leverage path to FPR reduction.`);
    lines.push('');
    lines.push('Suggested mapping to plan chantiers :');
    lines.push('- Bundle-side clusters (`is_bundle == yes`) -> compound tightening (C7) + bundle veto refinement.');
    lines.push('- Source-side clusters in mature packages -> mature stable cap (C5) + delta scanning (C3).');
    lines.push('- Clusters concentrated on dead code paths -> call-graph reachability (C2).');
    lines.push('- Clusters with high `LOW` severity share -> count-threshold tuning + multi-tier confidence (C6).');
    lines.push('');
  }

  return lines.join('\n');
}

function main() {
  const args = parseArgs(process.argv);
  const metricsPath = args.metrics || findLatestMetrics();

  if (!metricsPath) {
    console.error('No metrics file found. Run `npm run eval` first or pass --metrics path/to/v.json.');
    process.exit(1);
  }
  if (!fs.existsSync(metricsPath)) {
    console.error(`Metrics file not found : ${metricsPath}`);
    process.exit(1);
  }

  let report;
  try {
    report = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));
  } catch (err) {
    console.error(`Failed to parse metrics file : ${err.message}`);
    process.exit(1);
  }

  const fpClusters = report.fpClusters || null;

  if (args.json) {
    const out = JSON.stringify({
      version: report.version,
      date: report.date,
      fpClusters
    }, null, 2);
    if (args.out) {
      fs.writeFileSync(args.out, out);
      console.log(`Wrote JSON to ${args.out}`);
    } else {
      console.log(out);
    }
    return;
  }

  const md = renderMarkdown(report, fpClusters, args);

  if (args.out) {
    fs.writeFileSync(args.out, md);
    console.log(`Wrote markdown to ${args.out}`);
  } else {
    console.log(md);
  }
}

if (require.main === module) {
  main();
}

module.exports = { findLatestMetrics, renderMarkdown };
