#!/usr/bin/env node
'use strict';

/**
 * Quick FPR measurement on the 200-package random npm benign corpus only.
 * Used during the FPR plan iteration loop to avoid running the full evaluate
 * suite (~10min) when we only need to compare random-FPR deltas across flag
 * combinations.
 *
 * Usage : MUADDIB_DECAY=1 MUADDIB_MATURE_CAP=1 ... node scripts/eval-random-only.js
 *         MUADDIB_DECAY=1 ... node scripts/eval-random-only.js out.json
 */

const fs = require('fs');
const path = require('path');
const { evaluateBenignRandom, clusterFalsePositives } = require('../src/commands/evaluate.js');

async function main() {
  // Args : [outPath] [--corpus FILE]
  let outPath = null;
  let corpusFile = null;
  for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (a === '--corpus' && process.argv[i + 1]) { corpusFile = process.argv[++i]; }
    else if (!outPath) outPath = a;
  }
  const start = Date.now();

  // The function silently scans the corpus ; output JSON when not a TTY
  const result = await evaluateBenignRandom({ json: true, corpusFile });
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  const flags = {
    MUADDIB_MATURE_CAP: process.env.MUADDIB_MATURE_CAP === '1',
    MUADDIB_METADATA_FACTOR: process.env.MUADDIB_METADATA_FACTOR === '1',
    MUADDIB_FN_REACHABILITY: process.env.MUADDIB_FN_REACHABILITY === '1',
    MUADDIB_DELTA_MODE: process.env.MUADDIB_DELTA_MODE === '1',
    MUADDIB_DECAY: process.env.MUADDIB_DECAY === '1'
  };

  const fpClusters = clusterFalsePositives({ random: result.details || [] });

  const summary = {
    elapsed_sec: elapsed,
    flags,
    flagged: result.flagged,
    scanned: result.scanned,
    skipped: result.skipped,
    fpr: result.fpr,
    fpr_pct: ((result.fpr || 0) * 100).toFixed(2) + '%',
    flagged_packages: (result.details || []).filter(d => d.flagged).map(d => ({
      name: d.name, score: d.score
    })),
    top_clusters: (fpClusters && fpClusters.topClusters || []).slice(0, 8).map(c => ({
      count: c.count, type: c.rule_type, file: c.file_pattern, bundled: c.is_bundle
    }))
  };

  console.log(JSON.stringify(summary, null, 2));

  if (outPath) {
    const fullReport = { summary, details: result.details };
    fs.writeFileSync(outPath, JSON.stringify(fullReport, null, 2));
    console.error('Wrote ' + outPath);
  }
}

main().catch(err => {
  console.error('[ERROR]', err.stack || err.message);
  process.exit(1);
});
