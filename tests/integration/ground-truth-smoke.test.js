'use strict';

const path = require('path');
const { asyncTest, assert, runScanDirect } = require('../test-utils');

const GT_DIR = path.join(__dirname, '..', 'ground-truth', 'samples');

// 5 representative GT samples covering different detection vectors
const SMOKE_SAMPLES = [
  { dir: 'event-stream',   label: 'IOC match',          minScore: 3 },
  { dir: 'ua-parser-js',   label: 'lifecycle script',   minScore: 3 },
  { dir: 'shai-hulud',     label: 'shell + dataflow',   minScore: 3 },
  { dir: 'eslint-scope',   label: 'AST detection',      minScore: 3 },
  { dir: 'coa',            label: 'obfuscation',        minScore: 3 },
];

async function runGroundTruthSmokeTests() {
  for (const { dir, label, minScore } of SMOKE_SAMPLES) {
    await asyncTest(`GT smoke: ${dir} (${label})`, async () => {
      const sampleDir = path.join(GT_DIR, dir);
      const result = await runScanDirect(sampleDir);
      const score = result.summary.riskScore;
      assert(score >= minScore, `${dir}: expected score >= ${minScore}, got ${score}`);
    });
  }
}

module.exports = { runGroundTruthSmokeTests };
