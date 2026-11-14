#!/usr/bin/env node
'use strict';

/*
 * Product smoke test: scan a known-malicious dependency with MUAD'DIB AS A USER INSTALLS IT,
 * in an empty HOME (no IOC cache, no source checkout next to it).
 *
 *   node scripts/product-smoke.js <path to installed bin/muaddib.js> --expect detect
 *   node scripts/product-smoke.js <path to installed bin/muaddib.js> --expect not-safe
 *
 * --expect detect    score >= 75 and analysis COMPLETE (release gate, daily check)
 * --expect not-safe  either detected as above, or INCONCLUSIVE; never a COMPLETE score below 75
 *
 * Why (2026-11-14): the npm package ships no IOC data and the first-run download had been a
 * 404 for months; a fresh install scored a flatmap-stream@0.1.1 dependency 0 and nothing in CI
 * noticed, because no test ran the product as installed.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const [binArg, flag, expect] = process.argv.slice(2);
if (!binArg || flag !== '--expect' || !['detect', 'not-safe'].includes(expect)) {
  console.error('usage: product-smoke.js <bin/muaddib.js> --expect detect|not-safe');
  process.exit(2);
}
const bin = path.resolve(binArg);
if (!fs.existsSync(bin)) { console.error('::error::not found: ' + bin); process.exit(2); }

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-smoke-'));
const home = path.join(root, 'home');
const target = path.join(root, 'target');
fs.mkdirSync(home);
fs.mkdirSync(path.join(target, 'node_modules', 'flatmap-stream'), { recursive: true });
// event-stream incident (2018): flatmap-stream@0.1.1 carried the payload. Metadata only, no code.
fs.writeFileSync(path.join(target, 'package.json'), JSON.stringify({ name: 'smoke-victim', version: '1.0.0', dependencies: { 'flatmap-stream': '0.1.1' } }));
fs.writeFileSync(path.join(target, 'node_modules', 'flatmap-stream', 'package.json'), JSON.stringify({ name: 'flatmap-stream', version: '0.1.1' }));

const env = { ...process.env, HOME: home, USERPROFILE: home };
delete env.MUADDIB_NO_REGISTRY_FETCH; // the first-run IOC download is what is under test
const run = spawnSync(process.execPath, [bin, 'scan', target, '--json'], { env, encoding: 'utf8', timeout: 300000, maxBuffer: 64 * 1024 * 1024 });
process.stderr.write(run.stderr || '');

let result;
try { result = JSON.parse(run.stdout); } catch {
  console.error('::error::scan output is not JSON (exit ' + run.status + ')');
  process.exit(1);
}
const score = result.summary && result.summary.riskScore;
const status = result.analysis && result.analysis.status;
const types = [...new Set((result.threats || []).map(t => t.type))];
console.log(`score=${score} status=${status} types=${types.join(',') || '-'}`);
if (result.analysis && result.analysis.incomplete && result.analysis.incomplete.length) {
  console.log('incomplete: ' + JSON.stringify(result.analysis.incomplete));
}

const detected = score >= 75 && status === 'COMPLETE';
let ok;
if (expect === 'detect') ok = detected;
else ok = detected || status === 'INCONCLUSIVE';
fs.rmSync(root, { recursive: true, force: true });
if (!ok) {
  console.error(`::error::product smoke (${expect}) failed: a known-malicious dependency got score ${score}, status ${status}`);
  process.exit(1);
}
console.log(`product smoke (${expect}) passed`);
