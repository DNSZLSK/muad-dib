'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert } = require('../test-utils');
const { buildFprLiveReport } = require('../../src/commands/fpr-live.js');

function writeLedger(entries) {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fpr-')), 'ledger.jsonl');
  fs.writeFileSync(f, entries.map(e => JSON.stringify(e)).join('\n') + '\n');
  return f;
}

const TS = '2026-06-10T10:00:00.000Z';
function ledgerFixture() {
  return writeLedger([
    { ts: TS, name: 'a', version: '1', ecosystem: 'npm', outcome: 'dropped', score: null, types: [] },
    { ts: TS, name: 'b', version: '1', ecosystem: 'npm', outcome: 'clean', score: 5, types: [] },
    { ts: TS, name: 'c', version: '1', ecosystem: 'npm', outcome: 'suspect', score: 25, types: ['dependency_typosquat'] },
    { ts: TS, name: 'd', version: '1', ecosystem: 'npm', outcome: 'suspect', score: 80, types: ['reverse_shell', 'lifecycle_script'] },
    { ts: TS, name: 'e', version: '1', ecosystem: 'npm', outcome: 'confirmed', score: 90, types: ['known_malicious_package'] },
    { ts: TS, name: 'f', version: '1', ecosystem: 'pypi', outcome: 'suspect', score: 35, types: ['import_time_exec'] }
  ]);
}

async function runFprLiveTests() {
  console.log('\n=== FPR-LIVE TESTS (live alert-rate measurement) ===\n');

  await asyncTest('fpr-live: dropped entries are excluded from the scanned denominator', async () => {
    const r = await buildFprLiveReport({ ledgerFile: ledgerFixture() });
    // 6 entries, 1 dropped → 5 scanned
    assert(r.recentWindow.scanned === 5, `expected 5 scanned, got ${r.recentWindow.scanned}`);
    assert(r.recentWindow.dropped === 1, `expected 1 dropped, got ${r.recentWindow.dropped}`);
  });

  await asyncTest('fpr-live: alertRate = (suspect+confirmed) / scanned', async () => {
    const r = await buildFprLiveReport({ ledgerFile: ledgerFixture() });
    // alerted = c,d (suspect) + e (confirmed) + f (suspect) = 4 ; scanned = 5
    assert(r.recentWindow.alerted === 4, `expected 4 alerted, got ${r.recentWindow.alerted}`);
    assert(Math.abs(r.recentWindow.alertRate - 0.8) < 1e-9, `expected 0.8, got ${r.recentWindow.alertRate}`);
  });

  await asyncTest('fpr-live: score buckets classify alerts by score', async () => {
    const r = await buildFprLiveReport({ ledgerFile: ledgerFixture() });
    const b = r.recentWindow.scoreBuckets;
    // 25→20-29, 35→30-49, 80→75-100, 90→75-100
    assert(b['20-29'] === 1, `20-29 expected 1, got ${b['20-29']}`);
    assert(b['30-49'] === 1, `30-49 expected 1, got ${b['30-49']}`);
    assert(b['50-74'] === 0, `50-74 expected 0, got ${b['50-74']}`);
    assert(b['75-100'] === 2, `75-100 expected 2, got ${b['75-100']}`);
  });

  await asyncTest('fpr-live: top firing rules are tallied from alert entries only', async () => {
    const r = await buildFprLiveReport({ ledgerFile: ledgerFixture() });
    const byType = Object.fromEntries(r.recentWindow.topFiringRules.map(x => [x.type, x.count]));
    assert(byType['dependency_typosquat'] === 1, 'dependency_typosquat should be counted');
    assert(byType['reverse_shell'] === 1 && byType['lifecycle_script'] === 1, 'multi-type alert counts each type');
    // clean entry "b" has no types and must not contribute (it is not an alert anyway).
    assert(!('__clean__' in byType), 'no phantom types');
  });

  await asyncTest('fpr-live: per-ecosystem alert rates are split', async () => {
    const r = await buildFprLiveReport({ ledgerFile: ledgerFixture() });
    const eco = r.recentWindow.byEcosystem;
    assert(eco.npm && eco.npm.scanned === 4 && eco.npm.alerted === 3, `npm: ${JSON.stringify(eco.npm)}`);
    assert(eco.pypi && eco.pypi.scanned === 1 && eco.pypi.alerted === 1, `pypi: ${JSON.stringify(eco.pypi)}`);
  });

  await asyncTest('fpr-live: report carries the honest "upper bound on FPR" note', async () => {
    const r = await buildFprLiveReport({ ledgerFile: ledgerFixture() });
    assert(/UPPER BOUND/.test(r.note), 'note must state alertRate is an FPR upper bound, not the curated 1.10%');
  });

  await asyncTest('fpr-live: missing ledger file degrades gracefully (no throw)', async () => {
    const r = await buildFprLiveReport({ ledgerFile: '/nonexistent/ledger.jsonl' });
    assert(r.recentWindow.scanned === 0, 'absent ledger → zero scanned, no crash');
    assert(Array.isArray(r.recentWindow.topFiringRules), 'still returns a shaped report');
  });
}

module.exports = { runFprLiveTests };
