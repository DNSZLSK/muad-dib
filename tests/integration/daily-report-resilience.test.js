/**
 * P0a — Daily-report crash-safe headline reconciliation.
 *
 * A restart-storm can zero the in-memory daily counter (the monitor OOM-restarts
 * ~10×/day in prod), making the daily report publish "scanned=5" while ~44k
 * packages were really scanned that day. reconcileDailyHeadline() floors the
 * headline at the durable, monotonic scan-stats delta — but ONLY on catastrophic
 * loss, never on normal few-percent drift between the two counters.
 *
 * Behavioral, not source-grep: every test calls the real function and asserts its
 * return value / mutation. fs.readFileSync is stubbed to feed controlled
 * scan-stats.json / last-daily-report.json content without touching real data/.
 */

const fs = require('fs');
const { test, assert } = require('../test-utils');
const { reconcileDailyHeadline, captureScanStatsBaseline, saveLastDailyReportDate } = require('../../src/monitor/state.js');

// Stub fs.readFileSync so loadScanStats() (reads scan-stats.json) and
// reconcileDailyHeadline() (reads last-daily-report.json) see controlled content.
// `files` maps a path suffix → string content, or null to throw ENOENT.
// Everything else passes through to the real readFileSync.
function withFiles(files, fn) {
  const origRead = fs.readFileSync;
  const origWarn = console.warn;
  console.warn = () => {};
  fs.readFileSync = (p, enc) => {
    const key = Object.keys(files).find(k => String(p).endsWith(k));
    if (key !== undefined) {
      if (files[key] === null) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }
      return files[key];
    }
    return origRead(p, enc);
  };
  try { return fn(); } finally { fs.readFileSync = origRead; console.warn = origWarn; }
}

const scanStatsJson = (total, clean = 0, suspect = 0) =>
  JSON.stringify({ stats: { total_scanned: total, clean, suspect }, daily: [] });
const baselineJson = (total, clean = 0, suspect = 0) =>
  JSON.stringify({ lastReportDate: '2026-06-04', scanStatsBaseline: { total_scanned: total, clean, suspect } });

// In-memory fs keyed by basename, so atomicWriteFileSync (writeFileSync('<f>.tmp') +
// renameSync → '<f>') round-trips through readFileSync without touching real data/.
// The callback receives the live store so a test can advance scan-stats mid-flow.
function withMemFs(initial, fn) {
  const store = Object.assign({}, initial);
  const o = { read: fs.readFileSync, write: fs.writeFileSync, rename: fs.renameSync,
    mkdir: fs.mkdirSync, exists: fs.existsSync, warn: console.warn };
  const base = p => String(p).split(/[\\/]/).pop();
  console.warn = () => {};
  fs.readFileSync = (p, enc) => {
    const b = base(p);
    if (b in store) { if (store[b] == null) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; } return store[b]; }
    return o.read(p, enc);
  };
  fs.writeFileSync = (p, data) => { store[base(p)] = data; };
  fs.renameSync = (a, b) => { store[base(b)] = store[base(a)]; delete store[base(a)]; };
  fs.mkdirSync = () => {};
  fs.existsSync = () => true;
  try { return fn(store); }
  finally { fs.readFileSync = o.read; fs.writeFileSync = o.write; fs.renameSync = o.rename; fs.mkdirSync = o.mkdir; fs.existsSync = o.exists; console.warn = o.warn; }
}

async function runDailyReportResilienceTests() {
  console.log('\n=== DAILY REPORT RESILIENCE TESTS (P0a) ===\n');

  // POSITIVE: catastrophic in-memory loss → headline floored to the durable delta.
  test('P0a: reconcile floors scanned to durable delta on restart-storm loss', () => {
    const stats = { scanned: 5, clean: 3, suspect: 2 };
    const summary = withFiles({
      'last-daily-report.json': baselineJson(1_000_000, 800_000, 150_000),
      'scan-stats.json': scanStatsJson(1_044_000, 836_000, 156_000)  // delta: 44000 / 36000 / 6000
    }, () => reconcileDailyHeadline(stats));
    assert(summary.applied === true, 'reconcile should apply on catastrophic loss');
    assert(stats.scanned === 44000, `scanned should be floored to 44000, got ${stats.scanned}`);
    assert(stats.clean === 36000, `clean should be floored to 36000, got ${stats.clean}`);
    assert(stats.suspect === 6000, `suspect should be floored to 6000, got ${stats.suspect}`);
  });

  // POSITIVE: HALF-catastrophe — a few restarts dropped ~48% of the counter. The 0.8
  // floor ratio catches this; the old 0.5 ratio would have silently missed it.
  test('P0a: reconcile floors on a half-catastrophe (partial ~48% counter loss)', () => {
    const stats = { scanned: 25000, clean: 20000, suspect: 4000 };
    const summary = withFiles({
      'last-daily-report.json': baselineJson(1_000_000, 800_000, 150_000),
      'scan-stats.json': scanStatsJson(1_048_000, 838_000, 157_000)  // delta 48000 / 38000 / 7000
    }, () => reconcileDailyHeadline(stats));
    // 25000 < 48000 * 0.8 (=38400) → corrected. (Under the old 0.5 ratio: 25000 > 24000 → missed.)
    assert(summary.applied === true, 'reconcile should apply on a half-catastrophe (25k vs 48k)');
    assert(stats.scanned === 48000, `scanned should be floored to 48000, got ${stats.scanned}`);
  });

  // NEGATIVE: healthy day, normal drift (delta within 80-100% of in-memory) → NO floor.
  test('P0a: reconcile is a no-op on normal drift (healthy day)', () => {
    const stats = { scanned: 52000, clean: 41000, suspect: 8000 };
    const summary = withFiles({
      'last-daily-report.json': baselineJson(1_000_000),
      'scan-stats.json': scanStatsJson(1_053_000)  // delta 53000; 52000 > 53000*0.8 (=42400) → keep
    }, () => reconcileDailyHeadline(stats));
    assert(summary.applied === false, 'reconcile must NOT apply on normal drift');
    assert(stats.scanned === 52000, `scanned should stay 52000, got ${stats.scanned}`);
  });

  // NEGATIVE: no baseline yet (first report ever) → no-op.
  test('P0a: reconcile is a no-op when no baseline exists', () => {
    const stats = { scanned: 5, clean: 0, suspect: 0 };
    const summary = withFiles({
      'last-daily-report.json': JSON.stringify({ lastReportDate: '2026-06-04' }),  // no scanStatsBaseline
      'scan-stats.json': scanStatsJson(1_044_000)
    }, () => reconcileDailyHeadline(stats));
    assert(summary.applied === false, 'reconcile must NOT apply without a baseline');
    assert(stats.scanned === 5, `scanned should stay 5, got ${stats.scanned}`);
  });

  // NEGATIVE: last-daily-report.json missing entirely → safe no-op (no throw).
  test('P0a: reconcile tolerates a missing report-date file', () => {
    const stats = { scanned: 5 };
    const summary = withFiles({
      'last-daily-report.json': null,  // ENOENT
      'scan-stats.json': scanStatsJson(1_044_000)
    }, () => reconcileDailyHeadline(stats));
    assert(summary.applied === false, 'reconcile must be a safe no-op when the file is absent');
    assert(stats.scanned === 5, 'scanned unchanged when no baseline file');
  });

  // NEGATIVE: tiny durable delta (<=100) → no-op even if in-memory is lower.
  test('P0a: reconcile ignores tiny deltas (no spurious floor on low traffic)', () => {
    const stats = { scanned: 0 };
    const summary = withFiles({
      'last-daily-report.json': baselineJson(1_000_000),
      'scan-stats.json': scanStatsJson(1_000_040)  // delta 40 (< 100)
    }, () => reconcileDailyHeadline(stats));
    assert(summary.applied === false, 'reconcile must ignore deltas <= 100');
    assert(stats.scanned === 0, 'scanned unchanged on tiny delta');
  });

  // POSITIVE (restart-mid-report seam): the scan-stats baseline persisted at one
  // report survives to drive the NEXT report's reconciliation. Simulates: report
  // fires (capture+persist baseline) → a full day of scanning advances the durable
  // monotonic counter → a restart-storm zeroes the in-memory counter → next report
  // reconciles correctly from the persisted baseline. This is the crash-safety the
  // whole mechanism exists for.
  test('P0a: scan-stats baseline survives the report boundary (restart-mid-report)', () => {
    withMemFs({ 'scan-stats.json': scanStatsJson(1_000_000, 800_000, 150_000) }, (store) => {
      // Report T0: capture + persist baseline, exactly as sendDailyReport does.
      saveLastDailyReportDate('2026-06-04', captureScanStatsBaseline());
      const persisted = JSON.parse(store['last-daily-report.json']);
      assert(persisted.scanStatsBaseline.total_scanned === 1000000, 'baseline must be persisted to disk');

      // A day of scanning advances the durable, monotonic counter.
      store['scan-stats.json'] = scanStatsJson(1_044_000, 836_000, 156_000);

      // Report T1 after a restart-storm zeroed the in-memory counter.
      const stats = { scanned: 7, clean: 4, suspect: 3 };
      const summary = reconcileDailyHeadline(stats);
      assert(summary.applied === true, 'reconcile must apply using the persisted baseline');
      assert(stats.scanned === 44000, `scanned floored to durable 44000, got ${stats.scanned}`);
    });
  });

  // POSITIVE: captureScanStatsBaseline snapshots the monotonic totals.
  test('P0a: captureScanStatsBaseline snapshots monotonic scan-stats totals', () => {
    const baseline = withFiles({
      'scan-stats.json': scanStatsJson(1_234_567, 1_000_000, 200_000)
    }, () => captureScanStatsBaseline());
    assert(baseline.total_scanned === 1234567, `total_scanned wrong, got ${baseline.total_scanned}`);
    assert(baseline.clean === 1000000, `clean wrong, got ${baseline.clean}`);
    assert(baseline.suspect === 200000, `suspect wrong, got ${baseline.suspect}`);
  });

  console.log('  ✓ daily report resilience (P0a) tests passed');
}

module.exports = { runDailyReportResilienceTests };
