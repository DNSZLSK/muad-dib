'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, spyOn } = require('../test-utils');

// Load state.js with the per-scan ledger pointed at a fresh temp file. Re-require
// after setting env so SCAN_LEDGER_FILE / MAX_SCAN_LEDGER pick up the test values
// (same pattern the tarball-archive tests use with MUADDIB_ARCHIVE_DIR).
function freshState(ledgerFile, max) {
  process.env.MUADDIB_SCAN_LEDGER_FILE = ledgerFile;
  if (max !== undefined) process.env.MUADDIB_SCAN_LEDGER_MAX = String(max);
  else delete process.env.MUADDIB_SCAN_LEDGER_MAX;
  delete require.cache[require.resolve('../../src/monitor/state.js')];
  return require('../../src/monitor/state.js');
}

function runScanLedgerTests() {
  console.log('\n=== Scan Ledger Tests ===\n');

  test('appendScanLedger: writes a normalized entry (round-trip)', () => {
    const f = path.join(os.tmpdir(), `ledger-${Date.now()}-a.jsonl`);
    try {
      const s = freshState(f);
      s.appendScanLedger({ name: 'pkg-a', version: '1.0.0', ecosystem: 'npm', outcome: 'suspect',
        score: 42, tier: '1b', types: ['x', 'y'], sandbox: 'deferred', firstPublish: true, source: 'scan' });
      const e = s.loadScanLedger();
      assert(e.length === 1, `expected 1 entry, got ${e.length}`);
      const r = e[0];
      assert(r.name === 'pkg-a' && r.version === '1.0.0' && r.ecosystem === 'npm', 'core fields preserved');
      assert(r.outcome === 'suspect' && r.score === 42 && r.tier === '1b', 'outcome/score/tier preserved');
      assert(Array.isArray(r.types) && r.types.length === 2, 'types array preserved');
      assert(r.sandbox === 'deferred' && r.firstPublish === true, 'sandbox/firstPublish preserved');
      assert(typeof r.ts === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(r.ts), 'ts is ISO timestamp');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('appendScanLedger: unknown outcome normalizes to clean; missing name is a no-op', () => {
    const f = path.join(os.tmpdir(), `ledger-${Date.now()}-b.jsonl`);
    try {
      const s = freshState(f);
      s.appendScanLedger({ name: 'p', outcome: 'TOTALLY_BOGUS' });
      s.appendScanLedger({ outcome: 'clean' }); // no name → must be skipped
      const e = s.loadScanLedger();
      assert(e.length === 1, `missing-name entry must be skipped (got ${e.length})`);
      assert(e[0].outcome === 'clean', `unknown outcome should normalize to "clean", got ${e[0].outcome}`);
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('scan-ledger: compaction keeps only the most-recent MAX entries (bounded)', () => {
    const f = path.join(os.tmpdir(), `ledger-${Date.now()}-c.jsonl`);
    try {
      const s = freshState(f, 10);
      for (let i = 0; i < 14; i++) s.appendScanLedger({ name: `p${i}`, outcome: 'clean' });
      assert(s.loadScanLedger().length === 14, 'no auto-compact below the compaction interval');
      s._compactScanLedgerJsonl();
      const e = s.loadScanLedger();
      assert(e.length === 10, `compaction should cap at 10, got ${e.length}`);
      assert(e[0].name === 'p4' && e[e.length - 1].name === 'p13', 'keeps the most-recent (p4..p13)');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('loadScanLedger: tolerates malformed lines (skips, never throws)', () => {
    const f = path.join(os.tmpdir(), `ledger-${Date.now()}-d.jsonl`);
    try {
      const s = freshState(f);
      s.appendScanLedger({ name: 'ok1', outcome: 'clean' });
      fs.appendFileSync(f, '{ this is not valid json\n');
      s.appendScanLedger({ name: 'ok2', outcome: 'clean' });
      const e = s.loadScanLedger();
      assert(e.length === 2, `should parse 2 good entries and skip the bad one (got ${e.length})`);
      assert(e[0].name === 'ok1' && e[1].name === 'ok2', 'good entries preserved in order');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('appendScanLedger: never throws on write failure (ENOSPC/EROFS guard)', () => {
    const f = path.join(os.tmpdir(), `ledger-${Date.now()}-e.jsonl`);
    try {
      const s = freshState(f);
      // A ledger write failure must NEVER break the scan pipeline — verify it's swallowed.
      const spyNoSpace = spyOn(fs, 'appendFileSync', () => { const err = new Error('no space'); err.code = 'ENOSPC'; throw err; });
      try {
        s.appendScanLedger({ name: 'pkg', outcome: 'clean' });
        assert(spyNoSpace.callCount >= 1, 'appendFileSync should have been attempted');
      } finally { spyNoSpace.restore(); }
      const spyRo = spyOn(fs, 'appendFileSync', () => { const err = new Error('read-only fs'); err.code = 'EROFS'; throw err; });
      try { s.appendScanLedger({ name: 'pkg2', outcome: 'clean' }); } finally { spyRo.restore(); }
      // Reached here without an exception → guard works.
      assert(true, 'no exception propagated');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // --- Phase 0b: computeLedgerRollup (operational coverage) ---
  // These pass opts.file explicitly so they read the controlled fixture regardless of
  // env/module-cache state left by the freshState() tests above.
  const writeLedger = (f, entries) =>
    fs.writeFileSync(f, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');

  test('computeLedgerRollup: aggregates byOutcome / byEcosystem / scanned vs dropped', () => {
    const f = path.join(os.tmpdir(), `rollup-${Date.now()}-a.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        { ts: '2026-06-07T10:00:00.000Z', name: 'a', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-07T10:01:00.000Z', name: 'b', version: '1', ecosystem: 'npm', outcome: 'suspect' },
        { ts: '2026-06-07T10:02:00.000Z', name: 'c', version: '1', ecosystem: 'pypi', outcome: 'clean' },
        { ts: '2026-06-07T10:03:00.000Z', name: 'd', version: '1', ecosystem: 'npm', outcome: 'dropped' }
      ]);
      const r = s.computeLedgerRollup(null, { file: f });
      assert(r.total === 4, `total should be 4, got ${r.total}`);
      assert(r.scanned === 3, `scanned excludes dropped (expected 3, got ${r.scanned})`);
      assert(r.dropped === 1, `dropped should be 1, got ${r.dropped}`);
      assert(r.byOutcome.clean === 2 && r.byOutcome.suspect === 1 && r.byOutcome.dropped === 1, 'byOutcome counts');
      assert(r.byEcosystem.npm.total === 3 && r.byEcosystem.pypi.total === 1, 'byEcosystem totals');
      assert(r.byEcosystem.npm.scanned === 2 && r.byEcosystem.npm.dropped === 1, 'byEcosystem npm scanned/dropped split');
      assert(r.alerted === 1, `suspect counted as alerted (got ${r.alerted})`);
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('computeLedgerRollup: vanished = dropped-and-never-rescanned, both orderings', () => {
    const f = path.join(os.tmpdir(), `rollup-${Date.now()}-b.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        { ts: '2026-06-07T10:00:00.000Z', name: 'x', version: '1', ecosystem: 'npm', outcome: 'dropped' }, // never scanned → vanished
        { ts: '2026-06-07T10:01:00.000Z', name: 'y', version: '1', ecosystem: 'npm', outcome: 'dropped' }, // dropped then...
        { ts: '2026-06-07T10:02:00.000Z', name: 'y', version: '1', ecosystem: 'npm', outcome: 'clean' },   // ...rescued → not vanished
        { ts: '2026-06-07T10:03:00.000Z', name: 'z', version: '1', ecosystem: 'npm', outcome: 'dropped' }, // z@1 dropped...
        { ts: '2026-06-07T10:04:00.000Z', name: 'z', version: '2', ecosystem: 'npm', outcome: 'clean' },   // ...only z@2 scanned → z@1 vanished
        { ts: '2026-06-07T10:05:00.000Z', name: 'w', version: '1', ecosystem: 'npm', outcome: 'clean' },   // w@1 scanned first...
        { ts: '2026-06-07T10:06:00.000Z', name: 'w', version: '1', ecosystem: 'npm', outcome: 'dropped' }  // ...then dropped → not vanished (scan-before-drop)
      ]);
      const r = s.computeLedgerRollup(null, { file: f });
      assert(r.dropped === 4, `four drop events (got ${r.dropped})`);
      assert(r.vanished === 2, `only x@1 and z@1 vanished (got ${r.vanished})`);
      assert(r.exactVanished === true, 'count is exact below the key cap');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('computeLedgerRollup: sinceTs filters older entries (ms epoch and ISO string)', () => {
    const f = path.join(os.tmpdir(), `rollup-${Date.now()}-c.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        { ts: '2026-06-01T00:00:00.000Z', name: 'old', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-07T00:00:00.000Z', name: 'new', version: '1', ecosystem: 'npm', outcome: 'suspect' }
      ]);
      const since = Date.parse('2026-06-05T00:00:00.000Z');
      const r = s.computeLedgerRollup(since, { file: f });
      assert(r.total === 1 && r.scanned === 1, `only the in-window entry counts (got total=${r.total})`);
      assert(r.byOutcome.suspect === 1 && r.byOutcome.clean === undefined, 'old clean excluded by window');
      assert(r.alerted === 1, 'in-window suspect counted');
      const r2 = s.computeLedgerRollup('2026-06-05T00:00:00.000Z', { file: f });
      assert(r2.total === 1, 'ISO-string sinceTs behaves like the ms form');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('computeLedgerRollup: missing ledger → zero rollup, never throws', () => {
    const f = path.join(os.tmpdir(), `rollup-missing-${Date.now()}-d.jsonl`); // intentionally not created
    const s = require('../../src/monitor/state.js');
    const r = s.computeLedgerRollup(null, { file: f });
    assert(r.total === 0 && r.scanned === 0 && r.dropped === 0 && r.vanished === 0, 'all-zero rollup');
    assert(r.alertRate === null, 'alertRate is null when nothing was scanned');
    assert(r.exactVanished === true && typeof r.generatedAt === 'string', 'shape intact on empty');
  });

  test('computeLedgerRollup: alertRate = (suspect+confirmed)/scanned, dropped excluded from denom', () => {
    const f = path.join(os.tmpdir(), `rollup-${Date.now()}-e.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        { ts: '2026-06-07T10:00:00.000Z', name: 'a', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-07T10:01:00.000Z', name: 'b', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-07T10:02:00.000Z', name: 'c', version: '1', ecosystem: 'npm', outcome: 'suspect' },
        { ts: '2026-06-07T10:03:00.000Z', name: 'd', version: '1', ecosystem: 'npm', outcome: 'confirmed' },
        { ts: '2026-06-07T10:04:00.000Z', name: 'e', version: '1', ecosystem: 'npm', outcome: 'dropped' }
      ]);
      const r = s.computeLedgerRollup(null, { file: f });
      assert(r.scanned === 4, `dropped excluded from scanned (got ${r.scanned})`);
      assert(r.alerted === 2, `suspect + confirmed = 2 (got ${r.alerted})`);
      assert(Math.abs(r.alertRate - 0.5) < 1e-9, `alertRate = 2/4 = 0.5, dropped not in denom (got ${r.alertRate})`);
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // --- AUDIT 4: honest version-collapsed coverage (distinct package names) ---
  test('computeLedgerRollup: distinct coverage collapses versions; covered = ≥1 version scanned', () => {
    const f = path.join(os.tmpdir(), `rollup-${Date.now()}-distinct.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        // pkg "a": two versions, both scanned → one distinct name, covered
        { ts: '2026-06-07T10:00:00.000Z', name: 'a', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-07T10:01:00.000Z', name: 'a', version: '2', ecosystem: 'npm', outcome: 'clean' },
        // pkg "b": one version dropped, another scanned → covered (≥1 scanned)
        { ts: '2026-06-07T10:02:00.000Z', name: 'b', version: '1', ecosystem: 'npm', outcome: 'dropped' },
        { ts: '2026-06-07T10:03:00.000Z', name: 'b', version: '2', ecosystem: 'npm', outcome: 'suspect' },
        // pkg "c": only ever dropped → seen but NOT covered
        { ts: '2026-06-07T10:04:00.000Z', name: 'c', version: '1', ecosystem: 'npm', outcome: 'dropped' },
        // pkg "d": single scanned version → covered
        { ts: '2026-06-07T10:05:00.000Z', name: 'd', version: '1', ecosystem: 'pypi', outcome: 'clean' }
      ]);
      const r = s.computeLedgerRollup(null, { file: f });
      assert(r.total === 6, `6 raw events (got ${r.total})`);
      assert(r.distinctPackages === 4, `distinct names a,b,c,d = 4 (got ${r.distinctPackages})`);
      assert(r.distinctScanned === 3, `a,b,d covered; c never scanned = 3 (got ${r.distinctScanned})`);
      assert(Math.abs(r.distinctCoverage - 0.75) < 1e-9, `coverage = 3/4 = 0.75 (got ${r.distinctCoverage})`);
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('computeLedgerRollup: distinctCoverage is null on an empty ledger', () => {
    const f = path.join(os.tmpdir(), `rollup-empty-distinct-${Date.now()}.jsonl`); // not created
    const s = require('../../src/monitor/state.js');
    const r = s.computeLedgerRollup(null, { file: f });
    assert(r.distinctPackages === 0 && r.distinctScanned === 0, 'zero distinct on empty');
    assert(r.distinctCoverage === null, 'distinctCoverage null when nothing seen (no divide-by-zero)');
  });

  // Reset env + module cache so other suites get production defaults, not the test path.
  delete process.env.MUADDIB_SCAN_LEDGER_FILE;
  delete process.env.MUADDIB_SCAN_LEDGER_MAX;
  delete require.cache[require.resolve('../../src/monitor/state.js')];
}

module.exports = { runScanLedgerTests };
