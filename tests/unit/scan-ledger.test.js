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

  // --- AUDIT-A1: first-publish + burst-extra observability in the ledger ---
  test('appendScanLedger: persists firstPublish; isBurstExtra only when true', () => {
    const f = path.join(os.tmpdir(), `ledger-a1-${Date.now()}.jsonl`);
    try {
      const s = freshState(f);
      s.appendScanLedger({ name: 'newpkg', version: '1.0.0', ecosystem: 'npm', outcome: 'clean', source: 'scan', firstPublish: true });
      s.appendScanLedger({ name: 'tseven', version: '0.0.1', ecosystem: 'npm', outcome: 'dropped', source: 'burst_extras_cap', firstPublish: false, isBurstExtra: true });
      const e = s.loadScanLedger();
      assert(e[0].firstPublish === true, 'scanned first-publish recorded as firstPublish:true');
      assert(e[0].isBurstExtra === undefined, 'isBurstExtra omitted on non-burst entries (keeps ledger lean)');
      assert(e[1].firstPublish === false && e[1].isBurstExtra === true, 'dropped burst-extra carries isBurstExtra:true');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // --- Daily-report ledger headline (8h→8h window source) ---
  test('computeLedgerRollup: headline clean-bucket mapping is exhaustive over outcomes', () => {
    const f = path.join(os.tmpdir(), `rollup-headline-${Date.now()}-a.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        // clean bucket — all five benign terminal verdicts
        { ts: '2026-06-07T10:00:00.000Z', name: 'c1', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-07T10:01:00.000Z', name: 'c2', version: '1', ecosystem: 'npm', outcome: 'clean_low_signal' },
        { ts: '2026-06-07T10:02:00.000Z', name: 'c3', version: '1', ecosystem: 'npm', outcome: 'clean_tooling' },
        { ts: '2026-06-07T10:03:00.000Z', name: 'c4', version: '1', ecosystem: 'npm', outcome: 'ml_clean' },
        { ts: '2026-06-07T10:04:00.000Z', name: 'c5', version: '1', ecosystem: 'npm', outcome: 'llm_benign' },
        // suspect bucket
        { ts: '2026-06-07T10:05:00.000Z', name: 's1', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '1b' },
        { ts: '2026-06-07T10:06:00.000Z', name: 's2', version: '1', ecosystem: 'npm', outcome: 'confirmed', tier: '1a' },
        // errors bucket — only the ledgerized failure outcomes
        { ts: '2026-06-07T10:07:00.000Z', name: 'e1', version: '1', ecosystem: 'npm', outcome: 'error' },
        { ts: '2026-06-07T10:08:00.000Z', name: 'e2', version: '1', ecosystem: 'npm', outcome: 'static_timeout' },
        // in NO bucket: scanned but neither vouched-for nor failed
        { ts: '2026-06-07T10:09:00.000Z', name: 'n1', version: '1', ecosystem: 'npm', outcome: 'sandbox_inconclusive' },
        { ts: '2026-06-07T10:10:00.000Z', name: 'n2', version: '1', ecosystem: 'npm', outcome: 'size_skip' },
        // dropped: not scanned at all
        { ts: '2026-06-07T10:11:00.000Z', name: 'd1', version: '1', ecosystem: 'npm', outcome: 'dropped' }
      ]);
      const r = s.computeLedgerRollup(null, { file: f });
      assert(r.headline && typeof r.headline === 'object', 'headline present on rollup');
      assert(r.headline.scanned === 11, `headline.scanned = non-dropped count (expected 11, got ${r.headline.scanned})`);
      assert(r.headline.clean === 5, `all five clean outcomes bucketed (got ${r.headline.clean})`);
      assert(r.headline.suspect === 2, `suspect+confirmed = 2 (got ${r.headline.suspect})`);
      assert(r.headline.errors === 2, `error+static_timeout = 2 (got ${r.headline.errors})`);
      // clean + suspect + errors + neither-bucket = scanned (nothing double-counted or lost)
      assert(r.headline.clean + r.headline.suspect + r.headline.errors + 2 === r.headline.scanned,
        'buckets partition scanned (with 2 in no bucket)');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('computeLedgerRollup: headline byTier maps ledger tiers; t1 = t1a + t1b + legacy "1"', () => {
    const f = path.join(os.tmpdir(), `rollup-headline-${Date.now()}-b.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        { ts: '2026-06-07T10:00:00.000Z', name: 'a', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '1a' },
        { ts: '2026-06-07T10:01:00.000Z', name: 'b', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '1a' },
        { ts: '2026-06-07T10:02:00.000Z', name: 'c', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '1b' },
        { ts: '2026-06-07T10:03:00.000Z', name: 'd', version: '1', ecosystem: 'npm', outcome: 'confirmed', tier: '1' },
        { ts: '2026-06-07T10:04:00.000Z', name: 'e', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '2' },
        { ts: '2026-06-07T10:05:00.000Z', name: 'f', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '3' },
        { ts: '2026-06-07T10:06:00.000Z', name: 'g', version: '1', ecosystem: 'npm', outcome: 'suspect' }, // no tier → counted in suspect, no tier bucket
        { ts: '2026-06-07T10:07:00.000Z', name: 'h', version: '1', ecosystem: 'npm', outcome: 'clean', tier: '1a' } // tier on a clean entry is ignored
      ]);
      const r = s.computeLedgerRollup(null, { file: f });
      const bt = r.headline.byTier;
      assert(bt.t1a === 2 && bt.t1b === 1, `t1a=2/t1b=1 (got t1a=${bt.t1a}, t1b=${bt.t1b})`);
      assert(bt.t2 === 1 && bt.t3 === 1, `t2=1/t3=1 (got t2=${bt.t2}, t3=${bt.t3})`);
      assert(bt.t1 === 4, `t1 = t1a(2) + t1b(1) + legacy '1'(1) = 4 — in-memory suspectByTier semantics (got ${bt.t1})`);
      assert(r.headline.suspect === 7, `all 7 suspect/confirmed counted regardless of tier (got ${r.headline.suspect})`);
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('computeLedgerRollup: headline respects the sinceTs window (the 8h→8h contract)', () => {
    const f = path.join(os.tmpdir(), `rollup-headline-${Date.now()}-c.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      writeLedger(f, [
        { ts: '2026-06-08T07:00:00.000Z', name: 'before', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-08T09:00:00.000Z', name: 'inA', version: '1', ecosystem: 'npm', outcome: 'clean' },
        { ts: '2026-06-09T05:00:00.000Z', name: 'inB', version: '1', ecosystem: 'npm', outcome: 'suspect', tier: '1b' }
      ]);
      // ms-epoch sinceTs — the prod shape (safeLedgerRollup always passes Date.parse output).
      // The ISO-string form of the API is covered by the dedicated both-forms test above.
      const r = s.computeLedgerRollup(Date.parse('2026-06-08T08:00:00.000Z'), { file: f });
      assert(r.headline.scanned === 2, `only in-window entries (expected 2, got ${r.headline.scanned})`);
      assert(r.headline.clean === 1 && r.headline.suspect === 1, 'window split clean/suspect');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // Reset env + module cache so other suites get production defaults, not the test path.
  delete process.env.MUADDIB_SCAN_LEDGER_FILE;
  delete process.env.MUADDIB_SCAN_LEDGER_MAX;
  delete require.cache[require.resolve('../../src/monitor/state.js')];
}

module.exports = { runScanLedgerTests };
