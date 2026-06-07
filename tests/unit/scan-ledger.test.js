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

  // Reset env + module cache so other suites get production defaults, not the test path.
  delete process.env.MUADDIB_SCAN_LEDGER_FILE;
  delete process.env.MUADDIB_SCAN_LEDGER_MAX;
  delete require.cache[require.resolve('../../src/monitor/state.js')];
}

module.exports = { runScanLedgerTests };
