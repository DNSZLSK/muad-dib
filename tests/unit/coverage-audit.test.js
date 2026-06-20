'use strict';

const { test, assert } = require('../test-utils');
const { classifyCoverage, earliestLedgerTs } = require('../../scripts/coverage-audit.js');

function runCoverageAuditTests() {
  console.log('\n=== Coverage Audit Tests (Phase 5 capstone) ===\n');

  test('classifyCoverage: alerted via ledger suspect, and via archive (archive wins over clean)', () => {
    const denom = [
      { ecosystem: 'npm', name: 'caught-by-ledger' },
      { ecosystem: 'npm', name: 'caught-by-archive' }
    ];
    const ledger = [
      { ecosystem: 'npm', name: 'caught-by-ledger', outcome: 'suspect' },
      { ecosystem: 'npm', name: 'caught-by-archive', outcome: 'clean' } // ledger says clean...
    ];
    const archived = new Set(['caught-by-archive']); // ...but we archived it → alerted
    const r = classifyCoverage(denom, ledger, archived);
    assert(r.alerted === 2, `both alerted, got ${r.alerted}`);
    assert(r.scannedClean === 0, 'archive overrides a clean ledger outcome');
    assert(Math.abs(r.operationalTPR - 1) < 1e-9, 'TPR = 2/2');
  });

  test('classifyCoverage: scannedClean (MISS), dropped, and neverSeen are distinguished', () => {
    const denom = [
      { ecosystem: 'npm', name: 'miss' },     // scanned clean, not archived → MISS
      { ecosystem: 'npm', name: 'evicted' },  // only dropped
      { ecosystem: 'npm', name: 'ghost' }     // never in ledger
    ];
    const ledger = [
      { ecosystem: 'npm', name: 'miss', outcome: 'clean' },
      { ecosystem: 'npm', name: 'evicted', outcome: 'dropped' }
    ];
    const r = classifyCoverage(denom, ledger, new Set());
    assert(r.alerted === 0, 'none alerted');
    assert(r.scannedClean === 1 && r.misses.scannedClean[0] === 'npm/miss', 'miss recorded');
    assert(r.dropped === 1, 'dropped recorded');
    assert(r.neverSeen === 1 && r.misses.neverSeen[0] === 'npm/ghost', 'never-seen recorded');
    assert(Math.abs(r.operationalTPR - 0) < 1e-9, 'TPR = 0/3');
  });

  test('classifyCoverage: spilled is its OWN bucket, not neverSeen (regression: spill→ingestion-gap misclassification)', () => {
    const denom = [
      { ecosystem: 'npm', name: 'on-waiting-list' },      // only spilled    → spilled (recoverable)
      { ecosystem: 'npm', name: 'errored' },              // only error      → dropped (seen, no verdict)
      { ecosystem: 'npm', name: 'spilled-then-evicted' }, // spilled+dropped → dropped wins (not recoverable)
      { ecosystem: 'npm', name: 'truly-absent' }          // no ledger entry → the ONLY real neverSeen
    ];
    const ledger = [
      { ecosystem: 'npm', name: 'on-waiting-list', outcome: 'spilled' },
      { ecosystem: 'npm', name: 'errored', outcome: 'error' },
      { ecosystem: 'npm', name: 'spilled-then-evicted', outcome: 'spilled' },
      { ecosystem: 'npm', name: 'spilled-then-evicted', outcome: 'dropped' }
    ];
    const r = classifyCoverage(denom, ledger, new Set());
    assert(r.spilled === 1 && r.misses.spilled[0] === 'npm/on-waiting-list', `spilled bucket = 1, got ${r.spilled}`);
    assert(r.dropped === 2, `error + spilled-then-evicted → dropped, got ${r.dropped}`);
    assert(r.neverSeen === 1 && r.misses.neverSeen[0] === 'npm/truly-absent', `only the absent pkg is neverSeen, got ${r.neverSeen}`);
    assert(r.byEcosystem.npm.spilled === 1, 'per-ecosystem spilled tracked');
    assert(r.total === 4, `total 4, got ${r.total}`);
  });

  test('classifyCoverage: a scanned-clean THEN suspect (re-scan) counts as alerted', () => {
    const denom = [{ ecosystem: 'npm', name: 'p' }];
    const ledger = [
      { ecosystem: 'npm', name: 'p', outcome: 'clean' },
      { ecosystem: 'npm', name: 'p', outcome: 'suspect' } // a later scan flagged it
    ];
    const r = classifyCoverage(denom, ledger, new Set());
    assert(r.alerted === 1 && r.scannedClean === 0, 'any suspect outcome wins → alerted');
  });

  test('classifyCoverage: per-ecosystem breakdown + denominator dedup', () => {
    const denom = [
      { ecosystem: 'npm', name: 'a' },
      { ecosystem: 'npm', name: 'a' },   // duplicate (multiple advisories) → counted once
      { ecosystem: 'pypi', name: 'b' }
    ];
    const ledger = [{ ecosystem: 'npm', name: 'a', outcome: 'suspect' }];
    const r = classifyCoverage(denom, ledger, new Set());
    assert(r.total === 2, `dedup: 2 distinct, got ${r.total}`);
    assert(r.byEcosystem.npm.alerted === 1 && r.byEcosystem.npm.total === 1, 'npm: 1/1');
    assert(r.byEcosystem.pypi.total === 1 && r.byEcosystem.pypi.neverSeen === 1, 'pypi: 1 never-seen');
  });

  test('classifyCoverage: empty denominator → TPR null, no crash', () => {
    const r = classifyCoverage([], [], new Set());
    assert(r.total === 0 && r.operationalTPR === null, 'empty → null TPR');
  });

  test('earliestLedgerTs: returns the minimum ts (window anchor), null on empty', () => {
    const ts = earliestLedgerTs([
      { ts: '2026-06-05T10:00:00Z' },
      { ts: '2026-06-01T00:00:00Z' },
      { ts: '2026-06-07T00:00:00Z' }
    ]);
    assert(ts === Date.parse('2026-06-01T00:00:00Z'), 'earliest picked');
    assert(earliestLedgerTs([]) === null, 'empty → null');
  });
}

module.exports = { runCoverageAuditTests };
