const { test, asyncTest, assert } = require('../test-utils');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Phase C (governors program): work conservation — no item interrupted by a
 * protective action dies outside the ledger+spill.
 *
 * Regression context (2026-06-12 09:43): the EMERGENCY terminate killed 10
 * in-flight scans; they were ledgered error/scan_error and NEVER re-scanned —
 * an attacker who can spike RSS gets the scans of OTHER packages killed
 * terminally. Three silent killers found by the pressure-test are pinned
 * here: (1) the dedup set would discard the re-scan at drain time, (2)
 * SPILL_FIELDS stripped the retry counter (infinite respill loop), (3) an
 * unregistered ledger outcome coerces to 'clean' — killed scans counted clean.
 */

const STUB = path.join(__dirname, '..', 'fixtures', 'stub-scan-worker.js');

async function runInterruptedRecoveryTests() {
  console.log('\n=== INTERRUPTED RECOVERY TESTS (phase C) ===\n');

  const queue = require('../../src/monitor/queue.js');
  const { spillItems, drainBacklog } = require('../../src/monitor/spill.js');
  const { isProtected } = require('../../src/monitor/scan-queue.js');

  // ─── The terminate → SCAN_INTERRUPTED code path (real worker) ───

  await asyncTest('INTERRUPTED: terminateAllWorkers rejects in-flight scans with code SCAN_INTERRUPTED', async () => {
    const saved = process.env.MUADDIB_SCAN_WORKER_PATH;
    process.env.MUADDIB_SCAN_WORKER_PATH = STUB;
    try {
      const p = queue.runScanInWorker('/tmp/x', 30000,
        { name: 'victim-pkg', version: '1.0.0', _stub: 'side-only' });
      await new Promise(r => setTimeout(r, 400)); // worker boots
      const n = queue.terminateAllWorkers();
      assert(n >= 1, `terminate must reach the live worker (got ${n})`);
      let code = null;
      try { await p; } catch (e) { code = e.code; }
      assert(code === 'SCAN_INTERRUPTED', `interrupted scan must reject SCAN_INTERRUPTED (got ${code})`);
    } finally {
      if (saved === undefined) delete process.env.MUADDIB_SCAN_WORKER_PATH;
      else process.env.MUADDIB_SCAN_WORKER_PATH = saved;
    }
  });

  await asyncTest('INTERRUPTED (neg): a normal worker failure does NOT carry SCAN_INTERRUPTED', async () => {
    const saved = process.env.MUADDIB_SCAN_WORKER_PATH;
    process.env.MUADDIB_SCAN_WORKER_PATH = path.join(__dirname, '..', 'fixtures', 'does-not-exist.js');
    try {
      let code = 'unset';
      try {
        await queue.runScanInWorker('/tmp/x', 5000, { name: 'broken', version: '1.0.0' });
      } catch (e) { code = e.code; }
      assert(code !== 'SCAN_INTERRUPTED', 'an ordinary worker error must not masquerade as an interruption');
    } finally {
      if (saved === undefined) delete process.env.MUADDIB_SCAN_WORKER_PATH;
      else process.env.MUADDIB_SCAN_WORKER_PATH = saved;
    }
  });

  // ─── Spill round-trip: fields survive, drain re-enqueues, protected-first ───

  await asyncTest('INTERRUPTED: interruptRetries and interrupted survive the spill round-trip, and the item drains protected-first', async () => {
    const tmpFile = path.join(os.tmpdir(), `muaddib-test-spill-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`);
    const savedSpill = process.env.MUADDIB_SPILL_FILE;
    const savedOn = process.env.MUADDIB_QUEUE_SPILL;
    process.env.MUADDIB_SPILL_FILE = tmpFile;
    process.env.MUADDIB_QUEUE_SPILL = '1';
    try {
      // A plain item first, then an interrupted one — the drain must re-ingest
      // the interrupted one FIRST (protected class).
      spillItems([{ name: 'plain-pkg', version: '1.0.0', ecosystem: 'npm', tarballUrl: 'https://x/p.tgz' }]);
      spillItems([{ name: 'victim-pkg', version: '2.0.0', ecosystem: 'npm', tarballUrl: 'https://x/v.tgz', interrupted: true, interruptRetries: 1 }]);
      const scanQueue = [];
      const r = drainBacklog(scanQueue, {}, {
        maxItems: 1,
        enqueueFn: (q, it) => { q.push(it); return { dropped: 0 }; },
        isDuplicate: () => false
      });
      assert(r.drained === 1, `one item drained (got ${r.drained})`);
      assert(scanQueue[0].name === 'victim-pkg', `the interrupted item must drain FIRST (got ${scanQueue[0].name})`);
      assert(scanQueue[0].interrupted === true && scanQueue[0].interruptRetries === 1,
        `interruption fields must survive the spill round-trip (got ${JSON.stringify({ i: scanQueue[0].interrupted, r: scanQueue[0].interruptRetries })})`);
    } finally {
      if (savedSpill === undefined) delete process.env.MUADDIB_SPILL_FILE; else process.env.MUADDIB_SPILL_FILE = savedSpill;
      if (savedOn === undefined) delete process.env.MUADDIB_QUEUE_SPILL; else process.env.MUADDIB_QUEUE_SPILL = savedOn;
      try { fs.unlinkSync(tmpFile); } catch { /* gone */ }
    }
  });

  test('INTERRUPTED: an interrupted item is protected (never evicted before plain items)', () => {
    assert(isProtected({ name: 'x', interrupted: true }) === true, 'interrupted ⇒ protected');
    assert(isProtected({ name: 'x' }) === false, 'plain item stays unprotected (negative)');
  });

  test('INTERRUPTED: the third interruption gives up for good (bounded — no infinite respill)', () => {
    const item = { name: 'rss-bomb', version: '1.0.0', ecosystem: 'npm' };
    let d = queue.computeInterruptDisposition(item);
    assert(d.retries === 1 && d.giveUp === false, `first interruption respills (got ${JSON.stringify(d)})`);
    d = queue.computeInterruptDisposition(item);
    assert(d.retries === 2 && d.giveUp === false, `second interruption respills (got ${JSON.stringify(d)})`);
    d = queue.computeInterruptDisposition(item);
    assert(d.retries === 3 && d.giveUp === true, `third interruption must give up → dropped/interrupted_max (got ${JSON.stringify(d)})`);
    // The counter rides the item (and SPILL_FIELDS persists it): a respilled
    // item that comes back via the drain continues counting, never restarts.
    assert(item.interruptRetries === 3, 'the counter is carried ON the item');
  });

  // ─── Ledger semantics: registered outcome, never clean, counted with dropped ───

  await asyncTest('INTERRUPTED: ledger outcome is registered (does NOT coerce to clean) and rolls up as non-scanned', async () => {
    const tmpLedger = path.join(os.tmpdir(), `muaddib-test-ledger-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`);
    const saved = process.env.MUADDIB_SCAN_LEDGER_FILE;
    process.env.MUADDIB_SCAN_LEDGER_FILE = tmpLedger;
    const statePath = require.resolve('../../src/monitor/state.js');
    delete require.cache[statePath];
    try {
      const st = require(statePath);
      st.appendScanLedger({ name: 'victim-pkg', version: '1.0.0', ecosystem: 'npm', outcome: 'interrupted', source: 'emergency_terminate' });
      st.appendScanLedger({ name: 'ok-pkg', version: '1.0.0', ecosystem: 'npm', outcome: 'clean' });
      const lines = fs.readFileSync(tmpLedger, 'utf8').trim().split('\n').map(JSON.parse);
      assert(lines[0].outcome === 'interrupted',
        `outcome must persist as 'interrupted', not coerce to clean (got ${lines[0].outcome})`);
      const rollup = st.computeLedgerRollup(null, { file: tmpLedger });
      assert(rollup.scanned === 1 && rollup.dropped === 1,
        `interrupted counts on the non-scanned side (scanned=${rollup.scanned}, dropped=${rollup.dropped})`);
      assert(rollup.byOutcome.interrupted === 1, 'byOutcome keeps interrupted distinct');
    } finally {
      if (saved === undefined) delete process.env.MUADDIB_SCAN_LEDGER_FILE; else process.env.MUADDIB_SCAN_LEDGER_FILE = saved;
      delete require.cache[statePath];
      try { fs.unlinkSync(tmpLedger); } catch { /* gone */ }
    }
  });
}

module.exports = { runInterruptedRecoveryTests };
