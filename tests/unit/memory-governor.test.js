const { test, asyncTest, assert } = require('../test-utils');

/**
 * Phase B (governors program): memory governor — global admission by ticket.
 *
 * Regression context (2026-06-12 09:43): EMERGENCY at RSS 96% with main heap
 * 4% — 12 workers × ~650MB of sub-threshold scans (ATO burst). No per-package
 * or per-worker threshold could see the AGGREGATE; the governor bounds it at
 * admission, and freezes on real process RSS. The per-worker watermark's
 * combined metric (heap+external+arrayBuffers) closes the off-heap blind spot
 * (extraction Buffers are `external`, invisible to heapUsed alone).
 */

const gov = require('../../src/monitor/memory-governor.js');
const { watermarkBreached, watermarkLimitMb } = require('../../src/pipeline/watermark.js');

const MB = 1024 * 1024;

function withGovernor(env, fn) {
  const saved = {};
  const effective = { MUADDIB_MEMORY_GOVERNOR: '1', MUADDIB_RSS_LIMIT_MB: '10000', ...env };
  for (const [k, v] of Object.entries(effective)) { saved[k] = process.env[k]; process.env[k] = String(v); }
  gov.resetGovernor();
  const restore = () => {
    gov.resetGovernor();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
  return fn().finally(restore);
}

async function runMemoryGovernorTests() {
  console.log('\n=== MEMORY GOVERNOR TESTS (phase B) ===\n');

  // ─── Classifier ───

  test('GOVERNOR: classifyWeight — 0.5MB→light, 2MB→medium, oversize/truncated→heavy', () => {
    assert(gov.classifyWeight({ totalJsBytes: 512 * 1024, truncated: false }).cls === 'light', '0.5MB is light');
    assert(gov.classifyWeight({ totalJsBytes: 2 * MB, truncated: false }).cls === 'medium', '2MB is medium');
    assert(gov.classifyWeight({ totalJsBytes: 8 * MB, truncated: false }).cls === 'heavy', '8MB is heavy (isHeavyScan)');
    assert(gov.classifyWeight({ totalJsBytes: 1000, oversize: true, truncated: false }).cls === 'heavy', 'oversize forces heavy');
    assert(gov.classifyWeight({ totalJsBytes: 1000, truncated: true }).cls === 'heavy', 'truncated forces heavy');
    assert(gov.classifyWeight({ totalJsBytes: 100 * 1024, weightedJsBytes: 2 * MB, truncated: false }).cls === 'medium',
      'weighted bytes win over raw bytes');
    assert(gov.classifyWeight(null).cls === 'light', 'null weight is light');
  });

  // ─── Budget arithmetic (2 heavies fit, the 3rd waits — HEAVY_SCAN_MAX by arithmetic) ───

  await asyncTest('GOVERNOR: two heavies admitted, the third waits; release lets it through', async () => {
    await withGovernor({}, async () => {
      gov.updateGovernorRss(1000 * MB); // baseline 1000MB → budget 10000×0.7−1000 = 6000MB; heavy cap 5488MB
      const h1 = await gov.acquireMemoryTicket('heavy');
      const h2 = await gov.acquireMemoryTicket('heavy');
      assert(h1 && h2, 'two 2048MB heavies fit under the 5488MB heavy cap');
      let third = null;
      const p = gov.acquireMemoryTicket('heavy').then(t => { third = t; });
      await new Promise(r => setTimeout(r, 50));
      assert(third === null, 'third heavy (6144MB > cap) must wait');
      gov.releaseMemoryTicket(h1);
      await p;
      assert(third && third.cls === 'heavy', 'released heavy budget admits the waiter');
    });
  });

  await asyncTest('GOVERNOR: a light passes while heavies saturate the budget (carve-out)', async () => {
    await withGovernor({}, async () => {
      gov.updateGovernorRss(1000 * MB);
      await gov.acquireMemoryTicket('heavy');
      await gov.acquireMemoryTicket('heavy');
      const t0 = Date.now();
      const light = await gov.acquireMemoryTicket('light');
      assert(light && Date.now() - t0 < 100, 'light must be admitted immediately during heavy saturation');
    });
  });

  // ─── RSS freeze + liveness ───

  await asyncTest('GOVERNOR: RSS over the soft limit freezes medium/heavy; liveness admits 1 when nothing is in flight', async () => {
    await withGovernor({}, async () => {
      gov.updateGovernorRss(1000 * MB);            // baseline
      gov.updateGovernorRss(7600 * MB);            // > 75% of 10000 → frozen
      assert(gov.isFrozen() === true, 'governor must be frozen above the soft RSS limit');
      // Liveness: zero outstanding → one admission flows anyway.
      const t = await gov.acquireMemoryTicket('medium');
      assert(t, 'liveness must admit one scan when nothing is in flight');
      // Now something IS in flight: the next medium parks.
      let parked = null;
      const p = gov.acquireMemoryTicket('medium').then(x => { parked = x; });
      await new Promise(r => setTimeout(r, 50));
      assert(parked === null, 'frozen governor with in-flight work must park new admissions');
      // Unfreeze → drain.
      gov.updateGovernorRss(2000 * MB);
      await p;
      assert(parked && parked.cls === 'medium', 'unfreeze must drain parked waiters');
    });
  });

  // ─── Waiter contract (timeout, abort, trap #1) ───

  await asyncTest('GOVERNOR: TICKET_WAIT_TIMEOUT after maxWaitMs (the requeue contract)', async () => {
    await withGovernor({}, async () => {
      gov.updateGovernorRss(1000 * MB);
      gov.updateGovernorRss(7600 * MB);             // frozen
      await gov.acquireMemoryTicket('light');       // consume the liveness admission
      let code = null;
      try {
        await gov.acquireMemoryTicket('medium', { maxWaitMs: 100 });
      } catch (e) { code = e.code; }
      assert(code === 'TICKET_WAIT_TIMEOUT', `bounded wait must reject TICKET_WAIT_TIMEOUT (got ${code})`);
    });
  });

  await asyncTest('GOVERNOR: abort during the wait does not leak (trap #1) — a later release still drains cleanly', async () => {
    await withGovernor({}, async () => {
      gov.updateGovernorRss(1000 * MB);
      const h1 = await gov.acquireMemoryTicket('heavy');
      const h2 = await gov.acquireMemoryTicket('heavy');
      const ac = new AbortController();
      let code = null;
      const aborted = gov.acquireMemoryTicket('heavy', { signal: ac.signal }).catch(e => { code = e.code; });
      await new Promise(r => setTimeout(r, 20));
      ac.abort();
      await aborted;
      assert(code === 'ABORT_ERR', `abort must reject ABORT_ERR (got ${code})`);
      // The aborted waiter must have left the queue: the next release must NOT
      // wake a dead waiter and lose the grant.
      let next = null;
      const p = gov.acquireMemoryTicket('heavy').then(t => { next = t; });
      gov.releaseMemoryTicket(h1);
      await p;
      assert(next, 'release after an aborted waiter must reach the LIVE waiter (no leaked grant)');
      gov.releaseMemoryTicket(h2);
      const s = gov.getGovernorState();
      assert(s.waiting === 0, `no ghost waiters may remain (got ${s.waiting})`);
    });
  });

  await asyncTest('GOVERNOR: double release does not corrupt the ledger', async () => {
    await withGovernor({}, async () => {
      gov.updateGovernorRss(1000 * MB);
      const t = await gov.acquireMemoryTicket('medium');
      const before = gov.getGovernorState().outstandingMb;
      gov.releaseMemoryTicket(t);
      gov.releaseMemoryTicket(t); // double
      const after = gov.getGovernorState();
      assert(before === 256 && after.outstandingMb === 0 && after.outstandingCount === 0,
        `double release must subtract exactly once (before ${before}, after ${after.outstandingMb})`);
    });
  });

  await asyncTest('GOVERNOR: disabled (flag off) resolves false and freezes nothing', async () => {
    const saved = process.env.MUADDIB_MEMORY_GOVERNOR;
    delete process.env.MUADDIB_MEMORY_GOVERNOR;
    gov.resetGovernor();
    try {
      const t = await gov.acquireMemoryTicket('heavy');
      assert(t === false, 'disabled governor must resolve false (legacy heavy-lane path applies)');
      gov.updateGovernorRss(9999 * MB);
      assert(gov.isFrozen() === false, 'disabled governor never freezes the pump');
      gov.releaseMemoryTicket(t); // must be a no-op, not a crash
    } finally {
      if (saved !== undefined) process.env.MUADDIB_MEMORY_GOVERNOR = saved;
      gov.resetGovernor();
    }
  });

  // ─── Watermark combined metric (pure) ───

  test('WATERMARK: big external/arrayBuffers breach the combined threshold (the off-heap blind spot)', () => {
    const mem = { heapUsed: 300 * MB, external: 2200 * MB, arrayBuffers: 200 * MB }; // heap tiny, off-heap huge
    assert(watermarkBreached(mem, 2600) === true,
      'heap 300MB + external 2200MB + buffers 200MB = 2700MB must breach the 2600MB combined limit');
  });

  test('WATERMARK: a scan under the combined threshold does not bail (negative)', () => {
    const mem = { heapUsed: 1300 * MB, external: 800 * MB, arrayBuffers: 100 * MB }; // 2200MB combined
    assert(watermarkBreached(mem, 2600) === false, '2200MB combined must NOT breach 2600MB');
    assert(watermarkBreached({ heapUsed: 9999 * MB }, 0) === false, 'limit 0 disables the watchdog');
  });

  test('WATERMARK: legacy heap env value is honored but applied to the combined metric', () => {
    const env = { MUADDIB_WORKER_HEAP_WATERMARK_MB: '1000' };
    assert(watermarkLimitMb(env) === 1000, 'legacy env value reused');
    assert(watermarkLimitMb({ MUADDIB_WORKER_MEM_WATERMARK_MB: '3000', MUADDIB_WORKER_HEAP_WATERMARK_MB: '1000' }) === 3000,
      'new env wins over legacy');
    assert(watermarkLimitMb({}) === 2600, 'default 2600');
  });
}

module.exports = { runMemoryGovernorTests };
