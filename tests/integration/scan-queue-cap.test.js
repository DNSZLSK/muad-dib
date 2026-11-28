/**
 * P0c — Hard cap on the scan queue (bounded resource, CLAUDE.md §2).
 *
 * The scan queue was an unbounded array: a backpressure gap or the burst path could
 * grow it without limit. enqueueScan() caps it and drops the OLDEST item when full,
 * counting drops (stats.queueHardDrops) so the coverage loss is never silent.
 *
 * Behavioral: every test drives the real enqueueScan and asserts the array state /
 * counter. A small `max` is passed so the cap is exercised without 50k items.
 */

const { test, asyncTest, assert } = require('../test-utils');
const { enqueueScan, evictFromScanQueueBulk, dequeueScan, shouldPullNewest, MAX_SCAN_QUEUE } = require('../../src/monitor/scan-queue.js');

async function runScanQueueCapTests() {
  console.log('\n=== SCAN QUEUE HARD-CAP TESTS (P0c) ===\n');

  const origWarn = console.warn;
  console.warn = () => {}; // silence the rate-limited QUEUE_HARD_DROP line
  try {
    // NEGATIVE: below the cap, enqueue just pushes — no drop, no counter.
    test('P0c: enqueueScan pushes normally below the cap', () => {
      const q = []; const stats = {};
      let droppedAny = false;
      for (let i = 0; i < 5; i++) droppedAny = enqueueScan(q, { id: i }, stats, 10) || droppedAny;
      assert(q.length === 5, `length should be 5, got ${q.length}`);
      assert(droppedAny === false, 'no item dropped below cap');
      assert(!stats.queueHardDrops, 'queueHardDrops should not be set below cap');
    });

    // POSITIVE: at the cap, the oldest is dropped; length is bounded and the drop counted.
    test('P0c: enqueueScan drops oldest at the cap (bounded + counted)', () => {
      const q = []; const stats = {};
      for (let i = 0; i < 10; i++) enqueueScan(q, { id: i }, stats, 10);  // fill to cap
      const dropped = enqueueScan(q, { id: 10 }, stats, 10);              // 11th overflows
      assert(dropped === true, 'should report a drop at capacity');
      assert(q.length === 10, `length must stay capped at 10, got ${q.length}`);
      assert(q[0].id === 1, 'oldest (id 0) dropped → id 1 now at front');
      assert(q[q.length - 1].id === 10, 'newest (id 10) at back');
      assert(stats.queueHardDrops === 1, `queueHardDrops should be 1, got ${stats.queueHardDrops}`);
    });

    // Sustained overflow stays bounded and counts every drop.
    test('P0c: sustained overflow stays bounded and counts every drop', () => {
      const q = []; const stats = {};
      for (let i = 0; i < 25; i++) enqueueScan(q, { id: i }, stats, 10);  // 15 overflow the cap of 10
      assert(q.length === 10, `length must stay capped at 10, got ${q.length}`);
      assert(stats.queueHardDrops === 15, `should count 15 drops, got ${stats.queueHardDrops}`);
      assert(q[q.length - 1].id === 24, 'newest item retained');
    });

    // INVARIANT: the production default cap sits above the 30k soft-backpressure threshold,
    // so it only fires when backpressure is bypassed/broken (never in normal operation).
    test('P0c: default MAX_SCAN_QUEUE is above the 30k soft-backpressure threshold', () => {
      assert(MAX_SCAN_QUEUE >= 30_000, `hard cap (${MAX_SCAN_QUEUE}) must exceed the 30k soft threshold`);
    });

    // ── Phase 2b: protected eviction ──

    // POSITIVE: at the cap, the oldest UNPROTECTED item is dropped, not the protected head.
    test('P2b: eviction drops the oldest UNPROTECTED item, not the protected head', () => {
      const q = []; const stats = {};
      enqueueScan(q, { id: 'ioc', isIOCMatch: true }, stats, 5); // protected, at the head (oldest)
      for (let i = 0; i < 4; i++) enqueueScan(q, { id: i }, stats, 5);
      const dropped = enqueueScan(q, { id: 'new' }, stats, 5); // overflow
      assert(dropped === true, 'should report a drop');
      assert(q.length === 5, `bounded at 5, got ${q.length}`);
      assert(q.some(x => x.id === 'ioc'), 'protected IOC head must be retained');
      assert(!q.some(x => x.id === 0), 'oldest UNPROTECTED (id 0) is the victim');
      assert(q[q.length - 1].id === 'new', 'newest at back');
    });

    // Every protected class is honored.
    test('P2b: isIOCMatch / isBurst / firstPublish / atoSignal / isATOBurstExtra are protected', () => {
      for (const flag of ['isIOCMatch', 'isBurst', 'firstPublish', 'atoSignal', 'isATOBurstExtra']) {
        const q = []; const stats = {};
        enqueueScan(q, { id: 'prot', [flag]: true }, stats, 3); // oldest, protected
        enqueueScan(q, { id: 'a' }, stats, 3);
        enqueueScan(q, { id: 'b' }, stats, 3);
        enqueueScan(q, { id: 'c' }, stats, 3); // overflow → oldest unprotected (a) is dropped
        assert(q.some(x => x.id === 'prot'), `protected by ${flag} must survive`);
        assert(!q.some(x => x.id === 'a'), `oldest unprotected dropped (flag ${flag})`);
      }
    });

    // FALLBACK: if the head-window is entirely protected, drop the strict-oldest so the
    // queue never blocks. The drop is still counted (ledger uses queue_cap_protected).
    test('P2b: all-protected queue falls back to strict-oldest (never blocks)', () => {
      const q = []; const stats = {};
      for (let i = 0; i < 3; i++) enqueueScan(q, { id: i, isIOCMatch: true }, stats, 3);
      const dropped = enqueueScan(q, { id: 3, isIOCMatch: true }, stats, 3); // all protected
      assert(dropped === true, 'must still drop to stay bounded');
      assert(q.length === 3, `bounded at 3, got ${q.length}`);
      assert(!q.some(x => x.id === 0), 'strict-oldest (id 0) dropped in the all-protected fallback');
      assert(q[q.length - 1].id === 3, 'newest retained');
      assert(stats.queueHardDrops === 1, `drop still counted, got ${stats.queueHardDrops}`);
    });

    // REGRESSION: with no protected items, behavior is identical to plain FIFO drop-oldest.
    test('P2b: no protected items → identical to FIFO drop-oldest', () => {
      const q = []; const stats = {};
      for (let i = 0; i < 5; i++) enqueueScan(q, { id: i }, stats, 5);
      enqueueScan(q, { id: 5 }, stats, 5);
      assert(q[0].id === 1 && q[q.length - 1].id === 5,
        `FIFO preserved, got front=${q[0].id} back=${q[q.length - 1].id}`);
    });

    // ── Phase 2b retrofit: protected-aware BULK eviction (the daemon EMERGENCY path) ──
    // Behavioral: drive the real evictFromScanQueueBulk with an injected ledger sink (no file
    // I/O) and assert queue state + ledger rows. This is the single-source-of-truth the daemon
    // memory breaker now calls instead of the old raw splice(0,n).

    test('bulk-evict: drops oldest UNPROTECTED first, keeps protected + newest, ledgers each drop', () => {
      const led = [];
      const q = [{ name: 'ioc', isIOCMatch: true }, { name: 'ato', atoSignal: true }];
      for (let i = 0; i < 6; i++) q.push({ name: `p${i}` });   // total 8 → keep 4 → drop 4
      const r = evictFromScanQueueBulk(q, 4, 'mem_emergency', (e) => led.push(e));
      assert(q.length === 4, `kept 4, got ${q.length}`);
      assert(r.dropped === 4 && r.droppedProtected === 0, `dropped 4/0, got ${r.dropped}/${r.droppedProtected}`);
      assert(q.map(x => x.name).join(',') === 'ioc,ato,p4,p5',
        `protected head + newest unprotected survive in order, got ${q.map(x => x.name).join(',')}`);
      assert(led.length === 4 && led.every(e => e.outcome === 'dropped' && e.source === 'mem_emergency'),
        'every drop ledgered dropped/mem_emergency');
      assert(led.map(e => e.name).sort().join(',') === 'p0,p1,p2,p3', `ledgered the 4 oldest unprotected, got ${led.map(e => e.name)}`);
    });

    test('bulk-evict: FALLBACK drops oldest PROTECTED (distinct source) only when keep < protected count', () => {
      const led = [];
      const q = [];
      for (let i = 0; i < 5; i++) q.push({ name: `ioc${i}`, isIOCMatch: true });  // all 5 protected
      const r = evictFromScanQueueBulk(q, 2, 'mem_emergency', (e) => led.push(e));
      assert(q.length === 2 && q.map(x => x.name).join(',') === 'ioc3,ioc4', `newest 2 protected kept, got ${q.map(x => x.name)}`);
      assert(r.dropped === 3 && r.droppedProtected === 3, `dropped 3/3, got ${r.dropped}/${r.droppedProtected}`);
      assert(led.length === 3 && led.every(e => e.source === 'mem_emergency_protected'),
        'protected drops carry the _protected source so the rare case stays visible in the rollup');
    });

    test('bulk-evict: no protected items → plain FIFO drop-oldest (parity with the old splice)', () => {
      const led = [];
      const q = [];
      for (let i = 0; i < 10; i++) q.push({ name: `p${i}` });
      const r = evictFromScanQueueBulk(q, 4, 'mem_emergency', (e) => led.push(e));
      assert(q.map(x => x.name).join(',') === 'p6,p7,p8,p9', `newest 4 kept in order, got ${q.map(x => x.name)}`);
      assert(r.dropped === 6 && r.droppedProtected === 0 && led.length === 6, 'dropped 6 oldest, none protected, all ledgered');
    });

    test('bulk-evict: no-op when the queue is already at/below target', () => {
      const led = [];
      const q = [{ name: 'a' }, { name: 'b' }];
      const r = evictFromScanQueueBulk(q, 5, 'mem_emergency', (e) => led.push(e));
      assert(q.length === 2 && r.dropped === 0 && led.length === 0, 'no eviction at/below target');
    });

    test('bulk-evict: nameless items are dropped but skip the ledger (no crash, no phantom rows)', () => {
      const led = [];
      const q = [{ id: 0 }, { id: 1 }, { name: 'n' }, { id: 2 }];   // keep 1 → drop the 3 oldest
      const r = evictFromScanQueueBulk(q, 1, 'mem_emergency', (e) => led.push(e));
      assert(q.length === 1 && r.dropped === 3, `truncated to 1, got ${q.length}`);
      assert(led.length === 1 && led[0].name === 'n', `only the named drop is ledgered, got ${led.length}`);
    });
  } finally {
    console.warn = origWarn;
  }

  // --- AUDIT A2: priority dequeue (gated; tested via opts override) ---
  test('dequeueScan: default is strict FIFO (oldest first)', () => {
    const q = [{ name: 'a' }, { name: 'b', firstPublish: true }, { name: 'c' }];
    assert(dequeueScan(q).name === 'a', 'FIFO returns oldest regardless of firstPublish');
    assert(q.length === 2 && q[0].name === 'b', 'queue shifted from head');
  });

  test('dequeueScan: priority mode pulls oldest first-publish before older FIFO items', () => {
    const q = [{ name: 'old1' }, { name: 'old2' }, { name: 'fp', firstPublish: true }, { name: 'old3' }];
    const got = dequeueScan(q, { priority: true });
    assert(got.name === 'fp', `should pull the first-publish, got ${got.name}`);
    assert(q.length === 3 && !q.find(x => x.name === 'fp'), 'fp spliced out, others intact');
  });

  test('dequeueScan: priority covers IOC + burst-MAIN but NOT burst-extras', () => {
    const ioc = dequeueScan([{ name: 'x' }, { name: 'i', isIOCMatch: true }], { priority: true });
    assert(ioc.name === 'i', 'IOC match prioritized');
    const main = dequeueScan([{ name: 'x' }, { name: 'm', isBurst: true }], { priority: true });
    assert(main.name === 'm', 'burst-MAIN prioritized');
    // a burst EXTRA is NOT priority → FIFO returns the oldest regular item
    const extra = dequeueScan([{ name: 'x' }, { name: 'e', isBurst: true, isATOBurstExtra: true }], { priority: true });
    assert(extra.name === 'x', 'burst-extra is not prioritized (stays FIFO)');
  });

  test('dequeueScan: priority falls back to FIFO when no priority item in window', () => {
    const q = [{ name: 'a' }, { name: 'b' }, { name: 'fp', firstPublish: true }];
    const got = dequeueScan(q, { priority: true, window: 2 }); // fp is beyond the window
    assert(got.name === 'a', `window-bounded scan must fall back to FIFO, got ${got.name}`);
  });

  // --- Phase 2: fresh-first scheduling (gated; tested via opts override) ---
  test('dequeueScan: newest mode pulls the TAIL (most recent)', () => {
    const q = [{ name: 'a' }, { name: 'b' }, { name: 'c' }];
    assert(dequeueScan(q, { newest: true }).name === 'c', 'newest returns the tail');
    assert(q.length === 2 && q[q.length - 1].name === 'b', 'popped from the tail');
  });

  test('shouldPullNewest: disabled or no backlog → FIFO (oldest)', () => {
    assert(shouldPullNewest(0, 50000, 12, { enabled: false }) === false, 'disabled → false');
    assert(shouldPullNewest(0, 100, 12, { enabled: true, threshold: 5000 }) === false, 'below threshold → false');
  });

  test('shouldPullNewest: backlog → drainLanes pull oldest, the rest go fresh', () => {
    const opts = { enabled: true, threshold: 5000, drainLanes: 2 };
    const target = 12, q = 30000;
    let oldest = 0, newest = 0;
    for (let seq = 0; seq < target; seq++) (shouldPullNewest(seq, q, target, opts) ? newest++ : oldest++);
    assert(oldest === 2, `exactly drainLanes(2) pull oldest, got ${oldest}`);
    assert(newest === 10, `the rest (10) go fresh, got ${newest}`);
    assert(shouldPullNewest(0, q, target, opts) === false, 'seq 0 → oldest (drain lane)');
    assert(shouldPullNewest(2, q, target, opts) === true, 'seq 2 → newest (fresh lane)');
  });

  test('shouldPullNewest: clamps drainLanes to always leave ≥1 fresh lane', () => {
    const opts = { enabled: true, threshold: 0, drainLanes: 99 };
    assert(shouldPullNewest(0, 100, 2, opts) === false, 'lane 0 drains (oldest)');
    assert(shouldPullNewest(1, 100, 2, opts) === true, 'lane 1 stays fresh (clamp leaves ≥1)');
  });

  // ── Characterization of the current queue (lot 8 step 4) ─────────────────
  // Freezes today's behavior, quirks included, before the risk-ordered queue changes it.

  test('CHAR: an interrupted item is protected from cap and bulk eviction', () => {
    const q = [{ name: 'interrupted-old', interrupted: true }, { name: 'plain' }];
    enqueueScan(q, { name: 'new' }, {}, 2);
    assert(q.map(i => i.name).join(',') === 'interrupted-old,new', `cap eviction keeps the interrupted item, got ${q.map(i => i.name)}`);
    const b = [{ name: 'interrupted-old', interrupted: true }, { name: 'p1' }, { name: 'p2' }];
    evictFromScanQueueBulk(b, 1, 'test', () => {});
    assert(b.length === 1 && b[0].name === 'interrupted-old', `bulk eviction keeps the interrupted item, got ${b.map(i => i.name)}`);
  });

  test('CHAR: dequeue priority ignores atoSignal, interrupted and burst extras, which eviction protects', () => {
    for (const flag of ['atoSignal', 'interrupted', 'isATOBurstExtra']) {
      const q = [{ name: 'plain' }, { name: 'flagged', [flag]: true }];
      const first = dequeueScan(q, { priority: true });
      assert(first.name === 'plain', `${flag} is not a dequeue priority today, got ${first.name}`);
    }
  });

  test('CHAR: cap eviction looks for an unprotected victim in the first 1024 slots only', () => {
    const q = [];
    for (let i = 0; i < 1024; i++) q.push({ name: `prot-${i}`, firstPublish: true });
    q.push({ name: 'plain-beyond-window' });
    enqueueScan(q, { name: 'new' }, {}, q.length);
    assert(q[0].name === 'prot-1', `the oldest protected item is evicted, got head ${q[0].name}`);
    assert(q.some(i => i.name === 'plain-beyond-window'), 'the unprotected item past the window survives');
  });

  test('CHAR: pre-resolve sheds strictly above 2000 queued items', () => {
    const ingestion = require('../../src/monitor/ingestion.js');
    const limiter = require('../../src/shared/http-limiter.js');
    const origBrain = limiter.getBrainState;
    try {
      limiter.getBrainState = () => ({ level: 0 });
      assert(ingestion.preResolveShouldShed({ length: 2000 }) === false, '2000 queued: no shed');
      assert(ingestion.preResolveShouldShed({ length: 2001 }) === true, '2001 queued: shed');
    } finally {
      limiter.getBrainState = origBrain;
    }
  });

  // resolveTarballAndScan checks `signal.aborted` before and right after the temporal
  // load-shed decision: a signal that turns aborted on its third read stops the scan just
  // after the decision, before any download.
  const abortAfterShedDecision = () => { const s = { reads: 0 }; Object.defineProperty(s, 'aborted', { get() { return ++s.reads >= 3; } }); return s; };
  async function runShedDecision(item, queueLen) {
    const queue = require('../../src/monitor/queue.js');
    const stats = {};
    const logs = [];
    const origLog = console.log;
    const signal = abortAfterShedDecision();
    console.log = (...a) => logs.push(a.join(' '));
    try {
      await queue.resolveTarballAndScan(item, stats, [], new Set(), new Map(), new Array(queueLen), false, signal);
    } finally {
      console.log = origLog;
    }
    assert(signal.reads === 3, `the scan must stop right after the shed decision (signal read ${signal.reads} times)`);
    return { shed: stats.temporalLoadShed || 0, logged: logs.some(l => l.includes('TEMPORAL LOAD-SHED')) };
  }
  const npmItem = (extra) => ({ name: 'char-pkg', version: '1.0.0', ecosystem: 'npm', tarballUrl: 'https://registry.npmjs.org/char-pkg/-/char-pkg-1.0.0.tgz', ...extra });

  await asyncTest('CHAR: above 2000 queued items the temporal checks are shed for every class', async () => {
    for (const extra of [{}, { isIOCMatch: true }, { firstPublish: true }, { isBurst: true }, { atoSignal: true }]) {
      const r = await runShedDecision(npmItem(extra), 2001);
      assert(r.shed === 1 && r.logged, `shed for ${JSON.stringify(extra)}, got ${JSON.stringify(r)}`);
    }
  });

  await asyncTest('CHAR: a fast-tracked item skips the temporal checks without being counted as shed', async () => {
    const r = await runShedDecision(npmItem({ fastTrack: true }), 2001);
    assert(r.shed === 0 && !r.logged, `fast-track is not counted, got ${JSON.stringify(r)}`);
  });

  await asyncTest('CHAR: a PyPI item is never counted as temporal load-shed', async () => {
    const r = await runShedDecision({ name: 'char-py', version: '1.0.0', ecosystem: 'pypi', tarballUrl: 'https://files.example/char-py-1.0.0.tar.gz' }, 2001);
    assert(r.shed === 0 && !r.logged, `PyPI is not counted, got ${JSON.stringify(r)}`);
  });

  // Same-name items, before coalescing by name.
  const fillers = (n) => Array.from({ length: n }, (_, i) => ({ name: `filler-${i}`, version: '1.0.0', ecosystem: 'npm' }));
  const resolvedItem = (version) => ({
    name: 'char-coal', version, ecosystem: 'npm', tarballUrl: `https://registry.example/char-coal-${version}.tgz`,
    registryScripts: {}, _npmInfo: { age_days: 3000, version_count: 500, latestTagVersion: version },
  });

  test('CHAR: two unresolved items of the same npm name are both queued', () => {
    const q = [];
    enqueueScan(q, { name: 'char-coal', version: '', ecosystem: 'npm', tarballUrl: null }, {});
    enqueueScan(q, { name: 'char-coal', version: '', ecosystem: 'npm', tarballUrl: null }, {});
    assert(q.filter(i => i.name === 'char-coal').length === 2, `both unresolved items queued, got ${q.length}`);
  });

  test('CHAR: above 20000 queued items, two versions of an established npm package are both queued', () => {
    const q = fillers(20_000);
    enqueueScan(q, resolvedItem('1.0.1'), {});
    enqueueScan(q, resolvedItem('1.0.2'), {});
    const v = q.filter(i => i.name === 'char-coal').map(i => i.version).join(',');
    assert(v === '1.0.1,1.0.2', `both versions queued in order, got ${v}`);
  });

  console.log('  ✓ scan queue hard-cap (P0c) + priority-dequeue (A2) + fresh-first (Phase 2) tests passed');
}

module.exports = { runScanQueueCapTests };
