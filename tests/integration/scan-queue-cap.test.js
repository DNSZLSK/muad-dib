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

const { test, assert } = require('../test-utils');
const { enqueueScan, evictFromScanQueueBulk, dequeueScan, MAX_SCAN_QUEUE } = require('../../src/monitor/scan-queue.js');

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

  console.log('  ✓ scan queue hard-cap (P0c) + priority-dequeue (A2) tests passed');
}

module.exports = { runScanQueueCapTests };
