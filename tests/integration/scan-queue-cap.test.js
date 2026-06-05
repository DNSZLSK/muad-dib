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
const { enqueueScan, MAX_SCAN_QUEUE } = require('../../src/monitor/scan-queue.js');

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
  } finally {
    console.warn = origWarn;
  }

  console.log('  ✓ scan queue hard-cap (P0c) tests passed');
}

module.exports = { runScanQueueCapTests };
