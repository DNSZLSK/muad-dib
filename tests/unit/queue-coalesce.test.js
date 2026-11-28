'use strict';

const { test, assert } = require('../test-utils');
const { enqueueScan, evictFromScanQueueBulk, dequeueScan, registerRestoredQueue } = require('../../src/monitor/scan-queue.js');
const coalesce = require('../../src/monitor/queue-coalesce.js');

const unresolved = (name, over = {}) => ({ name, version: '', ecosystem: 'npm', tarballUrl: null, ...over });

async function runQueueCoalesceTests() {
  console.log('\n=== SCAN QUEUE COALESCING BY NAME TESTS ===\n');
  const origWarn = console.warn;
  console.warn = () => {};
  try {
    // Unresolved items resolve the latest version when dequeued, so two of the same
    // name scan the same version: the second is redundant.
    test('COALESCE: a second unresolved item of the same npm name is merged into the first', () => {
      const q = []; const stats = {};
      enqueueScan(q, unresolved('co-a'), stats);
      enqueueScan(q, unresolved('co-a', { isIOCMatch: true, firstPublish: true, _cacheTrigger: { shouldCache: true, reason: 'first_publish' } }), stats);
      assert(q.length === 1, `one item queued, got ${q.length}`);
      assert(q[0].isIOCMatch === true && q[0].firstPublish === true, `flags of the merged item kept, got ${JSON.stringify(q[0])}`);
      assert(q[0]._cacheTrigger && q[0]._cacheTrigger.reason === 'first_publish', 'cache trigger of the merged item kept');
      assert(stats.queueCoalescedUnresolved === 1, `counted, got ${stats.queueCoalescedUnresolved}`);
    });

    test('COALESCE: an unresolved and a resolved item of the same name are both queued', () => {
      const q = [];
      enqueueScan(q, unresolved('co-b'), {});
      enqueueScan(q, { name: 'co-b', version: '1.0.0', ecosystem: 'npm', tarballUrl: 'https://registry.example/co-b-1.0.0.tgz' }, {});
      enqueueScan(q, unresolved('co-b2', { version: '1.0.0', tarballUrl: 'https://registry.example/co-b2-1.0.0.tgz' }), {});
      enqueueScan(q, unresolved('co-b2'), {});
      assert(q.length === 4, `no merge across resolved and unresolved, got ${q.length}`);
    });

    test('COALESCE: unresolved PyPI items of the same name are both queued', () => {
      const q = [];
      enqueueScan(q, { name: 'co-py', version: '', ecosystem: 'pypi', tarballUrl: null }, {});
      enqueueScan(q, { name: 'co-py', version: '', ecosystem: 'pypi', tarballUrl: null }, {});
      assert(q.length === 2, `PyPI is not coalesced, got ${q.length}`);
    });

    test('COALESCE: a dequeued item is not a merge target', () => {
      const q = [];
      enqueueScan(q, unresolved('co-d'), {});
      const taken = dequeueScan(q);
      enqueueScan(q, unresolved('co-d', { isIOCMatch: true }), {});
      assert(q.length === 1 && q[0] !== taken, 'the new item is queued on its own');
      assert(!taken.isIOCMatch, 'the dequeued item is not modified');
    });

    test('COALESCE: an item evicted at the cap is not a merge target', () => {
      const q = [];
      enqueueScan(q, unresolved('co-e'), {}, 1);
      enqueueScan(q, { name: 'other', version: '1.0.0', ecosystem: 'npm', tarballUrl: 'x' }, {}, 1);
      enqueueScan(q, unresolved('co-e'), {}, 2);
      assert(q.filter(i => i.name === 'co-e').length === 1, `the new item is queued, got ${JSON.stringify(q.map(i => i.name))}`);
    });

    test('COALESCE: an item removed by bulk eviction is not a merge target', () => {
      const q = [];
      enqueueScan(q, unresolved('co-f'), {});
      enqueueScan(q, { name: 'keep', version: '1.0.0', ecosystem: 'npm', tarballUrl: 'x' }, {});
      evictFromScanQueueBulk(q, 1, 'test', () => {});
      enqueueScan(q, unresolved('co-f'), {});
      assert(q.filter(i => i.name === 'co-f').length === 1, `the new item is queued, got ${JSON.stringify(q.map(i => i.name))}`);
    });

    test('COALESCE: items restored at startup are merge targets', () => {
      const q = [unresolved('co-r')];
      registerRestoredQueue(q);
      enqueueScan(q, unresolved('co-r', { firstPublish: true }), {});
      assert(q.length === 1 && q[0].firstPublish === true, `merged into the restored item, got ${JSON.stringify(q)}`);
    });

    test('COALESCE: an item of another queue is not a merge target', () => {
      const a = []; const b = [];
      enqueueScan(a, unresolved('co-x'), {});
      enqueueScan(b, unresolved('co-x', { isIOCMatch: true }), {});
      assert(a.length === 1 && b.length === 1 && !a[0].isIOCMatch, 'each queue keeps its own item');
    });

    test('COALESCE: the daemon restore indexes the restored queue', () => {
      const fs = require('fs');
      const { persistQueue, restoreQueue, QUEUE_STATE_FILE } = require('../../src/monitor.js');
      const saved = [unresolved('co-boot')];
      try {
        persistQueue(saved, { npmLastSeq: 1 });
        const q = [];
        restoreQueue(q);
        enqueueScan(q, unresolved('co-boot', { firstPublish: true }), {});
        assert(q.length === 1 && q[0].firstPublish === true, `merged into the restored item, got ${JSON.stringify(q)}`);
      } finally {
        try { fs.unlinkSync(QUEUE_STATE_FILE); } catch { /* absent */ }
      }
    });

    test('COALESCE: the queue marker is not written to the persisted queue', () => {
      const q = [];
      enqueueScan(q, unresolved('co-j'), {});
      assert(JSON.stringify(q) === JSON.stringify([unresolved('co-j')]), `persisted form unchanged, got ${JSON.stringify(q)}`);
    });

    test('COALESCE: counters are logged every 60 s, then reset', () => {
      const T0 = 2_000_000_000_000;
      const lines = [];
      coalesce._resetCoalesceCounters(T0);
      coalesce._recordCoalesce('unresolved', T0 + 1000, l => lines.push(l));
      assert(lines.length === 0, 'no log before 60 s');
      coalesce._recordCoalesce('unresolved', T0 + 60_000, l => lines.push(l));
      assert(lines.length === 1 && lines[0].includes('QUEUE COALESCE') && lines[0].includes('unresolved 2'),
        `log line mismatch: ${JSON.stringify(lines)}`);
      const c = coalesce.getCoalesceCounters();
      assert(c.unresolved === 0, `reset after the log, got ${JSON.stringify(c)}`);
    });
  } finally {
    console.warn = origWarn;
  }
}

module.exports = { runQueueCoalesceTests };
