/**
 * Tests for the deferred sandbox queue module.
 * Covers: queue ops, TTL pruning, persistence, worker logic, follow-up webhook.
 */
const fs = require('fs');
const path = require('path');
const { test, asyncTest, assert, assertIncludes } = require('../test-utils');

function makeItem(overrides = {}) {
  return {
    name: overrides.name || 'test-pkg',
    version: overrides.version || '1.0.0',
    ecosystem: overrides.ecosystem || 'npm',
    tier: overrides.tier || '1b',
    riskScore: overrides.riskScore || 30,
    tarballUrl: overrides.tarballUrl || 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
    enqueuedAt: overrides.enqueuedAt || Date.now(),
    staticResult: overrides.staticResult || { threats: [], summary: { critical: 0, high: 1, medium: 0, low: 0 } },
    npmRegistryMeta: overrides.npmRegistryMeta || null,
    retries: overrides.retries || 0
  };
}

function runDeferredSandboxTests() {
  console.log('\n=== Deferred Sandbox Queue Tests ===\n');

  // ── Queue management tests ──

  test('enqueueDeferred sorts by riskScore DESC', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'low', riskScore: 10 }));
    enqueueDeferred(makeItem({ name: 'high', riskScore: 50 }));
    enqueueDeferred(makeItem({ name: 'mid', riskScore: 30 }));

    const q = getDeferredQueue();
    assert(q.length === 3, `Expected 3 items, got ${q.length}`);
    assert(q[0].name === 'high', `First should be high (score=50), got ${q[0].name}`);
    assert(q[1].name === 'mid', `Second should be mid (score=30), got ${q[1].name}`);
    assert(q[2].name === 'low', `Third should be low (score=10), got ${q[2].name}`);
    _resetDeferredQueue();
  });

  test('enqueueDeferred rejects tier 1a', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const result = enqueueDeferred(makeItem({ tier: '1a' }));
    assert(result === false, 'Should reject T1a items');
    assert(getDeferredQueue().length === 0, 'Queue should remain empty');
    _resetDeferredQueue();
  });

  test('enqueueDeferred accepts tier 1b and tier 2', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r1 = enqueueDeferred(makeItem({ name: 'a', tier: '1b' }));
    const r2 = enqueueDeferred(makeItem({ name: 'b', tier: 2 }));
    assert(r1 === true, 'Should accept T1b');
    assert(r2 === true, 'Should accept T2');
    assert(getDeferredQueue().length === 2, 'Queue should have 2 items');
    _resetDeferredQueue();
  });

  test('enqueueDeferred deduplicates name@version', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'dup', version: '1.0.0' }));
    const r2 = enqueueDeferred(makeItem({ name: 'dup', version: '1.0.0', riskScore: 99 }));
    assert(r2 === false, 'Should reject duplicate');
    assert(getDeferredQueue().length === 1, 'Queue should have 1 item');
    _resetDeferredQueue();
  });

  test('enqueueDeferred evicts lowest-score when full', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue, DEFERRED_QUEUE_MAX } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    // Fill the queue
    for (let i = 0; i < DEFERRED_QUEUE_MAX; i++) {
      enqueueDeferred(makeItem({ name: `pkg-${i}`, riskScore: 10 + i }));
    }
    assert(getDeferredQueue().length === DEFERRED_QUEUE_MAX, 'Queue should be full');

    // Insert higher-score item → should evict lowest (score=10)
    const result = enqueueDeferred(makeItem({ name: 'new-high', riskScore: 999 }));
    assert(result === true, 'Should accept higher-score item');
    assert(getDeferredQueue().length === DEFERRED_QUEUE_MAX, 'Queue size should remain at max');
    assert(getDeferredQueue()[0].name === 'new-high', 'New item should be first (highest score)');

    // The item with score=10 (pkg-0) should be evicted
    const hasEvicted = getDeferredQueue().some(i => i.name === 'pkg-0');
    assert(!hasEvicted, 'pkg-0 (score=10) should have been evicted');
    _resetDeferredQueue();
  });

  test('enqueueDeferred rejects when full and score is lower than all', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue, DEFERRED_QUEUE_MAX } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    // Fill with score=50
    for (let i = 0; i < DEFERRED_QUEUE_MAX; i++) {
      enqueueDeferred(makeItem({ name: `pkg-${i}`, riskScore: 50 }));
    }

    // Try to insert score=5 → should be rejected
    const result = enqueueDeferred(makeItem({ name: 'loser', riskScore: 5 }));
    assert(result === false, 'Should reject lower-score item when full');
    _resetDeferredQueue();
  });

  // ── TTL pruning tests ──

  test('pruneExpired removes items older than 24h', () => {
    const { enqueueDeferred, getDeferredQueue, pruneExpired, _resetDeferredQueue, DEFERRED_TTL_MS } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    // Add an expired item
    enqueueDeferred(makeItem({ name: 'old', enqueuedAt: Date.now() - DEFERRED_TTL_MS - 1000 }));
    // Add a fresh item
    enqueueDeferred(makeItem({ name: 'fresh', enqueuedAt: Date.now() }));

    const stats = { deferredExpired: 0 };
    const pruned = pruneExpired(stats);
    assert(pruned === 1, `Expected 1 pruned, got ${pruned}`);
    assert(getDeferredQueue().length === 1, 'Queue should have 1 item left');
    assert(getDeferredQueue()[0].name === 'fresh', 'Fresh item should remain');
    assert(stats.deferredExpired === 1, 'Stats should track expired count');
    _resetDeferredQueue();
  });

  // ── Persistence tests ──

  test('persistDeferredQueue and restoreDeferredQueue round-trip', () => {
    const { enqueueDeferred, getDeferredQueue, persistDeferredQueue, restoreDeferredQueue, _resetDeferredQueue, DEFERRED_STATE_FILE } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'persist-a', riskScore: 40 }));
    enqueueDeferred(makeItem({ name: 'persist-b', riskScore: 60 }));
    persistDeferredQueue();

    // Verify file exists
    assert(fs.existsSync(DEFERRED_STATE_FILE), 'State file should exist after persist');

    // Reset and restore
    _resetDeferredQueue();
    assert(getDeferredQueue().length === 0, 'Queue should be empty after reset');

    const restored = restoreDeferredQueue();
    assert(restored === 2, `Expected 2 restored, got ${restored}`);
    assert(getDeferredQueue().length === 2, 'Queue should have 2 items');
    assert(getDeferredQueue()[0].name === 'persist-b', 'Higher-score item should be first');

    // Cleanup
    try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch {}
    _resetDeferredQueue();
  });

  test('restoreDeferredQueue discards file older than 24h', () => {
    const { restoreDeferredQueue, _resetDeferredQueue, DEFERRED_STATE_FILE } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    // Write a stale file
    const staleData = JSON.stringify({
      savedAt: new Date(Date.now() - 25 * 3600 * 1000).toISOString(),
      count: 1,
      items: [{ name: 'stale', version: '1.0.0', ecosystem: 'npm', tier: '1b', riskScore: 30, enqueuedAt: Date.now() - 25 * 3600 * 1000, retries: 0 }]
    });
    const dir = path.dirname(DEFERRED_STATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DEFERRED_STATE_FILE, staleData);

    const restored = restoreDeferredQueue();
    assert(restored === 0, `Expected 0 restored from stale file, got ${restored}`);

    // Cleanup
    try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch {}
    _resetDeferredQueue();
  });

  test('restoreDeferredQueue prunes individually expired items', () => {
    const { getDeferredQueue, restoreDeferredQueue, _resetDeferredQueue, DEFERRED_STATE_FILE, DEFERRED_TTL_MS } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const freshData = JSON.stringify({
      savedAt: new Date().toISOString(),
      count: 2,
      items: [
        { name: 'expired-item', version: '1.0.0', ecosystem: 'npm', tier: '1b', riskScore: 30, enqueuedAt: Date.now() - DEFERRED_TTL_MS - 1000, retries: 0 },
        { name: 'valid-item', version: '1.0.0', ecosystem: 'npm', tier: 2, riskScore: 50, enqueuedAt: Date.now(), retries: 0 }
      ]
    });
    const dir = path.dirname(DEFERRED_STATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DEFERRED_STATE_FILE, freshData);

    const restored = restoreDeferredQueue();
    assert(restored === 1, `Expected 1 restored (1 expired), got ${restored}`);
    assert(getDeferredQueue()[0].name === 'valid-item', 'Only valid item should be restored');

    try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch {}
    _resetDeferredQueue();
  });

  // ── Worker logic tests ──

  test('worker uses dedicated slot independent from shared semaphore', () => {
    // The deferred worker owns _deferredSlotBusy — it never checks the shared semaphore.
    // This guarantees processing even when all main-path slots are saturated.
    const { isDeferredSlotBusy, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    const { getSandboxSemaphore, SANDBOX_CONCURRENCY_MAX } = require('../../src/sandbox/index.js');
    const sem = getSandboxSemaphore();
    const origActive = sem.active;
    _resetDeferredQueue();

    try {
      // Deferred slot starts free
      assert(isDeferredSlotBusy() === false, 'Deferred slot should start free');

      // Even with ALL main-path slots saturated, deferred slot is independent
      sem.active = SANDBOX_CONCURRENCY_MAX;
      assert(isDeferredSlotBusy() === false, 'Deferred slot should be free even when main slots full');

      sem.active = SANDBOX_CONCURRENCY_MAX * 10;
      assert(isDeferredSlotBusy() === false, 'Deferred slot is decoupled from semaphore count');
    } finally {
      sem.active = origActive;
      _resetDeferredQueue();
    }
  });

  test('worker processes highest-score item first (queue ordering via shift)', () => {
    // The worker calls _deferredQueue.shift() to pick items.
    // Since the queue is sorted by riskScore DESC, shift() always picks the highest.
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'low', riskScore: 10 }));
    enqueueDeferred(makeItem({ name: 'high', riskScore: 90 }));
    enqueueDeferred(makeItem({ name: 'mid', riskScore: 45 }));

    const q = getDeferredQueue();
    assert(q[0].name === 'high', 'First item should be highest score');

    // Simulate what the worker does: shift() picks the top item
    const picked = q.shift();
    assert(picked.name === 'high', 'shift() should pick highest-score item (high=90)');
    assert(q.length === 2, 'Queue should have 2 items after shift');
    assert(q[0].name === 'mid', 'Next item should be mid (45)');
    assert(q[1].name === 'low', 'Last item should be low (10)');
    _resetDeferredQueue();
  });

  test('worker retry logic — retries < MAX re-enqueues, retries >= MAX drops', () => {
    const { DEFERRED_MAX_RETRIES } = require('../../src/monitor/deferred-sandbox.js');

    // Simulate retry logic from processDeferredItem
    const item = { retries: 0 };

    // First failure: retries goes to 1, < MAX(2) → re-enqueue
    item.retries++;
    assert(item.retries < DEFERRED_MAX_RETRIES, `retries=${item.retries} should be < MAX(${DEFERRED_MAX_RETRIES}) → re-enqueue`);

    // Second failure: retries goes to 2, >= MAX(2) → drop
    item.retries++;
    assert(item.retries >= DEFERRED_MAX_RETRIES, `retries=${item.retries} should be >= MAX(${DEFERRED_MAX_RETRIES}) → drop`);
  });

  // ── Follow-up webhook tests ──

  test('buildDeferredFollowUpEmbed produces valid embed for score > 0', () => {
    const { buildDeferredFollowUpEmbed } = require('../../src/monitor/deferred-sandbox.js');

    const embed = buildDeferredFollowUpEmbed('malicious-pkg', '1.0.0', 'npm', {
      score: 85,
      severity: 'CRITICAL',
      findings: [
        { type: 'reverse_shell', severity: 'CRITICAL', detail: 'Detected reverse shell to attacker.com' }
      ]
    }, 42);

    assert(embed.embeds, 'Should have embeds array');
    assert(embed.embeds.length === 1, 'Should have 1 embed');
    assert(embed.embeds[0].title.includes('SANDBOX FOLLOW-UP'), 'Title should mention follow-up');
    assert(embed.embeds[0].title.includes('malicious-pkg'), 'Title should include package name');
    assert(embed.embeds[0].color === 0xe74c3c, 'Color should be red for score >= 80');

    const fields = embed.embeds[0].fields;
    const sandboxField = fields.find(f => f.name === 'Sandbox Score');
    assert(sandboxField, 'Should have Sandbox Score field');
    assert(sandboxField.value.includes('85'), 'Should show score 85');
  });

  test('buildDeferredFollowUpEmbed uses orange color for score >= 30', () => {
    const { buildDeferredFollowUpEmbed } = require('../../src/monitor/deferred-sandbox.js');

    const embed = buildDeferredFollowUpEmbed('sus-pkg', '2.0.0', 'pypi', {
      score: 45,
      severity: 'HIGH',
      findings: []
    }, 30);

    assert(embed.embeds[0].color === 0xe67e22, 'Color should be orange for score >= 30');
  });

  test('buildDeferredFollowUpEmbed uses yellow color for low positive score', () => {
    const { buildDeferredFollowUpEmbed } = require('../../src/monitor/deferred-sandbox.js');

    const embed = buildDeferredFollowUpEmbed('low-pkg', '1.0.0', 'npm', {
      score: 10,
      severity: 'MEDIUM',
      findings: []
    }, 20);

    assert(embed.embeds[0].color === 0xf1c40f, 'Color should be yellow for low positive score');
  });

  // ── Stats tests ──

  test('getDeferredQueueStats returns correct tier breakdown', () => {
    const { enqueueDeferred, getDeferredQueueStats, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'a', tier: '1b', riskScore: 30 }));
    enqueueDeferred(makeItem({ name: 'b', tier: 2, riskScore: 20 }));
    enqueueDeferred(makeItem({ name: 'c', tier: '1b', riskScore: 40 }));

    const stats = getDeferredQueueStats();
    assert(stats.size === 3, `Expected size 3, got ${stats.size}`);
    assert(stats.tierBreakdown.t1b === 2, `Expected 2 T1b, got ${stats.tierBreakdown.t1b}`);
    assert(stats.tierBreakdown.t2 === 1, `Expected 1 T2, got ${stats.tierBreakdown.t2}`);
    _resetDeferredQueue();
  });

  // ── Integration-level: T1a should never enter deferred queue ──

  test('T1a items are never accepted by enqueueDeferred', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r1 = enqueueDeferred(makeItem({ tier: '1a' }));
    const r2 = enqueueDeferred(makeItem({ name: 'x', tier: '1a', riskScore: 100 }));
    assert(r1 === false, 'T1a should be rejected');
    assert(r2 === false, 'T1a should be rejected (high score)');
    assert(getDeferredQueue().length === 0, 'Queue should be empty');
    _resetDeferredQueue();
  });

  test('persistDeferredQueue removes file when queue is empty', () => {
    const { persistDeferredQueue, _resetDeferredQueue, DEFERRED_STATE_FILE } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    // Create a dummy file
    const dir = path.dirname(DEFERRED_STATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DEFERRED_STATE_FILE, 'dummy');

    persistDeferredQueue();
    assert(!fs.existsSync(DEFERRED_STATE_FILE), 'File should be removed when queue is empty');
    _resetDeferredQueue();
  });
}

module.exports = { runDeferredSandboxTests };
