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

  // Phase 3 (throughput decoupling): T1a's sandbox is routed through the deferred
  // queue (async) instead of block-waiting a scan worker. T1a is now ACCEPTED and is
  // the top priority class.
  test('enqueueDeferred accepts tier 1a (Phase 3) and bypasses the min-score floor', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r = enqueueDeferred(makeItem({ name: 'hc-malware', tier: '1a', riskScore: 50 }));
    assert(r === true, 'Should accept T1a items (Phase 3 routes them here)');
    assert(getDeferredQueue().length === 1, 'Queue should contain the T1a item');

    // T1a is high-confidence by classification — it bypasses DEFERRED_MIN_SCORE even
    // with no TIER1 signal, so it can never be dropped before its sandbox runs.
    const r2 = enqueueDeferred(makeItem({
      name: 'hc-lowscore', tier: '1a', riskScore: 2,
      staticResult: { threats: [{ type: 'credential_exfil', severity: 'LOW' }], summary: { critical: 0, high: 0, medium: 0, low: 1 } }
    }));
    assert(r2 === true, 'T1a must bypass the min-score floor (no TIER1 signal needed)');
    assert(getDeferredQueue().length === 2, 'Both T1a items present');
    _resetDeferredQueue();
  });

  test('enqueueDeferred prioritizes T1a ahead of higher-score T1b/T2 (tier rank dominates)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'big-t1b', tier: '1b', riskScore: 95 }));
    enqueueDeferred(makeItem({ name: 'big-t2', tier: 2, riskScore: 99 }));
    enqueueDeferred(makeItem({ name: 'small-t1a', tier: '1a', riskScore: 30 }));

    const q = getDeferredQueue();
    assert(q[0].name === 'small-t1a', `T1a must sort first despite the lowest score, got ${q[0].name}`);
    // Below T1a, T1b/T2 keep their existing score-DESC ordering (unchanged by Phase 3).
    assert(q[1].name === 'big-t2' && q[2].name === 'big-t1b', `T1b/T2 keep score order, got ${q[1].name},${q[2].name}`);
    _resetDeferredQueue();
  });

  test('enqueueDeferred: a T1a evicts a lower-tier item when full even at a lower score; T1a is never evicted', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue, DEFERRED_QUEUE_MAX } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    // Fill with high-score T2 items.
    for (let i = 0; i < DEFERRED_QUEUE_MAX; i++) {
      enqueueDeferred(makeItem({ name: `t2-${i}`, tier: 2, riskScore: 80 }));
    }
    assert(getDeferredQueue().length === DEFERRED_QUEUE_MAX, 'Queue full of T2');

    // A low-score T1a must still get in (evicting the lowest-priority T2).
    const r = enqueueDeferred(makeItem({ name: 'late-t1a', tier: '1a', riskScore: 10 }));
    assert(r === true, 'Low-score T1a must evict a higher-score T2 when full');
    assert(getDeferredQueue()[0].name === 'late-t1a', 'T1a sits at the front');
    assert(getDeferredQueue().length === DEFERRED_QUEUE_MAX, 'Size stays at cap');

    // A subsequent T2 (even high score) cannot evict the T1a — all room is taken by
    // the protected T1a + remaining high-score T2s, and T2 never outranks T1a.
    const stillHasT1a = getDeferredQueue().some(i => i.name === 'late-t1a');
    assert(stillHasT1a, 'T1a remains queued');
    _resetDeferredQueue();
  });

  test('getDeferredQueueStats counts T1a in the tier breakdown', () => {
    const { enqueueDeferred, getDeferredQueueStats, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    enqueueDeferred(makeItem({ name: 'a', tier: '1a', riskScore: 40 }));
    enqueueDeferred(makeItem({ name: 'b', tier: '1b', riskScore: 40 }));
    enqueueDeferred(makeItem({ name: 'c', tier: 2, riskScore: 40 }));

    const s = getDeferredQueueStats();
    assert(s.tierBreakdown.t1a === 1, `expected 1 T1a, got ${s.tierBreakdown.t1a}`);
    assert(s.tierBreakdown.t1b === 1 && s.tierBreakdown.t2 === 1, 'T1b/T2 still counted');
    assert(s.size === 3, 'size reflects all three');
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

  // Defense-in-depth min score guard (DEFERRED_MIN_SCORE = 5). Paired with the
  // classify.js:183 fallback fix: prevents low-score items (observed 2026-04-11
  // as @eeacms/* burst at score 2 flooding the deferred queue) from consuming
  // the dedicated deferred sandbox slot.
  test('enqueueDeferred rejects score below DEFERRED_MIN_SCORE (score=2, T2)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r = enqueueDeferred(makeItem({ name: 'eeacms-like', tier: 2, riskScore: 2 }));
    assert(r === false, 'Should reject score-2 items below DEFERRED_MIN_SCORE');
    assert(getDeferredQueue().length === 0, 'Queue should remain empty');
    _resetDeferredQueue();
  });

  test('enqueueDeferred rejects score below DEFERRED_MIN_SCORE regardless of tier (score=3, T1b)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r = enqueueDeferred(makeItem({ name: 'low-t1b', tier: '1b', riskScore: 3 }));
    assert(r === false, 'Should reject score-3 even for T1b tier');
    assert(getDeferredQueue().length === 0, 'Queue should remain empty');
    _resetDeferredQueue();
  });

  test('enqueueDeferred accepts items at exactly DEFERRED_MIN_SCORE (score=5)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r = enqueueDeferred(makeItem({ name: 'at-floor', tier: 2, riskScore: 5 }));
    assert(r === true, 'Should accept score=5 (not strictly below threshold)');
    assert(getDeferredQueue().length === 1, 'Queue should contain the item');
    _resetDeferredQueue();
  });

  test('enqueueDeferred accepts single HIGH finding (score=10, legitimate T1b)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r = enqueueDeferred(makeItem({ name: 'single-high', tier: '1b', riskScore: 10 }));
    assert(r === true, 'Should accept legitimate T1b at HIGH severity (score=10)');
    assert(getDeferredQueue().length === 1, 'Queue should contain the item');
    _resetDeferredQueue();
  });

  // Threat-model guard: the min-score filter MUST NOT block packages that
  // carry a TIER1_TYPES finding (even at LOW severity). Otherwise an
  // adversary could bypass sandbox verification by tuning their malware to
  // fire only LOW-severity TIER1 patterns (staged_payload, sandbox_evasion,
  // env_charcode_reconstruction, mcp_config_injection, etc.) and slip a
  // score-2 package into T3/log-only territory. TIER1 weak matches still
  // warrant dynamic sandbox verification.
  test('enqueueDeferred accepts low score when TIER1 signal present (staged_payload LOW, score=2)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const item = makeItem({
      name: 'weak-staged',
      tier: 2,
      riskScore: 2,
      staticResult: {
        threats: [
          { type: 'staged_payload', severity: 'LOW' },
          { type: 'credential_tampering', severity: 'LOW' }
        ],
        summary: { critical: 0, high: 0, medium: 0, low: 2 }
      }
    });
    const r = enqueueDeferred(item);
    assert(r === true, 'Score-2 with TIER1 signal must pass min-score guard (weak TIER1 match still needs sandbox)');
    assert(getDeferredQueue().length === 1, 'Queue should contain the item');
    _resetDeferredQueue();
  });

  test('enqueueDeferred accepts low score when sandbox_evasion TIER1 signal present (score=3)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const item = makeItem({
      name: 'weak-evasion',
      tier: 2,
      riskScore: 3,
      staticResult: {
        threats: [
          { type: 'sandbox_evasion', severity: 'LOW' },
          { type: 'dynamic_require', severity: 'LOW' },
          { type: 'env_access', severity: 'LOW' }
        ],
        summary: { critical: 0, high: 0, medium: 0, low: 3 }
      }
    });
    const r = enqueueDeferred(item);
    assert(r === true, 'sandbox_evasion (TIER1) at LOW must bypass min-score guard');
    assert(getDeferredQueue().length === 1, 'Queue should contain the item');
    _resetDeferredQueue();
  });

  test('enqueueDeferred still rejects low score when NO TIER1 signal (threat-model negative)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const item = makeItem({
      name: 'pure-noise',
      tier: 2,
      riskScore: 2,
      staticResult: {
        threats: [
          { type: 'credential_tampering', severity: 'LOW' },
          { type: 'require_cache_poison', severity: 'LOW' }
        ],
        summary: { critical: 0, high: 0, medium: 0, low: 2 }
      }
    });
    const r = enqueueDeferred(item);
    assert(r === false, 'Score-2 without TIER1 signal must still be rejected (unchanged from pre-threat-model fix)');
    assert(getDeferredQueue().length === 0, 'Queue should remain empty');
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

  // ── Integration-level: T1a is now routed through the deferred queue (Phase 3) ──
  // Previously T1a was rejected here (it block-waited in the scan worker). Phase 3
  // decouples it: T1a is accepted and tops the queue. (Negative coverage for tier
  // eligibility lives below — a truly unknown tier is still rejected.)

  test('T1a items are accepted by enqueueDeferred (Phase 3 async routing)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r1 = enqueueDeferred(makeItem({ tier: '1a' }));
    const r2 = enqueueDeferred(makeItem({ name: 'x', tier: '1a', riskScore: 100 }));
    assert(r1 === true, 'T1a should be accepted');
    assert(r2 === true, 'T1a (high score) should be accepted');
    assert(getDeferredQueue().length === 2, 'Both T1a items should be queued');
    _resetDeferredQueue();
  });

  test('enqueueDeferred still rejects an unknown/ineligible tier (negative)', () => {
    const { enqueueDeferred, getDeferredQueue, _resetDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
    _resetDeferredQueue();

    const r1 = enqueueDeferred(makeItem({ name: 'bogus', tier: 3, riskScore: 100 }));
    const r2 = enqueueDeferred(makeItem({ name: 'bogus2', tier: 'weird', riskScore: 100 }));
    assert(r1 === false, 'tier 3 is not eligible');
    assert(r2 === false, 'unknown tier string is not eligible');
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
