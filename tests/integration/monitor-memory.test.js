/**
 * Tests for monitor memory management: backpressure, pruning, watchdog, abort signal.
 * Covers the OOM prevention mechanisms added in the monitor memory hardening fix.
 */

const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes
} = require('../test-utils');

async function runMonitorMemoryTests() {
  console.log('\n=== MONITOR MEMORY TESTS ===\n');

  const {
    scanQueue, recentlyScanned, alertedPackageRules, downloadsCache,
    MAX_RESTORE_QUEUE_SIZE, MAX_QUEUE_PERSIST_SIZE,
    QUEUE_STATE_FILE, persistQueue, restoreQueue,
    timeoutPromise, resolveTarballAndScan, dailyAlerts
  } = require('../../src/monitor.js');
  const {
    pruneMemoryCaches, MAX_RECENTLY_SCANNED, MAX_ALERTED_PACKAGES
  } = require('../../src/monitor/daemon.js');
  const { DOWNLOADS_CACHE_TTL } = require('../../src/monitor/classify.js');

  // ─── Chantier 1: Queue backpressure ───

  test('MEMORY: MAX_RESTORE_QUEUE_SIZE is exported and reasonable', () => {
    assert(typeof MAX_RESTORE_QUEUE_SIZE === 'number', 'MAX_RESTORE_QUEUE_SIZE should be a number');
    assert(MAX_RESTORE_QUEUE_SIZE === 100_000, `MAX_RESTORE_QUEUE_SIZE should be 100000, got ${MAX_RESTORE_QUEUE_SIZE}`);
    assert(MAX_RESTORE_QUEUE_SIZE < MAX_QUEUE_PERSIST_SIZE, 'MAX_RESTORE_QUEUE_SIZE should be less than MAX_QUEUE_PERSIST_SIZE');
  });

  test('MEMORY: restoreQueue truncates at MAX_RESTORE_QUEUE_SIZE', () => {
    // Setup: create a queue state file with more items than MAX_RESTORE_QUEUE_SIZE
    const dataDir = path.dirname(QUEUE_STATE_FILE);
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

    // Clear scanQueue before test
    scanQueue.length = 0;

    // Build oversize items (> 100K would be too slow; use 150K scaled test)
    const cap = MAX_RESTORE_QUEUE_SIZE;
    const oversizeCount = cap + 5_000;
    const oversizeItems = [];
    for (let i = 0; i < oversizeCount; i++) {
      oversizeItems.push({ name: `pkg-${i}`, version: '1.0.0', ecosystem: 'npm' });
    }

    fs.writeFileSync(QUEUE_STATE_FILE, JSON.stringify({
      savedAt: new Date().toISOString(),
      count: oversizeItems.length,
      items: oversizeItems
    }));

    const restored = restoreQueue(scanQueue);
    assert(restored <= cap, `Restored ${restored} items — should be capped at ${cap}`);
    assert(scanQueue.length <= cap, `Queue length ${scanQueue.length} — should be capped at ${cap}`);

    // Cleanup
    scanQueue.length = 0;
    try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
  });

  test('MEMORY: ingestion poll() has soft backpressure at 10K', () => {
    const ingestionSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'ingestion.js'), 'utf8'
    );
    assertIncludes(ingestionSource, 'SOFT_BACKPRESSURE_THRESHOLD', 'ingestion.js should define soft backpressure threshold');
    assertIncludes(ingestionSource, 'BACKPRESSURE: skipping poll', 'ingestion.js should log backpressure skip');
    assertIncludes(ingestionSource, 'seq not advanced, 0 packages lost', 'ingestion.js should document seq safety');
  });

  test('MEMORY: daemon uses adaptive concurrency', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    assertIncludes(daemonSource, 'computeTarget', 'daemon.js should use adaptive concurrency');
    assertIncludes(daemonSource, 'ADAPTIVE:', 'daemon.js should log adaptive concurrency changes');
    assertIncludes(daemonSource, 'ensureWorkers', 'daemon.js should use non-blocking ensureWorkers');
  });

  // ─── Chantier 2: Periodic memory pruning ───

  test('MEMORY: pruneMemoryCaches clears oversized recentlyScanned', () => {
    // Fill recentlyScanned beyond cap
    recentlyScanned.clear();
    for (let i = 0; i < MAX_RECENTLY_SCANNED + 100; i++) {
      recentlyScanned.add(`npm/test-pkg-${i}@1.0.0`);
    }
    assert(recentlyScanned.size > MAX_RECENTLY_SCANNED, 'recentlyScanned should be over cap before prune');

    const mockAlerted = new Map();
    pruneMemoryCaches(recentlyScanned, new Map(), mockAlerted);

    assert(recentlyScanned.size === 0, `recentlyScanned should be cleared after prune, got ${recentlyScanned.size}`);
    recentlyScanned.clear(); // cleanup
  });

  test('MEMORY: pruneMemoryCaches evicts expired downloadsCache entries', () => {
    const testCache = new Map();
    // Add fresh entry
    testCache.set('fresh-pkg', { downloads: 100, fetchedAt: Date.now() });
    // Add expired entry (25h old)
    testCache.set('old-pkg', { downloads: 50, fetchedAt: Date.now() - (25 * 60 * 60 * 1000) });

    pruneMemoryCaches(new Set(), testCache, new Map());

    assert(!testCache.has('old-pkg'), 'Expired entry should be evicted');
    assert(testCache.has('fresh-pkg'), 'Fresh entry should remain');
  });

  test('MEMORY: pruneMemoryCaches clears oversized alertedPackageRules', () => {
    const testAlerted = new Map();
    for (let i = 0; i < MAX_ALERTED_PACKAGES + 100; i++) {
      testAlerted.set(`pkg-${i}`, new Set(['rule-1']));
    }
    assert(testAlerted.size > MAX_ALERTED_PACKAGES, 'alertedPackageRules should be over cap before prune');

    pruneMemoryCaches(new Set(), new Map(), testAlerted);

    assert(testAlerted.size === 0, 'alertedPackageRules should be cleared after prune');
  });

  test('MEMORY: pruneMemoryCaches is a no-op when caches are within limits', () => {
    const testScanned = new Set(['a', 'b', 'c']);
    const testDownloads = new Map([['pkg', { downloads: 100, fetchedAt: Date.now() }]]);
    const testAlerted = new Map([['pkg', new Set(['r1'])]]);

    pruneMemoryCaches(testScanned, testDownloads, testAlerted);

    assert(testScanned.size === 3, 'Small recentlyScanned should not be cleared');
    assert(testDownloads.size === 1, 'Fresh downloadsCache should not be cleared');
    assert(testAlerted.size === 1, 'Small alertedPackageRules should not be cleared');
  });

  // ─── Chantier 3: Memory watchdog ───

  test('MEMORY: daemon main loop has memory watchdog', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    assertIncludes(daemonSource, 'MEMORY:', 'daemon.js should log memory usage');
    assertIncludes(daemonSource, 'process.memoryUsage()', 'daemon.js should call process.memoryUsage()');
    assertIncludes(daemonSource, 'MEMORY PRESSURE', 'daemon.js should detect memory pressure');
    assertIncludes(daemonSource, 'MEMORY_LOG_INTERVAL', 'daemon.js should have memory log interval');
  });

  // ─── Chantier 4: AbortController ───

  test('MEMORY: processQueueItem uses AbortController', () => {
    const queueSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'queue.js'), 'utf8'
    );
    assertIncludes(queueSource, 'AbortController', 'queue.js should use AbortController');
    assertIncludes(queueSource, 'controller.abort()', 'queue.js should call controller.abort() on timeout');
    assertIncludes(queueSource, 'clearTimeout(timeoutId)', 'queue.js should clear the timeout timer');
  });

  test('MEMORY: resolveTarballAndScan checks signal.aborted', () => {
    const queueSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'queue.js'), 'utf8'
    );
    // Should have multiple abort checks at different stages
    const abortChecks = (queueSource.match(/signal && signal\.aborted/g) || []).length;
    assert(abortChecks >= 3, `Expected at least 3 abort checks in resolveTarballAndScan, found ${abortChecks}`);
  });

  await asyncTest('MEMORY: resolveTarballAndScan bails on pre-aborted signal', async () => {
    const controller = new AbortController();
    controller.abort(); // Pre-abort

    // Should return immediately without doing anything
    const startTime = Date.now();
    await resolveTarballAndScan(
      { name: 'fake-pkg', version: '1.0.0', ecosystem: 'npm', tarballUrl: null },
      controller.signal
    );
    const elapsed = Date.now() - startTime;

    // If it returned quickly (< 1s), the abort check worked
    assert(elapsed < 1000, `Aborted scan should return immediately, took ${elapsed}ms`);
  });

  // ─── Chantier 5: systemd config documented ───

  test('MEMORY: seq/queue atomicity — persistQueue called after each poll', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    // Verify seq is persisted atomically with queue after each poll
    assertIncludes(daemonSource, 'persistQueue(scanQueue, state)', 'daemon.js should persist queue after poll');
    assertIncludes(daemonSource, 'saveNpmSeq(state.npmLastSeq)', 'daemon.js should save seq after queue persist');
  });
}

module.exports = { runMonitorMemoryTests };
