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
    pruneMemoryCaches, MAX_RECENTLY_SCANNED, MAX_ALERTED_PACKAGES,
    computeMemoryPressure, getMemoryPressureLevel, handleMemoryPressure,
    MEMORY_PRESSURE_LEVELS, MEMORY_THRESHOLD_HIGH, MEMORY_THRESHOLD_CRITICAL,
    MEMORY_THRESHOLD_EMERGENCY, EMERGENCY_QUEUE_KEEP,
    MEMORY_LOG_INTERVAL_NORMAL, MEMORY_LOG_INTERVAL_PRESSURE
  } = require('../../src/monitor/daemon.js');
  const { DOWNLOADS_CACHE_TTL } = require('../../src/monitor/classify.js');
  const { clearDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
  const {
    appendAlert, ALERTS_FILE, ALERTS_MAX_SIZE, MAX_DETECTIONS
  } = require('../../src/monitor/state.js');

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

  test('MEMORY: daemon main loop has memory watchdog with circuit breaker', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    assertIncludes(daemonSource, 'MEMORY:', 'daemon.js should log memory usage');
    assertIncludes(daemonSource, 'process.memoryUsage()', 'daemon.js should call process.memoryUsage()');
    assertIncludes(daemonSource, 'MEMORY PRESSURE', 'daemon.js should detect memory pressure');
    assertIncludes(daemonSource, 'computeMemoryPressure', 'daemon.js should use computeMemoryPressure in loop');
    assertIncludes(daemonSource, 'MEMORY_PRESSURE_LEVELS.HIGH', 'daemon.js should gate workers on pressure level');
  });

  // ─── Chantier 3b: Memory circuit breaker ───

  test('MEMORY CIRCUIT BREAKER: pressure levels are correctly defined', () => {
    assert(MEMORY_PRESSURE_LEVELS.NONE === 0, 'NONE should be 0');
    assert(MEMORY_PRESSURE_LEVELS.ELEVATED === 1, 'ELEVATED should be 1');
    assert(MEMORY_PRESSURE_LEVELS.HIGH === 2, 'HIGH should be 2');
    assert(MEMORY_PRESSURE_LEVELS.CRITICAL === 3, 'CRITICAL should be 3');
    assert(MEMORY_PRESSURE_LEVELS.EMERGENCY === 4, 'EMERGENCY should be 4');
  });

  test('MEMORY CIRCUIT BREAKER: thresholds are graduated and non-overlapping', () => {
    assert(MEMORY_THRESHOLD_HIGH > 0.70, 'HIGH threshold should be > 70%');
    assert(MEMORY_THRESHOLD_CRITICAL > MEMORY_THRESHOLD_HIGH, 'CRITICAL should be above HIGH');
    assert(MEMORY_THRESHOLD_EMERGENCY > MEMORY_THRESHOLD_CRITICAL, 'EMERGENCY should be above CRITICAL');
    assert(MEMORY_THRESHOLD_EMERGENCY <= 0.99, 'EMERGENCY should be <= 99%');
  });

  test('MEMORY CIRCUIT BREAKER: computeMemoryPressure uses heap_size_limit not heapTotal', () => {
    const { level, mem, ratio } = computeMemoryPressure();
    assert(typeof level === 'number', 'level should be a number');
    assert(level >= 0 && level <= 4, `level should be 0-4, got ${level}`);
    assert(typeof ratio === 'number', 'ratio should be a number');
    assert(ratio >= 0 && ratio <= 1, `ratio should be 0-1, got ${ratio}`);
    assert(typeof mem.heapUsed === 'number', 'mem.heapUsed should be a number');
    // Ratio should be against heap_size_limit (~4GB default), NOT heapTotal (~6MB).
    // With heapTotal, ratio would be ~70% even at startup. With heap_size_limit,
    // it should be < 5% in test context.
    assert(ratio < 0.50, `ratio ${ratio.toFixed(3)} looks like heapUsed/heapTotal — should use heap_size_limit`);
  });

  test('MEMORY CIRCUIT BREAKER: daemon uses v8.getHeapStatistics().heap_size_limit', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    assertIncludes(daemonSource, "require('v8')", 'daemon.js should import v8 module');
    assertIncludes(daemonSource, 'heap_size_limit', 'daemon.js should use heap_size_limit');
    // Must NOT use heapUsed / heapTotal for the ratio
    const badPattern = /mem\.heapUsed\s*\/\s*mem\.heapTotal/;
    assert(!badPattern.test(daemonSource),
      'daemon.js must NOT use heapUsed/heapTotal — V8 heapTotal is dynamic and structurally 70-85%');
  });

  test('MEMORY CIRCUIT BREAKER: getMemoryPressureLevel returns current level', () => {
    computeMemoryPressure(); // ensure it's computed at least once
    const level = getMemoryPressureLevel();
    assert(typeof level === 'number', 'getMemoryPressureLevel should return a number');
    assert(level >= 0 && level <= 4, `level should be 0-4, got ${level}`);
  });

  test('MEMORY CIRCUIT BREAKER: EMERGENCY_QUEUE_KEEP is reasonable', () => {
    assert(typeof EMERGENCY_QUEUE_KEEP === 'number', 'EMERGENCY_QUEUE_KEEP should be a number');
    assert(EMERGENCY_QUEUE_KEEP > 0, 'EMERGENCY_QUEUE_KEEP should be positive');
    assert(EMERGENCY_QUEUE_KEEP <= 1000, 'EMERGENCY_QUEUE_KEEP should be <= 1000');
  });

  test('MEMORY CIRCUIT BREAKER: handleMemoryPressure at HIGH clears caches', () => {
    const testScanned = new Set(['a', 'b', 'c']);
    const testDownloads = new Map([['pkg', { downloads: 100, fetchedAt: Date.now() }]]);
    const testQueue = [];

    handleMemoryPressure(
      MEMORY_PRESSURE_LEVELS.HIGH, 0.87,
      testScanned, testDownloads, testQueue
    );

    assert(testScanned.size === 0, 'HIGH should clear recentlyScanned');
    assert(testDownloads.size === 0, 'HIGH should clear downloadsCache');
  });

  test('MEMORY CIRCUIT BREAKER: handleMemoryPressure at EMERGENCY truncates queue', () => {
    const testScanned = new Set();
    const testDownloads = new Map();
    const testQueue = [];
    // Fill queue with 2000 items
    for (let i = 0; i < 2000; i++) {
      testQueue.push({ name: `pkg-${i}`, version: '1.0.0', ecosystem: 'npm' });
    }

    handleMemoryPressure(
      MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.96,
      testScanned, testDownloads, testQueue
    );

    assert(testQueue.length === EMERGENCY_QUEUE_KEEP,
      `Queue should be truncated to ${EMERGENCY_QUEUE_KEEP}, got ${testQueue.length}`);
    // Verify the NEWEST items are kept (those at the end of the array)
    assert(testQueue[0].name === `pkg-${2000 - EMERGENCY_QUEUE_KEEP}`,
      `First remaining item should be pkg-${2000 - EMERGENCY_QUEUE_KEEP}, got ${testQueue[0].name}`);
  });

  test('MEMORY CIRCUIT BREAKER: handleMemoryPressure EMERGENCY is no-op on small queue', () => {
    const testQueue = [];
    for (let i = 0; i < 100; i++) {
      testQueue.push({ name: `pkg-${i}`, version: '1.0.0' });
    }

    handleMemoryPressure(
      MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.96,
      new Set(), new Map(), testQueue
    );

    assert(testQueue.length === 100, `Small queue should not be truncated, got ${testQueue.length}`);
  });

  test('MEMORY CIRCUIT BREAKER: adaptive log interval — fast under pressure', () => {
    assert(MEMORY_LOG_INTERVAL_PRESSURE < MEMORY_LOG_INTERVAL_NORMAL,
      'Pressure log interval should be shorter than normal');
    assert(MEMORY_LOG_INTERVAL_PRESSURE <= 30_000,
      `Pressure interval should be <= 30s, got ${MEMORY_LOG_INTERVAL_PRESSURE}`);
    assert(MEMORY_LOG_INTERVAL_NORMAL >= 60_000,
      `Normal interval should be >= 60s, got ${MEMORY_LOG_INTERVAL_NORMAL}`);
  });

  test('MEMORY CIRCUIT BREAKER: ingestion has memory backpressure', () => {
    const ingestionSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'ingestion.js'), 'utf8'
    );
    assertIncludes(ingestionSource, 'getMemoryPressureLevel', 'ingestion.js should check memory pressure');
    assertIncludes(ingestionSource, 'MEMORY BACKPRESSURE', 'ingestion.js should log memory backpressure');
  });

  test('MEMORY CIRCUIT BREAKER: daemon gates ensureWorkers on pressure level', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    assertIncludes(daemonSource, 'pressureLevel < MEMORY_PRESSURE_LEVELS.HIGH',
      'daemon.js should gate ensureWorkers on pressure level');
  });

  test('MEMORY CIRCUIT BREAKER: clearDeferredQueue exported and functional', () => {
    assert(typeof clearDeferredQueue === 'function', 'clearDeferredQueue should be exported');
    // Should return 0 when queue is empty (non-destructive test)
    const count = clearDeferredQueue();
    assert(typeof count === 'number', 'clearDeferredQueue should return a number');
  });

  test('MEMORY CIRCUIT BREAKER: systemd service has --expose-gc', () => {
    const serviceFile = fs.readFileSync(
      path.join(__dirname, '..', '..', 'deploy', 'muaddib-monitor.service'), 'utf8'
    );
    assertIncludes(serviceFile, '--expose-gc', 'systemd service should pass --expose-gc to node');
    assertIncludes(serviceFile, '--max-old-space-size', 'systemd service should set --max-old-space-size');
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

  // ─── Bug fix: heap pressure uses v8.getHeapStatistics ───

  test('BUG1: computeMemoryPressure uses v8 heap_size_limit (not hardcoded)', () => {
    const daemonSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8'
    );
    assertIncludes(daemonSource, "require('v8')", 'daemon.js should import v8 module');
    assertIncludes(daemonSource, 'getHeapStatistics', 'daemon.js should use v8.getHeapStatistics()');
    assertIncludes(daemonSource, 'heap_size_limit', 'daemon.js should use heap_size_limit as denominator');
    assert(!daemonSource.includes('3072 * 1024 * 1024'),
      'daemon.js should not use hardcoded 3072MB denominator');
  });

  test('BUG1: computeMemoryPressure ratio matches v8 heap limit', () => {
    const v8 = require('v8');
    const { level, mem, ratio } = computeMemoryPressure();
    const heapLimit = v8.getHeapStatistics().heap_size_limit;
    const expectedRatio = mem.heapUsed / heapLimit;
    // Allow 1% tolerance for timing drift between calls
    assert(Math.abs(ratio - expectedRatio) < 0.01,
      `ratio ${ratio.toFixed(4)} should be close to heapUsed/heap_size_limit (${expectedRatio.toFixed(4)})`);
  });

  // ─── Bug fix: alerts JSONL append-only ───

  test('BUG2a: appendAlert uses JSONL append (not JSON read-parse-rewrite)', () => {
    const stateSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'state.js'), 'utf8'
    );
    assertIncludes(stateSource, 'appendFileSync', 'state.js should use appendFileSync for alerts');
    assertIncludes(stateSource, 'monitor-alerts.jsonl', 'ALERTS_FILE should use .jsonl extension');
    assert(!stateSource.includes("JSON.parse(fs.readFileSync(ALERTS_FILE"),
      'appendAlert should not read+parse the full alerts file');
  });

  test('BUG2a: alerts file has rotation', () => {
    const stateSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'state.js'), 'utf8'
    );
    assertIncludes(stateSource, 'maybeRotateAlerts', 'state.js should have alerts rotation');
    assert(typeof ALERTS_MAX_SIZE === 'number', 'ALERTS_MAX_SIZE should be exported');
    assert(ALERTS_MAX_SIZE === 100 * 1024 * 1024, `ALERTS_MAX_SIZE should be 100MB, got ${ALERTS_MAX_SIZE}`);
  });

  test('BUG2a: appendAlert writes valid JSONL lines', () => {
    // Test that appendAlert produces valid JSONL by checking the format:
    // appendAlert calls appendFileSync with JSON.stringify(alert) + '\n'
    const stateSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'state.js'), 'utf8'
    );
    // Verify the append pattern: JSON.stringify(alert) + '\n' followed by appendFileSync
    assertIncludes(stateSource, "JSON.stringify(alert) + '\\n'",
      'appendAlert should write single-line JSON with newline');
    assertIncludes(stateSource, 'appendFileSync(ALERTS_FILE, line',
      'appendAlert should use appendFileSync');
  });

  // ─── Bug fix: detections cap ───

  test('BUG2b: detections JSONL has MAX_DETECTIONS cap', () => {
    const stateSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'state.js'), 'utf8'
    );
    assertIncludes(stateSource, 'MAX_DETECTIONS', 'state.js should define MAX_DETECTIONS');
    assert(typeof MAX_DETECTIONS === 'number', 'MAX_DETECTIONS should be exported');
    assert(MAX_DETECTIONS === 10_000, `MAX_DETECTIONS should be 10000, got ${MAX_DETECTIONS}`);
    // Post OOM-fix: cap is enforced by _compactDetectionsJsonl (called from
    // appendDetection on a counter trigger) instead of slice() on every write.
    assertIncludes(stateSource, '_compactDetectionsJsonl', 'state.js should define the JSONL compactor');
    assertIncludes(stateSource, 'total <= MAX_DETECTIONS', 'compaction should short-circuit below cap');
  });

  // ─── Bug fix: temporal findings trimmed ───

  test('BUG2c: temporal findings are trimmed before persistence', () => {
    const stateSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'state.js'), 'utf8'
    );
    assertIncludes(stateSource, 'trimTemporalFindings', 'state.js should have trimTemporalFindings');
    assertIncludes(stateSource, 'trimTemporalFindings(findings)', 'appendTemporalDetection should trim findings');
  });

  // ─── Bug fix: deploy permissions ───

  test('BUG3: auto-update.sh fixes ownership after git pull', () => {
    const updateScript = fs.readFileSync(
      path.join(__dirname, '..', '..', 'deploy', 'auto-update.sh'), 'utf8'
    );
    assertIncludes(updateScript, 'chown', 'auto-update.sh should fix file ownership');
    assertIncludes(updateScript, 'muaddib:muaddib', 'auto-update.sh should chown to muaddib user');
    // chown must come AFTER npm ci and BEFORE systemctl restart
    const chownIdx = updateScript.indexOf('chown');
    const npmIdx = updateScript.indexOf('npm ci');
    const restartIdx = updateScript.indexOf('systemctl restart');
    assert(chownIdx > npmIdx, 'chown should come after npm ci');
    assert(chownIdx < restartIdx, 'chown should come before systemctl restart');
  });

  test('BUG3: monitor service has ExecStartPre for ownership fix', () => {
    const serviceFile = fs.readFileSync(
      path.join(__dirname, '..', '..', 'deploy', 'muaddib-monitor.service'), 'utf8'
    );
    assertIncludes(serviceFile, 'ExecStartPre', 'service should have ExecStartPre for ownership fix');
    assertIncludes(serviceFile, 'chown', 'ExecStartPre should run chown');
  });

  // ════════════════════════════════════════════════════════════════════════
  // P0 OOM-leak fix (fix/monitor-oom-leak)
  // The monitor was OOM-killed every ~1.5-3.5h from an off-heap leak (orphaned
  // gVisor sandbox containers + wedged scan workers) that the heap-only circuit
  // breaker was structurally blind to (heap sat at ~20% while RSS hit 10.3G).
  // ════════════════════════════════════════════════════════════════════════

  const os = require('os');
  const { RSS_LIMIT_MB, MAX_DOWNLOADS_CACHE } = require('../../src/monitor/daemon.js');
  const { runSingleSandbox, killAllSandboxContainers } = require('../../src/sandbox/index.js');
  const { terminateAllWorkers, runScanInWorker } = require('../../src/monitor/queue.js');

  // ─── P0b: RSS-aware circuit breaker ───

  test('P0b RSS: RSS_LIMIT_MB exported and a sane MB budget', () => {
    assert(typeof RSS_LIMIT_MB === 'number', 'RSS_LIMIT_MB should be a number');
    assert(RSS_LIMIT_MB > 1000 && RSS_LIMIT_MB <= 16000, `RSS_LIMIT_MB should be a sane MB budget, got ${RSS_LIMIT_MB}`);
  });

  test('P0b RSS: rss drives EMERGENCY even when heap is idle (positive)', () => {
    const v8 = require('v8');
    const heapLimit = v8.getHeapStatistics().heap_size_limit;
    // Tiny heap, rss at 95% of the budget → EMERGENCY via the rss arm (heap alone = NONE).
    const sample = { heapUsed: Math.round(heapLimit * 0.05), rss: Math.round(RSS_LIMIT_MB * 1024 * 1024 * 0.95) };
    const { level, ratio, rssRatio } = computeMemoryPressure(sample, RSS_LIMIT_MB);
    assert(level === MEMORY_PRESSURE_LEVELS.EMERGENCY, `rss at 95% of budget should be EMERGENCY, got level ${level}`);
    assert(ratio < 0.10, `ratio should stay the (idle) heap ratio, got ${ratio}`);
    assert(rssRatio > 0.92, `rssRatio should be > 0.92, got ${rssRatio}`);
  });

  test('P0b RSS: low rss + low heap = NONE (negative)', () => {
    const sample = { heapUsed: 50 * 1024 * 1024, rss: 500 * 1024 * 1024 };
    const { level } = computeMemoryPressure(sample, RSS_LIMIT_MB);
    assert(level === MEMORY_PRESSURE_LEVELS.NONE, `low heap + low rss should be NONE, got ${level}`);
  });

  test('P0b RSS: heap arm still fires when rss is idle (no regression)', () => {
    const v8 = require('v8');
    const heapLimit = v8.getHeapStatistics().heap_size_limit;
    const sample = { heapUsed: Math.round(heapLimit * 0.96), rss: 100 * 1024 * 1024 };
    const { level } = computeMemoryPressure(sample, RSS_LIMIT_MB);
    assert(level === MEMORY_PRESSURE_LEVELS.EMERGENCY, `heap at 96% should still be EMERGENCY, got ${level}`);
  });

  test('P0b RSS: pressure level is max(heap, rss)', () => {
    const v8 = require('v8');
    const heapLimit = v8.getHeapStatistics().heap_size_limit;
    const r1 = computeMemoryPressure({ heapUsed: Math.round(heapLimit * 0.87), rss: 10 * 1024 * 1024 }, RSS_LIMIT_MB);
    assert(r1.level === MEMORY_PRESSURE_LEVELS.HIGH, `heap 0.87 + idle rss → HIGH, got ${r1.level}`);
    const r2 = computeMemoryPressure({ heapUsed: 10 * 1024 * 1024, rss: Math.round(RSS_LIMIT_MB * 1024 * 1024 * 0.91) }, RSS_LIMIT_MB);
    assert(r2.level === MEMORY_PRESSURE_LEVELS.CRITICAL, `idle heap + rss 0.91 → CRITICAL, got ${r2.level}`);
  });

  // The two structural greps that used to live here ("daemon reads MUADDIB_RSS_LIMIT_MB",
  // "EMERGENCY calls killAllSandboxContainers()") were deleted: the first is redundant with
  // the four sample-driven tests above, and the second only proved a call *string* existed.
  // Both are replaced by behavioral tests that drive handleMemoryPressure() and assert on the
  // summary it now returns + the side effects it produces.

  test('P0b EMERGENCY: reclaim truncates to newest, clears caches, and runs the off-heap reclaim', () => {
    const q = [];
    for (let i = 0; i < 2000; i++) q.push({ name: `pkg-${i}` });
    const rs = new Set(['a', 'b']);
    const dc = new Map([['x', 1]]);
    const s = handleMemoryPressure(MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.96, rs, dc, q);
    // queue truncated to the NEWEST EMERGENCY_QUEUE_KEEP items; drop count reported in the summary
    assert(s.queueDropped === 2000 - EMERGENCY_QUEUE_KEEP, `queueDropped should be ${2000 - EMERGENCY_QUEUE_KEEP}, got ${s.queueDropped}`);
    assert(q.length === EMERGENCY_QUEUE_KEEP, `queue should hold ${EMERGENCY_QUEUE_KEEP}, got ${q.length}`);
    assert(q[0].name === `pkg-${2000 - EMERGENCY_QUEUE_KEEP}`, `oldest should be dropped, first kept = ${q[0] && q[0].name}`);
    // caches cleared (EMERGENCY >= HIGH)
    assert(s.cachesCleared === true, 'EMERGENCY should clear caches');
    assert(rs.size === 0 && dc.size === 0, 'recentlyScanned + downloadsCache should be emptied');
    // off-heap reclaim ACTUALLY RAN: a number (not undefined=deleted, not -1=threw). 0 is the
    // correct value in CI (empty registries) — the assertion is that the statement executed and
    // captured a result, which deleting the kill call (→ undefined) or breaking it (→ -1) fails.
    assert(typeof s.containersKilled === 'number' && s.containersKilled >= 0, `EMERGENCY should run the container reclaim, got ${s.containersKilled}`);
    assert(typeof s.workersTerminated === 'number' && s.workersTerminated >= 0, `EMERGENCY should run the worker reclaim, got ${s.workersTerminated}`);
  });

  test('P0b graduated response: HIGH clears caches but does NOT truncate the queue or reclaim off-heap', () => {
    const q = [];
    for (let i = 0; i < 2000; i++) q.push({ name: `pkg-${i}` });
    const rs = new Set(['a']);
    const dc = new Map([['x', 1]]);
    // alertedPackageRules is webhook.js's module Map; the breaker bounds it at HIGH too.
    alertedPackageRules.clear();
    for (let i = 0; i < 6000; i++) alertedPackageRules.set(`pkg-${i}`, new Set(['R']));
    const s = handleMemoryPressure(MEMORY_PRESSURE_LEVELS.HIGH, 0.87, rs, dc, q);
    assert(s.cachesCleared === true, 'HIGH should clear caches');
    assert(rs.size === 0 && dc.size === 0, 'HIGH should empty recentlyScanned + downloadsCache');
    assert(alertedPackageRules.size === 0, `HIGH should bound alertedPackageRules, got ${alertedPackageRules.size}`);
    assert(q.length === 2000 && s.queueDropped === 0, 'HIGH must NOT truncate the queue (graduated response)');
    // the off-heap reclaim is EMERGENCY-only: at HIGH those summary fields must stay unset.
    assert(s.containersKilled === undefined && s.workersTerminated === undefined, 'HIGH must NOT run the off-heap reclaim (EMERGENCY-only)');
  });

  // ─── P0a: real termination on timeout ───

  await asyncTest('P0a SANDBOX: pre-aborted signal → INCONCLUSIVE, never CLEAN (positive)', async () => {
    const ac = new AbortController();
    ac.abort();
    // Early-abort path returns before spawning docker — no docker needed in CI.
    const res = await runSingleSandbox('left-pad', { signal: ac.signal });
    assert(res.severity === 'INCONCLUSIVE', `aborted run should be INCONCLUSIVE, got ${res.severity}`);
    assert(res.score === -1, `aborted run score should be -1, got ${res.score}`);
    assert(res.inconclusive === true, 'aborted run should set inconclusive=true');
    assert(res.severity !== 'CLEAN', 'aborted run must NEVER be CLEAN (timeout-evasion guard)');
  });

  test('P0a SANDBOX: killAllSandboxContainers returns 0 on empty registry (negative)', () => {
    const n = killAllSandboxContainers();
    assert(n === 0, `no live containers → 0 removed, got ${n}`);
  });

  // Source-level, Docker-only. Reproducing these behaviorally needs a wedged gVisor container,
  // which this CI lane lacks (Docker absent → the repo's ~14.5k sandbox tests skip). They guard
  // SECURITY properties with no in-CI proxy: gVisor's runsc survives a soft `docker kill`, so
  // the ladder MUST `rm -f`; and a container that never exits after the kill MUST be
  // force-resolved INCONCLUSIVE, never left to hang (the multi-hour wedge that leaked slots +
  // off-heap memory). The behavioral anchor for the abort→INCONCLUSIVE resolution is the
  // pre-aborted-signal test above; this only pins the two strings whose silent change would
  // reintroduce the leak. This is the ONE structural assertion I could not make behavioral.
  test('P0a SANDBOX: kill ladder is `rm -f` (not soft kill) + watchdog force-resolves INCONCLUSIVE [source-level, Docker-only]', () => {
    const sboxSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'sandbox', 'index.js'), 'utf8'
    );
    assertIncludes(sboxSource, "['rm', '-f', containerName]", 'gVisor runsc survives `docker kill` — the ladder must `rm -f`');
    assertIncludes(sboxSource, 'force-resolving INCONCLUSIVE', 'a wedged container must be force-resolved INCONCLUSIVE, never left to hang');
  });

  test('P0a QUEUE: terminateAllWorkers returns 0 when no workers live (negative)', () => {
    const n = terminateAllWorkers();
    assert(typeof n === 'number', 'terminateAllWorkers should return a number');
    assert(n === 0, `no live workers → 0 terminated, got ${n}`);
  });

  // Replaces two source-grep tests ("AbortSignal plumbed", "timeout maps to INCONCLUSIVE") with
  // a real worker round-trip. We spawn the actual static-scan worker with a 1ms budget: it
  // cannot bootstrap the 20-scanner pipeline that fast, so the timeout arm must win, reject with
  // a timeout error, AND reap the worker (done() deletes it from _liveWorkers synchronously) —
  // the leak this fix closed. The scanPackage relabel of that timeout to INCONCLUSIVE-not-clean
  // is integration-level (STATIC_SCAN_TIMEOUT_MS is a const, not injectable into scanPackage), so
  // it is exercised by code path, not unit-forced here.
  await asyncTest('P0a QUEUE: runScanInWorker enforces its timeout and reaps the worker (behavioral)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-worktest-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = 1;\n');
    terminateAllWorkers(); // drain strays so the post-condition is unambiguous
    let err = null;
    try {
      await runScanInWorker(tmp, 1, { name: 't', monitorMode: true }, null);
    } catch (e) { err = e; }
    fs.rmSync(tmp, { recursive: true, force: true });
    assert(err && /static scan timeout/i.test(err.message), `1ms budget should reject with a static-scan-timeout error, got: ${err && err.message}`);
    assert(terminateAllWorkers() === 0, 'a timed-out worker must already be reaped, not leaked');
  });

  // ─── P0c: bounded caches (FIFO) ───

  test('P0c CACHE: pruneMemoryCaches enforces downloadsCache size cap (positive)', () => {
    const testDownloads = new Map();
    const now = Date.now();
    for (let i = 0; i < MAX_DOWNLOADS_CACHE + 50; i++) {
      testDownloads.set(`pkg-${i}`, { downloads: 1, fetchedAt: now }); // fresh → TTL won't evict
    }
    assert(testDownloads.size > MAX_DOWNLOADS_CACHE, 'should be over cap before prune');
    pruneMemoryCaches(new Set(), testDownloads, new Map());
    assert(testDownloads.size === MAX_DOWNLOADS_CACHE, `downloadsCache should be capped at ${MAX_DOWNLOADS_CACHE}, got ${testDownloads.size}`);
    assert(!testDownloads.has('pkg-0'), 'oldest entry should be evicted (FIFO)');
    assert(testDownloads.has(`pkg-${MAX_DOWNLOADS_CACHE + 49}`), 'newest entry should remain');
  });

  test('P0c CACHE: downloadsCache cap is a no-op when within limits (negative)', () => {
    const testDownloads = new Map([['a', { downloads: 1, fetchedAt: Date.now() }]]);
    pruneMemoryCaches(new Set(), testDownloads, new Map());
    assert(testDownloads.size === 1, 'small downloadsCache should be untouched');
  });

  // The insert-site FIFO caps (recentlyScanned in queue.js, alertedPackageRules in webhook.js)
  // are the SAME Map/Set eviction pattern proven behaviorally by the downloadsCache test above,
  // and alertedPackageRules' bound is additionally asserted by the HIGH-pressure test (it clears
  // a 6000-entry map to 0). The eviction is inline at the insert sites, not a callable seam, so a
  // dedicated source-grep here would add nothing the behavioral tests don't already cover — it
  // was removed rather than restated as a string.

  // ─── P0d: systemd cgroup memory limits ───
  // A unit file is config, so this asserts its content — but on the cross-config INVARIANT, not
  // mere presence: the three escalating limits must be strictly ordered so the gentlest reclaim
  // acts first (in-process RSS breaker → cgroup soft reclaim → cgroup hard restart), and the
  // in-process budget must match the value the unit injects (single source of truth).

  test('P0d SYSTEMD: rss budget <= MemoryHigh < MemoryMax, swap pinned, env matches RSS_LIMIT_MB', () => {
    const svc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'deploy', 'muaddib-monitor.service'), 'utf8'
    );
    const gToMb = (re) => { const m = svc.match(re); return m ? Math.round(parseFloat(m[1]) * 1024) : NaN; };
    const envMb = (() => { const m = svc.match(/MUADDIB_RSS_LIMIT_MB=(\d+)/); return m ? parseInt(m[1], 10) : NaN; })();
    const highMb = gToMb(/MemoryHigh=([\d.]+)G/);
    const maxMb = gToMb(/MemoryMax=([\d.]+)G/);
    assert(!isNaN(envMb) && !isNaN(highMb) && !isNaN(maxMb), 'service must define MUADDIB_RSS_LIMIT_MB + MemoryHigh + MemoryMax');
    assert(envMb <= highMb, `in-process rss budget (${envMb}MB) should be <= MemoryHigh (${highMb}MB) so it fires first`);
    assert(highMb < maxMb, `MemoryHigh (${highMb}MB) should be < MemoryMax (${maxMb}MB)`);
    assertIncludes(svc, 'MemorySwapMax=0', 'swap must be pinned to 0 so a leak cannot hide in swap');
    // Single source of truth: the unit's env value should match the daemon's compiled default
    // (both 8500 here). Only checked when the runner itself hasn't overridden the env, so a CI
    // box that exports MUADDIB_RSS_LIMIT_MB doesn't trip it.
    if (process.env.MUADDIB_RSS_LIMIT_MB === undefined) {
      assert(envMb === RSS_LIMIT_MB, `unit MUADDIB_RSS_LIMIT_MB (${envMb}) should equal the daemon default RSS_LIMIT_MB (${RSS_LIMIT_MB})`);
    }
  });

  // Reset the module-level pressure level after injecting synthetic samples above,
  // so later test files reading getMemoryPressureLevel() see the real value.
  computeMemoryPressure();
}

module.exports = { runMonitorMemoryTests };
