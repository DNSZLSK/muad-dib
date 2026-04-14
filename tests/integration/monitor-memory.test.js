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

  test('BUG2b: detections.json has MAX_DETECTIONS cap', () => {
    const stateSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'monitor', 'state.js'), 'utf8'
    );
    assertIncludes(stateSource, 'MAX_DETECTIONS', 'state.js should define MAX_DETECTIONS');
    assert(typeof MAX_DETECTIONS === 'number', 'MAX_DETECTIONS should be exported');
    assert(MAX_DETECTIONS === 10_000, `MAX_DETECTIONS should be 10000, got ${MAX_DETECTIONS}`);
    assertIncludes(stateSource, 'slice(-MAX_DETECTIONS)', 'appendDetection should cap with slice');
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
}

module.exports = { runMonitorMemoryTests };
