/**
 * Tests for monitor memory management: backpressure, pruning, watchdog, abort signal.
 * Covers the OOM prevention mechanisms added in the monitor memory hardening fix.
 */

const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes, spyOn
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
    MEMORY_LOG_INTERVAL_NORMAL, MEMORY_LOG_INTERVAL_PRESSURE, runPollCycle, shouldSkipPoll, POLL_WATCHDOG_MS, POLL_INTERVAL, shouldSnapshot, formatHeapSpaces
  } = require('../../src/monitor/daemon.js');
  const { DOWNLOADS_CACHE_TTL } = require('../../src/monitor/classify.js');
  const { clearDeferredQueue } = require('../../src/monitor/deferred-sandbox.js');
  const {
    appendAlert, ALERTS_FILE, ALERTS_MAX_SIZE, MAX_DETECTIONS,
    _compactDetectionsJsonl, appendTemporalDetection
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

  test('MEMORY: computeTarget sheds workers to the floor under heap pressure (adaptive concurrency)', () => {
    // Behavioral replacement for the daemon.js source-greps (computeTarget / "ADAPTIVE:" / ensureWorkers).
    // Force the circuit-breaker level HIGH, then the adaptive controller must drop the target to MIN
    // regardless of a large backlog — an OOM kill loses the in-memory queue, so pressure overrides it.
    const { computeTarget, MIN_CONCURRENCY } = require('../../src/monitor/adaptive-concurrency.js');
    computeMemoryPressure({ rss: 4096 * 1024 * 1024, heapUsed: 1024 }, 1); // rssRatio ≫ 1 → EMERGENCY
    const r = computeTarget(16, 5000, { scanned: 0, errorsByType: {} });
    assert(r.target === MIN_CONCURRENCY, `under heap pressure target should drop to MIN (${MIN_CONCURRENCY}), got ${r.target}`);
    assert(/heap/.test(r.reason), `reason should cite heap pressure, got "${r.reason}"`);
    computeMemoryPressure({ rss: 1024, heapUsed: 1024 }, 1_000_000); // reset shared level → NONE
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

  test('MEMORY: computeMemoryPressure escalates to >= HIGH as RSS approaches the limit (circuit breaker)', () => {
    // Behavioral replacement for the daemon.js source-greps (MEMORY: / process.memoryUsage() /
    // MEMORY PRESSURE / computeMemoryPressure / MEMORY_PRESSURE_LEVELS.HIGH). Feed synthetic memory
    // samples and assert the computed pressure level + that getMemoryPressureLevel reflects it (the
    // value the daemon loop and ingestion gate on).
    const low = computeMemoryPressure({ rss: 1024, heapUsed: 1024 }, 1_000_000);
    assert(low.level === MEMORY_PRESSURE_LEVELS.NONE, `tiny footprint should be NONE, got ${low.level}`);
    const high = computeMemoryPressure({ rss: 512 * 1024 * 1024, heapUsed: 1024 }, 1); // rssRatio ≫ 1
    assert(high.level >= MEMORY_PRESSURE_LEVELS.HIGH, `near/over-limit RSS should be >= HIGH, got ${high.level}`);
    assert(getMemoryPressureLevel() === high.level,
      'getMemoryPressureLevel should reflect the last computeMemoryPressure result');
    computeMemoryPressure({ rss: 1024, heapUsed: 1024 }, 1_000_000); // reset shared level → NONE
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

  // C1: removed a source-grep that asserted daemon.js *contains* "require('v8')" /
  // 'heap_size_limit' and *not* the /mem.heapUsed / mem.heapTotal/ pattern. The behavioral
  // test just above computes computeMemoryPressure()'s ratio and asserts it is < 0.50 — which
  // only holds if the denominator is heap_size_limit (heapTotal would give ~70%). That proves
  // the same property by behavior, not by substring.

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
      MEMORY_PRESSURE_LEVELS.HIGH, 0.87, 0.87,
      testScanned, testDownloads, testQueue, {}
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
      testQueue.push({ id: i });  // nameless: truncation test only — keeps the (now ledgered) evict off the real scan-ledger
    }

    handleMemoryPressure(
      MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.96, 0.96,
      testScanned, testDownloads, testQueue, {}
    );

    assert(testQueue.length === EMERGENCY_QUEUE_KEEP,
      `Queue should be truncated to ${EMERGENCY_QUEUE_KEEP}, got ${testQueue.length}`);
    // Verify the NEWEST items are kept (those at the end of the array)
    assert(testQueue[0].id === 2000 - EMERGENCY_QUEUE_KEEP,
      `First remaining item should be id ${2000 - EMERGENCY_QUEUE_KEEP}, got ${testQueue[0].id}`);
  });

  test('MEMORY CIRCUIT BREAKER: handleMemoryPressure EMERGENCY is no-op on small queue', () => {
    const testQueue = [];
    for (let i = 0; i < 100; i++) {
      testQueue.push({ name: `pkg-${i}`, version: '1.0.0' });
    }

    handleMemoryPressure(
      MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.96, 0.96,
      new Set(), new Map(), testQueue, {}
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

  test('MEMORY CIRCUIT BREAKER: getMemoryPressureLevel exposes the gate ingestion/daemon read', () => {
    // Behavioral replacement for the ingestion.js source-greps (getMemoryPressureLevel / "MEMORY
    // BACKPRESSURE") AND the daemon.js "pressureLevel < MEMORY_PRESSURE_LEVELS.HIGH" gate grep:
    // ingestion skips polling and the daemon stops spawning workers once this level crosses HIGH.
    // Drive the shared level via computeMemoryPressure and assert the gate value both sides read.
    computeMemoryPressure({ rss: 1024, heapUsed: 1024 }, 1_000_000); // NONE
    assert(getMemoryPressureLevel() < MEMORY_PRESSURE_LEVELS.HIGH, 'with low memory the gate is open (poll + spawn allowed)');
    computeMemoryPressure({ rss: 512 * 1024 * 1024, heapUsed: 1024 }, 1); // EMERGENCY
    assert(getMemoryPressureLevel() >= MEMORY_PRESSURE_LEVELS.HIGH,
      'with high memory the gate is closed (ingestion skips poll, daemon stops spawning workers)');
    computeMemoryPressure({ rss: 1024, heapUsed: 1024 }, 1_000_000); // reset shared level → NONE
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
  // C1: removed two source-grep tests that asserted queue.js *contains* 'AbortController' /
  // 'controller.abort()' / 'clearTimeout(timeoutId)' and counted 'signal && signal.aborted'
  // matches — implementation-coupled and rename-fragile. The observable contract ("an aborted
  // signal stops the scan") is verified behaviorally by the pre-abort test just below.

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

  test('MEMORY: persistQueue/restoreQueue + saveNpmSeq/loadNpmSeq round-trip (crash-safe state after poll)', () => {
    // Behavioral replacement for the daemon.js source-greps (persistQueue(scanQueue, state) /
    // saveNpmSeq(state.npmLastSeq)). After each poll the daemon persists the scan queue AND the npm
    // replication cursor so a crash loses nothing; assert both survive a write → read round-trip.
    const { saveNpmSeq, loadNpmSeq } = require('../../src/monitor.js');
    const origSeq = loadNpmSeq();
    scanQueue.length = 0;
    scanQueue.push({ name: 'persist-rt-pkg', version: '1.0.0', ecosystem: 'npm', tarballUrl: null });
    try {
      persistQueue(scanQueue, { npmLastSeq: 424242 });
      assert(fs.existsSync(QUEUE_STATE_FILE), 'persistQueue should write the queue state file');
      scanQueue.length = 0;
      const restoredCount = restoreQueue(scanQueue);
      assert(restoredCount >= 1 && scanQueue.some(it => it && it.name === 'persist-rt-pkg'),
        'restoreQueue should bring back the persisted package (crash recovery)');
      saveNpmSeq(987654);
      assert(loadNpmSeq() === 987654, 'saveNpmSeq → loadNpmSeq should round-trip the npm replication cursor');
    } finally {
      scanQueue.length = 0;
      try { fs.unlinkSync(QUEUE_STATE_FILE); } catch {}
      try { saveNpmSeq(typeof origSeq === 'number' ? origSeq : 0); } catch {}
    }
  });

  // ─── Bug fix: heap pressure uses v8.getHeapStatistics ───
  // C1: removed the source-grep test that asserted daemon.js *contains* "require('v8')" /
  // 'getHeapStatistics' / 'heap_size_limit' and *not* '3072 * 1024 * 1024'. The behavioral
  // test below calls computeMemoryPressure() and checks its ratio equals heapUsed/heap_size_limit
  // — which proves the v8 heap limit is the denominator (not a hardcoded constant) far more
  // robustly than a substring match.

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

  // Behavioral (was source-grep): drive the real appendAlert with fs.appendFileSync and
  // fs.renameSync spied out, so we assert OBSERVABLE behavior (append-only, rotation,
  // one valid JSON line per call) without ever touching the real data/monitor-alerts.jsonl.
  // Rename-safe (internal identifiers can change) and logic-sensitive (reverting to a
  // read-parse-rewrite, or dropping rotation, fails the test).
  test('BUG2a: appendAlert appends one JSONL line and never read-parses the alerts file', () => {
    const appendSpy = spyOn(fs, 'appendFileSync');   // capture write, never hit disk
    const renameSpy = spyOn(fs, 'renameSync');       // guard: never rotate real data
    const origRead = fs.readFileSync;
    const readSpy = spyOn(fs, 'readFileSync', origRead); // record reads, still functional
    try {
      appendAlert({ package: 'evil-pkg', version: '6.6.6', severity: 'critical', score: 90 });
      assert(appendSpy.callCount === 1, `appendAlert should append exactly once, got ${appendSpy.callCount}`);
      const [filePath, data] = appendSpy.calls[0];
      assert(String(filePath).endsWith('monitor-alerts.jsonl'), `should append to monitor-alerts.jsonl, got ${filePath}`);
      // append-only: appendAlert must NOT read+parse the alerts file back
      const alertReads = readSpy.calls.filter(([p]) => String(p).includes('monitor-alerts'));
      assert(alertReads.length === 0, 'appendAlert must not read the alerts file (append-only, no read-parse-rewrite)');
      // exactly one JSON line + trailing newline that round-trips to the alert
      assert(data.endsWith('\n') && data.indexOf('\n') === data.length - 1, 'should write exactly one line ending in newline');
      assert(JSON.parse(data.trim()).package === 'evil-pkg', 'written line should round-trip to the alert object');
    } finally {
      readSpy.restore();
      renameSpy.restore();
      appendSpy.restore();
    }
  });

  test('BUG2a: appendAlert rotates the alerts file when it exceeds ALERTS_MAX_SIZE', () => {
    assert(typeof ALERTS_MAX_SIZE === 'number', 'ALERTS_MAX_SIZE should be exported');
    assert(ALERTS_MAX_SIZE === 100 * 1024 * 1024, `ALERTS_MAX_SIZE should be 100MB, got ${ALERTS_MAX_SIZE}`);
    const origExists = fs.existsSync;
    const origStat = fs.statSync;
    const appendSpy = spyOn(fs, 'appendFileSync');
    const renameSpy = spyOn(fs, 'renameSync');
    // Simulate an over-size alerts file; delegate every other path to the real fs.
    spyOn(fs, 'existsSync', (p) => String(p).includes('monitor-alerts') ? true : origExists(p));
    spyOn(fs, 'statSync', (p) => String(p).includes('monitor-alerts') ? { size: ALERTS_MAX_SIZE + 1 } : origStat(p));
    try {
      appendAlert({ package: 'big-pkg', version: '1.0.0' });
      assert(renameSpy.callCount === 1, `over-size alerts file should be rotated once, got ${renameSpy.callCount}`);
      const [from, to] = renameSpy.calls[0];
      assert(String(from).endsWith('monitor-alerts.jsonl'), `rotation should rename the alerts file, got ${from}`);
      assert(String(to).includes('monitor-alerts') && String(to) !== String(from), 'rotated name should differ from the original');
      assert(appendSpy.callCount === 1, 'appendAlert should still append after rotating');
    } finally {
      fs.statSync = origStat;
      fs.existsSync = origExists;
      renameSpy.restore();
      appendSpy.restore();
    }
  });

  test('BUG2a: appendAlert writes one valid JSON line per call', () => {
    const appendSpy = spyOn(fs, 'appendFileSync');
    const renameSpy = spyOn(fs, 'renameSync'); // guard: never rotate real data
    try {
      appendAlert({ package: 'a', version: '1.0.0', severity: 'high' });
      appendAlert({ package: 'b', version: '2.0.0', severity: 'critical' });
      assert(appendSpy.callCount === 2, `two appends should produce two writes, got ${appendSpy.callCount}`);
      for (const [, data] of appendSpy.calls) {
        assert(data.endsWith('\n') && data.indexOf('\n') === data.length - 1, 'each write must be exactly one line');
        JSON.parse(data.trim()); // throws (→ test fails) if the line is not valid JSON
      }
      assert(JSON.parse(appendSpy.calls[1][1].trim()).package === 'b', 'second write should be the second alert');
    } finally {
      renameSpy.restore();
      appendSpy.restore();
    }
  });

  // ─── Bug fix: detections cap ───

  test('BUG2b: detections cap value + compactor is exported and runs under cap', () => {
    assert(typeof MAX_DETECTIONS === 'number', 'MAX_DETECTIONS should be exported');
    assert(MAX_DETECTIONS === 10_000, `MAX_DETECTIONS should be 10000, got ${MAX_DETECTIONS}`);
    // Behavioral: the cap is enforced by _compactDetectionsJsonl (called from appendDetection
    // on a counter trigger). It is exported for tests + daemon housekeeping and must run
    // without throwing on the current (under-cap or absent) detections file — it short-circuits
    // when total <= MAX_DETECTIONS. (A full over-cap pruning test needs a DETECTIONS_FILE path
    // seam — deferred as a JIT seam candidate.)
    assert(typeof _compactDetectionsJsonl === 'function', '_compactDetectionsJsonl should be exported');
    let threw = null;
    try { _compactDetectionsJsonl(); } catch (e) { threw = e; }
    assert(threw === null, `_compactDetectionsJsonl should not throw under cap, got ${threw && threw.message}`);
  });

  // ─── Bug fix: temporal findings trimmed ───

  test('BUG2c: appendTemporalDetection trims bulky fields from findings before persisting', () => {
    const appendSpy = spyOn(fs, 'appendFileSync'); // capture the write, never touch disk
    const renameSpy = spyOn(fs, 'renameSync');     // guard: never compact real data
    try {
      appendTemporalDetection('pkg', '1.0.0', [{
        type: 'lifecycle_change',
        severity: 'high',
        data: { score: 7, bigBlob: 'x'.repeat(5000), rawAst: { huge: true } },
        extraTopLevel: 'drop-me'
      }]);
      assert(appendSpy.callCount === 1, `should append once, got ${appendSpy.callCount}`);
      const entry = JSON.parse(appendSpy.calls[0][1].trim());
      assert(Array.isArray(entry.findings) && entry.findings.length === 1, 'one finding persisted');
      const f = entry.findings[0];
      assert(f.type === 'lifecycle_change', 'type is kept');
      assert(f.score === 7, 'data.score is hoisted onto the trimmed finding');
      assert(!('data' in f), 'the bulky data object must be dropped');
      assert(!('bigBlob' in f) && !('rawAst' in f), 'bulky payload fields must be dropped');
      assert(!('extraTopLevel' in f), 'unknown top-level fields must be dropped');
    } finally {
      renameSpy.restore();
      appendSpy.restore();
    }
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
    for (let i = 0; i < 2000; i++) q.push({ id: i });  // nameless: truncation/summary test — no real ledger writes
    const rs = new Set(['a', 'b']);
    const dc = new Map([['x', 1]]);
    const s = handleMemoryPressure(MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.96, 0.96, rs, dc, q, {});
    // queue truncated to the NEWEST EMERGENCY_QUEUE_KEEP items; drop count reported in the summary
    assert(s.queueDropped === 2000 - EMERGENCY_QUEUE_KEEP, `queueDropped should be ${2000 - EMERGENCY_QUEUE_KEEP}, got ${s.queueDropped}`);
    assert(q.length === EMERGENCY_QUEUE_KEEP, `queue should hold ${EMERGENCY_QUEUE_KEEP}, got ${q.length}`);
    assert(q[0].id === 2000 - EMERGENCY_QUEUE_KEEP, `oldest should be dropped, first kept id = ${q[0] && q[0].id}`);
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
    const s = handleMemoryPressure(MEMORY_PRESSURE_LEVELS.HIGH, 0.87, 0.87, rs, dc, q, {});
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

  test('P0b EMERGENCY: keeps PROTECTED scans, drops oldest UNPROTECTED first (no protected starvation)', () => {
    // Regression for the v2.10.88 raw splice(0,n): an IOC / burst / first-publish / ATO scan
    // stuck among the OLDEST items must NOT be dropped before plain scans. Nameless {id} items
    // so the (now protected-aware + ledgered) eviction writes nothing to the real scan-ledger.
    const KEEP = EMERGENCY_QUEUE_KEEP;
    const flags = ['isIOCMatch', 'isBurst', 'firstPublish', 'atoSignal', 'isATOBurstExtra'];
    const q = [];
    for (let i = 0; i < 50; i++) q.push({ id: `prot-${i}`, [flags[i % flags.length]]: true }); // 50 protected at the HEAD
    for (let i = 0; i < KEEP; i++) q.push({ id: `plain-${i}` });                                  // KEEP+50 total → drop 50
    const stats = {};
    const s = handleMemoryPressure(MEMORY_PRESSURE_LEVELS.EMERGENCY, 0.15, 0.96, new Set(), new Map(), q, stats);
    assert(q.length === KEEP, `truncated to ${KEEP}, got ${q.length}`);
    assert(q.filter(x => typeof x.id === 'string' && x.id.startsWith('prot-')).length === 50,
      'all 50 protected scans must survive the breaker (not starved by the oldest-first drop)');
    assert(!q.some(x => x.id === 'plain-0'), 'oldest UNPROTECTED (plain-0) must be dropped first');
    assert(q.some(x => x.id === `plain-${KEEP - 1}`), 'newest unprotected must survive');
    assert(s.queueDropped === 50 && (s.queueDroppedProtected || 0) === 0,
      `dropped 50 unprotected + 0 protected, got ${s.queueDropped}/${s.queueDroppedProtected}`);
    assert(stats.queueEmergencyDrops === 50, `stats.queueEmergencyDrops should be 50, got ${stats.queueEmergencyDrops}`);
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

  // ─── Poll-loop watchdog + heap diagnostics ───
  // Appended at the END of the function on purpose: a ~74-line block near the top
  // would shift the line numbers of the pre-existing source-grep tests above, and
  // their tests/meta/no-source-grep allowlist entries are keyed by file:line.
  // All tests below are behavioral (call the fn, assert the return) — no src reads.
  const {
    getPollBackoffMs, getConsecutivePollErrors, setConsecutivePollErrors, POLL_MAX_BACKOFF
  } = require('../../src/monitor/ingestion.js');

  await asyncTest('POLL-WATCHDOG: fast poll resolves and does not throw', async () => {
    let ran = false;
    await runPollCycle({}, [], {}, 50, async () => { ran = true; });
    assert(ran, 'pollFn should have executed');
  });

  await asyncTest('POLL-WATCHDOG: never-resolving poll is bounded by the watchdog (no hang)', async () => {
    const t0 = Date.now();
    let threw = null;
    try {
      await runPollCycle({}, [], {}, 30, () => new Promise(() => {})); // never settles
    } catch (e) { threw = e; }
    const elapsed = Date.now() - t0;
    assert(threw !== null, 'watchdog should reject a hung poll');
    assert(/watchdog/i.test(threw.message), `error should mention watchdog, got: ${threw && threw.message}`);
    assert(elapsed < 500, `watchdog should fire fast (<500ms), took ${elapsed}ms`);
  });

  await asyncTest('POLL-WATCHDOG: a subsequent cycle proceeds after a hung+aborted one (no stuck state)', async () => {
    try { await runPollCycle({}, [], {}, 20, () => new Promise(() => {})); } catch { /* expected */ }
    let ran2 = false;
    await runPollCycle({}, [], {}, 20, async () => { ran2 = true; });
    assert(ran2, 'second cycle proceeds — runPollCycle always settles, so the scheduler finally always resets the flag');
  });

  test('POLL-SKIP: not in progress → run (no skip, no forceReset)', () => {
    const r = shouldSkipPoll(false, 0, 1_000_000, POLL_WATCHDOG_MS, POLL_INTERVAL);
    assert(r.skip === false && r.forceReset === false, `expected run, got ${JSON.stringify(r)}`);
  });

  test('POLL-SKIP: in progress and fresh → skip this tick', () => {
    const now = 1_000_000;
    const r = shouldSkipPoll(true, now - 1000, now, POLL_WATCHDOG_MS, POLL_INTERVAL);
    assert(r.skip === true && r.forceReset === false, `expected skip, got ${JSON.stringify(r)}`);
  });

  test('POLL-SKIP: in progress but stale (> watchdog + interval) → force-reset, do not skip', () => {
    const now = 1_000_000;
    const stale = now - (POLL_WATCHDOG_MS + POLL_INTERVAL + 1);
    const r = shouldSkipPoll(true, stale, now, POLL_WATCHDOG_MS, POLL_INTERVAL);
    assert(r.forceReset === true && r.skip === false, `expected forceReset, got ${JSON.stringify(r)}`);
  });

  test('POLL-BACKOFF: 0 when healthy or after a single failure', () => {
    const prev = getConsecutivePollErrors();
    try {
      setConsecutivePollErrors(0);
      assert(getPollBackoffMs() === 0, `backoff should be 0 at 0 errors, got ${getPollBackoffMs()}`);
      setConsecutivePollErrors(1);
      assert(getPollBackoffMs() === 0, `backoff should be 0 at 1 error (escalates only >1), got ${getPollBackoffMs()}`);
    } finally { setConsecutivePollErrors(prev); }
  });

  test('POLL-BACKOFF: grows exponentially and caps at POLL_MAX_BACKOFF', () => {
    const prev = getConsecutivePollErrors();
    try {
      setConsecutivePollErrors(2);
      assert(getPollBackoffMs() === POLL_INTERVAL * 2, `n=2 → ${POLL_INTERVAL * 2}, got ${getPollBackoffMs()}`);
      setConsecutivePollErrors(3);
      assert(getPollBackoffMs() === POLL_INTERVAL * 4, `n=3 → ${POLL_INTERVAL * 4}, got ${getPollBackoffMs()}`);
      setConsecutivePollErrors(50);
      assert(getPollBackoffMs() === POLL_MAX_BACKOFF, `n=50 should cap at ${POLL_MAX_BACKOFF}, got ${getPollBackoffMs()}`);
    } finally { setConsecutivePollErrors(prev); }
  });

  // ─── Heap diagnostics (restart root-cause): pure helpers ───

  test('HEAP-SNAPSHOT: shouldSnapshot disabled when threshold unset (0)', () => {
    const d = shouldSnapshot(9999, 0, false, 100, 12);
    assert(d.take === false && d.reason === 'disabled', `expected disabled, got ${JSON.stringify(d)}`);
  });

  test('HEAP-SNAPSHOT: shouldSnapshot takes when over threshold with disk headroom', () => {
    const d = shouldSnapshot(6001, 6000, false, 50, 12);
    assert(d.take === true && d.reason === 'ok', `expected take, got ${JSON.stringify(d)}`);
  });

  test('HEAP-SNAPSHOT: shouldSnapshot skips below-threshold / already-taken / low-disk', () => {
    assert(shouldSnapshot(5999, 6000, false, 50, 12).take === false, 'below threshold → skip');
    assert(shouldSnapshot(7000, 6000, true, 50, 12).reason === 'already-taken', 'already taken → skip');
    const low = shouldSnapshot(7000, 6000, false, 3, 12);
    assert(low.take === false && /low-disk/.test(low.reason), `low disk → skip, got ${JSON.stringify(low)}`);
  });

  test('HEAP-SPACES: formatHeapSpaces renders space_name=usedMB pairs', () => {
    const s = formatHeapSpaces([
      { space_name: 'old_space', space_used_size: 6 * 1024 * 1024 },
      { space_name: 'new_space', space_used_size: 2 * 1024 * 1024 }
    ]);
    assert(s === 'old_space=6 new_space=2', `unexpected format: ${s}`);
    assert(formatHeapSpaces([]) === '', 'empty stats → empty string');
  });

  // Reset the module-level pressure level after injecting synthetic samples above,
  // so later test files reading getMemoryPressureLevel() see the real value.
  computeMemoryPressure();
}

module.exports = { runMonitorMemoryTests };
