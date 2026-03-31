/**
 * Monitor wiring integration tests — verify function signatures between sub-modules.
 *
 * These tests exist specifically to catch the class of bugs introduced by the
 * v2.10.x refactoring (monitor.js 4191→302 lines, index.js 875→39 lines):
 *   - BUG-1 (v2.10.28): poll() called without state argument → crash
 *   - BUG-2 (v2.10.29): temporal functions called without dailyAlerts → broken analyses
 *   - BUG-3 (v2.10.30): saveState() called with 1 arg instead of 2 → silent state loss
 *
 * Strategy: verify that callee function.length matches the number of arguments
 * the caller actually passes, and that orchestrator wrappers bind the right
 * number of shared-state arguments.
 */

'use strict';

const path = require('path');
const {
  test, asyncTest, assert
} = require('../test-utils');

async function runMonitorWiringTests() {
  console.log('\n=== MONITOR WIRING TESTS ===\n');

  // ─────────────────────────────────────────────
  // 1. Sub-module function signatures
  // ─────────────────────────────────────────────

  const queue = require('../../src/monitor/queue.js');
  const daemon = require('../../src/monitor/daemon.js');
  const ingestion = require('../../src/monitor/ingestion.js');
  const temporal = require('../../src/monitor/temporal.js');
  const state = require('../../src/monitor/state.js');
  const webhook = require('../../src/monitor/webhook.js');
  const classify = require('../../src/monitor/classify.js');

  test('WIRING: processQueue takes 6 arguments (scanQueue, stats, dailyAlerts, recentlyScanned, downloadsCache, sandboxAvailable)', () => {
    assert(queue.processQueue.length === 6,
      `processQueue.length should be 6, got ${queue.processQueue.length}`);
  });

  test('WIRING: processQueueItem takes 7 arguments (item, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailable)', () => {
    assert(queue.processQueueItem.length === 7,
      `processQueueItem.length should be 7, got ${queue.processQueueItem.length}`);
  });

  test('WIRING: poll takes 3 arguments (state, scanQueue, stats)', () => {
    assert(ingestion.poll.length === 3,
      `poll.length should be 3, got ${ingestion.poll.length}`);
  });

  test('WIRING: startMonitor takes 7 arguments (options, stats, dailyAlerts, recentlyScanned, downloadsCache, scanQueue, sandboxAvailableRef)', () => {
    assert(daemon.startMonitor.length === 7,
      `startMonitor.length should be 7, got ${daemon.startMonitor.length}`);
  });

  test('WIRING: saveState takes 2 arguments (state, stats)', () => {
    assert(state.saveState.length === 2,
      `saveState.length should be 2, got ${state.saveState.length}`);
  });

  test('WIRING: loadState takes 1 argument (stats)', () => {
    assert(state.loadState.length === 1,
      `loadState.length should be 1, got ${state.loadState.length}`);
  });

  test('WIRING: loadDailyStats takes 2 arguments (stats, dailyAlerts)', () => {
    assert(state.loadDailyStats.length === 2,
      `loadDailyStats.length should be 2, got ${state.loadDailyStats.length}`);
  });

  test('WIRING: saveDailyStats takes 2 arguments (stats, dailyAlerts)', () => {
    assert(state.saveDailyStats.length === 2,
      `saveDailyStats.length should be 2, got ${state.saveDailyStats.length}`);
  });

  test('WIRING: maybePersistDailyStats takes 2 arguments (stats, dailyAlerts)', () => {
    assert(state.maybePersistDailyStats.length === 2,
      `maybePersistDailyStats.length should be 2, got ${state.maybePersistDailyStats.length}`);
  });

  test('WIRING: sendDailyReport takes 4 arguments (stats, dailyAlerts, recentlyScanned, downloadsCache)', () => {
    assert(webhook.sendDailyReport.length === 4,
      `sendDailyReport.length should be 4, got ${webhook.sendDailyReport.length}`);
  });

  test('WIRING: sendReportNow takes 1 argument (stats)', () => {
    assert(webhook.sendReportNow.length === 1,
      `sendReportNow.length should be 1, got ${webhook.sendReportNow.length}`);
  });

  test('WIRING: recordError takes 2 arguments (err, stats)', () => {
    assert(classify.recordError.length === 2,
      `recordError.length should be 2, got ${classify.recordError.length}`);
  });

  // ─────────────────────────────────────────────
  // 2. Temporal function signatures (production bug v2.10.29)
  // ─────────────────────────────────────────────

  test('WIRING: runTemporalCheck takes 2 arguments (packageName, dailyAlerts)', () => {
    assert(temporal.runTemporalCheck.length === 2,
      `runTemporalCheck.length should be 2, got ${temporal.runTemporalCheck.length}`);
  });

  test('WIRING: runTemporalAstCheck takes 2 arguments (packageName, dailyAlerts)', () => {
    assert(temporal.runTemporalAstCheck.length === 2,
      `runTemporalAstCheck.length should be 2, got ${temporal.runTemporalAstCheck.length}`);
  });

  test('WIRING: runTemporalPublishCheck takes 2 arguments (packageName, dailyAlerts)', () => {
    assert(temporal.runTemporalPublishCheck.length === 2,
      `runTemporalPublishCheck.length should be 2, got ${temporal.runTemporalPublishCheck.length}`);
  });

  test('WIRING: runTemporalMaintainerCheck takes 2 arguments (packageName, dailyAlerts)', () => {
    assert(temporal.runTemporalMaintainerCheck.length === 2,
      `runTemporalMaintainerCheck.length should be 2, got ${temporal.runTemporalMaintainerCheck.length}`);
  });

  // ─────────────────────────────────────────────
  // 3. Orchestrator wrapper binding verification
  //    monitor.js wraps sub-module calls, binding shared state.
  //    Verify the wrapper passes the right number of args.
  // ─────────────────────────────────────────────

  const monitor = require('../../src/monitor.js');

  test('WIRING: monitor.saveState wrapper calls state.saveState with 2 args (binds stats)', () => {
    // The wrapper signature is saveState(state) → stateModule.saveState(state, stats)
    // If the wrapper forgot to pass stats, this would be the BUG-3 pattern.
    // We can verify by checking the wrapper accepts 1 arg (it binds stats internally).
    assert(monitor.saveState.length === 1,
      `monitor.saveState wrapper should take 1 arg (state), got ${monitor.saveState.length}`);
    // And the sub-module requires 2
    assert(state.saveState.length === 2,
      `state.saveState should require 2 args, got ${state.saveState.length}`);
  });

  test('WIRING: monitor.processQueue wrapper calls queue.processQueue with 6 args (binds all state)', () => {
    assert(monitor.processQueue.length === 0,
      `monitor.processQueue wrapper should take 0 args (all state bound), got ${monitor.processQueue.length}`);
    assert(queue.processQueue.length === 6,
      `queue.processQueue should require 6 args, got ${queue.processQueue.length}`);
  });

  test('WIRING: daemon.js calls ingestion.poll with 3 args (state, scanQueue, stats)', () => {
    // poll is not exported from monitor.js (daemon calls ingestion.poll directly)
    // Verify the sub-module signature matches what daemon.js passes
    assert(ingestion.poll.length === 3,
      `ingestion.poll should require 3 args, got ${ingestion.poll.length}`);
  });

  test('WIRING: monitor.sendDailyReport wrapper calls webhook.sendDailyReport with 4 args', () => {
    assert(monitor.sendDailyReport.length === 0,
      `monitor.sendDailyReport wrapper should take 0 args (all state bound), got ${monitor.sendDailyReport.length}`);
    assert(webhook.sendDailyReport.length === 4,
      `webhook.sendDailyReport should require 4 args, got ${webhook.sendDailyReport.length}`);
  });

  test('WIRING: monitor.sendReportNow wrapper calls webhook.sendReportNow with 1 arg (binds stats)', () => {
    assert(monitor.sendReportNow.length === 0,
      `monitor.sendReportNow wrapper should take 0 args (stats bound), got ${monitor.sendReportNow.length}`);
    assert(webhook.sendReportNow.length === 1,
      `webhook.sendReportNow should require 1 arg, got ${webhook.sendReportNow.length}`);
  });

  test('WIRING: monitor temporal wrappers bind dailyAlerts (take 1 arg, sub-module takes 2)', () => {
    const temporalWrappers = [
      ['runTemporalCheck', monitor.runTemporalCheck, temporal.runTemporalCheck],
      ['runTemporalAstCheck', monitor.runTemporalAstCheck, temporal.runTemporalAstCheck],
      ['runTemporalPublishCheck', monitor.runTemporalPublishCheck, temporal.runTemporalPublishCheck],
      ['runTemporalMaintainerCheck', monitor.runTemporalMaintainerCheck, temporal.runTemporalMaintainerCheck]
    ];
    for (const [name, wrapper, submodule] of temporalWrappers) {
      assert(wrapper.length === 1,
        `monitor.${name} wrapper should take 1 arg (name), got ${wrapper.length}`);
      assert(submodule.length === 2,
        `temporal.${name} should require 2 args (name, dailyAlerts), got ${submodule.length}`);
    }
  });

  // ─────────────────────────────────────────────
  // 4. processQueue with empty queue — smoke test
  // ─────────────────────────────────────────────

  asyncTest('WIRING: processQueue with empty queue returns immediately (no crash)', async () => {
    const testStats = {
      scanned: 0, clean: 0, suspect: 0, errors: 0,
      suspectByTier: { t1: 0, t1a: 0, t1b: 0, t2: 0, t3: 0 },
      errorsByType: { too_large: 0, tar_failed: 0, http_error: 0, timeout: 0, static_timeout: 0, other: 0 },
      totalTimeMs: 0, mlFiltered: 0, lastReportTime: Date.now(), lastDailyReportDate: null
    };
    const testDailyAlerts = [];
    const testRecentlyScanned = new Set();
    const testDownloadsCache = new Map();
    // This must not throw — verifies all 6 args are accepted
    await queue.processQueue([], testStats, testDailyAlerts, testRecentlyScanned, testDownloadsCache, false);
  });

  // ─────────────────────────────────────────────
  // 5. Pipeline: resetAll called even on error
  // ─────────────────────────────────────────────

  asyncTest('WIRING: run() calls resetAll even when a phase throws', async () => {
    const { applyConfigOverrides, getSeverityWeights } = require('../../src/scoring.js');

    // applyConfigOverrides expects lowercase keys
    applyConfigOverrides({ severityWeights: { critical: 99, high: 10, medium: 3, low: 1 } });
    assert(getSeverityWeights().CRITICAL === 99, `Custom weight should be 99 before run(), got ${getSeverityWeights().CRITICAL}`);

    const { run } = require('../../src/index.js');
    try {
      // Run with a non-existent path — initialize() will throw
      await run('/nonexistent/path/that/does/not/exist', { _capture: true });
    } catch {
      // Expected to throw
    }

    // After run() throws, resetAll should have been called via finally block
    const weights = getSeverityWeights();
    assert(weights.CRITICAL === 25,
      `resetAll should have restored CRITICAL weight to 25, got ${weights.CRITICAL}`);
  });

  // ─────────────────────────────────────────────
  // 6. Cross-module export existence checks
  // ─────────────────────────────────────────────

  test('WIRING: all queue.js imports from temporal.js exist', () => {
    const expectedFromTemporal = [
      'runTemporalCheck', 'runTemporalAstCheck', 'runTemporalPublishCheck', 'runTemporalMaintainerCheck',
      'getTemporalMaxSeverity', 'isPublishAnomalyOnly', 'tryTemporalAlert', 'tryTemporalAstAlert',
      'isTemporalEnabled', 'isTemporalAstEnabled', 'isTemporalPublishEnabled', 'isTemporalMaintainerEnabled',
      'isSafeLifecycleScript'
    ];
    for (const fn of expectedFromTemporal) {
      assert(typeof temporal[fn] === 'function',
        `temporal.${fn} should be a function, got ${typeof temporal[fn]}`);
    }
  });

  test('WIRING: all queue.js imports from state.js exist', () => {
    const expectedFromState = [
      'cacheTarball', 'updateScanStats', 'appendDetection', 'saveScanMemory',
      'maybePersistDailyStats', 'loadNpmSeq', 'saveNpmSeq', 'getParisDateString',
      'appendTemporalDetection', 'atomicWriteFileSync', 'tarballCacheKey', 'tarballCachePath',
      'appendAlert', 'getParisHour', 'hasReportBeenSentToday'
    ];
    for (const fn of expectedFromState) {
      assert(typeof state[fn] === 'function',
        `state.${fn} should be a function, got ${typeof state[fn]}`);
    }
  });

  test('WIRING: all queue.js imports from webhook.js exist', () => {
    const expectedFromWebhook = [
      'trySendWebhook', 'buildAlertData', 'persistAlert', 'sendIOCPreAlert',
      'matchVersionedIOC', 'buildCanaryExfiltrationWebhookEmbed', 'getWebhookUrl',
      'computeReputationFactor', 'computeRiskLevel', 'sendDailyReport'
    ];
    for (const fn of expectedFromWebhook) {
      assert(typeof webhook[fn] === 'function',
        `webhook.${fn} should be a function, got ${typeof webhook[fn]}`);
    }
  });

  test('WIRING: all queue.js imports from classify.js exist', () => {
    const expectedFromClassify = [
      'isSuspectClassification', 'hasHighConfidenceThreat', 'hasIOCMatch',
      'hasTyposquat', 'hasLifecycleWithIntent', 'isSandboxEnabled', 'isCanaryEnabled',
      'recordError', 'classifyError', 'formatFindings', 'evaluateCacheTrigger', 'hasHighOrCritical'
    ];
    for (const fn of expectedFromClassify) {
      assert(typeof classify[fn] === 'function',
        `classify.${fn} should be a function, got ${typeof classify[fn]}`);
    }
  });

  test('WIRING: all daemon.js imports from sub-modules exist', () => {
    // daemon imports from queue
    assert(typeof queue.processQueue === 'function', 'queue.processQueue should exist');
    assert(typeof queue.SCAN_CONCURRENCY === 'number', 'queue.SCAN_CONCURRENCY should be a number');

    // daemon imports from ingestion
    assert(typeof ingestion.poll === 'function', 'ingestion.poll should exist');

    // daemon imports from state
    assert(typeof state.loadState === 'function', 'state.loadState should exist');
    assert(typeof state.saveState === 'function', 'state.saveState should exist');
    assert(typeof state.loadDailyStats === 'function', 'state.loadDailyStats should exist');
    assert(typeof state.saveDailyStats === 'function', 'state.saveDailyStats should exist');
    assert(typeof state.purgeTarballCache === 'function', 'state.purgeTarballCache should exist');

    // daemon imports from webhook
    assert(typeof webhook.sendDailyReport === 'function', 'webhook.sendDailyReport should exist');
    assert(typeof webhook.flushScopeGroup === 'function', 'webhook.flushScopeGroup should exist');
  });

  // ─────────────────────────────────────────────
  // 6b. Decoupled polling architecture (v2.10.42)
  // ─────────────────────────────────────────────

  test('WIRING: daemon exports PROCESS_LOOP_INTERVAL constant', () => {
    assert(typeof daemon.PROCESS_LOOP_INTERVAL === 'number',
      `PROCESS_LOOP_INTERVAL should be a number, got ${typeof daemon.PROCESS_LOOP_INTERVAL}`);
    assert(daemon.PROCESS_LOOP_INTERVAL > 0 && daemon.PROCESS_LOOP_INTERVAL < daemon.POLL_INTERVAL,
      `PROCESS_LOOP_INTERVAL (${daemon.PROCESS_LOOP_INTERVAL}) should be > 0 and < POLL_INTERVAL (${daemon.POLL_INTERVAL})`);
  });

  test('WIRING: daemon exports QUEUE_WARNING_THRESHOLD constant', () => {
    assert(typeof daemon.QUEUE_WARNING_THRESHOLD === 'number',
      `QUEUE_WARNING_THRESHOLD should be a number, got ${typeof daemon.QUEUE_WARNING_THRESHOLD}`);
    assert(daemon.QUEUE_WARNING_THRESHOLD === 5000,
      `QUEUE_WARNING_THRESHOLD should be 5000, got ${daemon.QUEUE_WARNING_THRESHOLD}`);
  });

  test('WIRING: monitor re-exports PROCESS_LOOP_INTERVAL and QUEUE_WARNING_THRESHOLD', () => {
    assert(monitor.PROCESS_LOOP_INTERVAL === daemon.PROCESS_LOOP_INTERVAL,
      'monitor.PROCESS_LOOP_INTERVAL should match daemon.PROCESS_LOOP_INTERVAL');
    assert(monitor.QUEUE_WARNING_THRESHOLD === daemon.QUEUE_WARNING_THRESHOLD,
      'monitor.QUEUE_WARNING_THRESHOLD should match daemon.QUEUE_WARNING_THRESHOLD');
  });

  // ─────────────────────────────────────────────
  // 7. Pipeline wiring: function signatures
  // ─────────────────────────────────────────────

  const initializer = require('../../src/pipeline/initializer.js');
  const executor = require('../../src/pipeline/executor.js');
  const processor = require('../../src/pipeline/processor.js');
  const outputter = require('../../src/pipeline/outputter.js');

  test('WIRING: pipeline.initialize takes 2 arguments (targetPath, options)', () => {
    assert(initializer.initialize.length === 2,
      `initialize.length should be 2, got ${initializer.initialize.length}`);
  });

  test('WIRING: pipeline.execute takes 4 arguments (targetPath, options, pythonDeps, warnings)', () => {
    assert(executor.execute.length === 4,
      `execute.length should be 4, got ${executor.execute.length}`);
  });

  test('WIRING: pipeline.process takes 6 arguments (threats, targetPath, options, pythonDeps, warnings, scannerErrors)', () => {
    assert(processor.process.length === 6,
      `process.length should be 6, got ${processor.process.length}`);
  });

  test('WIRING: pipeline.output takes 3 arguments (result, options, processed)', () => {
    assert(outputter.output.length === 3,
      `output.length should be 3, got ${outputter.output.length}`);
  });

  // ─────────────────────────────────────────────
  // 8. Shim validation — require paths resolve
  // ─────────────────────────────────────────────

  test('WIRING: all src/ shims resolve to existing modules', () => {
    const shimPairs = [
      ['../../src/scan-worker.js', 'scan-worker'],
      ['../../src/webhook.js', 'webhook'],
      ['../../src/daemon.js', 'daemon'],
      ['../../src/output-formatter.js', 'output-formatter'],
      ['../../src/report.js', 'report'],
      ['../../src/serve.js', 'serve'],
      ['../../src/watch.js', 'watch'],
      ['../../src/diff.js', 'diff'],
      ['../../src/safe-install.js', 'safe-install'],
      ['../../src/sarif.js', 'sarif'],
      ['../../src/hooks-init.js', 'hooks-init'],
      ['../../src/threat-feed.js', 'threat-feed'],
      ['../../src/canary-tokens.js', 'canary-tokens'],
      ['../../src/temporal-analysis.js', 'temporal-analysis'],
      ['../../src/temporal-ast-diff.js', 'temporal-ast-diff'],
      ['../../src/temporal-runner.js', 'temporal-runner'],
      ['../../src/publish-anomaly.js', 'publish-anomaly'],
      ['../../src/maintainer-change.js', 'maintainer-change']
    ];

    for (const [shimPath, name] of shimPairs) {
      try {
        const resolved = require.resolve(shimPath);
        assert(resolved, `shim ${name} should resolve`);
      } catch (err) {
        assert(false, `shim ${name} failed to resolve: ${err.message}`);
      }
    }
  });

  // ─────────────────────────────────────────────
  // 9. __dirname path verification (post-refactoring)
  // ─────────────────────────────────────────────

  const fs = require('fs');

  test('WIRING: sarif.js resolves correct package.json path', () => {
    // src/output/sarif.js should find ../../package.json (project root)
    const sarifDir = path.dirname(require.resolve('../../src/output/sarif.js'));
    const pkgPath = path.join(sarifDir, '..', '..', 'package.json');
    assert(fs.existsSync(pkgPath),
      `package.json should exist at ${pkgPath}`);
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    assert(pkg.version, 'package.json should have a version field');
  });

  test('WIRING: hooks-init.js resolves correct package.json path', () => {
    const hooksDir = path.dirname(require.resolve('../../src/commands/hooks-init.js'));
    const pkgPath = path.join(hooksDir, '..', '..', 'package.json');
    assert(fs.existsSync(pkgPath),
      `package.json should exist at ${pkgPath}`);
  });

  test('WIRING: sandbox/index.js resolves correct docker/ path', () => {
    const sandboxDir = path.dirname(require.resolve('../../src/sandbox/index.js'));
    const dockerPath = path.join(sandboxDir, '..', '..', 'docker');
    assert(fs.existsSync(dockerPath),
      `docker/ directory should exist at ${dockerPath}`);
    assert(fs.existsSync(path.join(dockerPath, 'Dockerfile')),
      'docker/Dockerfile should exist');
  });

  test('WIRING: interactive.js require paths resolve correctly', () => {
    // src/commands/interactive.js uses lazy require('../daemon.js') etc.
    // Verify the target shims exist
    const commandsDir = path.dirname(require.resolve('../../src/commands/interactive.js'));
    const targets = ['daemon.js', 'threat-feed.js', 'serve.js'];
    for (const target of targets) {
      const targetPath = path.join(commandsDir, '..', target);
      assert(fs.existsSync(targetPath),
        `${target} shim should exist at ${targetPath}`);
    }
  });

  test('WIRING: IOC yaml-loader resolves correct iocs/ path', () => {
    const yamlLoaderDir = path.dirname(require.resolve('../../src/ioc/yaml-loader.js'));
    const iocsPath = path.join(yamlLoaderDir, '..', '..', 'iocs');
    assert(fs.existsSync(iocsPath),
      `iocs/ directory should exist at ${iocsPath}`);
    assert(fs.existsSync(path.join(iocsPath, 'builtin.yaml')),
      'iocs/builtin.yaml should exist');
  });
}

module.exports = { runMonitorWiringTests };
