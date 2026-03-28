const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runPublishAnomalyTests() {
  // ============================================
  // PUBLISH FREQUENCY ANOMALY TESTS
  // ============================================

  console.log('\n=== PUBLISH ANOMALY TESTS ===\n');

  const {
    analyzePublishFrequency,
    detectPublishAnomaly,
    MS_PER_DAY,
    MS_PER_HOUR,
    BURST_WINDOW_MS,
    BURST_MIN_VERSIONS,
    RAPID_WINDOW_MS,
    RAPID_MIN_VERSIONS,
    DORMANT_THRESHOLD_MS,
    MIN_VERSIONS_FOR_ANALYSIS
  } = require('../../src/publish-anomaly.js');

  // --- analyzePublishFrequency ---

  test('PUBLISH: analyzePublishFrequency with 5 regular versions → correct avgIntervalDays', () => {
    const metadata = {
      time: {
        created: '2023-01-01T00:00:00Z',
        modified: '2023-05-01T00:00:00Z',
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-02-01T00:00:00Z',
        '1.2.0': '2023-03-01T00:00:00Z',
        '1.3.0': '2023-04-01T00:00:00Z',
        '1.4.0': '2023-05-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {}, '1.3.0': {}, '1.4.0': {} }
    };
    const stats = analyzePublishFrequency(metadata);
    assert(stats.totalVersions === 5, 'Should have 5 versions, got ' + stats.totalVersions);
    assert(stats.avgIntervalDays > 28 && stats.avgIntervalDays < 32, 'Avg interval should be ~30 days, got ' + stats.avgIntervalDays);
    assert(stats.stdDevDays >= 0, 'StdDev should be >= 0');
    assert(stats.lastPublishedAt === '2023-05-01T00:00:00Z', 'Last published should be May');
    assert(stats.publishHistory.length === 5, 'History should have 5 entries');
    // Verify sorted chronologically
    for (let i = 1; i < stats.publishHistory.length; i++) {
      assert(new Date(stats.publishHistory[i].date) >= new Date(stats.publishHistory[i - 1].date), 'History should be sorted');
    }
  });

  test('PUBLISH: analyzePublishFrequency with 2 versions → valid stats', () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '2.0.0': '2023-07-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '2.0.0': {} }
    };
    const stats = analyzePublishFrequency(metadata);
    assert(stats.totalVersions === 2, 'Should have 2 versions');
    assert(stats.avgIntervalDays > 180 && stats.avgIntervalDays < 183, 'Avg interval should be ~181 days, got ' + stats.avgIntervalDays);
    assert(stats.stdDevDays === 0, 'StdDev should be 0 with single interval');
    assert(stats.publishHistory.length === 2, 'History should have 2 entries');
  });

  test('PUBLISH: analyzePublishFrequency with 1 version → totalVersions: 1, avgIntervalDays: 0', () => {
    const metadata = {
      time: { '1.0.0': '2023-01-01T00:00:00Z' },
      versions: { '1.0.0': {} }
    };
    const stats = analyzePublishFrequency(metadata);
    assert(stats.totalVersions === 1, 'Should have 1 version');
    assert(stats.avgIntervalDays === 0, 'Avg interval should be 0 with single version');
    assert(stats.stdDevDays === 0, 'StdDev should be 0');
    assert(stats.publishHistory.length === 1, 'History should have 1 entry');
  });

  test('PUBLISH: analyzePublishFrequency with empty metadata → totalVersions: 0', () => {
    const stats = analyzePublishFrequency({});
    assert(stats.totalVersions === 0, 'Should have 0 versions');
    assert(stats.avgIntervalDays === 0, 'Avg interval should be 0');
    assert(stats.lastPublishedAt === null, 'Last published should be null');
    assert(stats.publishHistory.length === 0, 'History should be empty');
  });

  test('PUBLISH: analyzePublishFrequency with null/undefined metadata → no crash', () => {
    const stats1 = analyzePublishFrequency(null);
    assert(stats1.totalVersions === 0, 'null metadata should return 0 versions');
    assert(stats1.lastPublishedAt === null, 'null metadata should return null lastPublishedAt');
    assert(stats1.publishHistory.length === 0, 'null metadata should return empty history');

    const stats2 = analyzePublishFrequency(undefined);
    assert(stats2.totalVersions === 0, 'undefined metadata should return 0 versions');

    const stats3 = analyzePublishFrequency({ time: undefined, versions: undefined });
    assert(stats3.totalVersions === 0, 'undefined time/versions should return 0 versions');

    const stats4 = analyzePublishFrequency({ time: { '1.0.0': '2023-01-01T00:00:00Z' }, versions: undefined });
    assert(stats4.totalVersions === 0, 'undefined versions should return 0 versions');
  });

  test('PUBLISH: analyzePublishFrequency skips unpublished versions', () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-02-01T00:00:00Z',
        '1.2.0': '2023-03-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.2.0': {} } // 1.1.0 unpublished
    };
    const stats = analyzePublishFrequency(metadata);
    assert(stats.totalVersions === 2, 'Should skip unpublished version, got ' + stats.totalVersions);
  });

  test('PUBLISH: analyzePublishFrequency skips created/modified keys', () => {
    const metadata = {
      time: {
        created: '2023-01-01T00:00:00Z',
        modified: '2023-06-01T00:00:00Z',
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-03-01T00:00:00Z',
        '1.2.0': '2023-06-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {} }
    };
    const stats = analyzePublishFrequency(metadata);
    assert(stats.totalVersions === 3, 'Should skip created/modified, got ' + stats.totalVersions);
  });

  // --- detectPublishAnomaly (mock) ---

  // Helper: mock fetchPackageMetadata by temporarily replacing the module
  function mockDetect(metadata) {
    const { analyzePublishFrequency: analyze, MIN_VERSIONS_FOR_ANALYSIS: minVer,
            BURST_WINDOW_MS: burstWin, BURST_MIN_VERSIONS: burstMin,
            RAPID_WINDOW_MS: rapidWin, RAPID_MIN_VERSIONS: rapidMin,
            DORMANT_THRESHOLD_MS: dormantMs, MS_PER_HOUR: msHour, MS_PER_DAY: msDay
          } = require('../../src/publish-anomaly.js');

    const stats = analyze(metadata);

    if (stats.totalVersions < minVer) {
      return { packageName: 'mock-pkg', suspicious: false, findings: [], stats };
    }

    const findings = [];
    const history = stats.publishHistory;

    // BURST
    for (let i = 0; i < history.length; i++) {
      const windowStart = new Date(history[i].date).getTime();
      const windowEnd = windowStart + burstWin;
      const inWindow = [];
      for (let j = i; j < history.length; j++) {
        if (new Date(history[j].date).getTime() <= windowEnd) inWindow.push(history[j]);
        else break;
      }
      if (inWindow.length >= burstMin) {
        const spanMs = new Date(inWindow[inWindow.length - 1].date) - new Date(inWindow[0].date);
        const spanHours = Math.round(spanMs / msHour * 10) / 10;
        findings.push({
          type: 'publish_burst',
          severity: 'HIGH',
          description: `${inWindow.length} versions published in ${spanHours} hours`,
          versions: inWindow.map(e => e.version)
        });
        break;
      }
    }

    // DORMANT_SPIKE
    if (history.length >= 2) {
      const gapMs = new Date(history[history.length - 1].date) - new Date(history[history.length - 2].date);
      if (gapMs >= dormantMs) {
        findings.push({
          type: 'dormant_spike',
          severity: 'HIGH',
          description: `Package dormant for ${Math.round(gapMs / msDay)} days`,
          versions: [history[history.length - 2].version, history[history.length - 1].version]
        });
      }
    }

    // RAPID_SUCCESSION
    for (let i = 0; i < history.length; i++) {
      const windowStart = new Date(history[i].date).getTime();
      const windowEnd = windowStart + rapidWin;
      const inWindow = [];
      for (let j = i; j < history.length; j++) {
        if (new Date(history[j].date).getTime() <= windowEnd) inWindow.push(history[j]);
        else break;
      }
      if (inWindow.length >= rapidMin) {
        findings.push({
          type: 'rapid_succession',
          severity: 'MEDIUM',
          description: `${inWindow.length} versions within 1 hour`,
          versions: inWindow.map(e => e.version)
        });
        break;
      }
    }

    return { packageName: 'mock-pkg', suspicious: findings.length > 0, findings, stats };
  }

  test('PUBLISH: detect burst — 4 versions in 12h → publish_burst', () => {
    const metadata = {
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.0.1': '2024-06-01T08:00:00Z',
        '1.0.2': '2024-06-01T12:00:00Z',
        '1.0.3': '2024-06-01T16:00:00Z',
        '1.0.4': '2024-06-01T20:00:00Z'
      },
      versions: { '1.0.0': {}, '1.0.1': {}, '1.0.2': {}, '1.0.3': {}, '1.0.4': {} }
    };
    const result = mockDetect(metadata);
    assert(result.suspicious === true, 'Should be suspicious');
    const burst = result.findings.find(f => f.type === 'publish_burst');
    assert(burst, 'Should have publish_burst finding');
    assert(burst.severity === 'HIGH', 'Burst severity should be HIGH');
    assert(burst.versions.length >= 3, 'Burst should have 3+ versions, got ' + burst.versions.length);
  });

  test('PUBLISH: detect dormant_spike — 8 months gap → dormant_spike', () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-03-01T00:00:00Z',
        '1.2.0': '2023-05-01T00:00:00Z',
        '2.0.0': '2024-06-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {}, '2.0.0': {} }
    };
    const result = mockDetect(metadata);
    assert(result.suspicious === true, 'Should be suspicious');
    const dormant = result.findings.find(f => f.type === 'dormant_spike');
    assert(dormant, 'Should have dormant_spike finding');
    assert(dormant.severity === 'HIGH', 'Dormant severity should be HIGH');
    assert(dormant.versions.length === 2, 'Should reference 2 versions');
    assert(dormant.versions[0] === '1.2.0', 'First version should be last before gap');
    assert(dormant.versions[1] === '2.0.0', 'Second version should be new version');
  });

  test('PUBLISH: detect rapid_succession — 2 versions in 30 min → rapid_succession', () => {
    const metadata = {
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.1.0': '2024-06-01T00:00:00Z',
        '1.1.1': '2024-06-01T00:15:00Z',
        '1.1.2': '2024-06-01T00:30:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.1.1': {}, '1.1.2': {} }
    };
    const result = mockDetect(metadata);
    assert(result.suspicious === true, 'Should be suspicious');
    const rapid = result.findings.find(f => f.type === 'rapid_succession');
    assert(rapid, 'Should have rapid_succession finding');
    assert(rapid.severity === 'MEDIUM', 'Rapid severity should be MEDIUM');
    assert(rapid.versions.length >= 2, 'Should have 2+ versions');
  });

  test('PUBLISH: normal pattern → suspicious: false', () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-04-01T00:00:00Z',
        '1.2.0': '2023-07-01T00:00:00Z',
        '1.3.0': '2023-10-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {}, '1.3.0': {} }
    };
    const result = mockDetect(metadata);
    assert(result.suspicious === false, 'Normal pattern should not be suspicious');
    assert(result.findings.length === 0, 'Should have no findings');
  });

  test('PUBLISH: package with <3 versions → suspicious: false', () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.0.1': '2023-02-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.0.1': {} }
    };
    const result = mockDetect(metadata);
    assert(result.suspicious === false, 'Should not be suspicious with <3 versions');
    assert(result.findings.length === 0, 'Should have no findings');
  });

  // --- Constants ---

  test('PUBLISH: constants have expected values', () => {
    assert(BURST_WINDOW_MS === 24 * 60 * 60 * 1000, 'BURST_WINDOW_MS should be 24h in ms');
    assert(BURST_MIN_VERSIONS === 3, 'BURST_MIN_VERSIONS should be 3');
    assert(RAPID_WINDOW_MS === 60 * 60 * 1000, 'RAPID_WINDOW_MS should be 1h in ms');
    assert(RAPID_MIN_VERSIONS === 2, 'RAPID_MIN_VERSIONS should be 2');
    assert(DORMANT_THRESHOLD_MS === 180 * 24 * 60 * 60 * 1000, 'DORMANT_THRESHOLD_MS should be 180 days');
    assert(MIN_VERSIONS_FOR_ANALYSIS === 3, 'MIN_VERSIONS_FOR_ANALYSIS should be 3');
  });

  test('PUBLISH: analyzePublishFrequency stdDevDays nonzero for irregular intervals', () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-01-10T00:00:00Z',
        '1.2.0': '2023-07-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {} }
    };
    const stats = analyzePublishFrequency(metadata);
    assert(stats.stdDevDays > 0, 'StdDev should be > 0 for irregular intervals, got ' + stats.stdDevDays);
  });

  // --- detectPublishAnomaly (mocked fetchPackageMetadata) ---

  const temporalPath = require.resolve('../../src/scanner/temporal-analysis.js');
  const publishPath = require.resolve('../../src/integrations/publish-anomaly.js');

  async function withMockedFetch(mockFn, testFn) {
    const origFetch = require.cache[temporalPath].exports.fetchPackageMetadata;
    require.cache[temporalPath].exports.fetchPackageMetadata = mockFn;
    delete require.cache[publishPath];
    try {
      const mod = require(publishPath);
      await testFn(mod.detectPublishAnomaly);
    } finally {
      require.cache[temporalPath].exports.fetchPackageMetadata = origFetch;
      delete require.cache[publishPath];
    }
  }

  await asyncTest('PUBLISH: detectPublishAnomaly detects burst', async () => {
    const metadata = {
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.0.1': '2024-06-01T08:00:00Z',
        '1.0.2': '2024-06-01T12:00:00Z',
        '1.0.3': '2024-06-01T16:00:00Z',
        '1.0.4': '2024-06-01T20:00:00Z'
      },
      versions: { '1.0.0': {}, '1.0.1': {}, '1.0.2': {}, '1.0.3': {}, '1.0.4': {} }
    };
    await withMockedFetch(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      assert(result.packageName === 'test-pkg', 'Package name should match');
      const burst = result.anomalies.find(f => f.type === 'publish_burst');
      assert(burst, 'Should have publish_burst finding');
      assert(burst.severity === 'HIGH', 'Burst severity should be HIGH');
    });
  });

  await asyncTest('PUBLISH: detectPublishAnomaly detects dormant spike', async () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-03-01T00:00:00Z',
        '1.2.0': '2023-05-01T00:00:00Z',
        '2.0.0': '2024-06-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {}, '2.0.0': {} }
    };
    await withMockedFetch(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const dormant = result.anomalies.find(f => f.type === 'dormant_spike');
      assert(dormant, 'Should have dormant_spike finding');
      assert(dormant.severity === 'HIGH', 'Dormant severity should be HIGH');
    });
  });

  await asyncTest('PUBLISH: detectPublishAnomaly detects rapid succession', async () => {
    const metadata = {
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.1.0': '2024-06-01T00:00:00Z',
        '1.1.1': '2024-06-01T00:15:00Z',
        '1.1.2': '2024-06-01T00:30:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.1.1': {}, '1.1.2': {} }
    };
    await withMockedFetch(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const rapid = result.anomalies.find(f => f.type === 'rapid_succession');
      assert(rapid, 'Should have rapid_succession finding');
      assert(rapid.severity === 'MEDIUM', 'Rapid severity should be MEDIUM');
    });
  });

  await asyncTest('PUBLISH: detectPublishAnomaly normal → not suspicious', async () => {
    const metadata = {
      time: {
        '1.0.0': '2023-01-01T00:00:00Z',
        '1.1.0': '2023-04-01T00:00:00Z',
        '1.2.0': '2023-07-01T00:00:00Z',
        '1.3.0': '2023-10-01T00:00:00Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {}, '1.3.0': {} }
    };
    await withMockedFetch(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.anomalies.length === 0, 'Should have no anomalies');
      assert(result.stats.totalVersions === 4, 'Should have 4 versions');
    });
  });

  await asyncTest('PUBLISH: detectPublishAnomaly <3 versions → not suspicious', async () => {
    const metadata = {
      time: { '1.0.0': '2023-01-01T00:00:00Z', '1.0.1': '2023-02-01T00:00:00Z' },
      versions: { '1.0.0': {}, '1.0.1': {} }
    };
    await withMockedFetch(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.stats.totalVersions === 2, 'Should have 2 versions');
    });
  });

  await asyncTest('PUBLISH: detectPublishAnomaly fetch failure → graceful fallback', async () => {
    await withMockedFetch(async () => { throw new Error('Network error'); }, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious on error');
      assert(result.anomalies.length === 0, 'Should have no anomalies');
      assert(result.stats.totalVersions === 0, 'Should have 0 versions');
    });
  });

  await asyncTest('PUBLISH: detectPublishAnomaly missing time/versions → fallback', async () => {
    await withMockedFetch(async () => ({ name: 'test-pkg' }), async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.anomalies.length === 0, 'Should have no anomalies');
    });
  });

  // --- Rules and playbooks ---

  test('PUBLISH: Rules MUADDIB-PUBLISH-001/002/003 exist', () => {
    const { getRule } = require('../../src/rules/index.js');
    const r1 = getRule('publish_burst');
    assert(r1.id === 'MUADDIB-PUBLISH-001', 'publish_burst rule ID should be MUADDIB-PUBLISH-001, got ' + r1.id);
    assert(r1.severity === 'HIGH', 'publish_burst severity should be HIGH');

    const r2 = getRule('dormant_spike');
    assert(r2.id === 'MUADDIB-PUBLISH-002', 'dormant_spike rule ID should be MUADDIB-PUBLISH-002, got ' + r2.id);
    assert(r2.severity === 'HIGH', 'dormant_spike severity should be HIGH');

    const r3 = getRule('rapid_succession');
    assert(r3.id === 'MUADDIB-PUBLISH-003', 'rapid_succession rule ID should be MUADDIB-PUBLISH-003, got ' + r3.id);
    assert(r3.severity === 'MEDIUM', 'rapid_succession severity should be MEDIUM');
  });

  test('PUBLISH: Playbooks exist for publish anomaly threat types', () => {
    const { getPlaybook } = require('../../src/response/playbooks.js');
    const p1 = getPlaybook('publish_burst');
    assertIncludes(p1, 'versions', 'publish_burst playbook should mention versions');

    const p2 = getPlaybook('dormant_spike');
    assertIncludes(p2, 'dormant', 'dormant_spike playbook should mention dormant');

    const p3 = getPlaybook('rapid_succession');
    assertIncludes(p3, 'rapid', 'rapid_succession playbook should mention rapid');
  });

  // --- Integration test (network) ---

  const skipNetwork = process.env.SKIP_NETWORK === 'true' || process.env.CI === 'true';

  if (!skipNetwork) {
    await asyncTest('PUBLISH: detectPublishAnomaly on lodash returns valid structure', async () => {
      const result = await detectPublishAnomaly('lodash');
      assert(result.packageName === 'lodash', 'packageName should be lodash');
      assert(typeof result.suspicious === 'boolean', 'suspicious should be boolean');
      assert(Array.isArray(result.anomalies), 'anomalies should be array');
      assert(result.stats, 'stats should exist');
      assert(result.stats.totalVersions > 10, 'lodash should have many versions, got ' + result.stats.totalVersions);
      assert(result.stats.avgIntervalDays > 0, 'avgIntervalDays should be > 0');
      assert(result.stats.publishHistory.length === result.stats.totalVersions, 'History length should match totalVersions');
    });
  } else {
    console.log('[SKIP] PUBLISH network tests (SKIP_NETWORK=true or CI=true)');
    addSkipped(1);
  }
}

module.exports = { runPublishAnomalyTests };
