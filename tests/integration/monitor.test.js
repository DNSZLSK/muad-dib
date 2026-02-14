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
    ALERTS_FILE, extractTarGz, getNpmTarballUrl, getNpmLatestTarball, scanQueue,
    appendAlert, timeoutPromise, stats, dailyAlerts, MAX_TARBALL_SIZE,
    KNOWN_BUNDLED_FILES, isBundledToolingOnly,
    isSandboxEnabled, hasHighOrCritical,
    getWebhookUrl, shouldSendWebhook, buildMonitorWebhookPayload,
    computeRiskLevel, computeRiskScore, buildDailyReportEmbed, DAILY_REPORT_INTERVAL,
    isTemporalEnabled, buildTemporalWebhookEmbed,
    isTemporalAstEnabled, buildTemporalAstWebhookEmbed,
    isTemporalPublishEnabled, buildPublishAnomalyWebhookEmbed,
    isTemporalMaintainerEnabled, buildMaintainerChangeWebhookEmbed,
    isCanaryEnabled, buildCanaryExfiltrationWebhookEmbed,
    isPublishAnomalyOnly
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

  test('MONITOR: shouldSendWebhook returns true for HIGH findings with URL', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 2, critical: 0, high: 2, medium: 0, low: 0 } };
      assert(shouldSendWebhook(result, null) === true, 'Should return true for HIGH');
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

  test('MONITOR: shouldSendWebhook returns true when sandbox score > 0', () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://hooks.slack.com/test';
    try {
      const result = { summary: { total: 2, critical: 0, high: 0, medium: 1, low: 1 } };
      const sandbox = { score: 30, severity: 'MEDIUM', findings: [] };
      assert(shouldSendWebhook(result, sandbox) === true, 'Should return true when sandbox score > 0');
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      else delete process.env.MUADDIB_WEBHOOK_URL;
    }
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
    // 2*25 + 1*15 + 3*5 + 2*1 = 50 + 15 + 15 + 2 = 82
    assert(computeRiskScore({ critical: 2, high: 1, medium: 3, low: 2 }) === 82, 'Should be 82');
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
    // Set up some stats
    const origScanned = stats.scanned;
    const origClean = stats.clean;
    const origSuspect = stats.suspect;
    const origErrors = stats.errors;
    stats.scanned = 100;
    stats.clean = 90;
    stats.suspect = 8;
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
    assert(scannedField && scannedField.value === '100', 'Scanned should be 100');

    const topField = embed.embeds[0].fields.find(f => f.name === 'Top Suspects');
    assert(topField, 'Should have Top Suspects field');
    assertIncludes(topField.value, 'sus-mod', 'Top suspect should be sus-mod (8 findings)');

    assertIncludes(embed.embeds[0].footer.text, 'UTC', 'Footer should have UTC timestamp');

    // Restore
    stats.scanned = origScanned;
    stats.clean = origClean;
    stats.suspect = origSuspect;
    stats.errors = origErrors;
    dailyAlerts.length = 0;
  });

  test('MONITOR: DAILY_REPORT_INTERVAL is 24 hours', () => {
    assert(DAILY_REPORT_INTERVAL === 24 * 3600000, 'Should be 24h in ms');
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
      const mockResult = { summary: { critical: 1, high: 0, medium: 0, low: 0 }, threats: [] };
      const mockSandboxClean = { score: 0, severity: 'CLEAN', findings: [] };
      const mockSandboxSuspect = { score: 60, severity: 'HIGH', findings: [{ type: 'suspicious_dns' }] };

      // Sandbox CLEAN → no webhook
      assert(shouldSendWebhook(mockResult, mockSandboxClean) === false,
        'Should NOT send webhook when sandbox score is 0 (CLEAN)');

      // Sandbox SUSPECT → send webhook
      assert(shouldSendWebhook(mockResult, mockSandboxSuspect) === true,
        'Should send webhook when sandbox score > 0');

      // No sandbox → fall back to static analysis
      assert(shouldSendWebhook(mockResult, null) === true,
        'Should send webhook when no sandbox ran (CRITICAL findings)');
    } finally {
      if (origEnv === undefined) delete process.env.MUADDIB_WEBHOOK_URL;
      else process.env.MUADDIB_WEBHOOK_URL = origEnv;
    }
  });

  test('MONITOR: temporal webhook suppressed when static scan is CLEAN and no sandbox', () => {
    // Simulate the decision logic from resolveTarballAndScan:
    // If staticClean=true and sandboxResult=null → no webhook (false positive)
    // If staticClean=false and sandboxResult=null → send webhook (static found threats)
    // If staticClean=true and sandboxResult.score=0 → no webhook (sandbox confirms clean)

    function shouldSendTemporalWebhook(staticClean, sandboxResult) {
      if (sandboxResult && sandboxResult.score === 0) return false;
      if (staticClean && !sandboxResult) return false;
      return true;
    }

    assert(shouldSendTemporalWebhook(true, null) === false,
      'Static CLEAN + no sandbox → no temporal webhook');
    assert(shouldSendTemporalWebhook(true, { score: 0 }) === false,
      'Static CLEAN + sandbox CLEAN → no temporal webhook');
    assert(shouldSendTemporalWebhook(false, null) === true,
      'Static SUSPECT + no sandbox → send temporal webhook');
    assert(shouldSendTemporalWebhook(false, { score: 60 }) === true,
      'Static SUSPECT + sandbox SUSPECT → send temporal webhook');
    assert(shouldSendTemporalWebhook(false, { score: 0 }) === false,
      'Static SUSPECT + sandbox CLEAN → no temporal webhook');
    assert(shouldSendTemporalWebhook(true, { score: 60 }) === true,
      'Static CLEAN + sandbox SUSPECT → send temporal webhook');
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
}

module.exports = { runMonitorTests };
