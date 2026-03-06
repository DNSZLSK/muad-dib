const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-bypass-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-bypass-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

function hasType(result, type) {
  return (result.threats || []).some(t => t.type === type);
}

function hasSeverity(result, severity) {
  return (result.threats || []).some(t => t.severity === severity);
}

async function runAstBypassRegressionTests() {
  console.log('\n=== AST BYPASS REGRESSION TESTS ===\n');
  // These tests document known bypasses that are NOT YET detected.
  // When detection is added (Batch 1), flip assert(!detected) to assert(detected).

  await asyncTest('BYPASS-REG: vm.runInThisContext(payload) — not yet detected', async () => {
    const tmp = makeTempPkg(`
const vm = require('vm');
const payload = Buffer.from('Y29uc29sZS5sb2coImV4ZWMiKQ==', 'base64').toString();
vm.runInThisContext(payload);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'vm_code_execution') || hasType(result, 'dangerous_call_function');
      // CURRENT: not detected — flip when Batch 1 adds vm detection
      assert(!detected, 'vm.runInThisContext bypass should NOT be detected yet (flip when fixed)');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: vm.runInNewContext(code, ctx) — not yet detected', async () => {
    const tmp = makeTempPkg(`
const vm = require('vm');
const code = 'process.env.SECRET';
const ctx = { process };
vm.runInNewContext(code, ctx);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'vm_code_execution') || hasType(result, 'dangerous_call_function');
      assert(!detected, 'vm.runInNewContext bypass should NOT be detected yet (flip when fixed)');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: Reflect.construct(Function, [code]) — not yet detected', async () => {
    const tmp = makeTempPkg(`
const code = 'return process.env.SECRET';
const fn = Reflect.construct(Function, [code]);
fn();
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_code_execution') || hasType(result, 'dangerous_call_function');
      assert(!detected, 'Reflect.construct(Function) bypass should NOT be detected yet (flip when fixed)');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: Reflect.apply(eval, null, [code]) — not yet detected', async () => {
    const tmp = makeTempPkg(`
const code = 'process.env.SECRET';
Reflect.apply(eval, null, [code]);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_code_execution') || hasType(result, 'dangerous_call_function');
      assert(!detected, 'Reflect.apply(eval) bypass should NOT be detected yet (flip when fixed)');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: process.binding("spawn_sync") — not yet detected', async () => {
    const tmp = makeTempPkg(`
const binding = process.binding('spawn_sync');
binding.spawn({ file: '/bin/sh', args: ['-c', 'whoami'] });
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'process_binding_abuse') || hasType(result, 'dangerous_call_function');
      assert(!detected, 'process.binding bypass should NOT be detected yet (flip when fixed)');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: process._linkedBinding("spawn_sync") — not yet detected', async () => {
    const tmp = makeTempPkg(`
const binding = process._linkedBinding('spawn_sync');
binding.spawn({ file: '/bin/sh', args: ['-c', 'id'] });
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'process_binding_abuse') || hasType(result, 'dangerous_call_function');
      assert(!detected, 'process._linkedBinding bypass should NOT be detected yet (flip when fixed)');
    } finally {
      cleanupTemp(tmp);
    }
  });
}

module.exports = { runAstBypassRegressionTests };
