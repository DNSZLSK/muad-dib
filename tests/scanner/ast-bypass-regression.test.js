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
  // These tests document bypasses that are NOW detected (Batch 1).

  await asyncTest('BYPASS-REG: vm.runInThisContext(payload) — detected', async () => {
    const tmp = makeTempPkg(`
const vm = require('vm');
const payload = Buffer.from('Y29uc29sZS5sb2coImV4ZWMiKQ==', 'base64').toString();
vm.runInThisContext(payload);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'vm_code_execution');
      assert(detected, 'vm.runInThisContext should be detected as vm_code_execution');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: vm.runInNewContext(code, ctx) — detected', async () => {
    const tmp = makeTempPkg(`
const vm = require('vm');
const code = 'process.env.SECRET';
const ctx = { process };
vm.runInNewContext(code, ctx);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'vm_code_execution');
      assert(detected, 'vm.runInNewContext should be detected as vm_code_execution');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: Reflect.construct(Function, [code]) — detected', async () => {
    const tmp = makeTempPkg(`
const code = 'return process.env.SECRET';
const fn = Reflect.construct(Function, [code]);
fn();
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_code_execution');
      assert(detected, 'Reflect.construct(Function) should be detected as reflect_code_execution');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: Reflect.apply(eval, null, [code]) — detected', async () => {
    const tmp = makeTempPkg(`
const code = 'process.env.SECRET';
Reflect.apply(eval, null, [code]);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_code_execution');
      assert(detected, 'Reflect.apply(eval) should be detected as reflect_code_execution');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: process.binding("spawn_sync") — detected', async () => {
    const tmp = makeTempPkg(`
const binding = process.binding('spawn_sync');
binding.spawn({ file: '/bin/sh', args: ['-c', 'whoami'] });
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'process_binding_abuse');
      assert(detected, 'process.binding("spawn_sync") should be detected as process_binding_abuse');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG: process._linkedBinding("spawn_sync") — detected', async () => {
    const tmp = makeTempPkg(`
const binding = process._linkedBinding('spawn_sync');
binding.spawn({ file: '/bin/sh', args: ['-c', 'id'] });
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'process_binding_abuse');
      assert(detected, 'process._linkedBinding("spawn_sync") should be detected as process_binding_abuse');
    } finally {
      cleanupTemp(tmp);
    }
  });
}

module.exports = { runAstBypassRegressionTests };
