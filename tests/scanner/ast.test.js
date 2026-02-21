const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-ast-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runAstTests() {
  console.log('\n=== AST TESTS ===\n');

  test('AST: Detects .npmrc access', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, '.npmrc', 'Should detect .npmrc');
  });

  test('AST: Detects .ssh access', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, '.ssh', 'Should detect .ssh');
  });

  test('AST: Detects GITHUB_TOKEN', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'GITHUB_TOKEN', 'Should detect GITHUB_TOKEN');
  });

  test('AST: Detects NPM_TOKEN', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'NPM_TOKEN', 'Should detect NPM_TOKEN');
  });

  test('AST: Detects AWS_SECRET', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'AWS_SECRET', 'Should detect AWS_SECRET');
  });

  test('AST: Detects eval()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'eval', 'Should detect eval');
  });

  test('AST: Detects exec()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'exec', 'Should detect exec');
  });

  test('AST: Detects new Function()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'Function', 'Should detect Function');
  });

  test('AST: Dynamic env access flagged as MEDIUM', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
    const result = JSON.parse(output);
    const dynamicEnv = result.threats.find(t => t.type === 'env_access' && t.severity === 'MEDIUM');
    assert(dynamicEnv, 'Dynamic process.env[var] should be MEDIUM');
  });

  // --- Indirect eval detection tests (P0-1, v2.2.13) ---

  await asyncTest('AST: Detects computed eval obj["eval"](x)', async () => {
    const tmp = makeTempPkg('const x = "code"; globalThis["eval"](x);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('computed property'));
      assert(t, 'Should detect obj["eval"]() as dangerous_call_eval');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects computed Function obj["Function"](x)', async () => {
    const tmp = makeTempPkg('const x = "return 1"; globalThis["Function"](x)();');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_function' && t.message.includes('computed property'));
      assert(t, 'Should detect obj["Function"]() as dangerous_call_function');
      assert(t.severity === 'MEDIUM', 'Should be MEDIUM severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects sequence eval (0, eval)(x)', async () => {
    const tmp = makeTempPkg('const x = "code"; (0, eval)(x);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('sequence expression'));
      assert(t, 'Should detect (0, eval)() as dangerous_call_eval');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects sequence Function (0, Function)(x)', async () => {
    const tmp = makeTempPkg('const x = "return 1"; (0, Function)(x);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_function' && t.message.includes('sequence expression'));
      assert(t, 'Should detect (0, Function)() as dangerous_call_function');
      assert(t.severity === 'MEDIUM', 'Should be MEDIUM severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects globalThis alias + variable computed call g[k]()', async () => {
    const tmp = makeTempPkg('const g = globalThis;\nconst k = "eval";\ng[k]("code");');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('Dynamic global dispatch'));
      assert(t, 'Should detect globalThis alias + variable computed call as dangerous_call_eval');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: No false positive for obj["toString"]()', async () => {
    const tmp = makeTempPkg('const obj = {};\nobj["toString"]();\nobj["hasOwnProperty"]("x");');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' || t.type === 'dangerous_call_function');
      assert(!t, 'obj["toString"]() should NOT trigger dangerous_call_eval/function');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects .mjs file with eval', async () => {
    const tmp = makeTempPkg('eval("code");', 'index.mjs');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should detect eval in .mjs file');
      assert(t.file === 'index.mjs', 'File should be index.mjs');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runAstTests };
