'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { asyncTest, assert, runScanDirect, test } = require('../test-utils');

const FIXTURES = path.join(__dirname, '..', 'samples', 'python-ast');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyast-'));
}
function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

async function runPythonAstTests() {
  console.log('\n=== PYTHON AST SCANNER TESTS ===\n');

  // ---------- Module + init ----------

  test('PYAST: module exports initPythonParser + scanPythonAST', () => {
    const m = require('../../src/scanner/python-ast.js');
    assert(typeof m.initPythonParser === 'function', 'initPythonParser missing');
    assert(typeof m.scanPythonAST === 'function', 'scanPythonAST missing');
  });

  await asyncTest('PYAST: initPythonParser loads WASM successfully', async () => {
    const { initPythonParser } = require('../../src/scanner/python-ast.js');
    const parser = await initPythonParser();
    assert(parser !== null, 'parser init returned null — WASM load failed');
  });

  // ---------- WASM provenance / SHA-256 audit ----------

  test('PYAST: vendored WASM SHA-256 matches sha256 file', () => {
    const wasmPath = path.join(__dirname, '..', '..', 'src', 'vendor', 'tree-sitter-python.wasm');
    const sha256File = path.join(__dirname, '..', '..', 'src', 'vendor', 'tree-sitter-python.wasm.sha256');
    assert(fs.existsSync(wasmPath), 'WASM not found at src/vendor/tree-sitter-python.wasm');
    assert(fs.existsSync(sha256File), 'SHA-256 file not found');

    const wasmBuf = fs.readFileSync(wasmPath);
    const computed = crypto.createHash('sha256').update(wasmBuf).digest('hex');
    const recorded = fs.readFileSync(sha256File, 'utf8').trim().split(/\s+/)[0];

    assert(
      computed === recorded,
      `WASM hash mismatch — expected ${recorded}, computed ${computed}. If you intentionally updated the WASM, also update tree-sitter-python.wasm.sha256.`
    );
  });

  // ---------- Per-rule positive fixtures (via runScanDirect — full pipeline) ----------

  async function expectThreatTypeFromFixture(fixture, type) {
    const result = await runScanDirect(path.join(FIXTURES, fixture));
    const found = result.threats.find(t => t.type === type);
    assert(found, `${fixture}: expected threat "${type}", got: ${result.threats.map(t => t.type).join(', ')}`);
    return found;
  }

  await asyncTest('PYAST-001: cmdclass override fires CRITICAL', async () => {
    const t = await expectThreatTypeFromFixture('cmdclass-override', 'pyast_setup_cmdclass_override');
    assert(t.severity === 'CRITICAL', `expected CRITICAL (install command), got ${t.severity}`);
  });

  await asyncTest('PYAST-001: cmdclass-legit (build_ext only) fires HIGH not CRITICAL', async () => {
    const t = await expectThreatTypeFromFixture('cmdclass-legit', 'pyast_setup_cmdclass_override');
    assert(t.severity === 'HIGH', `expected HIGH (build_ext only), got ${t.severity}`);
  });

  await asyncTest('PYAST-002: suspicious entry_points fires HIGH', async () => {
    const t = await expectThreatTypeFromFixture('entry-points-sus', 'pyast_setup_entry_points_suspicious');
    assert(t.severity === 'HIGH', `expected HIGH, got ${t.severity}`);
  });

  await asyncTest('PYAST-003: exec at module level fires CRITICAL', async () => {
    const t = await expectThreatTypeFromFixture('module-exec', 'pyast_module_level_exec');
    assert(t.severity === 'CRITICAL', `expected CRITICAL, got ${t.severity}`);
  });

  await asyncTest('PYAST-004: subprocess shell=True at module level fires CRITICAL', async () => {
    const t = await expectThreatTypeFromFixture('subprocess-shell', 'pyast_module_level_subprocess_shell');
    assert(t.severity === 'CRITICAL', `expected CRITICAL, got ${t.severity}`);
  });

  await asyncTest('PYAST-007: pickle.loads at module level fires CRITICAL', async () => {
    const t = await expectThreatTypeFromFixture('pickle-deser', 'pyast_module_level_unsafe_deserialization');
    assert(t.severity === 'CRITICAL', `expected CRITICAL, got ${t.severity}`);
  });

  await asyncTest('PYAST-008: __import__(subprocess) fires HIGH', async () => {
    const t = await expectThreatTypeFromFixture('dynamic-import', 'pyast_dynamic_dangerous_import');
    assert(t.severity === 'HIGH', `expected HIGH, got ${t.severity}`);
  });

  // ---------- Scope precision — the value-add over PYSRC regex ----------

  await asyncTest('PYAST-003: exec inside a function (not module level) does NOT fire', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'scoped-exec-safe'));
    const found = result.threats.find(t => t.type === 'pyast_module_level_exec');
    assert(!found, 'PYAST-003 should NOT fire on exec inside a function body');
    // Note: PYSRC-001 (regex) DOES fire on this fixture. That's the regex limitation
    // we are deliberately compensating for with the AST scanner. Both coexist.
  });

  // ---------- FP control on clean / legit fixtures ----------

  await asyncTest('PYAST: clean __init__.py — no PYAST fires', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'clean-init'));
    const pyastThreats = result.threats.filter(t => t.type.startsWith('pyast_'));
    assert(pyastThreats.length === 0,
      `clean-init: expected 0 PYAST fires, got: ${pyastThreats.map(t => t.type).join(', ')}`);
  });

  await asyncTest('PYAST: legit entry_points (normal CLI names) — no PYAST fires', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'entry-points-legit'));
    const pyastThreats = result.threats.filter(t => t.type.startsWith('pyast_'));
    assert(pyastThreats.length === 0,
      `entry-points-legit: expected 0 PYAST fires, got: ${pyastThreats.map(t => t.type).join(', ')}`);
  });

  // ---------- Direct API tests (bypass full pipeline) ----------

  await asyncTest('PYAST: scanPythonAST returns [] on non-Python target', async () => {
    const { initPythonParser, scanPythonAST } = require('../../src/scanner/python-ast.js');
    await initPythonParser();
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};\n');
      const threats = scanPythonAST(tmp);
      assert(threats.length === 0, 'should return [] when no .py present');
    } finally {
      cleanup(tmp);
    }
  });

  await asyncTest('PYAST: scanPythonAST does NOT crash on syntactically broken Python', async () => {
    const { initPythonParser, scanPythonAST } = require('../../src/scanner/python-ast.js');
    await initPythonParser();
    const tmp = createTempDir();
    try {
      // tree-sitter is error-tolerant by design (produces partial trees with
      // ERROR nodes). Make sure we don't crash on garbage input.
      fs.writeFileSync(path.join(tmp, '__init__.py'), 'def broken( :\n  if 3 = =\n');
      const threats = scanPythonAST(tmp);
      assert(Array.isArray(threats), 'should return an array even on broken input');
    } finally {
      cleanup(tmp);
    }
  });

  await asyncTest('PYAST: setup() called from inside a function does NOT fire (FP control)', async () => {
    const { initPythonParser, scanPythonAST } = require('../../src/scanner/python-ast.js');
    await initPythonParser();
    const tmp = createTempDir();
    try {
      // A helper named setup() inside a function with cmdclass-shaped args
      // would FP-fire on a naive regex scanner. AST + scope check makes sure
      // we only flag setuptools' real setup() at module level in setup.py.
      fs.writeFileSync(path.join(tmp, 'setup.py'),
        'def configure():\n    return setup(name="x", cmdclass={"install": object})\n');
      const threats = scanPythonAST(tmp);
      const cmdclass = threats.filter(t => t.type === 'pyast_setup_cmdclass_override');
      assert(cmdclass.length === 0,
        `setup() inside a function: expected 0 cmdclass fires, got ${cmdclass.length}`);
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // Phase 1b — taint-aware detectors (PYAST-005, 006, 009, 010)
  // =========================================================================

  await asyncTest('PYAST-005: fetch → exec taint fires CRITICAL', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'trapdoor-fetch-exec'));
    const exec3 = result.threats.find(t => t.type === 'pyast_module_level_exec');
    const taint5 = result.threats.find(t => t.type === 'pyast_fetch_to_exec_taint');
    assert(exec3, 'PYAST-003 (module-level exec) should still fire as baseline');
    assert(taint5, 'PYAST-005 (fetch+exec taint compound) should fire');
    assert(taint5.severity === 'CRITICAL', `PYAST-005 expected CRITICAL, got ${taint5.severity}`);
  });

  await asyncTest('PYAST-006: base64 → exec taint fires CRITICAL', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'base64-exec-taint'));
    const taint6 = result.threats.find(t => t.type === 'pyast_base64_to_exec_taint');
    assert(taint6, 'PYAST-006 should fire on base64→exec compound');
    assert(taint6.severity === 'CRITICAL', `PYAST-006 expected CRITICAL, got ${taint6.severity}`);
  });

  await asyncTest('PYAST-010: env (sensitive) → network POST fires CRITICAL', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'env-token-exfil'));
    const exfil = result.threats.find(t => t.type === 'pyast_env_to_network_write');
    assert(exfil, 'PYAST-010 should fire on env-token+POST');
    assert(exfil.severity === 'CRITICAL', `expected CRITICAL (sensitive env name GITHUB_TOKEN), got ${exfil.severity}`);
  });

  await asyncTest('PYAST-010: env (non-sensitive) → network POST fires HIGH', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'env-flag-exfil'));
    const exfil = result.threats.find(t => t.type === 'pyast_env_to_network_write');
    assert(exfil, 'PYAST-010 should still fire on non-sensitive env name (defense in depth)');
    assert(exfil.severity === 'HIGH', `expected HIGH (non-sensitive env name MY_FEATURE_FLAG), got ${exfil.severity}`);
  });

  await asyncTest('PYAST-009: ctypes literal suspicious path fires HIGH', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'ctypes-tmp-path'));
    const ctypes = result.threats.find(t => t.type === 'pyast_ctypes_shellcode_load');
    assert(ctypes, 'PYAST-009 should fire on ctypes.CDLL("/tmp/...")');
    assert(ctypes.severity === 'HIGH', `expected HIGH, got ${ctypes.severity}`);
  });

  await asyncTest('PYAST-009: ctypes with tainted-fetch arg fires HIGH', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'ctypes-tainted-fetch'));
    const ctypes = result.threats.find(t => t.type === 'pyast_ctypes_shellcode_load');
    assert(ctypes, 'PYAST-009 should fire when ctypes arg was assigned from a fetch');
  });

  // ---------- Phase 1b negatives ----------

  await asyncTest('PYAST-005: reassignment clears taint (no PYAST-005, but PYAST-003 still fires)', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'reassignment-cleared'));
    const taint5 = result.threats.find(t => t.type === 'pyast_fetch_to_exec_taint');
    const exec3 = result.threats.find(t => t.type === 'pyast_module_level_exec');
    assert(!taint5, 'PYAST-005 must NOT fire after reassignment clears the taint');
    assert(exec3, 'PYAST-003 (module-level exec) still fires regardless of taint');
  });

  await asyncTest('PYAST-005: V1 documented limitation — multi-hop alias NOT detected', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'multi-hop-not-detected'));
    const taint5 = result.threats.find(t => t.type === 'pyast_fetch_to_exec_taint');
    assert(!taint5,
      'V1 of the taint tracker does NOT propagate across `a = src(); b = a; sink(b)`. ' +
      'If this test starts failing, the implementation grew multi-hop support — bump to Phase 3.');
  });

  await asyncTest('PYAST-009: legit ctypes (system lib path) does NOT fire', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'ctypes-legit-lib'));
    const ctypes = result.threats.find(t => t.type === 'pyast_ctypes_shellcode_load');
    assert(!ctypes, 'ctypes.CDLL("libssl.so") / ctypes.CDLL("/usr/lib/libc.so") are legit, must NOT fire');
  });

  await asyncTest('PYAST-010: env read without network sink does NOT fire', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'env-no-network'));
    const exfil = result.threats.find(t => t.type === 'pyast_env_to_network_write');
    assert(!exfil, 'reading os.environ without POSTing it must NOT fire PYAST-010');
  });

  // ---------- Taint tracker unit tests (direct API) ----------

  await asyncTest('PYAST taint: classifyTaintSource detects fetch chains', async () => {
    const tsModule = require('web-tree-sitter');
    await tsModule.Parser.init();
    const lang = await tsModule.Language.load(
      path.join(__dirname, '..', '..', 'src', 'vendor', 'tree-sitter-python.wasm')
    );
    const parser = new tsModule.Parser();
    parser.setLanguage(lang);
    const { classifyTaintSource } = require('../../src/scanner/python-ast-detectors/taint-tracker.js');

    function rhsOf(src) {
      const tree = parser.parse(src);
      return tree.rootNode.firstChild.firstChild.childForFieldName('right');
    }

    assert(classifyTaintSource(rhsOf('x = requests.get("u").text')).sourceType === 'fetch',
      'requests.get(...).text should classify as fetch');
    assert(classifyTaintSource(rhsOf('x = base64.b64decode(b"a")')).sourceType === 'base64',
      'base64.b64decode should classify as base64');
    const env = classifyTaintSource(rhsOf('x = os.environ["NPM_TOKEN"]'));
    assert(env.sourceType === 'env' && env.envVarName === 'NPM_TOKEN',
      'os.environ["NPM_TOKEN"] should classify as env with name NPM_TOKEN');
    assert(classifyTaintSource(rhsOf('x = "harmless"')) === null,
      'plain string literal should not classify');
  });
}

module.exports = { runPythonAstTests };
