const fs = require('fs');
const path = require('path');
const os = require('os');
const { asyncTest, assert, runScanDirect, test } = require('../test-utils');
const {
  scanPythonSource,
  _internal: {
    stripPythonComments,
    stripTripleQuotedStrings,
    findTargetPythonFiles
  }
} = require('../../src/scanner/python-source.js');

const FIXTURES = path.join(__dirname, '..', 'samples', 'python-source');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pysrc-'));
}
function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

async function runPythonSourceTests() {
  console.log('\n=== PYTHON SOURCE SCANNER TESTS ===\n');

  // ---------- Module structure ----------

  test('PYSRC: scanner module exports scanPythonSource', () => {
    assert(typeof scanPythonSource === 'function', 'scanPythonSource should be a function');
  });

  // ---------- Helpers ----------

  test('PYSRC helper: stripPythonComments removes full-line comments only', () => {
    const input = '# pure comment\nx = 1  # inline kept\n  # indented comment\nprint(x)\n';
    const out = stripPythonComments(input);
    assert(!out.includes('# pure comment'), 'should remove full-line comment');
    assert(!out.includes('# indented comment'), 'should remove indented full-line comment');
    assert(out.includes('# inline kept'), 'should preserve inline trailing comment');
    assert(out.includes('print(x)'), 'should preserve code lines');
  });

  test('PYSRC helper: stripTripleQuotedStrings removes """ and \'\'\'', () => {
    const input = '"""module doc"""\nx = 1\n\'\'\'block string\'\'\'\nprint(x)\n';
    const out = stripTripleQuotedStrings(input);
    assert(!out.includes('module doc'), 'should remove """..."""');
    assert(!out.includes('block string'), 'should remove \'\'\'...\'\'\'');
    assert(out.includes('print(x)'), 'should preserve code');
  });

  test('PYSRC helper: findTargetPythonFiles picks up __init__.py + setup.py + src layout', () => {
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, '__init__.py'), '');
      fs.writeFileSync(path.join(tmp, 'setup.py'), '');
      fs.writeFileSync(path.join(tmp, 'module.py'), '');
      fs.mkdirSync(path.join(tmp, 'src', 'mypkg'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'src', 'mypkg', '__init__.py'), '');
      fs.mkdirSync(path.join(tmp, 'subpkg'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'subpkg', '__init__.py'), '');
      const targets = findTargetPythonFiles(tmp).map(p => path.relative(tmp, p).replace(/\\/g, '/'));
      assert(targets.includes('__init__.py'), `finds root __init__.py — got: ${targets.join(', ')}`);
      assert(targets.includes('setup.py'), 'finds setup.py');
      assert(targets.includes('module.py'), 'finds top-level .py');
      assert(targets.includes('src/mypkg/__init__.py'), 'finds src-layout __init__.py');
      assert(targets.includes('subpkg/__init__.py'), 'finds depth-1 __init__.py');
    } finally {
      cleanup(tmp);
    }
  });

  test('PYSRC helper: findTargetPythonFiles skips tests/ venv/ docs/ examples/', () => {
    const tmp = createTempDir();
    try {
      for (const skip of ['tests', 'venv', '.venv', 'docs', 'examples', '__pycache__', '.git']) {
        fs.mkdirSync(path.join(tmp, skip), { recursive: true });
        fs.writeFileSync(path.join(tmp, skip, '__init__.py'), 'exec("evil")\n');
      }
      const targets = findTargetPythonFiles(tmp);
      assert(targets.length === 0, `should skip excluded dirs, got: ${targets.join(', ')}`);
    } finally {
      cleanup(tmp);
    }
  });

  // ---------- Positive fixtures ----------

  async function expectThreatType(fixture, type) {
    const result = await runScanDirect(path.join(FIXTURES, fixture));
    const threat = result.threats.find(t => t.type === type);
    assert(threat, `${fixture}: expected threat type "${type}", got types: ${result.threats.map(t => t.type).join(', ')}`);
    return threat;
  }

  await asyncTest('PYSRC-001: import-time exec/eval fires on import-exec fixture', async () => {
    await expectThreatType('import-exec', 'import_time_exec');
  });

  await asyncTest('PYSRC-002: import-time subprocess fires on import-subprocess fixture', async () => {
    await expectThreatType('import-subprocess', 'import_time_subprocess');
  });

  await asyncTest('PYSRC-003: import-time os.system fires on import-os-system fixture', async () => {
    await expectThreatType('import-os-system', 'import_time_os_system');
  });

  await asyncTest('PYSRC-004: fetch+exec compound fires on trapdoor-mimic fixture', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'trapdoor-mimic'));
    const execThreat = result.threats.find(t => t.type === 'import_time_exec');
    const fetchExecThreat = result.threats.find(t => t.type === 'import_time_fetch_exec');
    assert(execThreat, 'should fire PYSRC-001 (exec)');
    assert(fetchExecThreat, 'should fire PYSRC-004 (fetch+exec compound)');
  });

  await asyncTest('PYSRC-005: base64+exec compound fires on base64-exec fixture', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'base64-exec'));
    const execThreat = result.threats.find(t => t.type === 'import_time_exec');
    const base64ExecThreat = result.threats.find(t => t.type === 'import_time_base64_exec');
    assert(execThreat, 'should fire PYSRC-001 (exec)');
    assert(base64ExecThreat, 'should fire PYSRC-005 (base64+exec compound)');
  });

  await asyncTest('PYSRC-006: pickle.loads fires on pickle-deser fixture', async () => {
    await expectThreatType('pickle-deser', 'import_time_deserialization');
  });

  await asyncTest('PYSRC-007: dynamic __import__ fires on dynamic-import fixture', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'dynamic-import'));
    const dynThreat = result.threats.find(t => t.type === 'dynamic_dangerous_import');
    assert(dynThreat, 'should fire PYSRC-007 (dynamic __import__ of subprocess)');
    // Note: PYSRC-002 does NOT fire here because the call is `_sp.Popen(...)` not
    // `subprocess.Popen(...)` — the literal "subprocess" name is hidden inside the
    // __import__ string. That is precisely the obfuscation pattern PYSRC-007 catches.
  });

  await asyncTest('PYSRC-008: ZW Unicode obfuscation fires on zw-unicode fixture', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'zw-unicode'));
    const zwThreat = result.threats.find(t => t.type === 'python_source_unicode_obfuscation');
    assert(zwThreat, 'should fire PYSRC-008 on file with >= 5 invisible Unicode chars');
    assert(zwThreat.severity === 'CRITICAL', 'PYSRC-008 should be CRITICAL');
  });

  // ---------- Negative fixtures (FP control) ----------

  async function expectNoPYSRC(fixture) {
    const result = await runScanDirect(path.join(FIXTURES, fixture));
    const pysrcThreats = result.threats.filter(t =>
      t.type === 'import_time_exec' ||
      t.type === 'import_time_subprocess' ||
      t.type === 'import_time_os_system' ||
      t.type === 'import_time_fetch_exec' ||
      t.type === 'import_time_base64_exec' ||
      t.type === 'import_time_deserialization' ||
      t.type === 'dynamic_dangerous_import' ||
      t.type === 'python_source_unicode_obfuscation'
    );
    assert(pysrcThreats.length === 0,
      `${fixture}: expected 0 PYSRC findings, got: ${pysrcThreats.map(t => t.type).join(', ')}`);
  }

  await asyncTest('PYSRC: no FP on clean __init__.py', async () => {
    await expectNoPYSRC('clean-init');
  });

  await asyncTest('PYSRC: no FP when exec/subprocess mentioned only in docstring', async () => {
    await expectNoPYSRC('docstring-mentions-exec');
  });

  await asyncTest('PYSRC: no FP on legitimate lazy-loading pattern (importlib)', async () => {
    await expectNoPYSRC('lazy-loading');
  });

  await asyncTest('PYSRC: no FP on legitimate setup.py with C extension', async () => {
    await expectNoPYSRC('setup-with-cext');
  });

  // ---------- Inline (no fixture) edge cases ----------

  await asyncTest('PYSRC: scanner returns [] on non-Python target', async () => {
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};\n');
      const threats = scanPythonSource(tmp);
      assert(threats.length === 0, 'should return empty when no .py files at root');
    } finally {
      cleanup(tmp);
    }
  });

  await asyncTest('PYSRC: scanner skips files > 1 MB', async () => {
    const tmp = createTempDir();
    try {
      // 1.1 MB file with exec() at module level
      const huge = 'x = 1\n'.repeat(180000) + 'exec("ignore")\n';
      fs.writeFileSync(path.join(tmp, '__init__.py'), huge);
      const threats = scanPythonSource(tmp);
      assert(threats.length === 0, 'should skip files over the 1 MB cap');
    } finally {
      cleanup(tmp);
    }
  });

  await asyncTest('PYSRC: Unicode normalization neutralizes ZW-split keywords in strings', async () => {
    // Note: Python rejects `e<U+200B>xec` as identifier (SyntaxError per PEP 3131),
    // so the realistic ZW vector is invisible chars hidden in strings/comments to
    // mislead grep + human review. We verify here that stripInvisibleUnicode is
    // applied before regex: if an attacker shipped a fake `setup.py` with
    // `e<U+200B>xec(payload)` it'd be a SyntaxError on install; what we WANT to
    // verify is that ZW-padded patterns inside our detection path still match.
    const tmp = createTempDir();
    try {
      const ZWSP = String.fromCodePoint(0x200B);
      const content = `import os${ZWSP}\nos.${ZWSP}system("echo synthetic")\n`;
      fs.writeFileSync(path.join(tmp, '__init__.py'), content);
      const threats = scanPythonSource(tmp);
      const ossys = threats.find(t => t.type === 'import_time_os_system');
      assert(ossys, 'should detect os.system even with ZW chars interspersed (post-normalization)');
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // PYSRC-009 / 010 — fork-exec inline interpreter (TrapDoor gap, v2.11.46)
  // =========================================================================

  await asyncTest('PYSRC-009: subprocess.run(["node", "-e", ...]) fires HIGH', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'fork-exec-node-e'));
    const t = result.threats.find(t => t.type === 'fork_exec_inline_interpreter');
    assert(t, 'PYSRC-009 should fire on node -e fork-exec');
    assert(t.severity === 'HIGH', `expected HIGH, got ${t.severity}`);
  });

  await asyncTest('PYSRC-010: fetch + fork-exec compound fires CRITICAL (TrapDoor signature)', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'trapdoor-fetch-fork-exec'));
    const atomic = result.threats.find(t => t.type === 'fork_exec_inline_interpreter');
    const compound = result.threats.find(t => t.type === 'fetch_to_fork_exec_inline');
    assert(atomic, 'PYSRC-009 should also fire (atomic + compound coexist)');
    assert(compound, 'PYSRC-010 (fetch + fork-exec compound) should fire');
    assert(compound.severity === 'CRITICAL', `expected CRITICAL, got ${compound.severity}`);
  });

  await asyncTest('PYSRC-009: bash -c variant fires', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'fork-exec-bash-c'));
    const t = result.threats.find(t => t.type === 'fork_exec_inline_interpreter');
    assert(t, 'PYSRC-009 should fire on bash -c fork-exec');
  });

  await asyncTest('PYSRC-009: python -c variant fires', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'fork-exec-python-c'));
    const t = result.threats.find(t => t.type === 'fork_exec_inline_interpreter');
    assert(t, 'PYSRC-009 should fire on python -c fork-exec');
  });

  await asyncTest('PYSRC-009: subprocess.run(["node", "script.js"]) without inline flag — no fire', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'subprocess-script-not-inline'));
    const t = result.threats.find(t => t.type === 'fork_exec_inline_interpreter');
    assert(!t,
      'PYSRC-009 should NOT fire when the list cmd has no inline flag (-e/-c); ' +
      'running a real script file is not the targeted pattern.');
  });

  await asyncTest('PYSRC-009: subprocess shell=True with string cmd — no PYSRC-009 fire', async () => {
    const result = await runScanDirect(path.join(FIXTURES, 'subprocess-no-list-cmd'));
    const t = result.threats.find(t => t.type === 'fork_exec_inline_interpreter');
    assert(!t,
      'PYSRC-009 targets the list-form `["node", "-e", code]`. String cmd via shell=True ' +
      'is handled by PYAST-004 separately, so PYSRC-009 must not fire here.');
  });

  await asyncTest('PYSRC-009: ruby -e and perl -e variants fire', async () => {
    const { _internal } = require('../../src/scanner/python-source.js');
    const { detectForkExecInlineInterpreter } = _internal;
    assert(detectForkExecInlineInterpreter('subprocess.run(["ruby", "-e", "puts 1"])\n'),
      'ruby -e should fire');
    assert(detectForkExecInlineInterpreter('subprocess.run(["perl", "-e", "print 1"])\n'),
      'perl -e should fire');
    assert(detectForkExecInlineInterpreter('subprocess.Popen(["php", "-r", "echo 1;"])\n'),
      'php -r should fire');
    assert(detectForkExecInlineInterpreter('subprocess.run(["powershell", "-c", "Get-Date"])\n'),
      'powershell -c should fire');
    assert(!detectForkExecInlineInterpreter('subprocess.run(["node", "build.js"])\n'),
      'node + script (no flag) should NOT fire');
    assert(!detectForkExecInlineInterpreter('subprocess.run(["unknown_tool", "-e", "x"])\n'),
      'unknown interpreter should NOT fire');
  });

  // ---------- Anti-evasion — PyPI parity for AST-096 (M2 follow-up, 2026-07) ----------

  test('PYSRC anti-evasion: detectPythonEnvMarkerEnumeration — enum + MUADDIB prefix fires, direct read does not', () => {
    const { _internal } = require('../../src/scanner/python-source.js');
    const { detectPythonEnvMarkerEnumeration } = _internal;
    assert(detectPythonEnvMarkerEnumeration("for k in os.environ:\n  if k.startswith('MUADDIB'): raise SystemExit"),
      'enum (for-in) + startswith(MUADDIB) should fire');
    assert(detectPythonEnvMarkerEnumeration("bad = [k for k in os.environ if 'MUADDIB_GVISOR' in k]"),
      'comprehension enum + MUADDIB membership should fire');
    assert(!detectPythonEnvMarkerEnumeration("DATA = os.environ.get('MUADDIB_DATA', '/opt/muaddib/data')"),
      "direct config read of a MUADDIB_* var (no enumeration) must NOT fire — MUAD'DIB tooling does exactly this");
    assert(!detectPythonEnvMarkerEnumeration("for k in os.environ:\n  print(k)"),
      'env enumeration without a MUADDIB marker test must NOT fire');
  });

  test('PYSRC anti-evasion: base64-encoded MUADDIB_GVISOR in __init__.py → analyzer_honeytoken_reference (CRITICAL)', () => {
    const tmp = createTempDir();
    try {
      const b64 = Buffer.from('MUADDIB_GVISOR').toString('base64');
      fs.writeFileSync(path.join(tmp, '__init__.py'), "import base64\np = base64.b64decode('" + b64 + "')\n");
      const t = scanPythonSource(tmp).find(x => x.type === 'analyzer_honeytoken_reference');
      assert(t && t.severity === 'CRITICAL', 'should emit CRITICAL analyzer_honeytoken_reference for the encoded marker');
    } finally { cleanup(tmp); }
  });

  test('PYSRC anti-evasion: os.environ enum for MUADDIB in setup.py → analyzer_honeytoken_reference', () => {
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, 'setup.py'),
        'import os, sys\nif any(k.startswith("MUADDIB") for k in os.environ):\n    sys.exit(0)\n');
      const t = scanPythonSource(tmp).find(x => x.type === 'analyzer_honeytoken_reference');
      assert(t, 'should emit analyzer_honeytoken_reference for os.environ enumeration testing a MUADDIB prefix');
    } finally { cleanup(tmp); }
  });

  test('PYSRC anti-evasion: legit MUADDIB_DATA config read → NO analyzer_honeytoken_reference (self-FP guard)', () => {
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, '__init__.py'),
        'import os\nMUADDIB_DATA = os.environ.get("MUADDIB_DATA", "/opt/muaddib/data")\nprint(MUADDIB_DATA)\n');
      const t = scanPythonSource(tmp).find(x => x.type === 'analyzer_honeytoken_reference');
      assert(!t, "a direct os.environ.get(MUADDIB_DATA) config read must NOT be flagged — this is exactly what MUAD'DIB's own tooling does");
    } finally { cleanup(tmp); }
  });

  test('PYSRC anti-evasion: legit container detection via /proc → NO analyzer_honeytoken_reference (gVisor-FP class blind spot)', () => {
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, '__init__.py'),
        'IS_CT = False\ntry:\n    with open("/proc/1/cgroup") as f:\n        data = f.read()\n        IS_CT = "docker" in data or "gvisor" in data\nexcept OSError:\n    pass\n');
      const t = scanPythonSource(tmp).find(x => x.type === 'analyzer_honeytoken_reference');
      assert(!t, 'legit container detection reading /proc + checking docker/gvisor must NOT fire — documented blind spot (the Python gVisor-FP class)');
    } finally { cleanup(tmp); }
  });
}

module.exports = { runPythonSourceTests };
