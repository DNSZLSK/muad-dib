'use strict';

// PYAST-001 parity for pyproject.toml [tool.setuptools.cmdclass] (pybitjs@0.1.0, 2026-08)
// and the F8 obfuscation_without_vector cap that ignored every PyPI execution vector.

const fs = require('fs');
const path = require('path');
const os = require('os');
const { asyncTest, assert, test } = require('../test-utils');

const { _internal: { extractCmdclassCommands }, scanPyprojectCmdclass } =
  require('../../src/scanner/python-ast-detectors/pyproject-cmdclass.js');
const { obfuscationWithoutVector } = require('../../src/ml/feature-extractor.js');
const { PYPI_IMPORT_TIME_RCE_TYPES } = require('../../src/shared/constants.js');

function withPyproject(content, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyproject-'));
  try {
    fs.writeFileSync(path.join(dir, 'pyproject.toml'), content);
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const cmds = s => [...extractCmdclassCommands(s)].sort().join(',');

async function runPyprojectCmdclassTests() {
  console.log('\n=== PYPROJECT CMDCLASS (PYAST-001 parity) ===\n');

  // Every TOML spelling of the same declaration must resolve to the same commands.
  const spellings = {
    'table header': '[tool.setuptools.cmdclass]\nbuild_py = "a.B"\ndevelop = "a.D"\n',
    'CRLF line endings': '[tool.setuptools.cmdclass]\r\ndevelop = "a.D"\r\n',
    'inline table': '[tool.setuptools]\ncmdclass = { develop = "a.D", "install" = "a.I" }\n',
    'multi-line inline table': '[tool.setuptools]\ncmdclass = {\n  develop = "a.D",\n}\n',
    'dotted key under [tool]': '[tool]\nsetuptools.cmdclass.develop = "a"\n',
    'dotted key at top level': 'tool.setuptools.cmdclass.install = "a"\n',
    'quoted and spaced header': '[ tool . "setuptools" . \'cmdclass\' ]  # c\n"develop" = "x"\n'
  };
  const expected = {
    'table header': 'build_py,develop', 'CRLF line endings': 'develop', 'inline table': 'develop,install',
    'multi-line inline table': 'develop', 'dotted key under [tool]': 'develop',
    'dotted key at top level': 'install', 'quoted and spaced header': 'develop'
  };
  for (const [name, src] of Object.entries(spellings)) {
    test(`PYPROJECT-CMDCLASS: ${name} is read`, () => {
      assert(cmds(src) === expected[name], `${name}: got "${cmds(src)}"`);
    });
  }

  // Evasions: a fake header inside a string or a nested array must not switch the table.
  const evasions = {
    'fake header in a """ string': '[tool.setuptools.cmdclass]\nx = """\n[project]\n"""\ndevelop = "evil"\n',
    'fake header in a \'\'\' string': '[tool.setuptools.cmdclass]\nx = \'\'\'\n[project]\n\'\'\'\ndevelop = "evil"\n',
    'nested array line [1]': '[tool.setuptools.cmdclass]\nx = [\n [1]\n]\ndevelop = "evil"\n',
    '# inside a string': '[tool.setuptools.cmdclass]\nx = "a # [project]"\ndevelop = "evil"\n'
  };
  for (const [name, src] of Object.entries(evasions)) {
    test(`PYPROJECT-CMDCLASS: evasion "${name}" still detected`, () => {
      assert(extractCmdclassCommands(src).has('develop'), `${name}: develop missed, got "${cmds(src)}"`);
    });
  }

  // Negatives.
  const negatives = {
    'other tables': '[tool.setuptools.package-data]\ndevelop = ["x"]\n[tool.other.cmdclass]\ndevelop = "x"\n',
    'declaration quoted in a multi-line string': '[project]\ndescription = """\n[tool.setuptools.cmdclass]\ndevelop = "x"\n"""\n',
    'commented out': '# [tool.setuptools.cmdclass]\n# develop = "x"\n'
  };
  for (const [name, src] of Object.entries(negatives)) {
    test(`PYPROJECT-CMDCLASS: ${name} -> nothing`, () => {
      assert(cmds(src) === '', `${name}: got "${cmds(src)}"`);
    });
  }

  test('PYPROJECT-CMDCLASS: develop override -> CRITICAL pyast_setup_cmdclass_override on pyproject.toml', () => {
    withPyproject('[tool.setuptools.cmdclass]\nbuild_py = "p.B"\ndevelop = "p.D"\n', dir => {
      const t = scanPyprojectCmdclass(dir);
      assert(t.length === 1 && t[0].type === 'pyast_setup_cmdclass_override', JSON.stringify(t));
      assert(t[0].severity === 'CRITICAL', `got ${t[0].severity}`);
      assert(t[0].file === 'pyproject.toml', `got ${t[0].file}`);
    });
  });

  test('PYPROJECT-CMDCLASS: build_py only -> HIGH (same grading as setup.py)', () => {
    withPyproject('[tool.setuptools.cmdclass]\nbuild_py = "p.B"\n', dir => {
      const t = scanPyprojectCmdclass(dir);
      assert(t.length === 1 && t[0].severity === 'HIGH', JSON.stringify(t));
    });
  });

  test('PYPROJECT-CMDCLASS: non install-time command (build_sphinx) -> nothing', () => {
    withPyproject('[tool.setuptools.cmdclass]\nbuild_sphinx = "p.S"\n', dir => {
      assert(scanPyprojectCmdclass(dir).length === 0, 'build_sphinx must not fire');
    });
  });

  test('PYPROJECT-CMDCLASS: no pyproject.toml -> nothing', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyproject-'));
    try { assert(scanPyprojectCmdclass(dir).length === 0, 'expected no finding'); }
    finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await asyncTest('PYPROJECT-CMDCLASS: wired into scanPythonAST', async () => {
    const { initPythonParser, scanPythonAST } = require('../../src/scanner/python-ast.js');
    await initPythonParser();
    withPyproject('[tool.setuptools.cmdclass]\ndevelop = "p.D"\n', dir => {
      assert(scanPythonAST(dir).some(t => t.type === 'pyast_setup_cmdclass_override'), 'not emitted by scanPythonAST');
    });
  });

  // F8: obfuscation + a PyPI execution vector is NOT "obfuscation without vector".
  test('F8: obfuscation alone is still capped (obfuscation_without_vector true)', () => {
    assert(obfuscationWithoutVector({ threats: [{ type: 'obfuscation_detected' }] }) === true, 'expected true');
  });
  for (const type of PYPI_IMPORT_TIME_RCE_TYPES) {
    test(`F8: obfuscation + ${type} is not capped as vector-less`, () => {
      const r = { threats: [{ type: 'obfuscation_detected' }, { type: 'js_obfuscation_pattern' }, { type }] };
      assert(obfuscationWithoutVector(r) === false, `${type} must count as an execution vector`);
    });
  }
}

module.exports = { runPyprojectCmdclassTests };
