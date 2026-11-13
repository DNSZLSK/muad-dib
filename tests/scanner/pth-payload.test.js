'use strict';

// PYSRC-011 pth_exec_payload: executable lines of shipped .pth files (LiteLLM 1.107.0 shape).

const fs = require('fs');
const path = require('path');
const os = require('os');
const { asyncTest, assert, test, runScanDirect, cleanupTemp } = require('../test-utils');

const { _internal: { scanPthFiles } } = require('../../src/scanner/python-source.js');
const { obfuscationWithoutVector } = require('../../src/ml/feature-extractor.js');

function withPth(content, fn, name = 'x.pth') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pth-'));
  try {
    fs.writeFileSync(path.join(dir, name), content);
    return fn(dir);
  } finally {
    cleanupTemp(dir);
  }
}

async function runPthPayloadTests() {
  console.log('\n=== PTH START-UP PAYLOAD (PYSRC-011) ===\n');

  const positives = {
    'base64 exec (LiteLLM shape)': 'import os, base64; exec(base64.b64decode("aW1wb3J0IG9z"))\n',
    'subprocess': 'import subprocess; subprocess.Popen(["node", "x.js"])\n',
    'network': 'import urllib.request as u; u.urlopen("http://example.invalid/p")\n',
    'exec of a variable': 'import sys; exec(sys.argv[0])\n',
    'exec of an f-string': 'import os; exec(f"{os.environ[\'X\']}")\n',
    '__import__ of a concatenation': 'import os; __import__("sub" + "process").run(["sh"])\n',
    'payload hidden in an exec literal': 'import sys; exec(\'import subprocess\')\n',
    'CRLF line ending': 'import os, base64; exec(base64.b64decode("eA=="))\r\n',
    'getattr by computed name': 'import os; getattr(__import__("os"), "sys" + "tem")("id")\n',
    'tab after import': 'import\tos, zlib; exec(zlib.decompress(b"x"))\n',
    'payload in a nested exec literal': 'import sys; exec("exec(\'import socket\')")\n',
    'f-string evaluated on the line': 'import os; f"{os.system(\'id\')}"\n'
  };
  for (const [name, src] of Object.entries(positives)) {
    test(`PTH: ${name} -> CRITICAL pth_exec_payload`, () => {
      withPth(src, dir => {
        const t = scanPthFiles(dir);
        assert(t.length === 1 && t[0].type === 'pth_exec_payload' && t[0].severity === 'CRITICAL', `${name}: ${JSON.stringify(t)}`);
      });
    });
  }

  // Real benign shipped .pth files (coverage 7.14, setuptools, namespace packages, python-hunter).
  const negatives = {
    'coverage a1_coverage.pth (exec of a literal)': 'import sys; exec(\'import os\\n\\nif os.getenv("COVERAGE_PROCESS_START"):\\n import coverage\\n coverage.process_startup()\')\n',
    'setuptools distutils-precedence.pth': 'import os; var = \'SETUPTOOLS_USE_DISTUTILS\'; enabled = os.environ.get(var, \'local\') == \'local\'; enabled and __import__(\'_distutils_hack\').add_shim(); \n',
    'namespace *-nspkg.pth': 'import sys, types, os;has_mfs = sys.version_info > (3, 5);importlib = has_mfs and __import__(\'importlib.util\');has_mfs and __import__(\'importlib.machinery\')\n',
    'hunter.pth (own module import)': 'import hunter; hunter._embed_via_environment()\n',
    'prismor immunity-agent.pth (exec of a literal importing its own module)': 'import sys; exec("try:\n import prismor.runtime._post_install; prismor.runtime._post_install.maybe_show()\nexcept Exception:\n pass")\n',
    'path-only line': '../lib/foo\n',
    'indented import (not executed by site.py)': '  import subprocess\n',
    'commented line': '# import subprocess; subprocess.run(["sh"])\n'
  };
  for (const [name, src] of Object.entries(negatives)) {
    test(`PTH: ${name} -> nothing`, () => {
      withPth(src, dir => {
        const t = scanPthFiles(dir);
        assert(t.length === 0, `${name}: ${JSON.stringify(t)}`);
      });
    });
  }

  test('PTH: real pytest-cov.pth (the word subprocess inside a message string) -> nothing', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'samples', 'pth', 'pytest-cov.pth'), 'utf8');
    withPth(src, dir => {
      const t = scanPthFiles(dir);
      assert(t.length === 0, `pytest-cov.pth: ${JSON.stringify(t)}`);
    });
  });

  test('PTH: .PTH upper-case extension is read too', () => {
    withPth('import subprocess; subprocess.run(["sh"])\n', dir => {
      assert(scanPthFiles(dir).length === 1, 'upper-case .PTH missed');
    }, 'X.PTH');
  });

  test('PTH: pth_exec_payload counts as an execution vector for F8', () => {
    assert(obfuscationWithoutVector({ threats: [{ type: 'obfuscation_detected' }, { type: 'pth_exec_payload' }] }) === false,
      'obfuscation + pth_exec_payload must not be capped as vector-less');
  });

  await asyncTest('PTH: end to end, a package shipping only a payload .pth alerts (>= 20)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pth-e2e-'));
    try {
      fs.writeFileSync(path.join(dir, 'setup.cfg'), '[metadata]\nname = demo-pth\nversion = 0.1.0\n');
      fs.writeFileSync(path.join(dir, 'demo_init.pth'), 'import os, base64; exec(base64.b64decode("aW1wb3J0IG9z"))\n');
      const result = await runScanDirect(dir);
      const t = result.threats.find(x => x.type === 'pth_exec_payload');
      assert(t, `pth_exec_payload not emitted: ${result.threats.map(x => x.type).join(', ')}`);
      assert(result.summary.riskScore >= 20, `expected an alert (>= 20), got ${result.summary.riskScore}`);
    } finally {
      cleanupTemp(dir);
    }
  });
}

module.exports = { runPthPayloadTests };
