const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const TESTS_DIR = path.join(__dirname, 'samples');
const BIN = path.join(__dirname, '..', 'bin', 'muaddib.js');

// Shared counters
let passed = 0;
let failed = 0;
let skipped = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`[FAIL] ${name}`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

async function asyncTest(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`[FAIL] ${name}`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertIncludes(str, substr, message) {
  if (!str.includes(substr)) {
    throw new Error(message || `Expected "${substr}" in output`);
  }
}

function assertNotIncludes(str, substr, message) {
  if (str.includes(substr)) {
    throw new Error(message || `Unexpected "${substr}" in output`);
  }
}

function runScan(target, options = '') {
  try {
    const cmd = `node "${BIN}" scan "${target}" ${options}`;
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

function runCommand(cmd) {
  try {
    return execSync(`node "${BIN}" ${cmd}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

function createTempPkg(packages) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
  const nmDir = path.join(tmpDir, 'node_modules');
  fs.mkdirSync(nmDir, { recursive: true });
  for (const pkg of packages) {
    const pkgDir = path.join(nmDir, ...pkg.name.split('/'));
    fs.mkdirSync(pkgDir, { recursive: true });
    if (!pkg.skipPkgJson) {
      const content = pkg.rawPkgJson || JSON.stringify({
        name: pkg.name,
        version: pkg.version || '1.0.0'
      });
      fs.writeFileSync(path.join(pkgDir, 'package.json'), content);
    }
    if (pkg.files) {
      for (const f of pkg.files) {
        fs.writeFileSync(path.join(pkgDir, f.name), f.content || '');
      }
    }
  }
  return tmpDir;
}

function cleanupTemp(tmpDir) {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

function getCounters() {
  return { passed, failed, skipped, failures };
}

function addSkipped(n) {
  skipped += n;
}

module.exports = {
  TESTS_DIR,
  BIN,
  test,
  asyncTest,
  assert,
  assertIncludes,
  assertNotIncludes,
  runScan,
  runCommand,
  createTempPkg,
  cleanupTemp,
  getCounters,
  addSkipped
};
