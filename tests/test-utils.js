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
  const t0 = Date.now();
  try {
    fn();
    const ms = Date.now() - t0;
    const tag = ms > 5000 ? ` [SLOW ${(ms/1000).toFixed(1)}s]` : ms > 1000 ? ` [${(ms/1000).toFixed(1)}s]` : '';
    console.log(`[PASS] ${name}${tag}`);
    passed++;
  } catch (e) {
    const ms = Date.now() - t0;
    console.log(`[FAIL] ${name} [${ms}ms]`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

async function asyncTest(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    const ms = Date.now() - t0;
    const tag = ms > 5000 ? ` [SLOW ${(ms/1000).toFixed(1)}s]` : ms > 1000 ? ` [${(ms/1000).toFixed(1)}s]` : '';
    console.log(`[PASS] ${name}${tag}`);
    passed++;
  } catch (e) {
    const ms = Date.now() - t0;
    console.log(`[FAIL] ${name} [${ms}ms]`);
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

// Cache for runScan/runCommand results — eliminates duplicate process spawns
const _scanCache = new Map();
const _cmdCache = new Map();

function runScan(target, options = '') {
  // Skip cache for commands that produce file side-effects
  const hasSideEffect = /--(?:sarif|html)\s/.test(options) || /--(?:sarif|html)$/.test(options);
  const key = `${target}::${options}`;
  if (!hasSideEffect && _scanCache.has(key)) return _scanCache.get(key);
  let result;
  try {
    const cmd = `node "${BIN}" scan "${target}" ${options}`;
    result = execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    result = e.stdout || e.stderr || '';
  }
  if (!hasSideEffect) _scanCache.set(key, result);
  return result;
}

function runCommand(cmd) {
  if (_cmdCache.has(cmd)) return _cmdCache.get(cmd);
  let result;
  try {
    result = execSync(`node "${BIN}" ${cmd}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    result = e.stdout || e.stderr || '';
  }
  _cmdCache.set(cmd, result);
  return result;
}

/**
 * In-process scan — calls run() directly without spawning a child process.
 * Returns the scan result object (same shape as --json output).
 * Use with asyncTest() since it's async.
 */
async function runScanDirect(target, options = {}) {
  const { run } = require('../src/index.js');
  return await run(target, { ...options, _capture: true });
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
  runScanDirect,
  runCommand,
  createTempPkg,
  cleanupTemp,
  getCounters,
  addSkipped
};
