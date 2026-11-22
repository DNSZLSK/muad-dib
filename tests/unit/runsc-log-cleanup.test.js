'use strict';
// Behavioral tests of deploy/runsc-log-cleanup.sh (gVisor trace retention): run against a
// temporary directory whose entries have controlled ages and sizes.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { test, assert, addSkipped } = require('../test-utils');

const SCRIPT = path.join(__dirname, '..', '..', 'deploy', 'runsc-log-cleanup.sh');
const fwd = p => p.replace(/\\/g, '/');

function hasTools() {
  const r = spawnSync('bash', ['-c', 'find --version >/dev/null 2>&1 && du --version >/dev/null 2>&1 && echo ok'], { encoding: 'utf8' });
  return r.status === 0 && /ok/.test(r.stdout || '');
}

function entry(dir, name, ageMin, kb) {
  const d = path.join(dir, name);
  fs.mkdirSync(d);
  fs.writeFileSync(path.join(d, 'runsc.log.boot.txt'), Buffer.alloc(kb * 1024, 0x61));
  const t = new Date(Date.now() - ageMin * 60000);
  fs.utimesSync(path.join(d, 'runsc.log.boot.txt'), t, t);
  fs.utimesSync(d, t, t);
}

function run(dir, ...limits) {
  return spawnSync('bash', [fwd(SCRIPT), fwd(dir), ...limits.map(String)], { encoding: 'utf8' });
}

function runRunscLogCleanupTests() {
  console.log('\n=== RUNSC LOG CLEANUP TESTS ===\n');
  if (!hasTools()) { addSkipped('runsc-log-cleanup: bash/find/du not available'); return; }
  const tmp = [];
  const mk = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-runsc-')); tmp.push(d); return d; };

  test('RUNSC-CLEANUP: traces older than the age limit are removed, recent ones kept', () => {
    const d = mk();
    entry(d, 'old-container', 45, 1);
    entry(d, 'fresh-container', 5, 1);
    const r = run(d, 30, 2048);
    assert(r.status === 0, `exit 0 expected, got ${r.status} ${r.stderr}`);
    assert(!fs.existsSync(path.join(d, 'old-container')), 'the 45-min-old trace must be removed');
    assert(fs.existsSync(path.join(d, 'fresh-container')), 'the 5-min-old trace must be kept');
    assert(fs.existsSync(d), 'the log directory itself must never be removed');
  });

  test('RUNSC-CLEANUP: above the size cap, the oldest recent traces go first until under the cap', () => {
    const d = mk();
    entry(d, 'a-oldest', 20, 400);
    entry(d, 'b-middle', 10, 400);
    entry(d, 'c-newest', 1, 400);
    const r = run(d, 30, 1); // 1 MB cap, 3 x 400 KB
    assert(r.status === 0, `exit 0 expected, got ${r.status} ${r.stderr}`);
    assert(!fs.existsSync(path.join(d, 'a-oldest')), 'the oldest must be removed to get under the cap');
    assert(fs.existsSync(path.join(d, 'c-newest')), 'the newest must be kept');
  });

  test('RUNSC-CLEANUP: non-numeric limits or a missing directory remove nothing (exit 2)', () => {
    const d = mk();
    entry(d, 'old-container', 45, 1);
    const bad = run(d, '30; rm -rf /', 2048);
    assert(bad.status === 2, `exit 2 expected for a non-numeric limit, got ${bad.status}`);
    assert(fs.existsSync(path.join(d, 'old-container')), 'nothing removed on bad input');
    const missing = run(path.join(d, 'does-not-exist'), 30, 2048);
    assert(missing.status === 2, `exit 2 expected for a missing directory, got ${missing.status}`);
  });

  for (const d of tmp) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
}

module.exports = { runRunscLogCleanupTests };
