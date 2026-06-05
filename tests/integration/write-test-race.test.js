/**
 * P0d — Fix the `.write-test` ENOENT race.
 *
 * resolveWritableDir probes a log dir's writability by writing then unlinking a
 * fixed-name `.write-test` file at module load. Each of the up-to-16 scan worker
 * threads loads state.js (transitively), so they all raced on that shared path and
 * threw ENOENT on unlink (~8/day in prod). Fix: skip the probe in worker threads,
 * use a per-process-unique probe name, and tolerate an already-gone probe on removal.
 *
 * Behavioral: drives the real resolveWritableDir (now with an injectable isMain flag)
 * and asserts what it writes / that it never throws. fs is spied so nothing touches
 * real log dirs.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, assert } = require('../test-utils');
const { resolveWritableDir } = require('../../src/monitor/state.js');

function spyFs(overrides, fn) {
  const saved = {};
  for (const k of Object.keys(overrides)) { saved[k] = fs[k]; fs[k] = overrides[k]; }
  try { return fn(); } finally { for (const k of Object.keys(saved)) fs[k] = saved[k]; }
}

async function runWriteTestRaceTests() {
  console.log('\n=== WRITE-TEST RACE TESTS (P0d) ===\n');
  const primary = path.join(os.tmpdir(), `muaddib-p0d-${process.pid}`);
  const fallback = path.join(os.tmpdir(), `muaddib-p0d-fb-${process.pid}`);

  // POSITIVE (worker): worker threads must skip the probe entirely (no write/unlink → no race).
  test('P0d: worker threads do not run the write-test probe', () => {
    const writes = [];
    const ret = spyFs({
      mkdirSync: () => {},
      writeFileSync: (p) => { writes.push(String(p)); },
      rmSync: () => {},
    }, () => resolveWritableDir(primary, fallback, /* isMain */ false));
    assert(ret === primary, 'should return the primary dir');
    assert(!writes.some(w => w.includes('.write-test')), `worker must not write a probe, wrote: ${writes.join(',')}`);
  });

  // POSITIVE (main): the main thread writes a probe whose name is unique per process+thread.
  test('P0d: main-thread probe filename is unique per process (pid+threadId)', () => {
    const writes = [];
    const ret = spyFs({
      mkdirSync: () => {},
      writeFileSync: (p) => { writes.push(String(p)); },
      rmSync: () => {},
    }, () => resolveWritableDir(primary, fallback, /* isMain */ true));
    assert(ret === primary, 'should return the primary dir');
    assert(writes.length === 1, `main thread should write exactly one probe, got ${writes.length}`);
    assert(/\.write-test-\d+-\d+$/.test(writes[0]), `probe name must be unique (pid-threadId), got ${writes[0]}`);
  });

  // NEGATIVE (the race): removing an already-gone probe must NOT throw ENOENT.
  test('P0d: probe removal tolerates an already-deleted file (no ENOENT)', () => {
    // writeFileSync no-ops → the probe is never created → the subsequent removal targets
    // a missing file, exactly like a concurrent process that won the race and deleted it.
    let threw = null, ret;
    try {
      ret = spyFs({ mkdirSync: () => {}, writeFileSync: () => {} /* rmSync real: force:true */ },
        () => resolveWritableDir(primary, fallback, /* isMain */ true));
    } catch (e) { threw = e; }
    assert(threw === null, `removing a missing probe must not throw, got ${threw && threw.code}`);
    assert(ret === primary, 'should still return the primary dir');
  });

  console.log('  ✓ write-test race (P0d) tests passed');
}

module.exports = { runWriteTestRaceTests };
