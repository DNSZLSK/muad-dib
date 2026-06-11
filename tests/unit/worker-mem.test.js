'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert } = require('../test-utils');
const { appendWorkerMem, sampleIntervalMs, workerMemEnabled } = require('../../src/monitor/worker-mem.js');

function withWorkerMemEnv(vars, fn) {
  const keys = ['MUADDIB_WORKER_MEM', 'MUADDIB_WORKER_MEM_FILE', 'MUADDIB_WORKER_MEM_MAX_MB', 'MUADDIB_WORKER_MEM_SAMPLE_MS'];
  const save = {};
  for (const k of keys) save[k] = process.env[k];
  for (const k of keys) {
    if (vars[k] !== undefined) process.env[k] = String(vars[k]);
    else delete process.env[k];
  }
  try { return fn(); }
  finally {
    for (const k of keys) {
      if (save[k] !== undefined) process.env[k] = save[k]; else delete process.env[k];
    }
  }
}

const readEntries = f => fs.readFileSync(f, 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l));

async function runWorkerMemTests() {
  console.log('\n=== WORKER-MEM (per-worker RSS instrumentation) TESTS ===\n');

  test('WORKER-MEM: OFF by default — no write, no file, sampling disabled', () => {
    const f = path.join(os.tmpdir(), `wm-${Date.now()}-off.jsonl`);
    withWorkerMemEnv({ MUADDIB_WORKER_MEM_FILE: f }, () => {
      assert(workerMemEnabled() === false, 'disabled without MUADDIB_WORKER_MEM=1');
      assert(appendWorkerMem({ ev: 'spawn', name: 'x' }) === false, 'append is a no-op when disabled');
      assert(!fs.existsSync(f), 'no file created when disabled');
      assert(sampleIntervalMs() === 0, 'sampling disabled when instrumentation off');
    });
  });

  test('WORKER-MEM: enabled append stamps ts and preserves fields', () => {
    const f = path.join(os.tmpdir(), `wm-${Date.now()}-on.jsonl`);
    try {
      withWorkerMemEnv({ MUADDIB_WORKER_MEM: 1, MUADDIB_WORKER_MEM_FILE: f }, () => {
        assert(appendWorkerMem({ ev: 'spawn', tid: 7, name: 'pkg-a', rss: 123 }) === true, 'append succeeds');
        appendWorkerMem({ ev: 'exit', tid: 7, name: 'pkg-a', code: 0, durMs: 42, rss: 456 });
        const e = readEntries(f);
        assert(e.length === 2, 'two lines appended');
        assert(typeof e[0].ts === 'string' && !isNaN(Date.parse(e[0].ts)), 'ts stamped (ISO)');
        assert(e[0].ev === 'spawn' && e[0].tid === 7 && e[0].rss === 123, 'spawn fields preserved');
        assert(e[1].ev === 'exit' && e[1].durMs === 42 && e[1].code === 0, 'exit fields preserved');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('WORKER-MEM: never throws on unwritable path (instrumentation must not crash the daemon)', () => {
    const f = path.join(os.tmpdir(), `wm-no-such-dir-${Date.now()}`, 'sub', 'wm.jsonl');
    withWorkerMemEnv({ MUADDIB_WORKER_MEM: 1, MUADDIB_WORKER_MEM_FILE: f }, () => {
      let ok = false;
      try { ok = appendWorkerMem({ ev: 'spawn', name: 'x' }); } catch (err) {
        assert(false, `appendWorkerMem threw: ${err.message}`);
      }
      assert(ok === false, 'returns false instead of throwing');
    });
  });

  test('WORKER-MEM: rotates past the byte cap (bounded resource), keeps appending after', () => {
    const f = path.join(os.tmpdir(), `wm-${Date.now()}-rot.jsonl`);
    try {
      withWorkerMemEnv({ MUADDIB_WORKER_MEM: 1, MUADDIB_WORKER_MEM_FILE: f, MUADDIB_WORKER_MEM_MAX_MB: 1 }, () => {
        const pad = 'x'.repeat(4096);
        // 300 × ~4KB ≈ 1.2MB > 1MB cap → the rotation must fire along the way
        for (let i = 0; i < 300; i++) appendWorkerMem({ ev: 'sample', i, pad });
        assert(fs.existsSync(f + '.1'), 'rotated file .1 exists once past the cap');
        const sizeNow = fs.statSync(f).size;
        assert(sizeNow < 1.1 * 1024 * 1024, `live file stays bounded after rotation (${sizeNow} bytes)`);
        assert(appendWorkerMem({ ev: 'sample', i: 'after' }) === true, 'append still works after rotation');
      });
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '.1'); } catch {}
    }
  });

  test('WORKER-MEM: sample interval — default when enabled, env override, 0 disables', () => {
    withWorkerMemEnv({ MUADDIB_WORKER_MEM: 1 }, () => {
      assert(sampleIntervalMs() === 10000, `default 10s when enabled, got ${sampleIntervalMs()}`);
    });
    withWorkerMemEnv({ MUADDIB_WORKER_MEM: 1, MUADDIB_WORKER_MEM_SAMPLE_MS: 50 }, () => {
      assert(sampleIntervalMs() === 50, 'env override respected');
    });
    withWorkerMemEnv({ MUADDIB_WORKER_MEM: 1, MUADDIB_WORKER_MEM_SAMPLE_MS: 0 }, () => {
      assert(sampleIntervalMs() === 0, 'explicit 0 disables sampling only');
    });
  });

  await asyncTest('WORKER-MEM: end-to-end — runScanInWorker emits spawn + exit (and worker samples) for the scanned package', async () => {
    const { runScanInWorker } = require('../../src/monitor/queue.js');
    const f = path.join(os.tmpdir(), `wm-${Date.now()}-e2e.jsonl`);
    const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'wm-fixture-'));
    fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({ name: 'wm-e2e-pkg', version: '1.0.0' }));
    fs.writeFileSync(path.join(fixture, 'index.js'), 'module.exports = 1;\n');
    const save = {};
    const vars = { MUADDIB_WORKER_MEM: '1', MUADDIB_WORKER_MEM_FILE: f, MUADDIB_WORKER_MEM_SAMPLE_MS: '25' };
    // env must be set un-scoped: the Worker inherits process.env at spawn and
    // outlives any synchronous with-env wrapper.
    for (const k of Object.keys(vars)) { save[k] = process.env[k]; process.env[k] = vars[k]; }
    try {
      await runScanInWorker(fixture, 60000, { name: 'wm-e2e-pkg', version: '1.0.0', ecosystem: 'npm' });
      // The scan promise resolves on the worker's result message; the 'exit'
      // event (which writes the ev:'exit' entry) fires a beat later — poll.
      // Filter by package name throughout: in the full suite, a leaked scan
      // from an earlier integration test can also write into this window.
      const mine = x => x.name === 'wm-e2e-pkg';
      let e = [];
      for (let i = 0; i < 100; i++) {
        e = readEntries(f);
        if (e.some(x => x.ev === 'exit' && mine(x))) break;
        await new Promise(r => setTimeout(r, 50));
      }
      const spawn = e.find(x => x.ev === 'spawn' && mine(x));
      const exit = e.find(x => x.ev === 'exit' && mine(x));
      assert(spawn, 'spawn entry written for the scanned package');
      assert(exit, 'exit entry written for the scanned package');
      assert(spawn.tid === exit.tid && spawn.tid >= 0, `spawn/exit share a real tid (got ${spawn.tid}/${exit.tid})`);
      assert(typeof exit.durMs === 'number' && exit.durMs >= 0, 'exit carries scan duration');
      assert(spawn.rss > 0 && exit.rss > 0, 'parent RSS recorded on both ends');
      const samples = e.filter(x => x.ev === 'sample' && x.name === 'wm-e2e-pkg');
      assert(samples.length >= 1, `at least one isolate sample at 25ms cadence (got ${samples.length})`);
      assert(samples[0].heapUsed > 0 && typeof samples[0].external === 'number', 'samples carry isolate heap/external');
      assert(samples[0].tid === spawn.tid, 'worker samples join with spawn/exit on tid');
    } finally {
      for (const k of Object.keys(vars)) {
        if (save[k] !== undefined) process.env[k] = save[k]; else delete process.env[k];
      }
      try { fs.unlinkSync(f); } catch {}
      try { fs.rmSync(fixture, { recursive: true, force: true }); } catch {}
    }
  });
}

module.exports = { runWorkerMemTests };
