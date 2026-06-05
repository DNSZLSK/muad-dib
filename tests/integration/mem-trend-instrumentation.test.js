/**
 * P1.0 — Memory-trend instrumentation.
 *
 * appendMemTrend() writes one JSONL sample per memory-watchdog tick so the off-heap
 * leak can be localised offline (rss vs heapUsed vs external/arrayBuffers vs
 * liveWorkers vs runscDirs). The file is bounded (rotate past 5MB) and the whole thing
 * is best-effort — instrumentation must never crash the daemon.
 *
 * Behavioral: drives the real appendMemTrend / countRunscDirs with fs stubbed so no
 * real data/ file is written.
 */

const fs = require('fs');
const { test, assert } = require('../test-utils');
const { appendMemTrend, countRunscDirs, cleanupRunscOrphans } = require('../../src/monitor/daemon.js');

function spyFs(overrides, fn) {
  const saved = {};
  for (const k of Object.keys(overrides)) { saved[k] = fs[k]; fs[k] = overrides[k]; }
  try { return fn(); } finally { for (const k of Object.keys(saved)) fs[k] = saved[k]; }
}

const MEM = { rss: 7_700_000_000, heapUsed: 3_300_000_000, heapTotal: 4_000_000_000, external: 2_000_000_000, arrayBuffers: 1_500_000_000 };

async function runMemTrendInstrumentationTests() {
  console.log('\n=== MEM-TREND INSTRUMENTATION TESTS (P1.0) ===\n');

  // POSITIVE: a tick writes a complete JSONL sample with every discriminator field.
  test('P1.0: appendMemTrend writes a complete JSONL sample', () => {
    let written = null;
    spyFs({
      statSync: () => { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }, // no file yet
      existsSync: () => false,                                                         // runscDirs → 0
      appendFileSync: (p, data) => { written = String(data); },
    }, () => appendMemTrend(MEM, 12, 24256));
    assert(written !== null, 'should append a line');
    assert(written.endsWith('\n'), 'JSONL line must end with newline');
    const e = JSON.parse(written.trim());
    assert(e.rss === MEM.rss && e.heapUsed === MEM.heapUsed && e.heapTotal === MEM.heapTotal, 'rss/heap fields present');
    assert(e.external === MEM.external && e.arrayBuffers === MEM.arrayBuffers, 'off-heap discriminators present');
    assert(e.liveWorkers === 12 && e.queueLen === 24256, 'worker + queue fields present');
    assert(typeof e.runscDirs === 'number', 'runscDirs present');
    assert(typeof e.ts === 'string' && e.ts.length > 0, 'timestamp present');
  });

  // BOUNDED: the JSONL rotates when it exceeds the cap (CLAUDE.md §2 bounded resource).
  test('P1.0: appendMemTrend rotates the JSONL past the size cap', () => {
    let renamed = null, appended = false;
    spyFs({
      statSync: () => ({ size: 6 * 1024 * 1024 }), // over the 5MB cap
      renameSync: (a, b) => { renamed = String(b); },
      existsSync: () => false,
      appendFileSync: () => { appended = true; },
    }, () => appendMemTrend(MEM, 1, 1));
    assert(renamed && renamed.endsWith('.1'), 'should rotate the oversized JSONL to .1');
    assert(appended === true, 'should still append after rotation');
  });

  // BEST-EFFORT: a failing write must never throw out of the daemon loop.
  test('P1.0: appendMemTrend never throws (best-effort)', () => {
    let threw = null;
    try {
      spyFs({
        statSync: () => { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; },
        existsSync: () => false,
        appendFileSync: () => { throw new Error('ENOSPC disk full'); }, // write fails
      }, () => appendMemTrend(MEM, 1, 1));
    } catch (e) { threw = e; }
    assert(threw === null, 'instrumentation must swallow errors, never crash the daemon');
  });

  // countRunscDirs: safe non-negative count, 0 when the dir is absent.
  test('P1.0: countRunscDirs counts dir entries and is safe when absent', () => {
    const n = spyFs({ existsSync: () => false }, () => countRunscDirs());
    assert(n === 0, 'no runsc dir → 0');
    const m = spyFs({ existsSync: () => true, readdirSync: () => ['a', 'b', 'c'] }, () => countRunscDirs());
    assert(m === 3, 'counts entries when dir exists');
  });

  // --- P1.2: runsc orphan cleanup (boot clears the dead process's containers) ---

  // Age-filtered: only dirs older than the threshold are removed.
  test('P1.2: cleanupRunscOrphans removes only dirs older than the age threshold', () => {
    const now = Date.now();
    const removed = [];
    const ret = spyFs({
      existsSync: () => true,
      readdirSync: () => ['old-container', 'new-container'],
      statSync: (p) => ({ mtimeMs: String(p).includes('old') ? now - 2 * 3600 * 1000 : now - 60 * 1000 }),
      rmSync: (p) => { removed.push(String(p)); },
    }, () => cleanupRunscOrphans(3600_000)); // 1h threshold
    assert(ret === 1, `should remove 1 old dir, got ${ret}`);
    assert(removed.length === 1 && removed[0].includes('old'), 'only the >1h dir should be removed');
  });

  // Boot semantics: age 0 clears ALL orphans (the crashed process owns none live).
  test('P1.2: cleanupRunscOrphans(0) clears all orphans (boot semantics)', () => {
    const removed = [];
    const ret = spyFs({
      existsSync: () => true,
      readdirSync: () => ['a', 'b', 'c'],
      statSync: () => ({ mtimeMs: Date.now() - 1000 }), // 1s old — would survive a 1h threshold
      rmSync: (p) => { removed.push(String(p)); },
    }, () => cleanupRunscOrphans(0));
    assert(ret === 3, `age 0 should clear all 3 orphans, got ${ret}`);
    assert(removed.length === 3, 'all three dirs removed at boot');
  });

  // Safe no-op when the runtime dir is absent.
  test('P1.2: cleanupRunscOrphans is a safe no-op when the dir is absent', () => {
    const ret = spyFs({ existsSync: () => false }, () => cleanupRunscOrphans());
    assert(ret === 0, 'no dir → 0 cleaned, no throw');
  });

  console.log('  ✓ mem-trend instrumentation (P1.0) + runsc cleanup (P1.2) tests passed');
}

module.exports = { runMemTrendInstrumentationTests };
