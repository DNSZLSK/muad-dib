'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');
const { test, asyncTest, assert, spyOn } = require('../test-utils');
const spill = require('../../src/monitor/spill.js');
const { enqueueScan, evictFromScanQueueBulk } = require('../../src/monitor/scan-queue.js');

function withSpillEnv(file, fn, { max } = {}) {
  const save = { f: process.env.MUADDIB_SPILL_FILE, m: process.env.MUADDIB_SPILL_MAX };
  process.env.MUADDIB_SPILL_FILE = file;
  if (max !== undefined) process.env.MUADDIB_SPILL_MAX = String(max);
  else delete process.env.MUADDIB_SPILL_MAX;
  try { return fn(); }
  finally {
    if (save.f !== undefined) process.env.MUADDIB_SPILL_FILE = save.f; else delete process.env.MUADDIB_SPILL_FILE;
    if (save.m !== undefined) process.env.MUADDIB_SPILL_MAX = save.m; else delete process.env.MUADDIB_SPILL_MAX;
  }
}

const item = (name, extra = {}) => ({ name, version: '1.0.0', ecosystem: 'npm', tarballUrl: `https://r/${name}.tgz`, ...extra });
const readBacklog = f => fs.readFileSync(f, 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l));

async function runSpillTests() {
  console.log('\n=== SPILL (disk waiting-list) TESTS ===\n');

  test('SPILL: spillItems persists the re-enqueue fields, strips the rest (bounded lines)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-a.jsonl`);
    try {
      withSpillEnv(f, () => {
        const n = spill.spillItems([
          item('pkg-a', { firstPublish: true, hugeIrrelevantField: 'x'.repeat(10_000) }),
          item('pkg-b', { isIOCMatch: true }),
          { version: 'no-name' } // nameless → skipped
        ]);
        assert(n === 2, `2 valid items persisted, got ${n}`);
        const e = readBacklog(f);
        assert(e.length === 2, 'two backlog lines');
        assert(e[0].name === 'pkg-a' && e[0].firstPublish === true && e[0].tarballUrl, 'fields preserved');
        assert(e[0].hugeIrrelevantField === undefined, 'non-whitelisted fields stripped');
        assert(typeof e[0].ts === 'string', 'spill timestamp recorded');
        assert(e[1].isIOCMatch === true, 'protection flags preserved (drain priority depends on them)');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // REGRESSION (2026-06-11 prod freeze): the EMERGENCY spill path must be
  // append-only — NO whole-file read/parse — or it allocates inside the reclaim
  // stall and wedges the handler. Below the byte budget, spillItems must not
  // read the backlog back; above it, compaction (read+rewrite) is allowed.
  test('SPILL: hot-path spill is append-only below cap (no whole-file read) — EMERGENCY-safe', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-hot.jsonl`);
    try {
      withSpillEnv(f, () => {
        // Seed a realistic mid-size backlog, then spill more — far below the
        // 200k-line byte budget. A read of `f` here would be the regression.
        spill.spillItems(Array.from({ length: 500 }, (_, i) => item(`seed-${i}`)));
        let readHits = 0;
        const realRead = fs.readFileSync;
        const spy = spyOn(fs, 'readFileSync', (p, ...a) => {
          if (String(p) === f) readHits++;
          return realRead(p, ...a);
        });
        try {
          const n = spill.spillItems(Array.from({ length: 2000 }, (_, i) => item(`burst-${i}`)));
          assert(n === 2000, `appended 2000, got ${n}`);
          assert(readHits === 0, `EMERGENCY-path spill must NOT read the backlog back, got ${readHits} read(s)`);
        } finally { spy.restore(); }
        assert(readBacklog(f).length === 2500, 'all items appended (seed + burst)');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: compaction DOES fire once the file exceeds the byte budget (cap still enforced)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-budget.jsonl`);
    try {
      // Tiny cap (10) → byte budget = 10 × 256 = 2560 bytes. A few hundred
      // lines blows past it, so the stat-gate must trigger compaction → file
      // capped to 10. (Proves the gate isn't "never compact".)
      withSpillEnv(f, () => {
        spill.spillItems(Array.from({ length: 300 }, (_, i) => item(`x-${i}`)));
        const kept = readBacklog(f);
        assert(kept.length === 10, `over-budget file must compact to the cap of 10, got ${kept.length}`);
      }, { max: 10 });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: write failure (EROFS) → returns 0, never throws (caller degrades to drop)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-rofs.jsonl`);
    withSpillEnv(f, () => {
      const spy = spyOn(fs, 'appendFileSync', () => { const e = new Error('ro'); e.code = 'EROFS'; throw e; });
      try {
        const n = spill.spillItems([item('pkg-a')]);
        assert(n === 0, 'failed spill reports 0 persisted');
      } finally { spy.restore(); }
    });
  });

  test('SPILL: cap compaction evicts oldest UNPROTECTED first, protected last resort, all ledgered', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-cap.jsonl`);
    try {
      withSpillEnv(f, () => {
        // 13 entries, cap 10 (the validator floor): oldest two are protected,
        // eleven unprotected follow → the 3 evictions hit plain-1..3 only.
        const entries = [
          item('prot-1', { isIOCMatch: true }), item('prot-2', { firstPublish: true }),
          ...Array.from({ length: 11 }, (_, i) => item(`plain-${i + 1}`))
        ];
        fs.writeFileSync(f, entries.map(e => JSON.stringify({ ts: 'x', ...e })).join('\n') + '\n');
        const ledgered = [];
        spill._compactBacklog(f, e => ledgered.push(e));
        const kept = readBacklog(f).map(e => e.name);
        assert(kept.length === 10, `capped to 10, got ${kept.length}`);
        assert(kept[0] === 'prot-1' && kept[1] === 'prot-2', `protected survive the cap, got ${kept.slice(0, 3).join(',')}`);
        assert(!kept.includes('plain-1') && !kept.includes('plain-3') && kept.includes('plain-4'),
          `the OLDEST unprotected are evicted, got ${kept.join(',')}`);
        assert(ledgered.length === 3 && ledgered.every(l => l.outcome === 'dropped' && l.source === 'spill_cap'),
          'every cap eviction ledgered as spill_cap');
      }, { max: 10 });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: cap compaction dips into protected only when everything else is gone', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-capp.jsonl`);
    try {
      withSpillEnv(f, () => {
        // 11 entries, ALL protected, cap 10 → exactly one last-resort eviction.
        const entries = Array.from({ length: 11 }, (_, i) => item(`prot-${i + 1}`, { isIOCMatch: true }));
        fs.writeFileSync(f, entries.map(e => JSON.stringify({ ts: 'x', ...e })).join('\n') + '\n');
        const ledgered = [];
        spill._compactBacklog(f, e => ledgered.push(e));
        assert(readBacklog(f).length === 10, 'capped to 10');
        assert(ledgered.length === 1 && ledgered[0].source === 'spill_cap_protected',
          `protected last-resort eviction gets the distinct source, got ${JSON.stringify(ledgered)}`);
        assert(ledgered[0].name === 'prot-1', 'the OLDEST protected is the last-resort victim');
      }, { max: 10 });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: drain takes protected first, respects the batch bound, rewrites the remainder', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-drain.jsonl`);
    try {
      withSpillEnv(f, () => {
        spill.spillItems([item('plain-old'), item('plain-mid'), item('prot-1', { firstPublish: true }), item('plain-new')]);
        const q = [];
        const stats = {};
        const r = spill.drainBacklog(q, stats, {
          maxItems: 2,
          enqueueFn: (queue, it) => queue.push(it)
        });
        assert(r.drained === 2 && r.remaining === 2, `batch of 2 drained, 2 left (got ${JSON.stringify(r)})`);
        // Protected drains FIRST even though it was spilled later.
        assert(q[0].name === 'prot-1', `protected first (got ${q[0] && q[0].name})`);
        assert(q[1].name === 'plain-old', 'then FIFO oldest');
        assert(q[1].ts === undefined, 'spill timestamp stripped on re-enqueue');
        const left = readBacklog(f).map(e => e.name);
        assert(JSON.stringify(left) === JSON.stringify(['plain-mid', 'plain-new']), `remainder rewritten (got ${left.join(',')})`);
        assert(stats.spillDrained === 2, 'stats.spillDrained counted');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: drain dedups against recentlyScanned/queue and discards the duplicate', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-dedup.jsonl`);
    try {
      withSpillEnv(f, () => {
        spill.spillItems([item('already-scanned'), item('fresh')]);
        const q = [];
        const stats = {};
        const r = spill.drainBacklog(q, stats, {
          maxItems: 10,
          enqueueFn: (queue, it) => queue.push(it),
          // Caller-owned key format (monitor: `${ecosystem}/${name}@${version}`)
          isDuplicate: e => `${e.ecosystem}/${e.name}@${e.version}` === 'npm/already-scanned@1.0.0'
        });
        assert(r.drained === 1 && r.deduped === 1 && r.remaining === 0, `got ${JSON.stringify(r)}`);
        assert(q.length === 1 && q[0].name === 'fresh', 'only the fresh item re-enqueued');
        // Crash-resilience contract: a re-drain after this point finds an empty backlog.
        const again = spill.drainBacklog(q, stats, { maxItems: 10, enqueueFn: (queue, it) => queue.push(it) });
        assert(again.drained === 0 && q.length === 1, 're-drain does not duplicate');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: drain tolerates a corrupt line (crash mid-write) and missing file', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-corrupt.jsonl`);
    try {
      withSpillEnv(f, () => {
        spill.spillItems([item('good')]);
        fs.appendFileSync(f, '{ torn-line\n');
        const q = [];
        const r = spill.drainBacklog(q, null, { maxItems: 10, enqueueFn: (queue, it) => queue.push(it) });
        assert(r.drained === 1 && q[0].name === 'good', 'good entry drained, torn line skipped');
      });
      const missing = path.join(os.tmpdir(), `spill-${Date.now()}-missing.jsonl`);
      withSpillEnv(missing, () => {
        const r = spill.drainBacklog([], null, { maxItems: 10, enqueueFn: () => {} });
        assert(r.drained === 0 && r.remaining === 0, 'missing backlog is a cheap no-op');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: shouldDrain — only at pressure NONE with queue headroom (pure predicate)', () => {
    assert(spill.shouldDrain(0, 100, 500) === true, 'NONE + headroom → drain');
    assert(spill.shouldDrain(0, 500, 500) === false, 'queue at threshold → no drain');
    assert(spill.shouldDrain(1, 100, 500) === false, 'any pressure level > NONE → no drain');
    assert(spill.shouldDrain(4, 0, 500) === false, 'EMERGENCY → no drain');
  });

  test('SPILL: shouldDrain — marge ceiling makes a steady-state queue drainable', () => {
    // Regression guard for the one-way-street bug: with a marge ceiling (a margin
    // below the 30K backpressure point, e.g. 25K), a live queue sitting in the
    // thousands — where the old 500/5000 ceiling was unreachable — must drain.
    const CEILING = 25_000; // SOFT_BACKPRESSURE_THRESHOLD(30K) - margin(5K)
    assert(spill.shouldDrain(0, 6663, CEILING) === true, 'NONE + steady-state queue (6663) below marge ceiling → drain');
    assert(spill.shouldDrain(0, 6663, 5000) === false, 'same queue under the OLD 5000 ceiling → never drains (the bug)');
    assert(spill.shouldDrain(0, 25_000, CEILING) === false, 'queue at the marge ceiling → no drain (leaves backpressure headroom)');
    assert(spill.shouldDrain(1, 100, CEILING) === false, 'pressure ELEVATED → no drain even with deep headroom (self-throttle)');
  });

  test('SPILL: isSpillEnabled reads the master switch at call time', () => {
    const save = process.env.MUADDIB_QUEUE_SPILL;
    try {
      delete process.env.MUADDIB_QUEUE_SPILL;
      assert(spill.isSpillEnabled() === false, 'default OFF');
      process.env.MUADDIB_QUEUE_SPILL = '1';
      assert(spill.isSpillEnabled() === true, 'enabled via env');
    } finally {
      if (save !== undefined) process.env.MUADDIB_QUEUE_SPILL = save;
      else delete process.env.MUADDIB_QUEUE_SPILL;
    }
  });

  // ── Eviction-path integration (scan-queue.js → spill) ──

  function withSpillOn(file, fn) {
    const save = process.env.MUADDIB_QUEUE_SPILL;
    process.env.MUADDIB_QUEUE_SPILL = '1';
    try { return withSpillEnv(file, fn); }
    finally {
      if (save !== undefined) process.env.MUADDIB_QUEUE_SPILL = save;
      else delete process.env.MUADDIB_QUEUE_SPILL;
    }
  }

  test('SPILL: evictFromScanQueueBulk spills the evicted batch + ledgers outcome=spilled', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-bulk.jsonl`);
    try {
      withSpillOn(f, () => {
        const q = [item('a'), item('b'), item('c', { isIOCMatch: true }), item('d'), item('e')];
        const ledgered = [];
        const r = evictFromScanQueueBulk(q, 2, 'mem_emergency', e => ledgered.push(e));
        assert(r.dropped === 3 && r.spilled === 3, `3 evicted, all spilled (got ${JSON.stringify(r)})`);
        assert(q.length === 2 && q.some(it => it.name === 'c'), 'protected survives in the live queue');
        const backlog = readBacklog(f).map(e => e.name);
        assert(JSON.stringify(backlog) === JSON.stringify(['a', 'b', 'd']), `evicted batch in backlog (got ${backlog.join(',')})`);
        assert(ledgered.length === 3 && ledgered.every(l => l.outcome === 'spilled' && l.source === 'mem_emergency_spill'),
          `ledgered as spilled/mem_emergency_spill, got ${JSON.stringify(ledgered[0])}`);
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // IOC-aware anti-spill (@longzy DPRK post-mortem): an item can carry NO isIOCMatch flag
  // (its enqueue-time lookup missed, was version-gated, or the IOC DB was refreshed while it
  // sat in the backlog) yet its NAME is known-malicious NOW. The injected iocIndex must keep
  // it in the live queue instead of shedding it. Covers BOTH index branches: wildcard
  // (all-versions) and packagesMap (specific-version entries present).
  test('SPILL: evictFromScanQueueBulk keeps IOC-known NAMES in the live queue (name-level, no isIOCMatch flag)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-ioc-name.jsonl`);
    try {
      withSpillOn(f, () => {
        const iocIndex = {
          wildcardPackages: new Set(['evil-wild']),
          packagesMap: new Map([['evil-map', [{ version: '1.0.0' }]]])
        };
        // evil-wild + evil-map are the OLDEST → first victims WITHOUT the guard.
        const q = [item('evil-wild'), item('evil-map'), item('b'), item('c'), item('d')];
        const ledgered = [];
        const r = evictFromScanQueueBulk(q, 2, 'mem_emergency', e => ledgered.push(e), { iocIndex });
        assert(r.dropped === 3, `3 evicted (got ${JSON.stringify(r)})`);
        const survivors = q.map(it => it.name).sort();
        assert(JSON.stringify(survivors) === JSON.stringify(['evil-map', 'evil-wild']),
          `both IOC-known names survived, plain items evicted (live queue: ${survivors.join(',')})`);
        const backlog = readBacklog(f).map(e => e.name).sort();
        assert(JSON.stringify(backlog) === JSON.stringify(['b', 'c', 'd']), `only plain items spilled (backlog: ${backlog.join(',')})`);
        assert(!ledgered.some(l => l.name === 'evil-wild' || l.name === 'evil-map'), 'IOC-known names never ledgered as evicted');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: evictFromScanQueueBulk still spills a name NOT in the IOC DB (guard is targeted, not a blanket keep)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-ioc-neg.jsonl`);
    try {
      withSpillOn(f, () => {
        const iocIndex = { wildcardPackages: new Set(['some-other-malware']), packagesMap: new Map() };
        const q = [item('plain-old'), item('plain-new')];
        const ledgered = [];
        const r = evictFromScanQueueBulk(q, 1, 'mem_emergency', e => ledgered.push(e), { iocIndex });
        assert(r.dropped === 1, `one unknown item evicted (got ${JSON.stringify(r)})`);
        const backlog = readBacklog(f).map(e => e.name);
        assert(JSON.stringify(backlog) === JSON.stringify(['plain-old']), `unknown oldest spilled (backlog: ${backlog.join(',')})`);
        assert(q.length === 1 && q[0].name === 'plain-new', 'newest unknown kept');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SPILL: evictFromScanQueueBulk degrades to dropped when the spill write fails', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-bulkfail.jsonl`);
    withSpillOn(f, () => {
      const spy = spyOn(fs, 'appendFileSync', () => { const e = new Error('full'); e.code = 'ENOSPC'; throw e; });
      const ledgered = [];
      try {
        const q = [item('a'), item('b'), item('c')];
        const r = evictFromScanQueueBulk(q, 1, 'mem_emergency', e => ledgered.push(e));
        assert(r.dropped === 2 && r.spilled === 0, 'spill failed → counted as plain drops');
      } finally { spy.restore(); }
      assert(ledgered.length === 2 && ledgered.every(l => l.outcome === 'dropped' && l.source === 'mem_emergency'),
        `pre-spill behavior preserved on failure, got ${JSON.stringify(ledgered[0])}`);
    });
  });

  test('SPILL: evictFromScanQueueBulk with flag OFF behaves exactly as before (dropped)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-off.jsonl`);
    withSpillEnv(f, () => {
      const save = process.env.MUADDIB_QUEUE_SPILL;
      delete process.env.MUADDIB_QUEUE_SPILL;
      try {
        const q = [item('a'), item('b')];
        const ledgered = [];
        const r = evictFromScanQueueBulk(q, 1, 'mem_emergency', e => ledgered.push(e));
        assert(r.dropped === 1 && r.spilled === 0, 'no spill when disabled');
        assert(!fs.existsSync(f), 'no backlog file created');
        assert(ledgered[0].outcome === 'dropped' && ledgered[0].source === 'mem_emergency', 'legacy ledger shape intact');
      } finally {
        if (save !== undefined) process.env.MUADDIB_QUEUE_SPILL = save;
      }
    });
  });

  test('SPILL: enqueueScan cap eviction spills the victim (queue_cap_spill)', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-cap-enq.jsonl`);
    // Point the lazily-required state.js ledger at a temp file so the real
    // data/scan-ledger.jsonl is never touched (freshState pattern).
    const ledgerFile = path.join(os.tmpdir(), `spill-${Date.now()}-cap-ledger.jsonl`);
    const saveLedger = process.env.MUADDIB_SCAN_LEDGER_FILE;
    process.env.MUADDIB_SCAN_LEDGER_FILE = ledgerFile;
    delete require.cache[require.resolve('../../src/monitor/state.js')];
    try {
      withSpillOn(f, () => {
        const q = [item('oldest'), item('mid')];
        const stats = {};
        const droppedFlag = enqueueScan(q, item('new'), stats, 2);
        assert(droppedFlag === true, 'cap eviction happened');
        assert(stats.spilled === 1, 'stats.spilled counted');
        const backlog = readBacklog(f);
        assert(backlog.length === 1 && backlog[0].name === 'oldest', 'victim in the backlog');
        const ledger = readBacklog(ledgerFile);
        assert(ledger.length === 1 && ledger[0].outcome === 'spilled' && ledger[0].source === 'queue_cap_spill',
          `ledgered spilled/queue_cap_spill, got ${JSON.stringify(ledger[0])}`);
      });
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(ledgerFile); } catch {}
      if (saveLedger !== undefined) process.env.MUADDIB_SCAN_LEDGER_FILE = saveLedger;
      else delete process.env.MUADDIB_SCAN_LEDGER_FILE;
      delete require.cache[require.resolve('../../src/monitor/state.js')];
    }
  });

  // ── Rollup: spilled counts on the NON-scanned side (honest coverage) ──
  test('SPILL: computeLedgerRollup counts spilled as non-scanned; drained re-scan covers it', () => {
    const f = path.join(os.tmpdir(), `spill-${Date.now()}-rollup.jsonl`);
    try {
      const s = require('../../src/monitor/state.js');
      fs.writeFileSync(f, [
        { ts: '2026-06-11T10:00:00.000Z', name: 'spilled-pending', version: '1', ecosystem: 'npm', outcome: 'spilled' },
        { ts: '2026-06-11T10:01:00.000Z', name: 'spilled-rescued', version: '1', ecosystem: 'npm', outcome: 'spilled' },
        { ts: '2026-06-11T10:02:00.000Z', name: 'spilled-rescued', version: '1', ecosystem: 'npm', outcome: 'clean' }
      ].map(e => JSON.stringify(e)).join('\n') + '\n');
      const r = s.computeLedgerRollup(null, { file: f });
      assert(r.scanned === 1, `only the drained re-scan counts as scanned (got ${r.scanned})`);
      assert(r.byOutcome.spilled === 2, 'spilled outcomes visible in byOutcome');
      assert(r.vanished === 1, `the never-drained spill is an honest coverage hole (got ${r.vanished})`);
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // ── resourceLimits: deterministic worker-OOM mechanics ──
  // A worker that allocates past its V8 cap dies with ERR_WORKER_OUT_OF_MEMORY
  // (the code queue.js's catch maps to ledger source `worker_oom`). This pins the
  // platform behavior the rollout relies on, without booting the full scanner.
  await asyncTest('SPILL: worker resourceLimits breach → ERR_WORKER_OUT_OF_MEMORY (the worker, not the process)', async () => {
    const err = await new Promise((resolve) => {
      const w = new Worker(
        'const a = []; while (true) a.push(new Array(65536).fill(1));',
        { eval: true, resourceLimits: { maxOldGenerationSizeMb: 32, maxYoungGenerationSizeMb: 16 } }
      );
      const t = setTimeout(() => { w.terminate(); resolve(new Error('TIMEOUT: worker did not OOM')); }, 20_000);
      w.on('error', e => { clearTimeout(t); resolve(e); });
      w.on('exit', code => { clearTimeout(t); resolve(new Error('exited ' + code + ' without error event')); });
    });
    assert(err && err.code === 'ERR_WORKER_OUT_OF_MEMORY',
      `expected ERR_WORKER_OUT_OF_MEMORY, got ${err && (err.code || err.message)}`);
    // The detection predicate used by queue.js's catch must match this error.
    const matched = err.code === 'ERR_WORKER_OUT_OF_MEMORY' ||
      /ERR_WORKER_OUT_OF_MEMORY|reached its memory limit/i.test(err.message || '');
    assert(matched, 'queue.js worker_oom predicate matches the platform error');
  });

  // ── resourceLimits wiring through runScanInWorker (env → workerOpts) ──
  // POSITIVE (anti-regression): a generous cap must not change the scan verdict.
  // NEGATIVE: a tiny cap kills the worker with the OOM error the monitor maps to
  // `worker_oom` — the scanner pipeline cannot even boot inside 8MB old-gen.
  await asyncTest('SPILL: runScanInWorker — generous limit scans identically; tiny limit OOMs the worker', async () => {
    const { runScanInWorker } = require('../../src/monitor/queue.js');
    const target = path.join(__dirname, '..', 'samples', 'entropy');
    const saveOld = process.env.MUADDIB_WORKER_MAX_OLD_MB;
    try {
      delete process.env.MUADDIB_WORKER_MAX_OLD_MB;
      const baseline = await runScanInWorker(target, 60_000, { name: 'spill-fixture', version: '0', ecosystem: 'npm' });
      process.env.MUADDIB_WORKER_MAX_OLD_MB = '1024';
      const limited = await runScanInWorker(target, 60_000, { name: 'spill-fixture', version: '0', ecosystem: 'npm' });
      assert(limited.summary.riskScore === baseline.summary.riskScore,
        `1024MB cap must not change the verdict (base=${baseline.summary.riskScore}, limited=${limited.summary.riskScore})`);

      process.env.MUADDIB_WORKER_MAX_OLD_MB = '8';
      let oomErr = null;
      try {
        await runScanInWorker(target, 60_000, { name: 'spill-fixture', version: '0', ecosystem: 'npm' });
      } catch (e) { oomErr = e; }
      assert(oomErr !== null, 'an 8MB old-gen cap must kill the scan worker');
      const isOom = oomErr.code === 'ERR_WORKER_OUT_OF_MEMORY' ||
        /ERR_WORKER_OUT_OF_MEMORY|reached its memory limit|exited with code/i.test(oomErr.message || '');
      assert(isOom, `rejection must be the OOM/exit family, got: ${oomErr.message}`);
    } finally {
      if (saveOld !== undefined) process.env.MUADDIB_WORKER_MAX_OLD_MB = saveOld;
      else delete process.env.MUADDIB_WORKER_MAX_OLD_MB;
    }
  });
}

module.exports = { runSpillTests };
