const { test, asyncTest, assert } = require('../test-utils');

/**
 * Event-loop stall attribution (2026-06-18). Instrumentation that NAMES the
 * synchronous op wedging the main-thread loop — the loop whose starvation
 * disables the RSS breaker / governor feed / EMERGENCY purge and lets RSS climb
 * to the cgroup cap (4-6 min of zero completions+logs before every OOM kill).
 * Pure observability: these tests assert the lag math, the breadcrumb overlap
 * attribution, and the end-to-end sampler — NO scan-behavior is exercised.
 */

const elm = require('../../src/monitor/event-loop-monitor.js');

async function runEventLoopMonitorTests() {
  // ── Lag core (pure) ──
  test('LOOP-MON: observeTick seeds, then measures time blocked past the interval', () => {
    elm._reset();
    elm.configure({ intervalMs: 1000, thresholdMs: 5000 });
    const seed = elm.observeTick(100);
    assert(seed.firstTick === true && seed.lagMs === 0, 'first tick seeds with zero lag');
    const onTime = elm.observeTick(1100); // exactly one interval later → 0 lag
    assert(onTime.lagMs === 0, `on-time tick has no lag, got ${onTime.lagMs}`);
    const late = elm.observeTick(400100); // ~399s later → blocked ~398s
    assert(late.lagMs === 400100 - 1100 - 1000, `lag = elapsed − interval, got ${late.lagMs}`);
    assert(late.windowStartMs === 1100, 'windowStart is the previous tick timestamp');
    elm._reset();
  });

  test('LOOP-MON: isStall honors the threshold (boundary inclusive)', () => {
    elm._reset();
    elm.configure({ intervalMs: 1000, thresholdMs: 5000 });
    assert(elm.isStall(4999) === false, '4999ms < 5000ms threshold is not a stall');
    assert(elm.isStall(5000) === true, '5000ms meets the threshold');
    assert(elm.isStall(30, 20) === true, 'explicit threshold override works');
    elm._reset();
  });

  // ── Breadcrumb overlap attribution (deterministic via injected clock) ──
  test('LOOP-MON: opOverlapping attributes a STILL-RUNNING op spanning the window', () => {
    let t = 100;
    elm._reset(() => t);
    const crumb = elm.beginOp('extract:quickscan', { name: 'big', version: '1.0.0', unpackedSizeMb: 47 });
    assert(crumb && crumb.startedAt === 100, 'beginOp stamps startedAt from the clock');
    t = 400100; // op never ended; loop blocked window [100, 400100]
    const op = elm.opOverlapping(100, 400100);
    assert(op && op.label === 'extract:quickscan' && op.running === true, 'running op is attributed');
    assert(op.meta.name === 'big' && op.elapsedMs === 400000, 'carries meta + elapsed');
    elm._reset();
  });

  test('LOOP-MON: opOverlapping attributes an op that ENDED during the blocked window', () => {
    let t = 100;
    elm._reset(() => t);
    const crumb = elm.beginOp('extract:prework', { name: 'native', version: '2' });
    t = 350100;
    elm.endOp(crumb); // ended inside the block
    t = 360000;
    const op = elm.opOverlapping(50, 360000);
    assert(op && op.label === 'extract:prework' && op.running === false, 'just-ended op is attributed');
    assert(op.durationMs === 350000, `reports how long it ran, got ${op.durationMs}`);
    elm._reset();
  });

  test('LOOP-MON: opOverlapping returns null when nothing was instrumented (signal to widen)', () => {
    let t = 1000;
    elm._reset(() => t);
    assert(elm.opOverlapping(0, 2000) === null, 'no breadcrumb → null (tells us to instrument more)');
    // An op that ended BEFORE the window must not be mis-attributed.
    const crumb = elm.beginOp('extract', { name: 'x' }); // started 1000
    t = 1200; elm.endOp(crumb); // ended 1200
    t = 9999;
    assert(elm.opOverlapping(5000, 9999) === null, 'op ending before the window is not attributed');
    elm._reset();
  });

  test('LOOP-MON: endOp ignores a mismatched token (nesting-safe)', () => {
    let t = 10;
    elm._reset(() => t);
    const a = elm.beginOp('outer', null);
    elm.endOp({ not: 'the token' }); // wrong token → must NOT clear `a`
    t = 50;
    const op = elm.opOverlapping(0, 50);
    assert(op && op.label === 'outer', 'mismatched endOp token leaves the current op intact');
    elm.endOp(a);
    elm._reset();
  });

  test('LOOP-MON: buildStallRecord carries blockedSec, op label/meta, rssMb', () => {
    let t = 0;
    elm._reset(() => t);
    elm.beginOp('extract:quickscan', { name: 'big', version: '3', unpackedSizeMb: 41 });
    t = 70000;
    const rec = elm.buildStallRecord(65000, 0, 70000);
    assert(rec.lagMs === 65000 && rec.blockedSec === 65, 'blockedSec derived from lagMs');
    assert(rec.op && rec.op.label === 'extract:quickscan' && rec.op.meta.unpackedSizeMb === 41, 'op + meta in the record');
    assert(typeof rec.rssMb === 'number' && rec.rssMb > 0, 'records process RSS at the stall');
    assert(typeof rec.ts === 'string' && rec.ts.includes('T'), 'ISO timestamp');
    elm._reset();
  });

  // ── End-to-end sampler (behavioral) ──
  await asyncTest('LOOP-MON: sampler fires on a real sync block and attributes the in-flight op (positive)', async () => {
    const os = require('os'); const pathM = require('path'); const fsM = require('fs');
    const tmpFile = pathM.join(os.tmpdir(), `loop-stalls-test-${process.pid}.jsonl`);
    const savedEnv = process.env.MUADDIB_LOOP_STALL_FILE;
    process.env.MUADDIB_LOOP_STALL_FILE = tmpFile; // isolate the stall log from prod data/
    const modPath = require.resolve('../../src/monitor/event-loop-monitor.js');
    delete require.cache[modPath];
    const elm2 = require('../../src/monitor/event-loop-monitor.js');
    let captured = null;
    const stop = elm2.startLagSampler({ intervalMs: 10, thresholdMs: 40, onStall: (r) => { captured = r; } });
    try {
      await new Promise(r => setTimeout(r, 50)); // let the sampler seed + tick normally first
      elm2.beginOp('extract:quickscan', { name: 'big-native', version: '1.0.0', unpackedSizeMb: 47 });
      const until = Date.now() + 120; while (Date.now() < until) { /* busy-wait: WEDGE the event loop */ }
      elm2.endOp();
      await new Promise(r => setTimeout(r, 80)); // let the post-block tick observe the lag
      assert(captured, 'onStall must fire after a >40ms loop block');
      assert(captured.lagMs >= 40, `lag reflects the ~120ms block, got ${captured.lagMs}`);
      assert(captured.op && captured.op.label === 'extract:quickscan', `attributes the in-flight op, got ${JSON.stringify(captured.op)}`);
      assert(captured.op.meta && captured.op.meta.name === 'big-native', 'attribution carries the package identity');
    } finally {
      stop();
      delete require.cache[modPath];
      if (savedEnv === undefined) delete process.env.MUADDIB_LOOP_STALL_FILE; else process.env.MUADDIB_LOOP_STALL_FILE = savedEnv;
      try { fsM.unlinkSync(tmpFile); } catch { /* best effort */ }
    }
  });

  await asyncTest('LOOP-MON: sampler stays silent on normal (unblocked) ticks (negative)', async () => {
    const modPath = require.resolve('../../src/monitor/event-loop-monitor.js');
    delete require.cache[modPath];
    const elm2 = require('../../src/monitor/event-loop-monitor.js');
    let fired = false;
    const stop = elm2.startLagSampler({ intervalMs: 10, thresholdMs: 5000, onStall: () => { fired = true; } });
    try {
      await new Promise(r => setTimeout(r, 90)); // ~9 normal ticks, none exceed 5s
      assert(fired === false, 'no stall reported when the loop is never blocked');
    } finally {
      stop();
      delete require.cache[modPath];
    }
  });

  // ── runInstrumented wrapper (the helper the daemon maintenance sites use) ──
  test('LOOP-MON: runInstrumented names the op WHILE fn runs and passes the return through', () => {
    let t = 100;
    elm._reset(() => t);
    let seenDuring = null;
    const ret = elm.runInstrumented('maint:runsc-cleanup', { dir: '/tmp/runsc' }, () => {
      t = 300100; // fn "blocks" ~300s of wall-clock
      seenDuring = elm.opOverlapping(100, 300100); // what a concurrent stall would attribute
      return 42;
    });
    assert(ret === 42, 'fn return value is passed through');
    assert(seenDuring && seenDuring.label === 'maint:runsc-cleanup' && seenDuring.running === true,
      `a stall during fn attributes to the wrapper op, got ${JSON.stringify(seenDuring)}`);
    assert(seenDuring.meta && seenDuring.meta.dir === '/tmp/runsc' && seenDuring.elapsedMs === 300000, 'carries meta + elapsed');
    elm._reset();
  });

  test('LOOP-MON: runInstrumented clears the breadcrumb after fn returns (no stale running op)', () => {
    let t = 100;
    elm._reset(() => t);
    elm.runInstrumented('maint:tarball-purge', null, () => { t = 200; });
    t = 5000;
    // _current is cleared → a window opening AFTER the op ended finds nothing running.
    assert(elm.opOverlapping(4000, 5000) === null, 'no running op after the wrapper returns');
    elm._reset();
  });

  test('LOOP-MON: runInstrumented clears the breadcrumb even when fn throws, and re-throws', () => {
    let t = 100;
    elm._reset(() => t);
    let threw = false;
    try {
      elm.runInstrumented('maint:disk-du-tmp', null, () => { throw new Error('du failed'); });
    } catch (e) { threw = true; assert(e.message === 'du failed', 're-throws the fn error verbatim'); }
    assert(threw, 'error propagates out of runInstrumented');
    t = 9000;
    assert(elm.opOverlapping(8000, 9000) === null, 'breadcrumb cleared in finally even on throw');
    elm._reset();
  });

  // ── Daemon wiring: the maintenance function actually runs UNDER a breadcrumb ──
  // Behavioral (not source-grep): call the real daemon fn, observe the live breadcrumb
  // from inside its first fs.statSync, and assert the stale dir is still removed.
  // NB: the sampler tests above delete event-loop-monitor from require.cache, so the
  // top-level `elm` can be a DIFFERENT module instance than the one daemon captures.
  // Reset both and re-require in order so the observed instance IS daemon's instance.
  test('LOOP-MON: daemon.cleanupRunscOrphans runs under maint:runsc-cleanup (wiring + behavior)', () => {
    const fsM = require('fs'); const osM = require('os'); const pathM = require('path');
    const { spyOn } = require('../test-utils');
    const elmPath = require.resolve('../../src/monitor/event-loop-monitor.js');
    const daemonPath = require.resolve('../../src/monitor/daemon.js');
    delete require.cache[daemonPath];
    delete require.cache[elmPath];
    const daemon = require(daemonPath);   // loads event-loop-monitor fresh; daemon captures it
    const elmLive = require(elmPath);     // same instance daemon just cached
    elmLive._reset(); // real clock — daemon uses Date.now via runInstrumented
    const tmp = fsM.mkdtempSync(pathM.join(osM.tmpdir(), 'runsc-wire-'));
    const stale = pathM.join(tmp, 'stale-container');
    fsM.mkdirSync(stale);
    const old = new Date(Date.now() - 2 * 3600 * 1000);
    fsM.utimesSync(stale, old, old);
    const savedDir = process.env.MUADDIB_GVISOR_LOG_DIR;
    process.env.MUADDIB_GVISOR_LOG_DIR = tmp;
    let labelDuring = null;
    const spy = spyOn(fsM, 'statSync', function (...args) {
      if (labelDuring === null) {
        const op = elmLive.opOverlapping(0, Date.now() + 1000);
        labelDuring = op ? op.label : 'NONE';
      }
      return spy.original.apply(fsM, args);
    });
    try {
      const cleaned = daemon.cleanupRunscOrphans(3600_000);
      assert(labelDuring === 'maint:runsc-cleanup', `cleanup must run under the breadcrumb, saw ${labelDuring}`);
      assert(cleaned === 1, `stale dir removed (return preserved), got ${cleaned}`);
      assert(!fsM.existsSync(stale), 'stale runsc dir actually removed (behavior preserved through the wrapper)');
    } finally {
      spy.restore();
      if (savedDir === undefined) delete process.env.MUADDIB_GVISOR_LOG_DIR; else process.env.MUADDIB_GVISOR_LOG_DIR = savedDir;
      fsM.rmSync(tmp, { recursive: true, force: true });
    }
  });

  // Prove the state.js scan-ledger compaction — the leading multi-minute loop-stall
  // suspect (O(file) synchronous rewrite of ~500K entries) — now runs UNDER a
  // 'compact:scan-ledger' breadcrumb, so a sampler firing mid-compaction names IT
  // (durationMs ~ lagMs) instead of the stale docker:rm crumb. Behavior preserved: the
  // rewrite still drops to cap. Same require-fresh trick as the maint test so the
  // observed elm instance IS the one state.js captured (env is read at load time).
  test('LOOP-MON: state.appendScanLedger compaction runs under compact:scan-ledger (wiring + behavior)', () => {
    const fsM = require('fs'); const osM = require('os'); const pathM = require('path');
    const { spyOn } = require('../test-utils');
    const elmPath = require.resolve('../../src/monitor/event-loop-monitor.js');
    const statePath = require.resolve('../../src/monitor/state.js');
    const savedFile = process.env.MUADDIB_SCAN_LEDGER_FILE;
    const savedMax = process.env.MUADDIB_SCAN_LEDGER_MAX;
    const tmpDir = fsM.mkdtempSync(pathM.join(osM.tmpdir(), 'scanledger-'));
    const tmpLedger = pathM.join(tmpDir, 'scan-ledger.jsonl');
    process.env.MUADDIB_SCAN_LEDGER_FILE = tmpLedger;
    process.env.MUADDIB_SCAN_LEDGER_MAX = '10'; // min cap so a 2000-append burst really compacts
    delete require.cache[statePath];
    delete require.cache[elmPath];
    const state = require(statePath); // loads event-loop-monitor fresh; state captures it + reads env
    const elmLive = require(elmPath);  // same fresh instance state just cached
    elmLive._reset(); // real clock — state uses Date.now via runInstrumented
    let labelDuring = null;
    const spy = spyOn(fsM, 'renameSync', function (...args) {
      if (labelDuring === null) {
        const op = elmLive.opOverlapping(0, Date.now() + 1000);
        labelDuring = op ? op.label : 'NONE';
      }
      return spy.original.apply(fsM, args);
    });
    try {
      for (let i = 0; i < 2000; i++) { // SCAN_LEDGER_COMPACT_INTERVAL — trips exactly one compaction
        state.appendScanLedger({ name: 'p' + i, version: '1.0.0', ecosystem: 'npm', outcome: 'clean' });
      }
      assert(labelDuring === 'compact:scan-ledger', `compaction must run under the breadcrumb, saw ${labelDuring}`);
      const kept = fsM.readFileSync(tmpLedger, 'utf8').trim().split('\n').filter(Boolean).length;
      assert(kept === 10, `compaction still drops to cap (behavior preserved through the wrapper), kept ${kept}`);
    } finally {
      spy.restore();
      delete require.cache[statePath];
      delete require.cache[elmPath];
      if (savedFile === undefined) delete process.env.MUADDIB_SCAN_LEDGER_FILE; else process.env.MUADDIB_SCAN_LEDGER_FILE = savedFile;
      if (savedMax === undefined) delete process.env.MUADDIB_SCAN_LEDGER_MAX; else process.env.MUADDIB_SCAN_LEDGER_MAX = savedMax;
      fsM.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
}

module.exports = { runEventLoopMonitorTests };
