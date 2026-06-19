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
}

module.exports = { runEventLoopMonitorTests };
