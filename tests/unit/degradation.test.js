const { test, asyncTest, assert } = require('../test-utils');
const os = require('os');
const path = require('path');

/**
 * Phase D (governors program): degradation registry — every degraded mode is
 * a named state, alarmed once on sustained entry, once on recovery, never
 * spamming the shared Discord webhook.
 *
 * Regression context (2026-06-12): the lean-IOC fallback re-armed the
 * per-worker RSS bomb behind one [WARN] line; temporal analysis shed itself
 * off for hours; the registry sat at max backoff all afternoon. Silent, all
 * of it.
 */

const deg = require('../../src/monitor/degradation.js');
const { capWorkersForDegradation } = require('../../src/monitor/queue.js');

const DEFS = {
  red0: { level: 'RED', sustainMs: 0 },
  yel30: { level: 'YELLOW', sustainMs: 30 * 60_000 }
};
const COOLDOWN = 6 * 3600_000;
const fresh = () => ({ states: {} });

async function runDegradationTests() {
  console.log('\n=== DEGRADATION REGISTRY TESTS (phase D) ===\n');

  // ─── Pure core ───

  test('DEGRADATION: instant state alarms once on entry and once on recovery', () => {
    let r = deg.evaluateDegradation({ red0: true }, fresh(), 1000, DEFS, COOLDOWN);
    assert(r.transitions.length === 1 && r.transitions[0].kind === 'enter' && r.transitions[0].level === 'RED',
      `entry must alarm (got ${JSON.stringify(r.transitions)})`);
    r = deg.evaluateDegradation({ red0: true }, r.nextState, 3000, DEFS, COOLDOWN);
    assert(r.transitions.length === 0 && r.active.includes('red0'),
      'still-active state must NOT re-alarm');
    r = deg.evaluateDegradation({ red0: false }, r.nextState, 5000, DEFS, COOLDOWN);
    assert(r.transitions.length === 1 && r.transitions[0].kind === 'recover',
      `clearing must emit one recovery (got ${JSON.stringify(r.transitions)})`);
    r = deg.evaluateDegradation({ red0: false }, r.nextState, 7000, DEFS, COOLDOWN);
    assert(r.transitions.length === 0, 'recovery must emit exactly once');
  });

  test('DEGRADATION: sustained state — 29min of signal is nothing, 31min is YELLOW', () => {
    const t0 = 1_000_000;
    let st = fresh();
    let r = deg.evaluateDegradation({ yel30: true }, st, t0, DEFS, COOLDOWN);
    assert(r.transitions.length === 0 && r.active.length === 0, 'fresh signal must not alarm');
    r = deg.evaluateDegradation({ yel30: true }, r.nextState, t0 + 29 * 60_000, DEFS, COOLDOWN);
    assert(r.transitions.length === 0, '29min sustained must not alarm');
    r = deg.evaluateDegradation({ yel30: true }, r.nextState, t0 + 31 * 60_000, DEFS, COOLDOWN);
    assert(r.transitions.length === 1 && r.transitions[0].kind === 'enter' && r.active.includes('yel30'),
      `31min sustained must alarm YELLOW (got ${JSON.stringify(r.transitions)})`);
  });

  test('DEGRADATION: flapping resets the sustain clock and never alarms (anti-spam)', () => {
    const t0 = 1_000_000;
    let st = fresh();
    // 20min on, 1 tick off, 20min on — never 30min continuous.
    let r = deg.evaluateDegradation({ yel30: true }, st, t0, DEFS, COOLDOWN);
    r = deg.evaluateDegradation({ yel30: true }, r.nextState, t0 + 20 * 60_000, DEFS, COOLDOWN);
    r = deg.evaluateDegradation({ yel30: false }, r.nextState, t0 + 21 * 60_000, DEFS, COOLDOWN);
    r = deg.evaluateDegradation({ yel30: true }, r.nextState, t0 + 22 * 60_000, DEFS, COOLDOWN);
    r = deg.evaluateDegradation({ yel30: true }, r.nextState, t0 + 42 * 60_000, DEFS, COOLDOWN);
    assert(r.transitions.length === 0 && r.active.length === 0,
      `interrupted signal must never alarm (got ${JSON.stringify(r.transitions)})`);
  });

  test('DEGRADATION: re-entry within the cooldown stays silent but the state shows active', () => {
    let r = deg.evaluateDegradation({ red0: true }, fresh(), 1000, DEFS, COOLDOWN);   // alarm
    r = deg.evaluateDegradation({ red0: false }, r.nextState, 2000, DEFS, COOLDOWN);  // recover
    r = deg.evaluateDegradation({ red0: true }, r.nextState, 3000, DEFS, COOLDOWN);   // re-enter, 1s later
    assert(r.transitions.length === 0, 're-entry under cooldown must not re-alarm the webhook');
    assert(r.active.includes('red0'), 'but the state must still be ACTIVE (honest visibility)');
    // After the cooldown, a fresh entry alarms again.
    r = deg.evaluateDegradation({ red0: false }, r.nextState, 4000, DEFS, COOLDOWN);
    r = deg.evaluateDegradation({ red0: true }, r.nextState, 4000 + COOLDOWN + 1, DEFS, COOLDOWN);
    assert(r.transitions.length === 1 && r.transitions[0].kind === 'enter',
      'post-cooldown entry must alarm again');
  });

  // ─── Tick integration (state file + dispatch, injectable) ───

  await asyncTest('DEGRADATION: tickDegradation dispatches one embed per transition and persists state', async () => {
    const savedFile = process.env.MUADDIB_DEGRADATION_FILE;
    process.env.MUADDIB_DEGRADATION_FILE = path.join(os.tmpdir(), `muaddib-test-deg-${process.pid}.json`);
    const degPath = require.resolve('../../src/monitor/degradation.js');
    delete require.cache[degPath];
    try {
      const d = require(degPath);
      d.resetDegradation();
      const sent = [];
      const dispatch = async (p) => sent.push(p.embeds[0].title);
      await d.tickDegradation({ 'ioc:full-fallback': true }, Date.now(), dispatch);
      assert(sent.length === 1 && /DEGRADED: ioc:full-fallback/.test(sent[0]),
        `entry must dispatch one embed (got ${JSON.stringify(sent)})`);
      assert(d.isDegraded('ioc:full-fallback') === true, 'isDegraded must reflect the active state');
      await d.tickDegradation({ 'ioc:full-fallback': true }, Date.now(), dispatch);
      assert(sent.length === 1, 'no re-dispatch while active');
      await d.tickDegradation({ 'ioc:full-fallback': false }, Date.now(), dispatch);
      assert(sent.length === 2 && /RECOVERED/.test(sent[1]), 'recovery dispatches once');
      assert(d.isDegraded('ioc:full-fallback') === false, 'recovered state is no longer active');
    } finally {
      if (savedFile === undefined) delete process.env.MUADDIB_DEGRADATION_FILE;
      else process.env.MUADDIB_DEGRADATION_FILE = savedFile;
      delete require.cache[degPath];
    }
  });

  // ─── ensureWorkers coupling (pure) ───

  test('DEGRADATION: ioc:full-fallback caps the worker pool at 4; inactive state caps nothing', () => {
    assert(capWorkersForDegradation(8, 0, true) === 4, 'fallback active: spawn capped to reach 4');
    assert(capWorkersForDegradation(8, 3, true) === 1, 'fallback active with 3 running: 1 more allowed');
    assert(capWorkersForDegradation(8, 6, true) === 0, 'fallback active above the cap: zero new spawns');
    assert(capWorkersForDegradation(8, 0, false) === 8, 'no degradation: spawn untouched (negative)');
  });
}

module.exports = { runDegradationTests };
