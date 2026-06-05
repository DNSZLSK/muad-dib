/**
 * P2.1 / P2.4 — Restart tracking + crash-loop alert.
 *
 * The chronic ~10×/day OOM crash-loop went unnoticed for weeks because nothing counted
 * restarts. recordRestart() logs each boot, counts the last 24h, and raises a CRASH-LOOP
 * ALERT (journal + rate-limited webhook) above a threshold. The 24h count is surfaced in
 * the daily report so the next incident is self-evident.
 *
 * Behavioral: drives the real recordRestart / countRecentRestarts with fs stubbed to an
 * in-memory store (so nothing touches real data/) and no webhook URL configured.
 */

const fs = require('fs');
const { test, assert } = require('../test-utils');
const { recordRestart, countRecentRestarts } = require('../../src/monitor/daemon.js');

function withMemFs(initial, fn) {
  const store = Object.assign({}, initial);
  const saved = {};
  for (const m of ['readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'renameSync', 'mkdirSync', 'unlinkSync']) saved[m] = fs[m];
  const base = p => String(p).split(/[\\/]/).pop();
  fs.existsSync = p => base(p) in store;
  fs.readFileSync = (p) => { const b = base(p); if (b in store) return store[b]; const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; };
  fs.writeFileSync = (p, data) => { store[base(p)] = data; };
  fs.appendFileSync = (p, data) => { store[base(p)] = (store[base(p)] || '') + data; };
  fs.renameSync = (a, b) => { store[base(b)] = store[base(a)]; delete store[base(a)]; };
  fs.mkdirSync = () => {};
  fs.unlinkSync = (p) => { delete store[base(p)]; };
  try { return fn(store); } finally { for (const m of Object.keys(saved)) fs[m] = saved[m]; }
}

const isoAgo = h => new Date(Date.now() - h * 3600 * 1000).toISOString();

async function runRestartTrackingTests() {
  console.log('\n=== RESTART TRACKING + CRASH-LOOP ALERT TESTS (P2) ===\n');

  // POSITIVE: only restarts within the window are counted.
  test('P2.1: countRecentRestarts counts only entries within the 24h window', () => {
    const lines = [
      JSON.stringify({ ts: isoAgo(1), pid: 1 }),   // 1h  ✓
      JSON.stringify({ ts: isoAgo(5), pid: 2 }),   // 5h  ✓
      JSON.stringify({ ts: isoAgo(30), pid: 3 }),  // 30h ✗
    ].join('\n') + '\n';
    const n = withMemFs({ 'restarts.jsonl': lines }, () => countRecentRestarts(24 * 3600 * 1000));
    assert(n === 2, `should count 2 within 24h, got ${n}`);
  });

  // POSITIVE (alert): above the threshold, recordRestart raises a CRASH-LOOP ALERT.
  test('P2.4: recordRestart raises a CRASH-LOOP ALERT above the threshold', () => {
    const lines = Array.from({ length: 7 }, (_, i) => JSON.stringify({ ts: isoAgo(i), pid: i })).join('\n') + '\n';
    const errs = [];
    const origErr = console.error, origLog = console.log;
    const origUrl = process.env.MUADDIB_WEBHOOK_URL; delete process.env.MUADDIB_WEBHOOK_URL; // no webhook in tests
    console.error = (...a) => errs.push(a.join(' ')); console.log = () => {};
    let count;
    try { count = withMemFs({ 'restarts.jsonl': lines }, () => recordRestart()); }
    finally { console.error = origErr; console.log = origLog; if (origUrl !== undefined) process.env.MUADDIB_WEBHOOK_URL = origUrl; }
    assert(count >= 8, `this boot should be counted too (>=8), got ${count}`);
    assert(errs.some(e => e.includes('CRASH-LOOP ALERT')), 'should log a CRASH-LOOP ALERT above threshold');
  });

  // NEGATIVE: a healthy history logs a normal BOOT line, no alert.
  test('P2.1: recordRestart on healthy history logs a normal boot (no alert)', () => {
    const logs = [], errs = [];
    const origErr = console.error, origLog = console.log;
    console.log = (...a) => logs.push(a.join(' ')); console.error = (...a) => errs.push(a.join(' '));
    let count;
    try { count = withMemFs({}, () => recordRestart()); } // empty history → this is restart #1
    finally { console.error = origErr; console.log = origLog; }
    assert(count === 1, `first boot → count 1, got ${count}`);
    assert(logs.some(l => l.includes('BOOT: restart #1')), 'should log a normal boot line');
    assert(!errs.some(e => e.includes('CRASH-LOOP')), 'no crash-loop alert on healthy history');
  });

  // BOUNDED: recordRestart trims restarts.jsonl to the cap (CLAUDE.md §2).
  test('P2.1: recordRestart bounds restarts.jsonl to the line cap', () => {
    const many = Array.from({ length: 600 }, (_, i) => JSON.stringify({ ts: isoAgo(0), pid: i })).join('\n') + '\n';
    let stored;
    const origLog = console.log, origErr = console.error; console.log = () => {}; console.error = () => {};
    try {
      withMemFs({ 'restarts.jsonl': many }, (store) => { recordRestart(); stored = store['restarts.jsonl']; });
    } finally { console.log = origLog; console.error = origErr; }
    const lineCount = stored.split('\n').filter(Boolean).length;
    assert(lineCount <= 500, `should trim to <=500 lines, got ${lineCount}`);
  });

  console.log('  ✓ restart tracking + crash-loop alert (P2) tests passed');
}

module.exports = { runRestartTrackingTests };
