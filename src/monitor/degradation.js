'use strict';

/**
 * Degradation registry (governors program, phase D) — every degraded mode of
 * the monitor becomes a NAMED state: alarmed once on entry (webhook), once on
 * recovery, visible in the hourly Stability log and the daily report.
 *
 * Why: the failure mode of 2026-06-12 was not crashing — it was degrading
 * SILENTLY. The lean-IOC fallback re-arms the per-worker RSS bomb with a
 * single [WARN] line; a corrupted lean continues with FEWER IOCs (coverage
 * loss, no fallback at all); temporal analysis sheds itself off above queue
 * 2000 and stays off for hours; the registry sat at max backoff for an
 * afternoon. None of these pages anyone unless someone greps the journal.
 *
 * Modeled on feed-health.js (pure decision core + persisted state file +
 * edge-triggered webhook with recovery), EXTENDED with sustain durations:
 * `evaluateDegradation(signals, prev, now)` tracks per-state activeSince so
 * flapping signals (queue oscillating around the temporal shed threshold)
 * never alarm, and only conditions sustained past their threshold do.
 * Re-entry within REALARM_COOLDOWN_MS of the last alarm stays silent (the
 * state still shows active everywhere) — the Discord webhook is shared with
 * detection alerts and must never be flooded.
 *
 * The registry also feeds one defensive coupling: ensureWorkers caps the pool
 * at FALLBACK_WORKER_CAP while `ioc:full-fallback` is active — each worker in
 * fallback parses the full 223MB iocs.json (~450MB peak), and 12 of them is
 * exactly the RSS bomb the lean projection removed.
 */

const fs = require('fs');
const path = require('path');

const STATE_FILE = process.env.MUADDIB_DEGRADATION_FILE
  || path.join(__dirname, '..', '..', 'data', 'degradation.json');

// One alarm per entry; re-entry within the cooldown stays silent.
const REALARM_COOLDOWN_MS = (() => {
  const v = parseInt(process.env.MUADDIB_DEGRADATION_COOLDOWN_MS, 10);
  return Number.isFinite(v) && v >= 0 ? v : 6 * 3600_000;
})();

// Sustain thresholds: how long a raw signal must hold before it IS a
// degradation. Instant for the IOC states (each affected worker spawn costs
// ~450MB / loses coverage immediately); duration-gated for the flappy ones.
const STATE_DEFS = {
  'ioc:full-fallback': { level: 'RED', sustainMs: 0, desc: 'iocs-lean.json missing/stale — every worker spawn parses the FULL 223MB iocs.json (~450MB peak each)' },
  'ioc:lean-parse-failed': { level: 'RED', sustainMs: 0, desc: 'iocs-lean.json unparseable — scans run with FEWER IOCs (silent coverage loss, no fallback)' },
  'registry:max-backoff': { level: 'RED', sustainMs: 15 * 60_000, desc: 'a registry host has been at maximum backoff pause — enrichment fetches are starving' },
  'temporal:shed': { level: 'YELLOW', sustainMs: 30 * 60_000, desc: 'temporal analysis has been load-shedding continuously (queue above the shed threshold)' },
  'workers:memory-floored': { level: 'YELLOW', sustainMs: 10 * 60_000, desc: 'the memory governor has been freezing admissions — budget likely outgrown by baseline drift' }
};

/**
 * Pure decision core (exported for tests — no I/O, no Date.now()).
 *
 * @param {Object<string,boolean>} signals - raw signal per state name, this tick
 * @param {{states: Object}} prev - previous registry state
 * @param {number} now - timestamp ms
 * @returns {{transitions: Array<{name, kind:'enter'|'recover', level, sinceMs}>,
 *            active: string[], nextState: {states: Object}}}
 */
function evaluateDegradation(signals, prev, now, defs = STATE_DEFS, cooldownMs = REALARM_COOLDOWN_MS) {
  const prevStates = (prev && prev.states) || {};
  const nextStates = {};
  const transitions = [];
  const active = [];

  for (const [name, def] of Object.entries(defs)) {
    const raw = !!signals[name];
    const p = prevStates[name] || {};
    if (raw) {
      const activeSince = p.activeSince || now;
      const sustained = now - activeSince >= def.sustainMs;
      let alarmedAt = p.alarmedAt || 0;
      let lastAlarmAt = p.lastAlarmAt || 0;
      if (sustained && !alarmedAt) {
        // Cooldown only gates RE-entries (lastAlarmAt > 0): a virgin state must
        // alarm immediately regardless of how small `now` is.
        if (!lastAlarmAt || now - lastAlarmAt >= cooldownMs) {
          transitions.push({ name, kind: 'enter', level: def.level, sinceMs: now - activeSince });
          lastAlarmAt = now;
        }
        // alarmed (or silently re-entered under cooldown): either way the
        // state is ACTIVE and a future recovery must be emitted.
        alarmedAt = now;
      }
      if (sustained) active.push(name);
      nextStates[name] = { activeSince, alarmedAt: alarmedAt || undefined, lastAlarmAt: lastAlarmAt || undefined };
    } else {
      if (p.alarmedAt) {
        transitions.push({ name, kind: 'recover', level: def.level, sinceMs: p.activeSince ? now - p.activeSince : 0 });
      }
      // Keep lastAlarmAt across the recovery: it is the re-entry cooldown anchor.
      nextStates[name] = p.lastAlarmAt ? { lastAlarmAt: p.lastAlarmAt } : {};
    }
  }
  return { transitions, active, nextState: { states: nextStates } };
}

// ─── Module state (daemon tick) ───

let _state = null;
let _active = new Set();

function _loadState() {
  if (_state) return _state;
  try { _state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { _state = { states: {} }; }
  return _state;
}

function _saveState() {
  try {
    const tmp = STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(_state));
    fs.renameSync(tmp, STATE_FILE);
  } catch { /* observability state is best-effort */ }
}

/**
 * Daemon tick: evaluate raw signals, persist, dispatch alarms for transitions.
 * Cheap (a few statSync upstream + pure math here) — runs from the 2s loop.
 * `dispatch` is injectable for tests; defaults to the shared webhook.
 */
async function tickDegradation(signals, now = Date.now(), dispatch = _defaultDispatch) {
  const prev = _loadState();
  const { transitions, active, nextState } = evaluateDegradation(signals, prev, now);
  _state = nextState;
  _active = new Set(active);
  if (transitions.length > 0) {
    _saveState();
    for (const t of transitions) {
      const def = STATE_DEFS[t.name] || {};
      const enter = t.kind === 'enter';
      console[enter ? 'warn' : 'log'](`[DEGRADATION] ${enter ? 'ENTER' : 'RECOVER'} ${t.level} ${t.name}${enter ? '' : ` (was active ${Math.round(t.sinceMs / 60000)}min)`}`);
      try {
        await dispatch({
          embeds: [{
            title: enter ? `🔻 DEGRADED: ${t.name}` : `✅ RECOVERED: ${t.name}`,
            color: enter ? (t.level === 'RED' ? 0xe74c3c : 0xf39c12) : 0x2ecc71,
            description: enter ? (def.desc || t.name) : `Degradation cleared after ${Math.round(t.sinceMs / 60000)} min.`,
            footer: { text: "MUAD'DIB degradation registry" },
            timestamp: new Date(now).toISOString()
          }]
        });
      } catch { /* alarm is best-effort — the journal line above is the record */ }
    }
  } else {
    _saveState();
  }
  return { transitions, active };
}

async function _defaultDispatch(payload) {
  const url = process.env.MUADDIB_WEBHOOK_URL;
  if (!url) return;
  const { sendWebhook } = require('../webhook.js');
  await sendWebhook(url, payload, { rawPayload: true });
}

/** Synchronous view for couplings (ensureWorkers cap) and the daily report. */
function getActiveDegradations() {
  return Array.from(_active);
}

function isDegraded(name) {
  return _active.has(name);
}

/** Test helper. */
function resetDegradation() {
  _state = { states: {} };
  _active = new Set();
}

module.exports = {
  STATE_DEFS,
  evaluateDegradation,
  tickDegradation,
  getActiveDegradations,
  isDegraded,
  resetDegradation
};
