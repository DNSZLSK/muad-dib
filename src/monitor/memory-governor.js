'use strict';

/**
 * Memory governor (governors program, phase B) — global admission control for
 * scan memory, by ticket.
 *
 * Why: every prior guard bounded a LOCAL variable while the resource is
 * global. The per-worker watermark watches one isolate; the heavy-lane
 * serializes packages that are individually heavy. The 2026-06-12 09:43
 * EMERGENCY (RSS 96%, main heap 4%) was neither: 12 workers × ~650MB of
 * sub-threshold scans (an ATO burst of SDK packages) — no individual
 * threshold crossed, the AGGREGATE blew the breaker. The governor bounds the
 * aggregate at ADMISSION: each scan pays a ticket sized by its weight class
 * before the worker spawns; Σ outstanding tickets ≤ budget; and admissions
 * freeze on REAL process RSS (sampled by the daemon's 2s breaker loop — NOT
 * worker-mem samples, which land on disk every 10s and starve during the
 * synchronous parses that matter).
 *
 * Ticket classes are FIXED (env-overridable), never learned from observed
 * usage: auto-calibrated weights would be shapeable by an attacker crafting
 * packages, and config-debt review (2026-06-11) bans measurement→threshold
 * feedback loops.
 *
 * Invariants:
 *   - Carve-out: heavies can consume at most (budget − LIGHT_CARVEOUT); a
 *     light is never blocked by heavy consumption — preserves the heavy-lane
 *     "lights are NEVER blocked" guarantee, and an attacker publishing heavy
 *     packages cannot starve everyone else's scans.
 *   - Liveness: when frozen with ZERO outstanding tickets, one scan is
 *     admitted anyway (a stuck-high RSS reading must never deadlock the
 *     queue; the EMERGENCY breaker remains the backstop).
 *   - The governor is OFF unless MUADDIB_MEMORY_GOVERNOR=1 — acquire resolves
 *     `false` (nothing to release) and the legacy heavy-lane path applies.
 *
 * Same waiter contract as heavy-lane.js (abort-aware, wait-timeout, and the
 * "trap #1": any waiter leaving the queue without being woken MUST splice
 * itself out, or a release hands its grant to a dead waiter and leaks it).
 * EMERGENCY purge + adaptive-concurrency + rssAdmissionCap are all kept as
 * backstops (defense in depth) — the governor is the front gate, not a
 * replacement for them.
 */

const { isHeavyScan } = require('./heavy-lane.js');

// Env knobs (read at call time so tests can flip them around resetGovernor()):
function isGovernorEnabled() {
  return process.env.MUADDIB_MEMORY_GOVERNOR === '1';
}

function _envMb(name, dflt) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v > 0 ? v : dflt;
}

function ticketMb(cls) {
  if (cls === 'heavy') return _envMb('MUADDIB_TICKET_HEAVY_MB', 2048);
  if (cls === 'medium') return _envMb('MUADDIB_TICKET_MEDIUM_MB', 256);
  return _envMb('MUADDIB_TICKET_LIGHT_MB', 64);
}

// medium starts at 1 MiB of weighted JS (heavy-lane's threshold is 3 MiB —
// the band between them is where the "many at once" aggregate risk lives).
function mediumThresholdBytes() {
  const v = parseInt(process.env.MUADDIB_TICKET_MEDIUM_THRESHOLD_BYTES, 10);
  return Number.isFinite(v) && v > 0 ? v : 1024 * 1024;
}

function lightCarveoutMb() {
  return _envMb('MUADDIB_GOVERNOR_LIGHT_CARVEOUT_MB', 512);
}

function rssSoftPct() {
  const v = parseInt(process.env.MUADDIB_GOVERNOR_RSS_SOFT_PCT, 10);
  return Number.isFinite(v) && v > 0 && v < 100 ? v : 75;
}

function rssLimitMb() {
  const v = parseInt(process.env.MUADDIB_RSS_LIMIT_MB, 10);
  return Number.isFinite(v) && v > 0 ? v : 8500;
}

// ─── State ───

const _gov = {
  outstandingMb: 0,
  outstandingCount: 0,
  byCls: { light: 0, medium: 0, heavy: 0 },
  heavyOutstandingMb: 0,
  queue: [], // FIFO of {cls, mb, grant(ticket), bail-able — see acquire}
  lastRssBytes: 0,
  baselineRssBytes: 0,
  freezes: 0,
  granted: 0,
  denied: 0
};

/**
 * Pure classifier (exported for tests). heavy ≡ isHeavyScan (oversize /
 * truncated / ≥3MiB weighted); medium = weighted JS ≥ mediumThresholdBytes;
 * light otherwise (including a null weight — an unmeasurable-but-not-truncated
 * package is small).
 */
function classifyWeight(jsWeight) {
  if (jsWeight && isHeavyScan(jsWeight)) return { cls: 'heavy', mb: ticketMb('heavy') };
  const effective = jsWeight
    ? (Number.isFinite(jsWeight.weightedJsBytes) ? jsWeight.weightedJsBytes : (jsWeight.totalJsBytes || 0))
    : 0;
  if (effective >= mediumThresholdBytes()) return { cls: 'medium', mb: ticketMb('medium') };
  return { cls: 'light', mb: ticketMb('light') };
}

/** Budget in MB: rssLimit×0.7 − boot baseline. 0 until the first RSS sample. */
function _budgetMb() {
  if (!_gov.baselineRssBytes) return 0;
  return Math.max(0, Math.floor(rssLimitMb() * 0.7 - _gov.baselineRssBytes / 1024 / 1024));
}

function isFrozen() {
  if (!isGovernorEnabled()) return false;
  if (!_gov.lastRssBytes) return false;
  return _gov.lastRssBytes / 1024 / 1024 > rssLimitMb() * (rssSoftPct() / 100);
}

function _canAdmit(cls, mb) {
  if (isFrozen()) return false;
  if (cls === 'light') return true; // carve-out: lights only ever blocked by the RSS freeze
  const budget = _budgetMb();
  if (budget <= 0) return true; // no baseline yet (boot) — admit, breaker backstops
  if (_gov.outstandingMb + mb > budget) return false;
  if (cls === 'heavy' && _gov.heavyOutstandingMb + mb > Math.max(0, budget - lightCarveoutMb())) return false;
  return true;
}

function _grant(cls, mb) {
  _gov.outstandingMb += mb;
  _gov.outstandingCount += 1;
  _gov.byCls[cls] += 1;
  if (cls === 'heavy') _gov.heavyOutstandingMb += mb;
  _gov.granted += 1;
  return { cls, mb, _released: false };
}

function _drainWaiters() {
  if (_gov.queue.length === 0) return;
  // FIFO with anti head-of-line for lights: a blocked heavy/medium must not
  // park the lights queued behind it (they are admittable whenever unfrozen).
  for (let i = 0; i < _gov.queue.length; ) {
    const w = _gov.queue[i];
    const liveness = isFrozen() && _gov.outstandingCount === 0 && i === 0;
    if (liveness || _canAdmit(w.cls, w.mb)) {
      _gov.queue.splice(i, 1);
      w.wake(_grant(w.cls, w.mb));
    } else if (w.cls !== 'light' ) {
      i++; // blocked non-light: skip it, lights behind may still pass
    } else {
      i++; // frozen light — nothing passes until unfreeze/liveness
    }
  }
}

/**
 * Acquire a memory ticket. Resolves the ticket object, or `false` when the
 * governor is disabled (nothing to release — mirrors acquireHeavySlot).
 * Rejects err.code='ABORT_ERR' on outer-scan abort, 'TICKET_WAIT_TIMEOUT'
 * after maxWaitMs (caller requeues, same path as the heavy lane).
 */
function acquireMemoryTicket(cls, opts = {}) {
  if (!isGovernorEnabled()) return Promise.resolve(false);
  const mb = ticketMb(cls);
  // Liveness: a frozen governor with nothing in flight must still move.
  if ((_canAdmit(cls, mb)) || (isFrozen() && _gov.outstandingCount === 0)) {
    return Promise.resolve(_grant(cls, mb));
  }
  if (isFrozen()) _gov.freezes += 1;
  const { signal, maxWaitMs } = opts;
  return new Promise((resolve, reject) => {
    let timer = null;
    const cleanup = () => {
      if (timer) { clearTimeout(timer); timer = null; }
      if (signal) { try { signal.removeEventListener('abort', onAbort); } catch { /* not added */ } }
    };
    const waiter = {
      cls,
      mb,
      wake: (ticket) => { cleanup(); resolve(ticket); }
    };
    // Trap #1 (heavy-lane.js): leaving the queue WITHOUT being woken must
    // splice the waiter out, or a future drain wakes a dead waiter and the
    // ticket leaks permanently.
    const bail = (err) => {
      const i = _gov.queue.indexOf(waiter);
      if (i === -1) return; // already woken — the grant path owns the ticket
      _gov.queue.splice(i, 1);
      cleanup();
      _gov.denied += 1;
      reject(err);
    };
    const onAbort = () => {
      const err = new Error('Memory-ticket wait aborted (outer scan timeout)');
      err.code = 'ABORT_ERR';
      bail(err);
    };
    _gov.queue.push(waiter);
    if (signal) {
      if (signal.aborted) { onAbort(); return; }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    if (Number.isFinite(maxWaitMs) && maxWaitMs > 0) {
      // NOT unref'd: a pending admission is active work (an extracted package
      // on tmp disk waiting to scan) — it must keep the process alive.
      timer = setTimeout(() => {
        const err = new Error(`Memory ticket (${cls}, ${mb}MB) not acquired within ${maxWaitMs}ms`);
        err.code = 'TICKET_WAIT_TIMEOUT';
        bail(err);
      }, maxWaitMs);
    }
  });
}

function releaseMemoryTicket(ticket) {
  if (!ticket || ticket._released) return;
  ticket._released = true;
  _gov.outstandingMb = Math.max(0, _gov.outstandingMb - ticket.mb);
  _gov.outstandingCount = Math.max(0, _gov.outstandingCount - 1);
  _gov.byCls[ticket.cls] = Math.max(0, _gov.byCls[ticket.cls] - 1);
  if (ticket.cls === 'heavy') _gov.heavyOutstandingMb = Math.max(0, _gov.heavyOutstandingMb - ticket.mb);
  _drainWaiters();
}

/**
 * Feed the governor the process RSS (daemon breaker loop, every 2s). The
 * FIRST sample becomes the boot baseline the budget is computed against —
 * a frozen-at-boot dette documented in the plan: the baseline drifts up over
 * days; phase D's `workers:memory-floored` state is the visibility loop.
 */
function updateGovernorRss(rssBytes) {
  if (!Number.isFinite(rssBytes) || rssBytes <= 0) return;
  if (!_gov.baselineRssBytes) _gov.baselineRssBytes = rssBytes;
  const wasFrozen = isFrozen();
  _gov.lastRssBytes = rssBytes;
  if (wasFrozen && !isFrozen()) _drainWaiters();
}

function getGovernorState() {
  return {
    enabled: isGovernorEnabled(),
    frozen: isFrozen(),
    outstandingMb: _gov.outstandingMb,
    outstandingCount: _gov.outstandingCount,
    byCls: { ..._gov.byCls },
    heavyOutstandingMb: _gov.heavyOutstandingMb,
    waiting: _gov.queue.length,
    budgetMb: _budgetMb(),
    baselineRssMb: Math.round(_gov.baselineRssBytes / 1024 / 1024),
    lastRssMb: Math.round(_gov.lastRssBytes / 1024 / 1024),
    granted: _gov.granted,
    freezes: _gov.freezes
  };
}

/** Test helper — same role as resetHeavyLane. */
function resetGovernor() {
  _gov.outstandingMb = 0;
  _gov.outstandingCount = 0;
  _gov.byCls = { light: 0, medium: 0, heavy: 0 };
  _gov.heavyOutstandingMb = 0;
  while (_gov.queue.length > 0) {
    const w = _gov.queue.shift();
    w.wake(_grant(w.cls, w.mb)); // release parked waiters so tests never hang
  }
  _gov.outstandingMb = 0;
  _gov.outstandingCount = 0;
  _gov.byCls = { light: 0, medium: 0, heavy: 0 };
  _gov.heavyOutstandingMb = 0;
  _gov.lastRssBytes = 0;
  _gov.baselineRssBytes = 0;
  _gov.freezes = 0;
  _gov.granted = 0;
  _gov.denied = 0;
}

module.exports = {
  isGovernorEnabled,
  classifyWeight,
  acquireMemoryTicket,
  releaseMemoryTicket,
  updateGovernorRss,
  isFrozen,
  getGovernorState,
  resetGovernor,
  ticketMb
};
