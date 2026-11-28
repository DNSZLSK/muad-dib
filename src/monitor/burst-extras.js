'use strict';

/**
 * Backpressure on burst extras (the other recent versions of a package queued next to
 * the version a change event resolved to, queue.js resolveTarballAndScan).
 *
 * Extras are protected from queue-cap eviction, so under saturation they stay queued
 * while ordinary first scans are evicted, and they keep the queue above the ingestion
 * backpressure (ingestion.js SOFT_BACKPRESSURE_THRESHOLD): polls are skipped and the
 * changes feed stops advancing. Above MUADDIB_BURST_EXTRA_MAX_QUEUE queued items, an
 * ordinary extra is no longer queued. An extra is still queued, whatever the queue length,
 * when it carries a signal:
 *   - ioc:             the package name is in the IOC database (wildcard or any version),
 *                      or the parent is an IOC match
 *   - ato:             the parent carries the ATO signal (published version != latest tag)
 *   - kept_for_signal: kept past the recency cap for an install-hook delta (ingestion.js)
 *   - hook_delta:      its install hooks differ from the resolved version
 *   - burst_new:       burst of a package that is not established (the Shai-Hulud /
 *                      Miasma shape: a new or low-reputation package suddenly bursting)
 * Lost: an intermediate version of an ordinary burst (established package, or no burst),
 * with the same install hooks as the resolved version, while the queue is above the
 * threshold. Each one is written to the scan ledger (outcome dropped,
 * source burst_extra_backpressure).
 */

const { _hasInstallHookDelta } = require('./ingestion.js');

const DEFAULT_MAX_QUEUE = 20_000;
const COUNTER_LOG_INTERVAL_MS = 60_000;
const REASONS = ['below_threshold', 'ioc', 'ato', 'kept_for_signal', 'hook_delta', 'burst_new'];

function burstExtraMaxQueue() {
  const v = parseInt(process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE, 10);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_MAX_QUEUE;
}

// Same predicate as the burst pre-alert anti-flood (queue.js): mature and many versions.
function isEstablishedPackage(npmInfo) {
  const np = npmInfo || {};
  return Number.isFinite(np.age_days) && np.age_days > 730 &&
    Number.isFinite(np.version_count) && np.version_count > 100;
}

function isIOCKnownName(iocs, name) {
  if (!iocs || !name) return false;
  const wild = iocs.wildcardPackages;
  const pkgs = iocs.packagesMap;
  return !!((wild && typeof wild.has === 'function' && wild.has(name)) ||
            (pkgs && typeof pkgs.has === 'function' && pkgs.has(name)));
}

/**
 * Pure decision for one extra. `getIocs` is called only above the threshold.
 * @returns {{enqueue: boolean, reason: string}}
 */
function decideBurstExtra(extra, ctx) {
  if (ctx.queueLength < ctx.maxQueue) return { enqueue: true, reason: 'below_threshold' };
  const parent = ctx.parent || {};
  if (parent.isIOCMatch || isIOCKnownName(ctx.getIocs ? ctx.getIocs() : null, parent.name)) {
    return { enqueue: true, reason: 'ioc' };
  }
  if (parent.atoSignal) return { enqueue: true, reason: 'ato' };
  if (extra.keptForSignal) return { enqueue: true, reason: 'kept_for_signal' };
  if (_hasInstallHookDelta(extra.scripts, ctx.parentScripts)) return { enqueue: true, reason: 'hook_delta' };
  if (ctx.isBurst && !ctx.established) return { enqueue: true, reason: 'burst_new' };
  return { enqueue: false, reason: 'backpressure' };
}

// Per-interval counters (fixed key set, bounded).
let _counters = _emptyCounters();
let _lastLog = Date.now();

function _emptyCounters() {
  const enqueued = {};
  for (const r of REASONS) enqueued[r] = 0;
  return { enqueued, dropped: 0 };
}

function _maybeLogCounters(now, log) {
  if (now - _lastLog < COUNTER_LOG_INTERVAL_MS) return;
  const c = _counters;
  const total = REASONS.reduce((a, r) => a + c.enqueued[r], 0);
  if (total > 0 || c.dropped > 0) {
    const parts = REASONS.filter(r => c.enqueued[r] > 0).map(r => `${r} ${c.enqueued[r]}`).join(', ');
    log(`[MONITOR] BURST EXTRAS (last ${Math.round((now - _lastLog) / 1000)}s): enqueued ${total}${parts ? ` (${parts})` : ''}, dropped ${c.dropped} (backpressure)`);
  }
  _counters = _emptyCounters();
  _lastLog = now;
}

function _defaultGetIocs() {
  try { return require('../ioc/updater.js').loadCachedIOCs(); } catch { return null; }
}

function _defaultLedger(e) {
  try { require('./state.js').appendScanLedger(e); } catch { /* best-effort */ }
}

/**
 * Decide, count, and ledger a drop. Returns true when the extra must be queued.
 * ctx: { parent, parentScripts, isBurst, established, queueLength,
 *        maxQueue?, getIocs?, ledger?, now?, log? }
 */
function admitBurstExtra(extra, ctx) {
  const decision = decideBurstExtra(extra, {
    ...ctx,
    maxQueue: Number.isFinite(ctx.maxQueue) ? ctx.maxQueue : burstExtraMaxQueue(),
    getIocs: ctx.getIocs || _defaultGetIocs,
  });
  if (decision.enqueue) {
    _counters.enqueued[decision.reason]++;
  } else {
    _counters.dropped++;
    (ctx.ledger || _defaultLedger)({
      name: ctx.parent && ctx.parent.name, version: extra.version, ecosystem: 'npm',
      outcome: 'dropped', source: 'burst_extra_backpressure', isBurstExtra: true,
    });
  }
  _maybeLogCounters(Number.isFinite(ctx.now) ? ctx.now : Date.now(), ctx.log || console.log);
  return decision.enqueue;
}

function getBurstExtraCounters() {
  return JSON.parse(JSON.stringify(_counters));
}

function _resetBurstExtraCounters(now = Date.now()) {
  _counters = _emptyCounters();
  _lastLog = now;
}

module.exports = {
  DEFAULT_MAX_QUEUE,
  COUNTER_LOG_INTERVAL_MS,
  burstExtraMaxQueue,
  isEstablishedPackage,
  decideBurstExtra,
  admitBurstExtra,
  getBurstExtraCounters,
  _resetBurstExtraCounters,
};
