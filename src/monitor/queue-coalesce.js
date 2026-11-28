'use strict';

/**
 * Coalescing of scan-queue items by package name (npm only).
 *
 * Unresolved items (no version, no tarball: the pre-resolve was shed under load) resolve
 * the latest version when a worker dequeues them, so two unresolved items of the same
 * name scan the same version and the second one ends on "SKIP (already scanned)" after
 * holding a queue slot and a registry request. The second one is merged into the first:
 * its protective flags are kept on the queued item, nothing else is lost.
 *
 * The index maps a name to the last queued item of that name. An item carries a marker
 * (a symbol, so it is never persisted) naming the queue it is in; scan-queue.js clears it
 * on every removal path, and a lookup only trusts an item whose marker is this queue.
 */

const QUEUED = Symbol('muaddib.scanQueue');
const INDEX_MAX = 200_000;
const COUNTER_LOG_INTERVAL_MS = 60_000;
const MERGED_FLAGS = ['isIOCMatch', 'firstPublish', 'isBurst', 'atoSignal', 'interrupted'];
const KINDS = ['unresolved'];

const _index = new Map();

function _key(item) {
  return item && item.ecosystem === 'npm' && typeof item.name === 'string' && item.name ? item.name : null;
}

function _isUnresolved(item) {
  return !item.version && !item.tarballUrl;
}

function registerQueued(scanQueue, item) {
  const k = _key(item);
  if (!k) return;
  item[QUEUED] = scanQueue;
  if (_index.size >= INDEX_MAX && !_index.has(k)) _index.clear(); // bounded; lookups fall back to a plain enqueue
  _index.set(k, item);
}

function unregisterQueued(item) {
  if (!item || !item[QUEUED]) return;
  item[QUEUED] = null;
  const k = _key(item);
  if (k && _index.get(k) === item) _index.delete(k);
}

/**
 * Merge `item` into a queued item of the same name when that loses nothing.
 * @returns {boolean} true when `item` was absorbed and must not be queued.
 */
function tryCoalesce(scanQueue, item, stats) {
  const k = _key(item);
  if (!k) return false;
  const cand = _index.get(k);
  if (!cand || cand === item || cand[QUEUED] !== scanQueue) return false;
  if (_isUnresolved(item) && _isUnresolved(cand)) {
    for (const f of MERGED_FLAGS) if (item[f]) cand[f] = true;
    if (item._cacheTrigger && !cand._cacheTrigger) cand._cacheTrigger = item._cacheTrigger;
    if (stats) stats.queueCoalescedUnresolved = (stats.queueCoalescedUnresolved || 0) + 1;
    _recordCoalesce('unresolved');
    return true;
  }
  return false;
}

// Per-interval counters (fixed key set, bounded).
let _counters = _emptyCounters();
let _lastLog = Date.now();

function _emptyCounters() {
  const c = {};
  for (const k of KINDS) c[k] = 0;
  return c;
}

function _recordCoalesce(kind, now = Date.now(), log = console.log) {
  if (kind in _counters) _counters[kind]++;
  if (now - _lastLog < COUNTER_LOG_INTERVAL_MS) return;
  log(`[MONITOR] QUEUE COALESCE (last ${Math.round((now - _lastLog) / 1000)}s): ${KINDS.map(k => `${k} ${_counters[k]}`).join(', ')}`);
  _counters = _emptyCounters();
  _lastLog = now;
}

function getCoalesceCounters() {
  return { ..._counters };
}

function _resetCoalesceCounters(now = Date.now()) {
  _counters = _emptyCounters();
  _lastLog = now;
}

module.exports = {
  registerQueued,
  unregisterQueued,
  tryCoalesce,
  getCoalesceCounters,
  _recordCoalesce,
  _resetCoalesceCounters,
};
