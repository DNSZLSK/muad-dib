/**
 * Deferred Sandbox Queue
 *
 * When T1b/T2 packages are skipped due to sandbox slot pressure,
 * they are enqueued here and retried when slots free up.
 * Items are sorted by riskScore DESC (highest-risk first) to defend
 * against queue-poisoning attacks.
 *
 * The worker owns a dedicated POOL of sandbox slots (DEFERRED_SANDBOX_SLOTS,
 * _deferredSlotsActive) that is completely independent from the shared semaphore
 * used by the synchronous path. This guarantees the deferred worker can always
 * process, regardless of how many main-path sandboxes are running, and runs
 * several items concurrently so the queue actually drains (a single slot
 * serialized all T1a deep sandboxes and the queue stayed permanently full).
 */
const fs = require('fs');
const path = require('path');
const { runSandbox } = require('../sandbox/index.js');
const { isCanaryEnabled, TIER1_TYPES } = require('./classify.js');
const { getWebhookUrl, alertedPackageRules, persistAlert, buildAlertData } = require('./webhook.js');
const { sendWebhook } = require('../webhook.js');
const { atomicWriteFileSync, markSandboxed } = require('./state.js');

// ── Constants ──
const DEFERRED_QUEUE_MAX = 500;
const DEFERRED_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const DEFERRED_MAX_RETRIES = 2;
const DEFERRED_WORKER_INTERVAL_MS = 30_000; // 30s
const DEFERRED_STATE_FILE = path.join(__dirname, '..', '..', 'data', 'deferred-queue.json');
// Defense-in-depth: sandbox slot is precious. A T1b/T2 below this score
// threshold is almost certainly a classification fallback false positive
// (cf. classify.js:183 remediation) and should never consume the deferred
// slot. HIGH=10 pts is the intended T1b floor — values below 5 are LOW-only
// aggregates which carry no actionable sandbox signal.
const DEFERRED_MIN_SCORE = 5;
// Hard ceiling on a single deferred sandbox run so a deferred slot can never
// wedge. maxRuns=1 self-bounds at ~SINGLE_RUN_TIMEOUT (90s) + the sandbox
// watchdog grace; this AbortController is belt-and-suspenders.
const DEFERRED_SANDBOX_TIMEOUT_MS = 150_000;
// Number of CONCURRENT deferred sandbox runs. The old design used a single
// boolean slot (1 at a time), which serialized ALL deferred T1a deep sandboxes
// — measured at ~1 run / several minutes, so the queue (cap DEFERRED_QUEUE_MAX)
// sat permanently full with items aging out at TTL. Phase 3 routed T1a's sandbox
// here AND bypasses the shared semaphore, so the main pool (MUADDIB_SANDBOX_CONCURRENCY)
// was sitting idle while everything queued behind one deferred slot. This pool
// uses that idle capacity. Default 3 (conservative under the typical 4-slot main
// pool); each gVisor container is ~512 MB, so 3 ≈ 1.5 GB — keep an eye on host
// RSS if raised. Env-tunable for live ops.
const DEFERRED_SANDBOX_SLOTS = (() => {
  const v = parseInt(process.env.MUADDIB_DEFERRED_SANDBOX_SLOTS, 10);
  return Number.isFinite(v) && v >= 1 ? v : 3;
})();

// Tier priority for the deferred queue. Phase 3 routes T1a's sandbox here (async)
// instead of block-waiting a scan worker, so T1a is the highest-confidence tier and
// must be processed first and evicted last — it must never sit behind a high-score
// T1b/T2. Minimal blast radius: ONLY T1a is elevated (rank 0); T1b and T2 keep the
// same rank (1) so their existing riskScore-DESC ordering between them is unchanged.
// Map (not a plain object) keeps numeric tier 2 and string tiers distinct and avoids
// an object-injection sink.
const _TIER_RANK = new Map([['1a', 0], ['1b', 1], [2, 1]]);
function _tierRank(tier) {
  return _TIER_RANK.has(tier) ? _TIER_RANK.get(tier) : 1;
}
function _deferredCompare(a, b) {
  const r = _tierRank(a.tier) - _tierRank(b.tier);
  return r !== 0 ? r : (b.riskScore - a.riskScore);
}
function _tierLabel(tier) {
  return tier === '1a' ? 'T1a' : tier === 2 ? 'T2' : 'T1b';
}

// ── Mutable state ──
const _deferredQueue = [];
const _deferredSeen = new Set(); // name@version dedup
let _workerHandle = null;
let _stats = null; // reference to shared stats object
let _deferredSlotsActive = 0;    // Concurrent deferred sandbox runs in flight (0..DEFERRED_SANDBOX_SLOTS)
// Indirection so tests can inject a controllable async sandbox without Docker
// (the concurrency contract is verified behaviorally, not by source-grep).
let _runSandboxFn = runSandbox;

// ── Queue management ──

/**
 * Enqueue a T1b/T2 package for deferred sandbox analysis.
 * Items are sorted by riskScore DESC (highest risk first).
 * When the queue is full, the lowest-score item is evicted if the new item scores higher.
 *
 * @param {object} item - Package to defer
 * @returns {boolean} true if enqueued, false if rejected
 */
function enqueueDeferred(item) {
  // Guard: T1a (Phase 3 async-routed high-confidence tier), T1b and T2 are eligible.
  // T1a was previously block-waited in the scan worker; it now runs on the dedicated
  // deferred slot at top priority (see _deferredCompare).
  if (item.tier !== '1a' && item.tier !== '1b' && item.tier !== 2) {
    console.error(`[DEFERRED] REJECTED: ${item.name}@${item.version} — tier ${item.tier} not eligible`);
    return false;
  }

  // Defense-in-depth: block low-score items regardless of tier. With the
  // classify.js:183 fallback fix in place, no legitimate enqueue should
  // reach this function with score < DEFERRED_MIN_SCORE unless it carries
  // a TIER1_TYPES signal. Logging with console.error makes a future
  // regression (new classification path that leaks low-score items) loud
  // in operator logs.
  //
  // Threat-model exception: packages containing any TIER1_TYPES finding
  // (even at LOW severity) must bypass this min-score guard. TIER1_TYPES
  // are "quasi-never legitimate in benign packages" and weak matches
  // still warrant sandbox verification — an adversary could otherwise
  // tune their malware to fire only LOW-severity TIER1 patterns to
  // bypass sandbox entirely.
  // T1a is high-confidence malice by classification — it always bypasses the
  // min-score floor (it must never be dropped before its sandbox runs).
  const itemThreats = (item.staticResult && item.staticResult.threats) || [];
  const hasTier1Signal = itemThreats.some(t => TIER1_TYPES.has(t.type));
  if (item.tier !== '1a' && (item.riskScore || 0) < DEFERRED_MIN_SCORE && !hasTier1Signal) {
    console.error(`[DEFERRED] REJECTED: ${item.name}@${item.version} — score=${item.riskScore || 0} below minimum ${DEFERRED_MIN_SCORE}, no TIER1 signal (possible classification regression)`);
    return false;
  }

  const key = `${item.name}@${item.version}`;

  // Dedup
  if (_deferredSeen.has(key)) {
    console.log(`[DEFERRED] DEDUP: ${key} already in deferred queue`);
    return false;
  }

  // Queue full — evict the lowest-priority item (by tier then score) if the new
  // item outranks it, else reject. Tier-aware so a T1a can always displace a
  // lower-tier item even when its score is lower.
  if (_deferredQueue.length >= DEFERRED_QUEUE_MAX) {
    const lowest = _deferredQueue[_deferredQueue.length - 1];
    if (_deferredCompare(item, lowest) < 0) {
      const evictKey = `${lowest.name}@${lowest.version}`;
      _deferredQueue.pop();
      _deferredSeen.delete(evictKey);
      console.log(`[DEFERRED] EVICTED: ${evictKey} (${_tierLabel(lowest.tier)}, score=${lowest.riskScore}) to make room for ${key} (${_tierLabel(item.tier)}, score=${item.riskScore})`);
    } else {
      console.log(`[DEFERRED] QUEUE FULL: ${key} (${_tierLabel(item.tier)}, score=${item.riskScore}) rejected — all ${DEFERRED_QUEUE_MAX} items rank higher`);
      return false;
    }
  }

  _deferredQueue.push(item);
  _deferredSeen.add(key);
  // Strip large fields to reduce in-memory footprint.
  // Keep minimal staticResult for buildAlertData() if sandbox detects something.
  // Disk persistence already strips staticResult (persistDeferredQueue), this
  // does the same in-memory — each item drops from ~10-50KB to ~1-2KB.
  if (item.staticResult) {
    item.staticResult = {
      threats: (item.staticResult.threats || []).map(t => ({
        type: t.type, severity: t.severity, rule_id: t.rule_id, file: t.file
      })),
      summary: item.staticResult.summary ? {
        total: item.staticResult.summary.total,
        riskScore: item.staticResult.summary.riskScore,
        maxSeverity: item.staticResult.summary.maxSeverity
      } : {}
    };
  }
  delete item.npmRegistryMeta;
  // Sort by tier priority then riskScore DESC (T1a first, then highest score)
  _deferredQueue.sort(_deferredCompare);
  console.log(`[DEFERRED] ENQUEUED: ${key} (tier=${_tierLabel(item.tier)}, score=${item.riskScore}, queue=${_deferredQueue.length})`);
  return true;
}

function getDeferredQueue() {
  return _deferredQueue;
}

function getDeferredQueueStats() {
  const tierBreakdown = { t1a: 0, t1b: 0, t2: 0 };
  for (const item of _deferredQueue) {
    if (item.tier === '1a') tierBreakdown.t1a++;
    else if (item.tier === '1b') tierBreakdown.t1b++;
    else if (item.tier === 2) tierBreakdown.t2++;
  }
  return {
    size: _deferredQueue.length,
    oldest: _deferredQueue.length > 0
      ? _deferredQueue[_deferredQueue.length - 1].enqueuedAt
      : null,
    tierBreakdown
  };
}

// ── TTL pruning ──

function pruneExpired(stats) {
  const now = Date.now();
  let pruned = 0;
  for (let i = _deferredQueue.length - 1; i >= 0; i--) {
    if (now - _deferredQueue[i].enqueuedAt > DEFERRED_TTL_MS) {
      const item = _deferredQueue[i];
      const key = `${item.name}@${item.version}`;
      _deferredQueue.splice(i, 1);
      _deferredSeen.delete(key);
      if (stats) stats.deferredExpired = (stats.deferredExpired || 0) + 1;
      console.log(`[DEFERRED] EXPIRED: ${key} (age=${((now - item.enqueuedAt) / 3600000).toFixed(1)}h)`);
      pruned++;
    }
  }
  return pruned;
}

// ── Worker ──

/**
 * Process one deferred item. Exported for testing.
 * @returns {object|null} sandboxResult or null if nothing processed
 */
async function processDeferredItem(stats) {
  // 1. Prune expired items
  pruneExpired(stats);

  if (_deferredQueue.length === 0) return null;

  // 2. Pool slot check — completely independent from main semaphore. The
  // synchronous prefix below (shift + increment) runs before the first await,
  // so processDeferredBatch can launch several of these in a tight loop without
  // over-subscribing: each increment is visible to the next iteration.
  if (_deferredSlotsActive >= DEFERRED_SANDBOX_SLOTS) {
    if (stats) stats.deferredSkipped = (stats.deferredSkipped || 0) + 1;
    return null;
  }

  // 3. Pick highest-score item
  const item = _deferredQueue.shift();
  const key = `${item.name}@${item.version}`;
  _deferredSeen.delete(key);

  console.log(`[DEFERRED] PROCESSING: ${key} (tier=${_tierLabel(item.tier)}, score=${item.riskScore}, retries=${item.retries}, slots=${_deferredSlotsActive + 1}/${DEFERRED_SANDBOX_SLOTS})`);

  // 4. Run sandbox on a pool slot (bypasses shared semaphore)
  _deferredSlotsActive++;
  let sandboxResult;
  const ac = new AbortController();
  const deadline = setTimeout(() => ac.abort(), DEFERRED_SANDBOX_TIMEOUT_MS);
  try {
    const canary = isCanaryEnabled();
    // T1a keeps multi-run time-bomb detection (maxRuns=undefined) — that was its
    // behavior on the old blocking in-worker path, preserved here for detection
    // parity (Phase 3 only moves WHERE it runs, not how thoroughly). T1b/T2 stay
    // single-run (maxRuns=1, ~90s vs ~270s) for fast deferred-queue drain.
    const maxRuns = item.tier === '1a' ? undefined : 1;
    markSandboxed(item.name); // stamp for sandbox-revalidation cadence (matches the synchronous path)
    sandboxResult = await _runSandboxFn(item.name, { canary, skipSemaphore: true, maxRuns, signal: ac.signal });
    console.log(`[DEFERRED] SANDBOX COMPLETE: ${key} -> score=${sandboxResult.score}, severity=${sandboxResult.severity}`);
  } catch (err) {
    console.error(`[DEFERRED] SANDBOX ERROR: ${key} — ${err.message}`);
    item.retries = (item.retries || 0) + 1;
    if (item.retries >= DEFERRED_MAX_RETRIES) {
      console.log(`[DEFERRED] DROPPED: ${key} after ${item.retries} failed attempts`);
    } else {
      // Re-enqueue for retry
      _deferredQueue.push(item);
      _deferredSeen.add(key);
      _deferredQueue.sort(_deferredCompare);
      console.log(`[DEFERRED] RE-ENQUEUED: ${key} for retry (attempt ${item.retries + 1}/${DEFERRED_MAX_RETRIES})`);
    }
    return null;
  } finally {
    clearTimeout(deadline);
    _deferredSlotsActive--;
  }

  // 5. Follow-up webhook if sandbox found something
  if (stats) stats.deferredProcessed = (stats.deferredProcessed || 0) + 1;

  if (sandboxResult && sandboxResult.score > 0) {
    const deferredDedupKey = 'deferred_sandbox';
    const previousRules = alertedPackageRules.get(item.name);
    const alreadySentFollowUp = previousRules && previousRules.has(deferredDedupKey);

    if (!alreadySentFollowUp) {
      const url = getWebhookUrl();
      if (url) {
        try {
          const embed = buildDeferredFollowUpEmbed(
            item.name, item.version, item.ecosystem,
            sandboxResult,
            item.riskScore
          );
          await sendWebhook(url, embed, { rawPayload: true });
          console.log(`[DEFERRED] FOLLOW-UP WEBHOOK: ${key} (sandbox score=${sandboxResult.score})`);

          // Track in dedup map
          if (previousRules) {
            previousRules.add(deferredDedupKey);
          } else {
            alertedPackageRules.set(item.name, new Set([deferredDedupKey]));
          }
        } catch (webhookErr) {
          console.error(`[DEFERRED] FOLLOW-UP WEBHOOK FAILED: ${key} — ${webhookErr.message}`);
        }
      }

      // Persist updated alert with sandbox data
      try {
        const alertData = buildAlertData(
          item.name, item.version, item.ecosystem,
          item.staticResult, sandboxResult
        );
        persistAlert(item.name, item.version, item.ecosystem, alertData);
        console.log(`[DEFERRED] ALERT PERSISTED: ${key} (with sandbox data)`);
      } catch (persistErr) {
        console.error(`[DEFERRED] ALERT PERSIST FAILED: ${key} — ${persistErr.message}`);
      }
    } else {
      console.log(`[DEFERRED] DEDUP: follow-up already sent for ${item.name}`);
    }
  } else {
    console.log(`[DEFERRED] CLEAN: ${key} (sandbox score=0, static score=${item.riskScore})`);
  }

  return sandboxResult;
}

/**
 * Tick dispatcher: launch deferred items CONCURRENTLY up to the free pool slots.
 * processDeferredItem runs its slot-acquire (shift + increment) synchronously
 * before its first await, so each launch is visible to the next loop iteration —
 * no over-subscription past DEFERRED_SANDBOX_SLOTS. Calls are fire-and-forget:
 * processDeferredItem is fully self-contained (its try/catch/finally swallows
 * sandbox errors and always releases the slot), so a launched run never rejects
 * the dispatcher. Returns the number launched this tick (for tests/observability).
 * @returns {number}
 */
function processDeferredBatch(stats) {
  let launched = 0;
  // Bound the loop by the free slot count so a transient queue can't spin it.
  while (_deferredSlotsActive < DEFERRED_SANDBOX_SLOTS && _deferredQueue.length > 0) {
    const before = _deferredSlotsActive;
    const p = processDeferredItem(stats);
    // If the slot wasn't acquired (e.g. queue emptied by pruning inside the call),
    // stop — otherwise the guard above could loop without progress.
    if (_deferredSlotsActive === before) break;
    launched++;
    if (p && typeof p.catch === 'function') p.catch(() => { /* self-handled */ });
  }
  return launched;
}

/**
 * Build Discord embed for deferred sandbox follow-up.
 */
function buildDeferredFollowUpEmbed(name, version, ecosystem, sandboxResult, staticScore) {
  const npmLink = ecosystem === 'npm'
    ? `https://www.npmjs.com/package/${encodeURIComponent(name)}`
    : `https://pypi.org/project/${encodeURIComponent(name)}/`;

  const color = sandboxResult.score >= 80 ? 0xe74c3c    // red: critical
    : sandboxResult.score >= 30 ? 0xe67e22              // orange: high
    : 0xf1c40f;                                          // yellow: moderate

  const fields = [
    { name: 'Package', value: `[${name}@${version}](${npmLink})`, inline: true },
    { name: 'Ecosystem', value: ecosystem.toUpperCase(), inline: true },
    { name: 'Sandbox Score', value: `**${sandboxResult.score}/100** (${sandboxResult.severity})`, inline: true },
    { name: 'Static Score', value: String(staticScore), inline: true },
    { name: 'Status', value: 'Deferred sandbox completed after initial static-only alert', inline: false }
  ];

  // Top sandbox findings (max 5)
  if (sandboxResult.findings && sandboxResult.findings.length > 0) {
    const findingLines = sandboxResult.findings.slice(0, 5)
      .map(f => `- [${f.severity || 'UNKNOWN'}] ${f.type}: ${(f.detail || '').slice(0, 100)}`)
      .join('\n');
    fields.push({ name: 'Sandbox Findings', value: findingLines.slice(0, 1024), inline: false });
  }

  return {
    embeds: [{
      title: `SANDBOX FOLLOW-UP \u2014 ${name}@${version}`,
      color,
      fields,
      footer: {
        text: `MUAD'DIB Deferred Sandbox | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`
      },
      timestamp: new Date().toISOString()
    }]
  };
}

// ── Worker lifecycle ──

function startDeferredWorker(stats) {
  _stats = stats;
  if (_workerHandle) return _workerHandle;
  console.log(`[DEFERRED] Worker started (interval=${DEFERRED_WORKER_INTERVAL_MS / 1000}s, max=${DEFERRED_QUEUE_MAX}, slots=${DEFERRED_SANDBOX_SLOTS}, ttl=${DEFERRED_TTL_MS / 3600000}h)`);
  _workerHandle = setInterval(() => {
    try {
      // Fill free pool slots each tick. The dispatcher launches concurrent runs
      // (fire-and-forget); long-running sandboxes keep their slots across ticks,
      // so steady state is DEFERRED_SANDBOX_SLOTS in flight while the queue drains.
      pruneExpired(_stats);
      processDeferredBatch(_stats);
    } catch (err) {
      console.error(`[DEFERRED] Worker tick error: ${err.message}`);
    }
  }, DEFERRED_WORKER_INTERVAL_MS);
  return _workerHandle;
}

function stopDeferredWorker() {
  if (_workerHandle) {
    clearInterval(_workerHandle);
    _workerHandle = null;
    console.log('[DEFERRED] Worker stopped');
  }
}

// ── Persistence ──

function persistDeferredQueue() {
  try {
    if (_deferredQueue.length === 0) {
      // Remove stale file
      try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch { /* ignore missing */ }
      return;
    }
    // Strip staticResult to reduce file size (can be large)
    // Keep only essential fields for persistence
    const items = _deferredQueue.map(item => ({
      name: item.name,
      version: item.version,
      ecosystem: item.ecosystem,
      tier: item.tier,
      riskScore: item.riskScore,
      tarballUrl: item.tarballUrl,
      enqueuedAt: item.enqueuedAt,
      retries: item.retries || 0
      // staticResult and npmRegistryMeta are NOT persisted (too large, stale after restart)
    }));
    const payload = JSON.stringify({
      savedAt: new Date().toISOString(),
      count: items.length,
      items
    });
    atomicWriteFileSync(DEFERRED_STATE_FILE, payload);
  } catch (err) {
    console.error(`[DEFERRED] Failed to persist queue: ${err.message}`);
  }
}

function restoreDeferredQueue() {
  // Cleanup orphan .tmp from previous crash / disk-full (ENOSPC)
  const tmpFile = DEFERRED_STATE_FILE + '.tmp';
  try {
    if (fs.existsSync(tmpFile)) {
      const stat = fs.statSync(tmpFile);
      console.log(`[DEFERRED] Cleaning up orphan ${path.basename(tmpFile)} (${stat.size} bytes)`);
      fs.unlinkSync(tmpFile);
    }
  } catch { /* best-effort */ }

  try {
    if (!fs.existsSync(DEFERRED_STATE_FILE)) return 0;
    const raw = fs.readFileSync(DEFERRED_STATE_FILE, 'utf8');
    const data = JSON.parse(raw);

    if (!data || !Array.isArray(data.items) || !data.savedAt) {
      console.log('[DEFERRED] State file invalid \u2014 ignoring');
      try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch { /* ignore missing */ }
      return 0;
    }

    // Check file age
    const ageMs = Date.now() - new Date(data.savedAt).getTime();
    if (ageMs > DEFERRED_TTL_MS) {
      console.log(`[DEFERRED] State file expired (${Math.round(ageMs / 3600000)}h old) \u2014 ignoring`);
      try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch { /* ignore missing */ }
      return 0;
    }

    // Restore items, pruning individually expired ones
    const now = Date.now();
    let restored = 0;
    for (const item of data.items) {
      if (now - item.enqueuedAt > DEFERRED_TTL_MS) continue; // expired
      const key = `${item.name}@${item.version}`;
      if (_deferredSeen.has(key)) continue; // dedup
      _deferredQueue.push(item);
      _deferredSeen.add(key);
      restored++;
    }

    // Sort after bulk insert
    _deferredQueue.sort(_deferredCompare);

    if (restored > 0) {
      console.log(`[DEFERRED] Restored ${restored} items from disk (saved at ${data.savedAt})`);
    }

    // Delete after successful restore
    try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch { /* ignore missing */ }
    return restored;
  } catch (err) {
    console.log(`[DEFERRED] WARNING: could not restore state: ${err.message}`);
    try { fs.unlinkSync(DEFERRED_STATE_FILE); } catch { /* ignore missing */ }
    return 0;
  }
}

// ── Reset (for testing) ──

function _resetDeferredQueue() {
  _deferredQueue.length = 0;
  _deferredSeen.clear();
  _stats = null;
  _deferredSlotsActive = 0;
  _runSandboxFn = runSandbox;
  stopDeferredWorker();
}

// Test seam: inject a controllable sandbox runner (restored by _resetDeferredQueue).
function _setRunSandboxForTest(fn) {
  _runSandboxFn = fn || runSandbox;
}

// True while at least one deferred sandbox is in flight. Kept for back-compat
// (callers/tests that only care "is the deferred path active"); use
// getDeferredSlotsActive() for the concurrent count.
function isDeferredSlotBusy() {
  return _deferredSlotsActive > 0;
}

function getDeferredSlotsActive() {
  return _deferredSlotsActive;
}

/**
 * Emergency clear: drop all deferred items and free their staticResult references.
 * Called by daemon.js memory circuit breaker at EMERGENCY level.
 * Returns the count of items dropped for logging.
 */
function clearDeferredQueue() {
  const count = _deferredQueue.length;
  _deferredQueue.length = 0;
  _deferredSeen.clear();
  return count;
}

module.exports = {
  enqueueDeferred,
  getDeferredQueue,
  getDeferredQueueStats,
  startDeferredWorker,
  stopDeferredWorker,
  processDeferredItem,
  processDeferredBatch,
  persistDeferredQueue,
  restoreDeferredQueue,
  buildDeferredFollowUpEmbed,
  pruneExpired,
  isDeferredSlotBusy,
  getDeferredSlotsActive,
  clearDeferredQueue,
  _resetDeferredQueue,
  _setRunSandboxForTest,
  DEFERRED_QUEUE_MAX,
  DEFERRED_SANDBOX_SLOTS,
  DEFERRED_TTL_MS,
  DEFERRED_MAX_RETRIES,
  DEFERRED_WORKER_INTERVAL_MS,
  DEFERRED_STATE_FILE
};
