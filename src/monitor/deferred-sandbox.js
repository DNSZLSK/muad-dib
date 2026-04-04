/**
 * Deferred Sandbox Queue
 *
 * When T1b/T2 packages are skipped due to sandbox slot pressure,
 * they are enqueued here and retried when slots free up.
 * Items are sorted by riskScore DESC (highest-risk first) to defend
 * against queue-poisoning attacks.
 *
 * The worker owns a dedicated sandbox slot (_deferredSlotBusy) that is
 * completely independent from the shared semaphore used by T1a/T1b/T2.
 * This guarantees the deferred worker can always process, regardless of
 * how many main-path sandboxes are running. The VPS supports N+1
 * concurrent gVisor containers (3 main + 1 deferred).
 */
const fs = require('fs');
const path = require('path');
const { runSandbox } = require('../sandbox/index.js');
const { isCanaryEnabled } = require('./classify.js');
const { getWebhookUrl, alertedPackageRules, persistAlert, buildAlertData } = require('./webhook.js');
const { sendWebhook } = require('../webhook.js');
const { atomicWriteFileSync } = require('./state.js');

// ── Constants ──
const DEFERRED_QUEUE_MAX = 500;
const DEFERRED_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const DEFERRED_MAX_RETRIES = 2;
const DEFERRED_WORKER_INTERVAL_MS = 30_000; // 30s
const DEFERRED_STATE_FILE = path.join(__dirname, '..', '..', 'data', 'deferred-queue.json');

// ── Mutable state ──
const _deferredQueue = [];
const _deferredSeen = new Set(); // name@version dedup
let _workerHandle = null;
let _stats = null; // reference to shared stats object
let _deferredSlotBusy = false;   // Dedicated slot: true while deferred sandbox is running

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
  // Guard: only T1b and T2 are allowed
  if (item.tier !== '1b' && item.tier !== 2) {
    console.error(`[DEFERRED] REJECTED: ${item.name}@${item.version} — tier ${item.tier} not eligible`);
    return false;
  }

  const key = `${item.name}@${item.version}`;

  // Dedup
  if (_deferredSeen.has(key)) {
    console.log(`[DEFERRED] DEDUP: ${key} already in deferred queue`);
    return false;
  }

  // Queue full — evict lowest or reject
  if (_deferredQueue.length >= DEFERRED_QUEUE_MAX) {
    const lowest = _deferredQueue[_deferredQueue.length - 1];
    if (item.riskScore > lowest.riskScore) {
      const evictKey = `${lowest.name}@${lowest.version}`;
      _deferredQueue.pop();
      _deferredSeen.delete(evictKey);
      console.log(`[DEFERRED] EVICTED: ${evictKey} (score=${lowest.riskScore}) to make room for ${key} (score=${item.riskScore})`);
    } else {
      console.log(`[DEFERRED] QUEUE FULL: ${key} (score=${item.riskScore}) rejected — all ${DEFERRED_QUEUE_MAX} items have higher scores`);
      return false;
    }
  }

  _deferredQueue.push(item);
  _deferredSeen.add(key);
  // Sort by riskScore DESC (highest first)
  _deferredQueue.sort((a, b) => b.riskScore - a.riskScore);
  console.log(`[DEFERRED] ENQUEUED: ${key} (tier=${item.tier === 2 ? 'T2' : 'T1b'}, score=${item.riskScore}, queue=${_deferredQueue.length})`);
  return true;
}

function getDeferredQueue() {
  return _deferredQueue;
}

function getDeferredQueueStats() {
  const tierBreakdown = { t1b: 0, t2: 0 };
  for (const item of _deferredQueue) {
    if (item.tier === '1b') tierBreakdown.t1b++;
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

  // 2. Dedicated slot check — completely independent from main semaphore
  if (_deferredSlotBusy) {
    if (stats) stats.deferredSkipped = (stats.deferredSkipped || 0) + 1;
    return null;
  }

  // 3. Pick highest-score item
  const item = _deferredQueue.shift();
  const key = `${item.name}@${item.version}`;
  _deferredSeen.delete(key);

  console.log(`[DEFERRED] PROCESSING: ${key} (tier=${item.tier === 2 ? 'T2' : 'T1b'}, score=${item.riskScore}, retries=${item.retries})`);

  // 4. Run sandbox on dedicated slot (bypasses shared semaphore)
  _deferredSlotBusy = true;
  let sandboxResult;
  try {
    const canary = isCanaryEnabled();
    sandboxResult = await runSandbox(item.name, { canary, skipSemaphore: true });
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
      _deferredQueue.sort((a, b) => b.riskScore - a.riskScore);
      console.log(`[DEFERRED] RE-ENQUEUED: ${key} for retry (attempt ${item.retries + 1}/${DEFERRED_MAX_RETRIES})`);
    }
    return null;
  } finally {
    _deferredSlotBusy = false;
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
  console.log(`[DEFERRED] Worker started (interval=${DEFERRED_WORKER_INTERVAL_MS / 1000}s, max=${DEFERRED_QUEUE_MAX}, ttl=${DEFERRED_TTL_MS / 3600000}h)`);
  _workerHandle = setInterval(async () => {
    try {
      await processDeferredItem(_stats);
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
    _deferredQueue.sort((a, b) => b.riskScore - a.riskScore);

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
  _deferredSlotBusy = false;
  stopDeferredWorker();
}

function isDeferredSlotBusy() {
  return _deferredSlotBusy;
}

module.exports = {
  enqueueDeferred,
  getDeferredQueue,
  getDeferredQueueStats,
  startDeferredWorker,
  stopDeferredWorker,
  processDeferredItem,
  persistDeferredQueue,
  restoreDeferredQueue,
  buildDeferredFollowUpEmbed,
  pruneExpired,
  isDeferredSlotBusy,
  _resetDeferredQueue,
  DEFERRED_QUEUE_MAX,
  DEFERRED_TTL_MS,
  DEFERRED_MAX_RETRIES,
  DEFERRED_WORKER_INTERVAL_MS,
  DEFERRED_STATE_FILE
};
