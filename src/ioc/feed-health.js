/**
 * IOC feed-health alarm (Phase 2c, part 1).
 *
 * The audit that started the coverage plan traced the 24.5% operational-coverage
 * collapse to a SILENT ops failure: the OSM feed went dark (returned 0) for weeks, so
 * the IOC store went stale and nothing alarmed. This module closes that blind spot.
 *
 * After every IOC refresh, `checkFeedHealth` compares each feed's returned count against
 * a persisted per-feed baseline. When a feed that has previously shown a healthy count
 * suddenly returns 0, it raises a ONE-SHOT alarm (console + webhook) on the healthy→dark
 * transition — not every cycle — and a recovery notice on dark→alive. Best-effort: a
 * feed-health failure must NEVER break the IOC refresh.
 *
 * The decision core (`evaluateFeedHealth`) is a pure function (counts + prev state →
 * alarms/recoveries/next state) so it is fully unit-testable without I/O or network.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const FEED_HEALTH_FILE = process.env.MUADDIB_FEED_HEALTH_FILE ||
  path.join(__dirname, '..', '..', 'data', 'feed-health.json');

// A feed must have shown at least this many IOCs at least once before a later zero counts
// as "went dark". Below this a feed is too small/volatile to alarm on (FP guard). Real
// feeds (GenSecAI/DataDog/OSV/OSM) return hundreds–thousands, so 5 is a safe floor.
const MIN_HEALTHY_BASELINE = (() => {
  const n = parseInt(process.env.MUADDIB_FEED_HEALTH_MIN, 10);
  return Number.isFinite(n) && n > 0 ? n : 5;
})();

function loadFeedHealth(file = FEED_HEALTH_FILE) {
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    return (data && typeof data === 'object' && data.feeds && typeof data.feeds === 'object') ? data.feeds : {};
  } catch {
    return {};
  }
}

function saveFeedHealth(state, file = FEED_HEALTH_FILE) {
  try {
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ updatedAt: new Date().toISOString(), feeds: state }, null, 2));
    fs.renameSync(tmp, file);
  } catch (err) {
    // Best-effort: a read-only / full disk must not break the refresh.
    if (err && ['EROFS', 'EACCES', 'EPERM', 'ENOSPC'].includes(err.code)) return;
    console.warn('[FEED-HEALTH] Failed to persist state: ' + err.message);
  }
}

/**
 * PURE decision core. Given current per-feed counts and the previous state, compute:
 *   - alarms: feeds with a healthy baseline that returned 0 this cycle (healthy→dark edge)
 *   - recoveries: dark feeds that returned data again (dark→alive edge)
 *   - nextState: updated per-feed { lastHealthy, lastHealthyAt, dark }
 * Feeds present in prevState but absent from `counts` keep their baseline (carry-forward).
 *
 * @param {Object<string,number>} counts
 * @param {Object<string,{lastHealthy:number,lastHealthyAt:?string,dark:boolean}>} prevState
 * @param {string} nowIso
 */
function evaluateFeedHealth(counts, prevState, nowIso) {
  const alarms = [];
  const recoveries = [];
  const nextState = {};

  for (const feed of Object.keys(counts || {})) {
    const cur = Number(counts[feed]) || 0;
    const prev = (prevState && prevState[feed]) || { lastHealthy: 0, lastHealthyAt: null, dark: false };
    const entry = { lastHealthy: prev.lastHealthy || 0, lastHealthyAt: prev.lastHealthyAt || null, dark: !!prev.dark };

    if (cur >= MIN_HEALTHY_BASELINE) {
      entry.lastHealthy = cur;
      entry.lastHealthyAt = nowIso;
    }

    if (cur === 0) {
      if ((prev.lastHealthy || 0) >= MIN_HEALTHY_BASELINE && !prev.dark) {
        alarms.push({ feed, lastHealthy: prev.lastHealthy, lastHealthyAt: prev.lastHealthyAt || null });
      }
      entry.dark = true;
    } else {
      if (prev.dark) recoveries.push({ feed, count: cur });
      entry.dark = false;
    }
    nextState[feed] = entry;
  }

  // Carry forward feeds not reported this cycle so their baseline is not lost.
  for (const feed of Object.keys(prevState || {})) {
    if (!(feed in nextState)) nextState[feed] = prevState[feed];
  }

  return { alarms, recoveries, nextState };
}

function buildFeedHealthAlarmEmbed(alarms, recoveries) {
  const fields = [];
  for (const a of alarms) {
    fields.push({
      name: `🔴 ${a.feed} returned 0`,
      value: `Last healthy: ${a.lastHealthy} IOC(s)${a.lastHealthyAt ? ` (${a.lastHealthyAt})` : ''}. ` +
        'Feed likely down / token expired / endpoint moved — IOC store is going stale. Investigate now.',
      inline: false
    });
  }
  for (const r of (recoveries || [])) {
    fields.push({ name: `🟢 ${r.feed} recovered`, value: `Now returning ${r.count} IOC(s).`, inline: false });
  }
  return {
    embeds: [{
      title: '⚠️ MUAD\'DIB IOC Feed Health',
      color: alarms.length ? 0xe74c3c : 0x2ecc71,
      fields,
      footer: { text: 'MUAD\'DIB IOC feed-health monitor' },
      timestamp: new Date().toISOString()
    }]
  };
}

async function _defaultDispatch(payload) {
  const url = process.env.MUADDIB_WEBHOOK_URL;
  if (!url) return; // no webhook configured — the console alarm already fired
  try {
    const { sendWebhook } = require('../webhook.js');
    await sendWebhook(url, payload, { rawPayload: true });
  } catch (err) {
    console.warn('[FEED-HEALTH] webhook dispatch failed: ' + err.message);
  }
}

/**
 * Load → evaluate → persist → dispatch. Best-effort: NEVER throws (a feed-health failure
 * must not break the IOC refresh). Returns { alarms, recoveries }.
 *
 * @param {Object<string,number>} counts - per-feed IOC counts from this refresh
 * @param {Object} [opts]
 * @param {function(object):Promise} [opts.dispatch] - injectable webhook sender (tests)
 * @param {string} [opts.file] - state file override (tests)
 */
async function checkFeedHealth(counts, opts = {}) {
  try {
    const file = opts.file || FEED_HEALTH_FILE;
    const prev = loadFeedHealth(file);
    const { alarms, recoveries, nextState } = evaluateFeedHealth(counts, prev, new Date().toISOString());
    saveFeedHealth(nextState, file);

    for (const a of alarms) {
      console.warn(`[FEED-HEALTH] ALARM: feed "${a.feed}" returned 0 (last healthy ${a.lastHealthy}). Stale IOCs degrade coverage — check the source.`);
    }
    for (const r of recoveries) {
      console.log(`[FEED-HEALTH] RECOVERED: feed "${r.feed}" now returns ${r.count}.`);
    }
    if (alarms.length || recoveries.length) {
      const dispatch = opts.dispatch || _defaultDispatch;
      await dispatch(buildFeedHealthAlarmEmbed(alarms, recoveries));
    }
    return { alarms, recoveries };
  } catch (err) {
    console.warn('[FEED-HEALTH] check failed (non-fatal): ' + err.message);
    return { alarms: [], recoveries: [] };
  }
}

module.exports = {
  evaluateFeedHealth,
  checkFeedHealth,
  loadFeedHealth,
  saveFeedHealth,
  buildFeedHealthAlarmEmbed,
  FEED_HEALTH_FILE,
  MIN_HEALTHY_BASELINE
};
