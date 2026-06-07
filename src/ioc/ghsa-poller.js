/**
 * GHSA active poller (Phase 2c, part 2).
 *
 * Polls the public GitHub Advisory Database for type=malware advisories on a short
 * cadence (~15 min) and:
 *   - persists each advisory's malicious package(s) to a denominator JSONL
 *     (data/ghsa-malware.jsonl) — the authoritative "what SHOULD we have caught" list
 *     that the Phase 5 coverage-audit joins against the scan-ledger (closes 105/429);
 *   - pre-alerts genuinely fresh names (updated since our cursor) as an early warning;
 *   - records withdrawn advisories (withdrawn_at set) to the scan-ledger as
 *     outcome:'dropped', source:'ghsa_gone' so a removed package keeps an identity;
 *   - feeds the GHSA fetch count into the feed-health alarm (a GHSA feed that returns 0
 *     after a healthy baseline = API down / auth broken).
 *
 * HONEST SCOPE (v1): this does NOT inject scans into the live queue. GHSA lags the
 * downstream vendors, so by the time a name lands here it is usually already removed from
 * the registry (a scan would just 404) or already in the IOC store via the OSV scraper —
 * injection would mostly burn registry calls for no coverage gain. The value here is the
 * denominator (Phase 5) + the early-warning pre-alert + withdrawn tracking. The poller
 * runs as the muaddib daemon, which has no `gh` CLI auth, so it hits the REST API directly
 * (public endpoint; an optional GITHUB_TOKEN raises the rate limit).
 *
 * First run (no cursor) SEEDS silently: it records the recent page to the denominator and
 * sets the cursor, but does not pre-alert (those advisories are historical relative to our
 * start, not "fresh"). Subsequent runs pre-alert only advisories newer than the cursor.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');

const GHSA_API_HOST = 'api.github.com';
const GHSA_ECOSYSTEMS = ['npm', 'pypi'];
const GHSA_CURSOR_FILE = process.env.MUADDIB_GHSA_CURSOR_FILE ||
  path.join(__dirname, '..', '..', 'data', 'ghsa-cursor.json');
const GHSA_MALWARE_FILE = process.env.MUADDIB_GHSA_MALWARE_FILE ||
  path.join(__dirname, '..', '..', 'data', 'ghsa-malware.jsonl');
const GHSA_MALWARE_MAX = 200_000; // denominator cap (GHSA malware is ~thousands; safety bound)
const GHSA_POLL_INTERVAL_MS = (() => {
  const n = parseInt(process.env.MUADDIB_GHSA_POLL_INTERVAL_MS, 10);
  return Number.isFinite(n) && n >= 60_000 ? n : 15 * 60 * 1000; // 15 min default
})();
// Cap pre-alerts per poll so a cursor gap (downtime catch-up) can't blast Discord.
const GHSA_PREALERT_CAP = (() => {
  const n = parseInt(process.env.MUADDIB_GHSA_PREALERT_CAP, 10);
  return Number.isFinite(n) && n > 0 ? n : 25;
})();

let _pollHandle = null;

// ── low-level fetch (dep-injectable) ──

/**
 * GET a GitHub REST API path and parse JSON. Sets the required User-Agent and an optional
 * bearer token (GITHUB_TOKEN/GH_TOKEN). Resolves { status, json } — never rejects on a
 * non-200 (returns the status so the caller can decide); rejects only on transport error.
 */
function _httpGetJson(pathName, { token, httpImpl = https, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {
      'User-Agent': 'MUADDIB-Scanner/3.0',
      'Accept': 'application/vnd.github+json'
    };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const req = httpImpl.get({ hostname: GHSA_API_HOST, path: pathName, headers, timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(body); } catch { /* leave null */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('timeout', () => { req.destroy(new Error('GHSA request timeout')); });
    req.on('error', reject);
  });
}

/**
 * Fetch the most-recent page of type=malware advisories for one ecosystem (sorted by
 * updated desc). Returns an array (possibly empty). Throws on transport / non-200 so the
 * caller skips the cursor advance + feed-health for this ecosystem (an error is NOT a 0).
 */
async function _defaultFetch(ecosystem, opts = {}) {
  const token = opts.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
  // GHSA names the Python ecosystem "pip" (not "pypi") in BOTH the query and the response;
  // querying ecosystem=pypi returns HTTP 422. Map our internal name to GHSA's for the query.
  const apiEco = ecosystem === 'pypi' ? 'pip' : ecosystem;
  const p = `/advisories?type=malware&ecosystem=${encodeURIComponent(apiEco)}&per_page=100&sort=updated&direction=desc`;
  const { status, json } = await _httpGetJson(p, { token, httpImpl: opts.httpImpl });
  if (status !== 200 || !Array.isArray(json)) {
    throw new Error(`GHSA fetch ${ecosystem} failed: HTTP ${status}`);
  }
  return json;
}

// ── parsing (pure) ──

/**
 * Flatten one advisory into per-package denominator rows. PURE.
 * @returns {Array<{ghsa_id,ecosystem,name,versionRange,published_at,updated_at,withdrawn:boolean}>}
 */
function parseAdvisory(adv, ecosystems = GHSA_ECOSYSTEMS) {
  if (!adv || !adv.ghsa_id || !Array.isArray(adv.vulnerabilities)) return [];
  const out = [];
  for (const v of adv.vulnerabilities) {
    const pkg = v && v.package;
    if (!pkg || !pkg.name || !pkg.ecosystem) continue;
    let eco = String(pkg.ecosystem).toLowerCase();
    if (eco === 'pip') eco = 'pypi'; // normalize GHSA's "pip" to our internal "pypi"
    if (ecosystems && !ecosystems.includes(eco)) continue;
    out.push({
      ghsa_id: adv.ghsa_id,
      ecosystem: eco,
      name: pkg.name,
      versionRange: v.vulnerable_version_range || '*',
      published_at: adv.published_at || null,
      updated_at: adv.updated_at || null,
      withdrawn: !!adv.withdrawn_at
    });
  }
  return out;
}

// ── cursor + denominator persistence (self-contained, atomic) ──

function loadGhsaCursor(file = GHSA_CURSOR_FILE) {
  try {
    const d = JSON.parse(fs.readFileSync(file, 'utf8'));
    return (d && typeof d.cursor === 'string') ? d.cursor : null;
  } catch { return null; }
}

function saveGhsaCursor(cursor, file = GHSA_CURSOR_FILE) {
  try {
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ cursor, updatedAt: new Date().toISOString() }, null, 2));
    fs.renameSync(tmp, file);
  } catch (err) {
    if (err && ['EROFS', 'EACCES', 'EPERM', 'ENOSPC'].includes(err.code)) return;
    console.warn('[GHSA] Failed to persist cursor: ' + err.message);
  }
}

/** Append denominator rows (best-effort) with a coarse size cap. */
function appendGhsaMalware(rows, file = GHSA_MALWARE_FILE) {
  if (!rows || rows.length === 0) return;
  try {
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString();
    const lines = rows.map(r => JSON.stringify({ ts, ...r })).join('\n') + '\n';
    fs.appendFileSync(file, lines, 'utf8');
    _maybeCompactMalware(file);
  } catch (err) {
    if (err && ['EROFS', 'EACCES', 'EPERM', 'ENOSPC'].includes(err.code)) return;
    console.warn('[GHSA] Failed to persist denominator: ' + err.message);
  }
}

function _maybeCompactMalware(file) {
  try {
    const txt = fs.readFileSync(file, 'utf8');
    const lines = txt.split('\n').filter(Boolean);
    if (lines.length <= GHSA_MALWARE_MAX) return;
    const kept = lines.slice(lines.length - GHSA_MALWARE_MAX).join('\n') + '\n';
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, kept, 'utf8');
    fs.renameSync(tmp, file);
  } catch { /* best-effort */ }
}

// ── pre-alert dispatch ──

function buildGhsaPreAlertEmbed(row) {
  const link = row.ecosystem === 'pypi'
    ? `https://pypi.org/project/${encodeURIComponent(row.name)}/`
    : `https://www.npmjs.com/package/${encodeURIComponent(row.name)}`;
  return {
    embeds: [{
      title: '⚠️ GHSA PRE-ALERT — Fresh Malware Advisory',
      color: 0xe74c3c,
      fields: [
        { name: 'Package', value: `[${row.ecosystem}/${row.name}](${link})`, inline: true },
        { name: 'Range', value: String(row.versionRange || '*'), inline: true },
        { name: 'Advisory', value: `[${row.ghsa_id}](https://github.com/advisories/${row.ghsa_id})`, inline: true },
        { name: 'Source', value: 'GitHub Advisory DB (type=malware) — active poller', inline: false }
      ],
      footer: { text: `MUAD'DIB GHSA Pre-Alert | ${new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}` },
      timestamp: new Date().toISOString()
    }]
  };
}

async function _defaultDispatch(payload) {
  const url = process.env.MUADDIB_WEBHOOK_URL;
  if (!url) return;
  try {
    const { sendWebhook } = require('../webhook.js');
    await sendWebhook(url, payload, { rawPayload: true });
  } catch (err) {
    console.warn('[GHSA] pre-alert dispatch failed: ' + err.message);
  }
}

function _defaultLedger(entry) {
  try { require('../monitor/state.js').appendScanLedger(entry); } catch { /* best-effort */ }
}

// ── orchestration ──

/**
 * One poll pass. Best-effort: never throws. Dep-injectable for tests via opts.
 * @returns {Promise<{fresh:number, withdrawn:number, prealerted:number, seeded:boolean, errors:string[]}>}
 */
async function pollGhsaOnce(opts = {}) {
  const ecosystems = opts.ecosystems || GHSA_ECOSYSTEMS;
  const fetchImpl = opts.fetchImpl || _defaultFetch;
  const dispatch = opts.dispatch || _defaultDispatch;
  const appendLedger = opts.appendLedger || _defaultLedger;
  const cursorFile = opts.cursorFile || GHSA_CURSOR_FILE;
  const malwareFile = opts.malwareFile || GHSA_MALWARE_FILE;
  const prealertCap = opts.prealertCap != null ? opts.prealertCap : GHSA_PREALERT_CAP;

  const summary = { fresh: 0, withdrawn: 0, prealerted: 0, seeded: false, errors: [] };
  const prevCursor = loadGhsaCursor(cursorFile);
  const seeding = !prevCursor; // first run: seed silently, no pre-alert blast
  summary.seeded = seeding;

  const healthCounts = {};
  let maxUpdated = prevCursor || '';
  const freshRows = [];
  const seenRows = [];
  const withdrawnRows = [];

  for (const eco of ecosystems) {
    let advisories;
    try {
      advisories = await fetchImpl(eco, opts);
    } catch (err) {
      // A transport/HTTP error is NOT a "feed returned 0" — skip this ecosystem entirely
      // (no cursor advance, no feed-health entry → carry-forward).
      summary.errors.push(`${eco}: ${err.message}`);
      continue;
    }
    healthCounts[`GHSA-${eco}`] = advisories.length;

    for (const adv of advisories) {
      const rows = parseAdvisory(adv, ecosystems);
      for (const row of rows) {
        seenRows.push(row);
        if (row.updated_at && row.updated_at > maxUpdated) maxUpdated = row.updated_at;
        const isNew = !prevCursor || (row.updated_at && row.updated_at > prevCursor);
        if (!isNew) continue;
        if (row.withdrawn) withdrawnRows.push(row);
        else freshRows.push(row);
      }
    }
  }

  // Persist the denominator: on first run, the whole recent page; afterwards, only the
  // new/changed rows. (Phase 5 dedups by ghsa_id+ecosystem+name, latest-wins.)
  appendGhsaMalware(seeding ? seenRows : freshRows.concat(withdrawnRows), malwareFile);

  // Withdrawn advisories → ledger (a removed package keeps an identity for coverage-audit).
  for (const w of withdrawnRows) {
    appendLedger({ name: w.name, version: null, ecosystem: w.ecosystem, outcome: 'dropped', source: 'ghsa_gone' });
    summary.withdrawn++;
  }

  // Pre-alert genuinely fresh names (not on the seeding run), capped.
  summary.fresh = freshRows.length;
  if (!seeding) {
    let sent = 0;
    for (const row of freshRows) {
      if (sent >= prealertCap) {
        console.warn(`[GHSA] pre-alert cap (${prealertCap}) reached — ${freshRows.length - sent} fresh advisory row(s) not pinged this cycle (still persisted to denominator)`);
        break;
      }
      try { await dispatch(buildGhsaPreAlertEmbed(row)); sent++; } catch { /* dispatch is best-effort */ }
    }
    summary.prealerted = sent;
  }

  // Advance the cursor only if we successfully fetched at least one ecosystem.
  if (Object.keys(healthCounts).length > 0 && maxUpdated && maxUpdated !== prevCursor) {
    saveGhsaCursor(maxUpdated, cursorFile);
  }

  // Feed-health on the GHSA feed(s) (only ecosystems that actually fetched successfully).
  // opts.feedHealthFile lets tests/smoke keep the shared data/feed-health.json untouched.
  if (Object.keys(healthCounts).length > 0) {
    try {
      await require('./feed-health.js').checkFeedHealth(healthCounts,
        opts.feedHealthFile ? { file: opts.feedHealthFile } : {});
    } catch { /* best-effort */ }
  }

  if (seeding) {
    console.log(`[GHSA] seeded denominator with ${seenRows.length} advisory row(s); cursor=${maxUpdated || '(none)'} (no pre-alerts on first run)`);
  } else {
    console.log(`[GHSA] poll: ${summary.fresh} fresh, ${summary.withdrawn} withdrawn, ${summary.prealerted} pre-alerted${summary.errors.length ? `, errors: ${summary.errors.join('; ')}` : ''}`);
  }
  return summary;
}

// ── daemon lifecycle ──

function startGhsaPoller(stats) {
  if (_pollHandle) return _pollHandle;
  console.log(`[GHSA] Active poller started (interval=${GHSA_POLL_INTERVAL_MS / 60000}min)`);
  // Initial poll (best-effort, fire-and-forget — never blocks daemon startup).
  pollGhsaOnce({ stats }).catch(err => console.warn('[GHSA] initial poll error: ' + err.message));
  _pollHandle = setInterval(() => {
    pollGhsaOnce({ stats }).catch(err => console.warn('[GHSA] poll error: ' + err.message));
  }, GHSA_POLL_INTERVAL_MS);
  if (_pollHandle.unref) _pollHandle.unref();
  return _pollHandle;
}

function stopGhsaPoller() {
  if (_pollHandle) { clearInterval(_pollHandle); _pollHandle = null; console.log('[GHSA] Poller stopped'); }
}

module.exports = {
  parseAdvisory,
  pollGhsaOnce,
  loadGhsaCursor,
  saveGhsaCursor,
  appendGhsaMalware,
  buildGhsaPreAlertEmbed,
  startGhsaPoller,
  stopGhsaPoller,
  _httpGetJson,
  _defaultFetch,
  GHSA_CURSOR_FILE,
  GHSA_MALWARE_FILE,
  GHSA_POLL_INTERVAL_MS,
  GHSA_PREALERT_CAP
};
