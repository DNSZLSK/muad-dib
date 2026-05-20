/**
 * Monitor ingestion module — polling/ingestion functions extracted from monitor.js.
 *
 * Handles all registry polling (npm CouchDB changes stream, npm RSS, PyPI RSS),
 * HTTP helpers, tarball URL resolution, and download caching.
 */

'use strict';

const https = require('https');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');
const { loadCachedIOCs } = require('../ioc/updater.js');
const {
  loadNpmSeq, saveNpmSeq, CHANGES_STREAM_URL, CHANGES_LIMIT, CHANGES_CATCHUP_MAX,
  savePypiSerial, PYPI_XMLRPC_URL, PYPI_CATCHUP_MAX
} = require('./state.js');
const { sendIOCPreAlert, sendCampaignPreAlert } = require('./webhook.js');

// Active-campaign name patterns. Pre-alert fires on match BEFORE tarball
// download so operators have visibility while IOC lists catch up (typical
// lag: hours to days).
// did-NNNN (May 2026): wave of did-0001..did-9999 publications observed in
// the changes stream — name shape alone is enough to flag for fast triage.
const CAMPAIGN_PATTERNS = [
  { name: 'did-NNNN', re: /^did-\d{4}$/ }
];

function matchCampaignPattern(name) {
  for (const c of CAMPAIGN_PATTERNS) {
    if (c.re.test(name)) return c.name;
  }
  return null;
}
const { evaluateCacheTrigger, POPULAR_THRESHOLD, downloadsCache, DOWNLOADS_CACHE_TTL } = require('./classify.js');

const SELF_PACKAGE_NAME = require('../../package.json').name;

const POLL_INTERVAL = 60_000;
const POLL_MAX_BACKOFF = 960_000; // 16 minutes max backoff

// --- Mutable state ---
let consecutivePollErrors = 0;

// Test seam: code paths that need to be stubbed in tests call these through
// `_deps` instead of the bare module-local name, so a test can swap
// `ingestion._deps.httpsPost = fakePost` and have it take effect inside
// pollPyPIChangelog. Kept tiny on purpose — only network I/O lives here.
const _deps = {
  httpsPost: null // populated below once httpsPost is defined
};

function getConsecutivePollErrors() {
  return consecutivePollErrors;
}

function setConsecutivePollErrors(val) {
  consecutivePollErrors = val;
}

// --- Utility ---

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --- HTTP helpers ---

function httpsGet(url, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        const location = res.headers.location;
        if (!location) return reject(new Error(`Redirect without Location for ${url}`));
        return httpsGet(location, timeoutMs).then(resolve, reject);
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout for ${url}`));
    });
  });
}

/**
 * Minimal HTTPS POST. Used for PyPI XML-RPC; kept inside the ingestion module
 * (rather than pulled into shared/) because XML-RPC is its only consumer today.
 */
function httpsPost(url, body, headers = {}, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      method: 'POST',
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + (u.search || ''),
      timeout: timeoutMs,
      headers: {
        'Content-Type': 'text/xml',
        'Content-Length': Buffer.byteLength(body),
        ...headers
      }
    };
    const req = https.request(options, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for POST ${url}`));
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout for POST ${url}`));
    });
    req.write(body);
    req.end();
  });
}

_deps.httpsPost = httpsPost;

async function getWeeklyDownloads(packageName) {
  const cached = downloadsCache.get(packageName);
  if (cached && (Date.now() - cached.fetchedAt) < DOWNLOADS_CACHE_TTL) {
    return cached.downloads;
  }
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
    const body = await httpsGet(url, 3000);
    const data = JSON.parse(body);
    const downloads = typeof data.downloads === 'number' ? data.downloads : -1;
    downloadsCache.set(packageName, { downloads, fetchedAt: Date.now() });
    return downloads;
  } catch {
    return -1;
  }
}

// --- Tarball URL helpers ---

function getNpmTarballUrl(pkgData) {
  return (pkgData.dist && pkgData.dist.tarball) || null;
}

async function getPyPITarballUrl(packageName, packageVersion = '') {
  // Per-version endpoint when we know the version (e.g. from the XML-RPC changelog) —
  // guarantees we scan the artifact that just landed, not whatever became "latest"
  // between event detection and scan. Falls back to /pypi/<name>/json (latest) otherwise.
  const url = packageVersion
    ? `https://pypi.org/pypi/${encodeURIComponent(packageName)}/${encodeURIComponent(packageVersion)}/json`
    : `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
  const body = await httpsGet(url);
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from PyPI for ${packageName}: ${e.message}`);
  }
  const version = (data.info && data.info.version) || packageVersion || '';
  const urls = data.urls || [];
  // Prefer sdist (.tar.gz)
  const sdist = urls.find(u => u.packagetype === 'sdist' && u.url);
  if (sdist) return { url: sdist.url, version };
  // Fallback: any .tar.gz
  const tarGz = urls.find(u => u.url && u.url.endsWith('.tar.gz'));
  if (tarGz) return { url: tarGz.url, version };
  // Fallback: first available file
  if (urls.length > 0 && urls[0].url) return { url: urls[0].url, version };
  return { url: null, version };
}

// --- RSS parsing ---

/**
 * Parse npm RSS XML (same regex approach as parsePyPIRss).
 * Returns array of package names from <title> tags inside <item>.
 */
function parseNpmRss(xml) {
  const packages = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemContent = match[1];
    const titleMatch = itemContent.match(/<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/title>/);
    if (titleMatch) {
      const title = titleMatch[1].trim();
      const name = title.split(/\s+/)[0];
      if (name) {
        packages.push(name);
      }
    }
  }
  return packages;
}

/**
 * Parse PyPI RSS XML (simple regex, no deps).
 * Returns array of package names from <title> tags inside <item>.
 */
function parsePyPIRss(xml) {
  const packages = [];
  // Match each <item>...</item> block
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemContent = match[1];
    // Extract <title>...</title> inside item (handles CDATA)
    const titleMatch = itemContent.match(/<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/title>/);
    if (titleMatch) {
      // Title format is usually "package-name 1.0.0"
      const title = titleMatch[1].trim();
      // Extract just the package name (first word before space or version)
      const name = title.split(/\s+/)[0];
      if (name) {
        packages.push(name);
      }
    }
  }
  return packages;
}

// --- CouchDB doc extraction ---

// Burst-publish window: extra versions published within this window before the
// most-recent one are also enqueued for scanning. Covers the case where an
// account-takeover attacker publishes several versions in a short burst.
const RECENT_PUBLISH_WINDOW_MS = 24 * 60 * 60 * 1000;
const RECENT_PUBLISH_MAX = 5;

/**
 * Pure function: pick the most-recently-published version from a packument and
 * return its metadata, plus context useful for ATO detection.
 *
 * Critical: we sort by `time[version]` publish timestamp, NOT `dist-tags.latest`.
 * Account-takeover attacks (TeamPCP / @antv 2026-05-19, SAP, every Shai-Hulud
 * derivative) publish malicious versions without moving the latest tag — semver
 * resolution on `npm install` will still pull them. Selecting by latest tag
 * scans the wrong (clean) version and lets the malicious tarball ship.
 *
 * Falls back to `dist-tags.latest` only when `time` is missing or yields no
 * usable entries (very old legacy packages).
 *
 * @param {Object} packument - npm packument (full /<pkg> response or CouchDB doc)
 * @param {Object} [options]
 * @param {number} [options.recentWindowMs=86400000] - window for collecting extra recent versions
 * @param {number} [options.maxRecent=5] - hard cap on extras returned
 * @returns {Object|null} - {
 *   version, tarball, unpackedSize, scripts, homepage, description,
 *   latestTagVersion,       // dist-tags.latest (may differ from `version` under ATO)
 *   recentVersions: [{ version, tarball, unpackedSize, scripts }, ...]
 * } or null if no usable version found
 */
function selectMostRecentVersion(packument, options = {}) {
  const recentWindowMs = options.recentWindowMs != null ? options.recentWindowMs : RECENT_PUBLISH_WINDOW_MS;
  const maxRecent = options.maxRecent != null ? options.maxRecent : RECENT_PUBLISH_MAX;

  if (!packument || typeof packument !== 'object') return null;
  const versions = packument.versions || {};
  const time = packument.time || {};
  const distTags = packument['dist-tags'] || {};
  const latestTagVersion = (typeof distTags.latest === 'string') ? distTags.latest : null;

  // Build [version, timestamp] pairs from `time`, skipping non-version keys
  // (created/modified) and entries for unpublished versions (present in `time`
  // but absent from `versions` — npm leaves the tombstone after `npm unpublish`).
  const versionTimes = [];
  for (const [v, tsStr] of Object.entries(time)) {
    if (v === 'created' || v === 'modified') continue;
    if (!versions[v]) continue;
    const ts = Date.parse(tsStr);
    if (!Number.isFinite(ts)) continue;
    versionTimes.push([v, ts]);
  }

  let mostRecentVersion = null;
  if (versionTimes.length > 0) {
    versionTimes.sort((a, b) => b[1] - a[1]);
    mostRecentVersion = versionTimes[0][0];
  } else if (latestTagVersion && versions[latestTagVersion]) {
    // Legacy fallback: no usable time data, accept dist-tag latest
    mostRecentVersion = latestTagVersion;
  }
  if (!mostRecentVersion) return null;

  const versionData = versions[mostRecentVersion];
  if (!versionData) return null;

  const result = {
    version: versionData.version || mostRecentVersion,
    tarball: (versionData.dist && versionData.dist.tarball) || null,
    unpackedSize: (versionData.dist && versionData.dist.unpackedSize) || 0,
    scripts: versionData.scripts || {},
    homepage: (typeof versionData.homepage === 'string') ? versionData.homepage : '',
    description: (typeof versionData.description === 'string') ? versionData.description : '',
    latestTagVersion,
    recentVersions: [],
  };

  // Burst extras: other versions published within the recent window, excluding
  // the most-recent one. Bounded by maxRecent. Each extra carries enough
  // metadata for the queue to enqueue it directly without re-fetching the packument.
  if (versionTimes.length > 1) {
    const cutoff = versionTimes[0][1] - recentWindowMs;
    for (let i = 1; i < versionTimes.length && result.recentVersions.length < maxRecent; i++) {
      const [v, ts] = versionTimes[i];
      if (ts < cutoff) break; // sorted desc, so once we cross the cutoff we're done
      const vData = versions[v];
      if (!vData) continue;
      result.recentVersions.push({
        version: vData.version || v,
        tarball: (vData.dist && vData.dist.tarball) || null,
        unpackedSize: (vData.dist && vData.dist.unpackedSize) || 0,
        scripts: vData.scripts || {},
      });
    }
  }

  return result;
}

/**
 * Layer 2: Extract metadata for the most-recently-published version from a
 * CouchDB changes document (when using include_docs=true). Eliminates the
 * separate registry roundtrip that can 404 if the package is unpublished
 * between detection and scan.
 *
 * Currently dead code post-May 2025 CouchDB migration (include_docs deprecated,
 * change.doc is always null). Kept defensive in case the registry restores it
 * or a different upstream mirror provides docs again.
 *
 * @param {Object} doc - CouchDB document (change.doc), structurally a packument
 */
function extractTarballFromDoc(doc) {
  try {
    if (!doc || !doc.versions || !doc['dist-tags']) return null;
    return selectMostRecentVersion(doc);
  } catch {
    return null; // Parse failure -> fallback to lazy resolution
  }
}

/**
 * Fetch most-recently-published version metadata for an npm package.
 *
 * Uses the full packument (`registry.npmjs.org/<pkg>`) rather than the `/latest`
 * endpoint so we can detect ATO attacks that publish without moving the latest
 * dist-tag (see selectMostRecentVersion for full threat model).
 *
 * Returned object includes `latestTagVersion` and `recentVersions` so callers
 * can flag the ATO signature and enqueue burst extras for scanning.
 */
async function getNpmLatestTarball(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
  await acquireRegistrySlot();
  let body;
  try {
    body = await httpsGet(url);
  } finally {
    releaseRegistrySlot();
  }
  let packument;
  try {
    packument = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from npm registry for ${packageName}: ${e.message}`);
  }
  const result = selectMostRecentVersion(packument);
  if (!result) {
    return {
      version: '', tarball: null, unpackedSize: 0, scripts: {},
      homepage: '', description: '',
      latestTagVersion: null, recentVersions: [],
    };
  }
  return result;
}

// --- npm polling ---

/**
 * Poll npm changes stream (replicate.npmjs.com/registry/_changes).
 * Returns count of new packages queued, or -1 on error.
 * Filters out deleted packages and metadata-only updates (no new version).
 *
 * @param {Object} state - Monitor state object (npmLastSeq, npmLastPackage, pypiLastPackage)
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 */
async function pollNpmChanges(state, scanQueue, stats) {
  try {
    let lastSeq = state.npmLastSeq;

    // First run: initialize to current seq ("now") via root endpoint
    if (lastSeq == null) {
      const infoBody = await httpsGet('https://replicate.npmjs.com/registry/', 10000);
      const info = JSON.parse(infoBody);
      const currentSeq = info.update_seq;
      if (currentSeq == null) {
        console.warn('[MONITOR] Changes stream init: no update_seq in root response');
        return -1;
      }
      state.npmLastSeq = currentSeq;
      saveNpmSeq(currentSeq);
      console.log(`[MONITOR] Changes stream initialized at seq ${currentSeq}`);
      return 0;
    }

    // Post May 2025 npm CouchDB migration: include_docs is no longer supported.
    // Tarball URLs are resolved lazily in resolveTarballAndScan() via getNpmLatestTarball().
    const url = `${CHANGES_STREAM_URL}?since=${lastSeq}&limit=${CHANGES_LIMIT}`;
    let body, data;
    try {
      body = await httpsGet(url, 60000);
      data = JSON.parse(body);
    } catch (fetchErr) {
      // Invalid seq (stale from pre-migration CouchDB) or transient error — re-init to current seq
      console.warn(`[MONITOR] Changes stream fetch failed (${fetchErr.message}) — attempting seq re-init`);
      try {
        const reinitBody = await httpsGet('https://replicate.npmjs.com/registry/', 10000);
        const reinitData = JSON.parse(reinitBody);
        if (reinitData.update_seq != null) {
          state.npmLastSeq = reinitData.update_seq;
          saveNpmSeq(reinitData.update_seq);
          console.log(`[MONITOR] Changes stream re-initialized at seq ${reinitData.update_seq} (was ${lastSeq})`);
          return 0;
        }
      } catch (reinitErr) {
        console.error(`[MONITOR] Seq re-init also failed: ${reinitErr.message}`);
      }
      return -1;
    }

    if (!data.results || !Array.isArray(data.results)) {
      console.warn('[MONITOR] Changes stream returned unexpected format');
      return -1;
    }

    // Catch-up protection: if too far behind, skip to current
    if (data.results.length === CHANGES_LIMIT) {
      const currentSeqBody = await httpsGet('https://replicate.npmjs.com/registry/', 10000);
      const currentSeqData = JSON.parse(currentSeqBody);
      const currentSeq = currentSeqData.update_seq;
      if (typeof currentSeq === 'number' && typeof data.last_seq === 'number' &&
          (currentSeq - data.last_seq) > CHANGES_CATCHUP_MAX) {
        const gap = currentSeq - lastSeq;
        console.warn(`[MONITOR] Changes stream too far behind (${gap} changes) — skipping to current`);
        stats.npmCatchupSkips = (stats.npmCatchupSkips || 0) + 1;
        stats.npmCatchupSkippedSeqs = (stats.npmCatchupSkippedSeqs || 0) + gap;
        state.npmLastSeq = currentSeq;
        saveNpmSeq(currentSeq);
        return 0;
      }
    }

    let queued = 0;
    for (const change of data.results) {
      // Skip deleted packages
      if (change.deleted) continue;

      const name = change.id;

      // Skip design docs and internal CouchDB docs
      if (!name || name.startsWith('_design/')) continue;

      // Skip self
      if (name === SELF_PACKAGE_NAME) continue;

      // Skip @types/* packages — contain only .d.ts type declarations, no executable JS.
      // Zero security risk: TypeScript declaration files cannot contain runtime code.
      // Exception: still check IOC database (a compromised @types package would be listed).
      if (name.startsWith('@types/')) {
        let isTypesIOC = false;
        try {
          const iocs = loadCachedIOCs();
          isTypesIOC = iocs.wildcardPackages && iocs.wildcardPackages.has(name);
        } catch { /* IOC load failure — skip anyway */ }
        if (!isTypesIOC) continue;
      }

      // Layer 1: IOC pre-alert — send immediate webhook for known malicious packages
      // before queueing. Catches packages that may be unpublished before scan completes.
      // Hoisted so scanQueue item can carry isIOCMatch for fallback webhook on scan failure.
      // Only wildcard IOCs trigger here (all versions malicious). Versioned IOCs are checked
      // later in resolveTarballAndScan() once the exact version is known.
      let isKnownIOC = false;
      try {
        const iocs = loadCachedIOCs(); // 10s TTL cache, negligible cost per poll cycle
        isKnownIOC = iocs.wildcardPackages && iocs.wildcardPackages.has(name);
        if (isKnownIOC) {
          console.log(`[MONITOR] IOC PRE-ALERT: ${name} — known malicious package detected in changes stream`);
          stats.iocPreAlerts = (stats.iocPreAlerts || 0) + 1;
          // Fire-and-forget: do not block polling
          sendIOCPreAlert(name).catch(err => {
            console.error(`[MONITOR] IOC pre-alert webhook failed for ${name}: ${err.message}`);
          });
        }
      } catch (err) {
        // IOC load failure is non-fatal — proceed with normal queue
        console.warn(`[MONITOR] IOC pre-check failed: ${err.message}`);
      }

      // Layer 1b: Campaign pre-alert — fire on name-pattern matches when the
      // package isn't already a known IOC (avoid duplicate webhooks for the
      // same publication). Lets us flag campaign waves while IOC lists lag.
      if (!isKnownIOC) {
        const campaign = matchCampaignPattern(name);
        if (campaign) {
          console.log(`[MONITOR] CAMPAIGN PRE-ALERT: ${name} — matches ${campaign}`);
          stats.campaignPreAlerts = (stats.campaignPreAlerts || 0) + 1;
          sendCampaignPreAlert(name, campaign).catch(err => {
            console.error(`[MONITOR] campaign pre-alert webhook failed for ${name}: ${err.message}`);
          });
        }
      }

      // Layer 2: Extract tarball URL from CouchDB doc (eliminates lazy resolution 404 race)
      const docMeta = change.doc ? extractTarballFromDoc(change.doc) : null;

      // Layer 3: Evaluate if this package should be cached
      const cacheTrigger = evaluateCacheTrigger(name, docMeta, change.doc || null);

      // Layer 2: Extract tarball URL from CouchDB doc (eliminates lazy resolution 404 race)
      // NOTE: fastTrack flag is computed in resolveTarballAndScan() AFTER metadata
      // resolution via getNpmLatestTarball(). It cannot be computed here because
      // post-May 2025, include_docs is deprecated and change.doc is always null.
      scanQueue.push({
        name,
        version: docMeta ? docMeta.version : '',
        ecosystem: 'npm',
        tarballUrl: docMeta ? docMeta.tarball : null,
        unpackedSize: docMeta ? docMeta.unpackedSize : 0,
        registryScripts: docMeta ? docMeta.scripts : null,
        _cacheTrigger: cacheTrigger.shouldCache ? cacheTrigger : null,
        isIOCMatch: isKnownIOC
      });
      queued++;
    }

    // Update seq in memory only — disk persistence is handled by daemon.js
    // after both queue and seq are saved atomically (prevents data loss on crash).
    if (data.last_seq != null) {
      state.npmLastSeq = data.last_seq;
    }

    if (queued > 0) {
      console.log(`[MONITOR] Changes stream: ${queued} packages queued (seq ${lastSeq} → ${data.last_seq})`);
    }

    // Track metric
    stats.changesStreamPackages = (stats.changesStreamPackages || 0) + queued;

    return queued;
  } catch (err) {
    console.error(`[MONITOR] Changes stream error: ${err.message} — falling back to RSS`);
    return -1;
  }
}

/**
 * Poll npm via RSS feed (legacy).
 * Kept as fallback when the CouchDB changes stream is unavailable.
 *
 * @param {Object} state - Monitor state object
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 */
async function pollNpmRss(state, scanQueue, stats) {
  const url = 'https://registry.npmjs.org/-/rss?descending=true&limit=200';

  try {
    await acquireRegistrySlot();
    let body;
    try {
      body = await httpsGet(url);
    } finally {
      releaseRegistrySlot();
    }
    const packages = parseNpmRss(body);

    // Find new packages (those after the last seen one)
    let newPackages;
    if (!state.npmLastPackage) {
      newPackages = packages;
    } else {
      const lastIdx = packages.indexOf(state.npmLastPackage);
      if (lastIdx === -1) {
        newPackages = packages;
      } else {
        newPackages = packages.slice(0, lastIdx);
      }
    }

    for (const name of newPackages) {
      if (name === SELF_PACKAGE_NAME) {
        console.log(`[MONITOR] SKIPPED (self): ${name}`);
        continue;
      }
      // Skip @types/* — no executable code (same logic as changes stream)
      if (name.startsWith('@types/')) {
        let isTypesIOC = false;
        try {
          const iocs = loadCachedIOCs();
          isTypesIOC = iocs.wildcardPackages && iocs.wildcardPackages.has(name);
        } catch { /* IOC load failure — skip anyway */ }
        if (!isTypesIOC) continue;
      }
      console.log(`[MONITOR] New npm: ${name}`);

      // Layer 1: IOC pre-alert (RSS fallback path)
      // Only wildcard IOCs trigger here; versioned IOCs checked in resolveTarballAndScan().
      let isKnownIOC = false;
      try {
        const iocs = loadCachedIOCs();
        isKnownIOC = iocs.wildcardPackages && iocs.wildcardPackages.has(name);
        if (isKnownIOC) {
          console.log(`[MONITOR] IOC PRE-ALERT: ${name} — known malicious package detected via RSS`);
          stats.iocPreAlerts = (stats.iocPreAlerts || 0) + 1;
          sendIOCPreAlert(name).catch(err => {
            console.error(`[MONITOR] IOC pre-alert webhook failed for ${name}: ${err.message}`);
          });
        }
      } catch { /* IOC load failure is non-fatal */ }

      // Layer 1b: Campaign pre-alert (RSS fallback path) — mirrors pollNpmChanges.
      if (!isKnownIOC) {
        const campaign = matchCampaignPattern(name);
        if (campaign) {
          console.log(`[MONITOR] CAMPAIGN PRE-ALERT: ${name} — matches ${campaign} (RSS)`);
          stats.campaignPreAlerts = (stats.campaignPreAlerts || 0) + 1;
          sendCampaignPreAlert(name, campaign).catch(err => {
            console.error(`[MONITOR] campaign pre-alert webhook failed for ${name}: ${err.message}`);
          });
        }
      }

      // Queue npm packages — tarball URL resolved during scan
      scanQueue.push({
        name,
        version: '',
        ecosystem: 'npm',
        tarballUrl: null // resolved lazily via resolveTarballAndScan (no CouchDB doc in RSS)
      });
    }

    // Remember the most recent package (first in RSS)
    if (packages.length > 0) {
      state.npmLastPackage = packages[0];
    }

    return newPackages.length;
  } catch (err) {
    console.error(`[MONITOR] npm poll error: ${err.message}`);
    return -1;
  }
}

/**
 * Poll npm registry for new packages.
 * Primary: CouchDB changes stream (replicate.npmjs.com).
 * Fallback: RSS feed (registry.npmjs.org) when changes stream fails.
 *
 * @param {Object} state - Monitor state object
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 */
async function pollNpm(state, scanQueue, stats) {
  const count = await pollNpmChanges(state, scanQueue, stats);
  if (count >= 0) {
    return count;
  }
  // Fallback to RSS on changes stream failure
  console.log('[MONITOR] Using RSS fallback for npm');
  stats.rssFallbackCount = (stats.rssFallbackCount || 0) + 1;
  return pollNpmRss(state, scanQueue, stats);
}

// --- PyPI polling ---

const PYPI_USER_AGENT = `${SELF_PACKAGE_NAME} (security-monitor; +https://github.com/DNSZLSK/muaddib)`;

/**
 * Build an XML-RPC methodCall envelope. PyPI accepts only <int> and <string>
 * params for the methods we use (changelog_last_serial, changelog_since_serial),
 * so this builder is deliberately minimal.
 */
function buildXmlRpcCall(method, params) {
  const paramXml = params.map((p) => {
    if (typeof p === 'number' && Number.isInteger(p)) {
      return `<param><value><int>${p}</int></value></param>`;
    }
    if (typeof p === 'string') {
      // Method names + serial numbers only — no user-supplied strings reach this path.
      const escaped = p.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `<param><value><string>${escaped}</string></value></param>`;
    }
    throw new Error(`Unsupported XML-RPC param type: ${typeof p}`);
  }).join('');
  return `<?xml version="1.0"?><methodCall><methodName>${method}</methodName><params>${paramXml}</params></methodCall>`;
}

/**
 * Parse a PyPI changelog_since_serial response.
 *
 * Response shape (per https://warehouse.pypa.io/api-reference/xml-rpc.html):
 *   <array><data>
 *     <value><array><data>
 *       <value><string>NAME</string></value>     <!-- index 0 -->
 *       <value><string>VERSION</string></value>  <!-- index 1, may be empty -->
 *       <value><int>TIMESTAMP</int></value>      <!-- index 2 -->
 *       <value><string>ACTION</string></value>   <!-- index 3 -->
 *       <value><int>SERIAL</int></value>         <!-- index 4 -->
 *     </data></array></value>
 *     ...
 *   </data></array>
 *
 * Returns array of { name, version, timestamp, action, serial }. Invalid tuples
 * are skipped silently — partial data is better than dropping the whole batch.
 */
function parseXmlRpcChangelog(xml) {
  const out = [];
  if (typeof xml !== 'string' || !xml.includes('<methodResponse>')) return out;
  if (xml.includes('<fault>')) return out; // PyPI fault → caller should treat as failure

  // The response is a nested array: outer <array><data>...inner tuples...</data></array>.
  // We strip the outer wrapper first so the inner-tuple regex can't accidentally
  // greedy-match across the outer boundary (which would swallow tuple #1).
  const outerArrayStart = xml.indexOf('<array>');
  if (outerArrayStart === -1) return out;
  const outerDataStart = xml.indexOf('<data>', outerArrayStart);
  if (outerDataStart === -1) return out;
  const outerDataEnd = xml.lastIndexOf('</data>');
  if (outerDataEnd === -1 || outerDataEnd <= outerDataStart) return out;
  const body = xml.slice(outerDataStart + '<data>'.length, outerDataEnd);

  // Each tuple inside `body` is exactly: <value><array><data>...</data></array></value>
  const tupleRegex = /<value>\s*<array>\s*<data>([\s\S]*?)<\/data>\s*<\/array>\s*<\/value>/g;
  let m;
  while ((m = tupleRegex.exec(body)) !== null) {
    const inner = m[1];
    const values = [];
    const valRegex = /<value>\s*(?:<string>([\s\S]*?)<\/string>|<int>(-?\d+)<\/int>)\s*<\/value>/g;
    let v;
    while ((v = valRegex.exec(inner)) !== null) {
      if (v[1] !== undefined) {
        // Decode the XML entities we encode on the way in
        values.push(v[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));
      } else {
        values.push(parseInt(v[2], 10));
      }
    }
    if (values.length !== 5) continue;
    const [name, version, timestamp, action, serial] = values;
    if (typeof name !== 'string' || typeof action !== 'string' ||
        typeof timestamp !== 'number' || typeof serial !== 'number') continue;
    out.push({ name, version: typeof version === 'string' ? version : '', timestamp, action, serial });
  }
  return out;
}

/**
 * Parse a changelog_last_serial response. Returns the integer or null.
 */
function parseXmlRpcInt(xml) {
  if (typeof xml !== 'string' || xml.includes('<fault>')) return null;
  const m = xml.match(/<value>\s*<int>(-?\d+)<\/int>\s*<\/value>/);
  return m ? parseInt(m[1], 10) : null;
}

/**
 * Decide whether a changelog event introduces scannable content.
 *
 * KEEP (something new was published, scan the release):
 *   - "new release"               → version metadata created
 *   - "add source file …"         → sdist uploaded
 *   - "add py3 file …" / "add cp… file …" / "add … file …" → wheel uploaded
 *
 * SKIP (no new artifact to scan):
 *   - "remove …", "yank release", "unyank release" → removal, not a new threat
 *   - "create"                                      → package shell, no version yet
 *   - "add Owner", "remove Owner", "accepted Owner" → ACL changes
 *   - empty version → administrative event at the package level
 */
function isPypiScannableAction(action, version) {
  if (!version) return false;
  if (typeof action !== 'string') return false;
  if (action === 'new release') return true;
  if (action.startsWith('add ') && action.includes(' file ')) return true;
  return false;
}

/**
 * Poll PyPI changelog via XML-RPC (primary path).
 * Equivalent of pollNpmChanges: strictly monotonic serial, lossless resume.
 *
 * @param {Object} state - Monitor state (pypiLastSerial)
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 * @returns {Promise<number>} Number of packages queued, or -1 on error
 */
async function pollPyPIChangelog(state, scanQueue, stats) {
  try {
    let lastSerial = state.pypiLastSerial;

    // First run: anchor to "now" rather than replaying months of history
    if (lastSerial == null) {
      await acquireRegistrySlot();
      let initBody;
      try {
        initBody = await _deps.httpsPost(
          PYPI_XMLRPC_URL,
          buildXmlRpcCall('changelog_last_serial', []),
          { 'User-Agent': PYPI_USER_AGENT },
          10_000
        );
      } finally {
        releaseRegistrySlot();
      }
      const current = parseXmlRpcInt(initBody);
      if (current == null) {
        console.warn('[MONITOR] PyPI changelog init: no serial in response');
        return -1;
      }
      state.pypiLastSerial = current;
      savePypiSerial(current);
      console.log(`[MONITOR] PyPI changelog initialized at serial ${current}`);
      return 0;
    }

    await acquireRegistrySlot();
    let body;
    try {
      body = await _deps.httpsPost(
        PYPI_XMLRPC_URL,
        buildXmlRpcCall('changelog_since_serial', [lastSerial]),
        { 'User-Agent': PYPI_USER_AGENT },
        60_000
      );
    } finally {
      releaseRegistrySlot();
    }

    const events = parseXmlRpcChangelog(body);
    if (events.length === 0) {
      // Either nothing happened or the response was a fault — distinguish.
      if (body && body.includes('<fault>')) {
        console.error('[MONITOR] PyPI changelog returned XML-RPC fault — falling back to RSS');
        return -1;
      }
      return 0;
    }

    // Catch-up protection: if events span more than PYPI_CATCHUP_MAX serials,
    // skip to the latest serial to avoid an avalanche after long downtime.
    const lastEventSerial = events[events.length - 1].serial;
    const gap = lastEventSerial - lastSerial;
    if (gap > PYPI_CATCHUP_MAX) {
      console.warn(`[MONITOR] PyPI changelog too far behind (${gap} events) — skipping to current`);
      stats.pypiCatchupSkips = (stats.pypiCatchupSkips || 0) + 1;
      stats.pypiCatchupSkippedEvents = (stats.pypiCatchupSkippedEvents || 0) + gap;
      state.pypiLastSerial = lastEventSerial;
      savePypiSerial(lastEventSerial);
      return 0;
    }

    // Dedupe (name, version) within the batch: a single release usually emits
    // multiple events (new release + add source file + add wheel files…), but
    // there's only one thing to scan.
    const seen = new Set();
    let queued = 0;
    let maxSerial = lastSerial;

    for (const ev of events) {
      if (ev.serial > maxSerial) maxSerial = ev.serial;

      if (!isPypiScannableAction(ev.action, ev.version)) continue;

      const key = `${ev.name}@${ev.version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Skip self (mirror of the npm path — defensive even though we don't publish to PyPI)
      if (ev.name === SELF_PACKAGE_NAME) continue;

      // IOC pre-alert for known-malicious PyPI packages
      let isKnownIOC = false;
      try {
        const iocs = loadCachedIOCs();
        // PyPI IOCs are namespaced "pypi:<name>" in the wildcardPackages set
        const pypiKey = `pypi:${ev.name}`;
        isKnownIOC = iocs.wildcardPackages && (
          iocs.wildcardPackages.has(pypiKey) || iocs.wildcardPackages.has(ev.name)
        );
        if (isKnownIOC) {
          console.log(`[MONITOR] IOC PRE-ALERT (pypi): ${ev.name} — known malicious package`);
          stats.iocPreAlerts = (stats.iocPreAlerts || 0) + 1;
          sendIOCPreAlert(ev.name).catch(err => {
            console.error(`[MONITOR] IOC pre-alert webhook failed for ${ev.name}: ${err.message}`);
          });
        }
      } catch { /* IOC load failure is non-fatal */ }

      scanQueue.push({
        name: ev.name,
        version: ev.version,
        ecosystem: 'pypi',
        tarballUrl: null, // resolved lazily via getPyPITarballUrl()
        isIOCMatch: isKnownIOC
      });
      queued++;
    }

    // Persist the serial both in memory and on disk before returning.
    // daemon.js also flushes state.json after the queue is saved, but writing the
    // dedicated serial file here means a crash between the two flush points costs
    // at most one poll of replay — and re-queuing the same (name, version) is
    // handled idempotently by the scan-memory dedupe downstream.
    state.pypiLastSerial = maxSerial;
    if (maxSerial !== lastSerial) {
      savePypiSerial(maxSerial);
    }

    if (queued > 0) {
      console.log(`[MONITOR] PyPI changelog: ${queued} packages queued (serial ${lastSerial} → ${maxSerial}, ${events.length} events)`);
    }
    stats.pypiChangelogPackages = (stats.pypiChangelogPackages || 0) + queued;
    stats.pypiChangelogEvents = (stats.pypiChangelogEvents || 0) + events.length;

    return queued;
  } catch (err) {
    console.error(`[MONITOR] PyPI changelog error: ${err.message} — falling back to RSS`);
    return -1;
  }
}

/**
 * Poll PyPI RSS feed (legacy fallback).
 * Only covers newly-registered packages (first-ever publish) and is capped at ~40 items —
 * a single burst can silently lose events. Used only when the XML-RPC changelog fails.
 *
 * @param {Object} state - Monitor state object (pypiLastPackage)
 * @param {Array} scanQueue - Mutable scan queue array
 */
async function pollPyPIRss(state, scanQueue) {
  const url = 'https://pypi.org/rss/packages.xml';

  try {
    const body = await httpsGet(url);
    const packages = parsePyPIRss(body);

    // Find new packages (those after the last seen one)
    let newPackages;
    if (!state.pypiLastPackage) {
      // First run: log all and remember the first one
      newPackages = packages;
    } else {
      const lastIdx = packages.indexOf(state.pypiLastPackage);
      if (lastIdx === -1) {
        // Last seen not in feed — all are new
        newPackages = packages;
      } else {
        // Items before lastIdx are newer (RSS is newest-first)
        newPackages = packages.slice(0, lastIdx);
      }
    }

    for (const name of newPackages) {
      console.log(`[MONITOR] New pypi (rss): ${name}`);
      // Queue PyPI packages — tarball URL resolved during scan
      scanQueue.push({
        name,
        version: '',
        ecosystem: 'pypi',
        tarballUrl: null // resolved lazily in scanPackage wrapper
      });
    }

    // Remember the most recent package (first in RSS)
    if (packages.length > 0) {
      state.pypiLastPackage = packages[0];
    }

    return newPackages.length;
  } catch (err) {
    console.error(`[MONITOR] PyPI RSS poll error: ${err.message}`);
    return -1;
  }
}

/**
 * Poll PyPI for new packages and versions.
 * Primary: XML-RPC changelog_since_serial (lossless, captures new versions).
 * Fallback: RSS feed (new registrations only, lossy on bursts).
 *
 * @param {Object} state - Monitor state object
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 */
async function pollPyPI(state, scanQueue, stats = {}) {
  const count = await pollPyPIChangelog(state, scanQueue, stats);
  if (count >= 0) return count;
  console.log('[MONITOR] Using RSS fallback for PyPI');
  stats.pypiRssFallbackCount = (stats.pypiRssFallbackCount || 0) + 1;
  return pollPyPIRss(state, scanQueue);
}

// --- Main poll orchestrator ---

/**
 * Poll all registries (npm + PyPI) and manage backoff on consecutive failures.
 *
 * @param {Object} state - Monitor state object
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 */
const SOFT_BACKPRESSURE_THRESHOLD = 30_000;

async function poll(state, scanQueue, stats) {
  // Memory-based backpressure: skip poll when heap is at CRITICAL+ (90%+).
  // This is the primary defense against the 2026-04-13 death spiral where
  // ingestion continued at 50 pkg/min while processing was at 0 throughput.
  // Safe because: CouchDB seq is NOT advanced — next poll resumes from same point.
  try {
    const { getMemoryPressureLevel } = require('./daemon.js');
    const pressureLevel = getMemoryPressureLevel();
    // CRITICAL=3, EMERGENCY=4
    if (pressureLevel >= 3) {
      console.log(`[MONITOR] MEMORY BACKPRESSURE: skipping poll (pressure level ${pressureLevel} >= CRITICAL) — seq not advanced, 0 packages lost`);
      return;
    }
  } catch { /* daemon.js not loaded yet (initial poll) — proceed normally */ }

  // Queue-depth backpressure: skip poll when queue is very deep.
  // Safe because: CouchDB seq is NOT advanced (stays in memory only, persisted
  // by daemon.js AFTER poll returns) — next poll resumes from the same point.
  // Combined with adaptive concurrency: workers scale up → queue drains → poll resumes.
  // This prevents the queue from growing to 30-40K during catch-up (OOM risk).
  if (scanQueue.length >= SOFT_BACKPRESSURE_THRESHOLD) {
    console.log(`[MONITOR] BACKPRESSURE: skipping poll (queue ${scanQueue.length} >= ${SOFT_BACKPRESSURE_THRESHOLD}) — seq not advanced, 0 packages lost`);
    return;
  }
  if (scanQueue.length > 5_000) {
    console.log(`[MONITOR] QUEUE_DEPTH: ${scanQueue.length} items — polling continues`);
  }

  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  console.log(`[MONITOR] ${timestamp} — polling registries...`);

  const [npmCount, pypiCount] = await Promise.all([
    pollNpm(state, scanQueue, stats),
    pollPyPI(state, scanQueue, stats)
  ]);

  // Track consecutive poll failures for backoff
  if (npmCount === -1 && pypiCount === -1) {
    consecutivePollErrors++;
    if (consecutivePollErrors > 1) {
      const backoff = Math.min(POLL_INTERVAL * Math.pow(2, consecutivePollErrors - 1), POLL_MAX_BACKOFF);
      console.log(`[MONITOR] Both registries failed (${consecutivePollErrors}x) — backing off ${(backoff / 1000).toFixed(0)}s`);
      await sleep(backoff);
    }
  } else {
    consecutivePollErrors = 0;
  }

  const npmDisplay = npmCount === -1 ? 'error' : npmCount;
  const pypiDisplay = pypiCount === -1 ? 'error' : pypiCount;
  console.log(`[MONITOR] Found ${npmDisplay} npm + ${pypiDisplay} PyPI new packages`);
}

module.exports = {
  // Constants
  SELF_PACKAGE_NAME,
  POLL_INTERVAL,
  POLL_MAX_BACKOFF,

  // Mutable state
  getConsecutivePollErrors,
  setConsecutivePollErrors,

  // HTTP helpers
  httpsGet,
  httpsPost,
  getWeeklyDownloads,

  // Tarball URL helpers
  getNpmTarballUrl,
  getPyPITarballUrl,
  getNpmLatestTarball,

  // RSS parsing
  parseNpmRss,
  parsePyPIRss,

  // XML-RPC (PyPI changelog)
  buildXmlRpcCall,
  parseXmlRpcChangelog,
  parseXmlRpcInt,
  isPypiScannableAction,

  // CouchDB doc extraction
  extractTarballFromDoc,
  selectMostRecentVersion,
  RECENT_PUBLISH_WINDOW_MS,
  RECENT_PUBLISH_MAX,

  // Polling functions
  pollNpmChanges,
  pollNpmRss,
  pollNpm,
  pollPyPIChangelog,
  pollPyPIRss,
  pollPyPI,
  poll,

  // Active-campaign name watch (did-NNNN, etc.)
  CAMPAIGN_PATTERNS,
  matchCampaignPattern,

  // Test seam — see _deps definition near the top of this file.
  _deps
};
