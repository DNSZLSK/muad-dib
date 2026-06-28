/**
 * Monitor ingestion module — polling/ingestion functions extracted from monitor.js.
 *
 * Handles all registry polling (npm CouchDB changes stream, npm RSS, PyPI RSS),
 * HTTP helpers, tarball URL resolution, and download caching.
 */

'use strict';

const https = require('https');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');
const { registryAuthHeaders } = require('../shared/registry-auth.js');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { enqueueScan } = require('./scan-queue.js');
const {
  saveNpmSeq, CHANGES_STREAM_URL, CHANGES_LIMIT, CHANGES_CATCHUP_MAX,
  savePypiSerial, PYPI_XMLRPC_URL, PYPI_CATCHUP_MAX, appendScanLedger
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
const { evaluateCacheTrigger, downloadsCache, DOWNLOADS_CACHE_TTL } = require('./classify.js');

const SELF_PACKAGE_NAME = require('../../package.json').name;

const POLL_INTERVAL = 60_000;
const POLL_MAX_BACKOFF = 960_000; // 16 minutes max backoff
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024; // OOM guard: cap a single buffered HTTP (JSON/XML metadata) response at 64MB

// --- Mutable state ---
let consecutivePollErrors = 0;

// Test seam: code paths that need to be stubbed in tests call these through
// `_deps` instead of the bare module-local name, so a test can swap
// `ingestion._deps.httpsPost = fakePost` and have it take effect inside
// pollPyPIChangelog. Kept tiny on purpose — only network I/O lives here.
const _deps = {
  httpsPost: null, // populated below once httpsPost is defined
  httpsGet: null,  // populated below; used by npm pollers so tests can stub
  // Low-level client (https.get / https.request). Routing through _deps lets a
  // test inject a fake req/res to exercise the absolute-deadline timer without
  // real TLS. Production always uses the real `https` module.
  https
};

function getConsecutivePollErrors() {
  return consecutivePollErrors;
}

function setConsecutivePollErrors(val) {
  consecutivePollErrors = val;
}

/**
 * Backoff (ms) the poll scheduler should wait before its next cycle, derived
 * from consecutive total-registry failures. Returns 0 when healthy or after a
 * single failure; otherwise exponential POLL_INTERVAL * 2^(n-1), capped at
 * POLL_MAX_BACKOFF (16min). Pure read of module state — poll() never sleeps;
 * the scheduler (daemon.js) owns the wait. See poll() for why the sleep was
 * hoisted out (it used to hold pollInProgress for up to 16min).
 * @returns {number}
 */
function getPollBackoffMs() {
  if (consecutivePollErrors <= 1) return 0;
  return Math.min(POLL_INTERVAL * Math.pow(2, consecutivePollErrors - 1), POLL_MAX_BACKOFF);
}

// --- HTTP helpers ---

function httpsGet(url, timeoutMs = 30_000, deadlineMs = Math.max(timeoutMs * 2, 90_000)) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let req;
    // Absolute deadline. Node's `{ timeout }` option is a socket-INACTIVITY
    // timeout, not an overall deadline: a response whose body trickles forever
    // (heartbeat/keep-alive bytes, or a long-poll feed that never sends 'end')
    // keeps the socket "active", so the inactivity timeout never fires and this
    // promise never settles — wedging the poll loop. The deadline bounds the
    // WHOLE request+body and destroys the socket so it can't leak.
    const deadline = setTimeout(() => {
      if (req) req.destroy(new Error(`Overall deadline (${Math.round(deadlineMs / 1000)}s) exceeded for ${url}`));
    }, deadlineMs);
    const done = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (err) reject(err); else resolve(value);
    };
    req = _deps.https.get(url, { timeout: timeoutMs, headers: registryAuthHeaders(url) }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        const location = res.headers.location;
        if (!location) return done(new Error(`Redirect without Location for ${url}`));
        // Hand the deadline off to the recursive call, which has its own.
        settled = true;
        clearTimeout(deadline);
        return httpsGet(location, timeoutMs, deadlineMs).then(resolve, reject);
      }
      if (res.statusCode === 429) {
        res.resume();
        // Coordinated backoff: drain the SHARED token bucket so every in-flight registry fetch
        // slows together. This high-volume packument/changes path must signal 429 like the
        // metadata path (npm-registry.js) does — not just acquire a slot (CLAUDE.md 429 storm).
        try { const _l = require('../shared/http-limiter.js'); _l.signal429(_l.hostForUrl(url)); } catch { /* limiter best-effort */ }
        return done(new Error(`HTTP 429 rate limited for ${url}`));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return done(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      let total = 0;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) {
          req.destroy(new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes for ${url}`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => done(null, Buffer.concat(chunks).toString('utf8')));
      res.on('error', (err) => done(err));
    });
    req.on('error', (err) => done(err));
    req.on('timeout', () => {
      req.destroy(new Error(`Timeout for ${url}`));
    });
  });
}

/**
 * Minimal HTTPS POST. Used for PyPI XML-RPC; kept inside the ingestion module
 * (rather than pulled into shared/) because XML-RPC is its only consumer today.
 */
function httpsPost(url, body, headers = {}, timeoutMs = 30_000, deadlineMs = Math.max(timeoutMs * 2, 90_000)) {
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
    let settled = false;
    let req;
    // Absolute deadline — see httpsGet for the rationale (inactivity timeout is
    // not an overall deadline; a trickling body would hang forever otherwise).
    const deadline = setTimeout(() => {
      if (req) req.destroy(new Error(`Overall deadline (${Math.round(deadlineMs / 1000)}s) exceeded for POST ${url}`));
    }, deadlineMs);
    const done = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (err) reject(err); else resolve(value);
    };
    req = _deps.https.request(options, (res) => {
      if (res.statusCode === 429) {
        res.resume();
        try { const _l = require('../shared/http-limiter.js'); _l.signal429(_l.hostForUrl(url)); } catch { /* limiter best-effort */ }
        return done(new Error(`HTTP 429 rate limited for POST ${url}`));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return done(new Error(`HTTP ${res.statusCode} for POST ${url}`));
      }
      const chunks = [];
      let total = 0;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) {
          req.destroy(new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes for POST ${url}`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => done(null, Buffer.concat(chunks).toString('utf8')));
      res.on('error', (err) => done(err));
    });
    req.on('error', (err) => done(err));
    req.on('timeout', () => {
      req.destroy(new Error(`Timeout for POST ${url}`));
    });
    req.write(body);
    req.end();
  });
}

_deps.httpsPost = httpsPost;
_deps.httpsGet = httpsGet;

async function getWeeklyDownloads(packageName) {
  const cached = downloadsCache.get(packageName);
  if (cached && (Date.now() - cached.fetchedAt) < DOWNLOADS_CACHE_TTL) {
    return cached.downloads;
  }
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
    // Routed via _deps so tests can stub the downloads endpoint independently
    // of the registry endpoint (Stage 2.1 added parallel-fetch from
    // preResolveNpmBatch).
    const body = await _deps.httpsGet(url, 3000);
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
  // Always hit the package-level endpoint. It contains:
  //   - info.version  → latest version
  //   - urls          → files for the latest version
  //   - releases      → files for ALL versions (so we can find packageVersion's
  //                     exact artifact, same anti-race guarantee as the per-
  //                     version endpoint used to provide)
  // We extract triage metadata (age_days, version_count) from `releases` in
  // the same round-trip — keeps Stage 2's PyPI cost at 1 HTTP call.
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
  const body = await _deps.httpsGet(url);
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from PyPI for ${packageName}: ${e.message}`, { cause: e });
  }

  const latestVersion = (data.info && data.info.version) || '';
  const version = packageVersion || latestVersion;
  const releases = (data && data.releases) || {};

  // Pick files for the requested version (preserves the original anti-race
  // guarantee — we scan the exact version flagged by the changelog). If
  // absent (e.g. lazy resolution without a known version), use latest urls.
  const files = (packageVersion && Array.isArray(releases[packageVersion]))
    ? releases[packageVersion]
    : (Array.isArray(data.urls) ? data.urls : []);

  // Tarball selection priority unchanged: sdist > .tar.gz > .whl/.zip.
  // Legacy .egg / .tar.bz2 / .exe intentionally not returned (they were the
  // cause of ~2773 tar_failed/day before the original fix).
  let tarballUrl = null;
  const sdist = files.find(u => u && u.packagetype === 'sdist' && u.url);
  if (sdist) {
    tarballUrl = sdist.url;
  } else {
    const tarGz = files.find(u => u && u.url && u.url.endsWith('.tar.gz'));
    if (tarGz) {
      tarballUrl = tarGz.url;
    } else {
      const wheel = files.find(u => u && u.url && (u.url.endsWith('.whl') || u.url.endsWith('.zip')));
      if (wheel) tarballUrl = wheel.url;
    }
  }

  // Stage 2 triage metadata: derived from `releases` once per fetch.
  const versionCount = Object.keys(releases).length;
  let earliestUpload = Number.MAX_SAFE_INTEGER;
  for (const v of Object.keys(releases)) {
    const versionFiles = releases[v];
    if (!Array.isArray(versionFiles)) continue;
    for (const f of versionFiles) {
      if (f && f.upload_time) {
        const ts = Date.parse(f.upload_time);
        if (Number.isFinite(ts) && ts < earliestUpload) earliestUpload = ts;
      }
    }
  }
  const ageDays = earliestUpload !== Number.MAX_SAFE_INTEGER
    ? Math.floor((Date.now() - earliestUpload) / 86_400_000)
    : null;

  return {
    url: tarballUrl,
    version,
    age_days: ageDays,
    version_count: versionCount,
  };
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
 *   recentVersions: [{ version, tarball, unpackedSize, scripts }, ...],  // capped at maxRecent
 *   recentWindowCount,      // TRUE (uncapped) count of versions in the window (Phase 2b burst)
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
    droppedBurstVersions: [],
  };

  // Burst extras: other versions published within the recent window, excluding the
  // most-recent one. The enqueue list is bounded by maxRecent, but recentWindowCount is
  // the TRUE (uncapped) number of versions in the window — Phase 2b burst detection uses it
  // so a 96-version Miasma burst is distinguishable from a legit 3-5 patch-release day (the
  // capped list alone tops out at maxRecent+1 and can't tell them apart).
  result.recentWindowCount = 1; // includes the most-recent version itself
  if (versionTimes.length > 1) {
    const cutoff = versionTimes[0][1] - recentWindowMs;
    for (let i = 1; i < versionTimes.length; i++) {
      const [v, ts] = versionTimes[i];
      if (ts < cutoff) break; // sorted desc, so once we cross the cutoff we're done
      result.recentWindowCount++;
      if (result.recentVersions.length >= maxRecent) {
        // Burst beyond the enqueue cap: collect the version so the caller ledgers it as a
        // coverage loss (it is never enqueued/scanned). Keeps a Miasma-style burst that
        // outruns maxRecent visible instead of vanishing silently (CLAUDE.md "no silent caps").
        result.droppedBurstVersions.push(v);
        continue; // enqueue list capped; count continues
      }
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
    body = await _deps.httpsGet(url);
  } finally {
    releaseRegistrySlot();
  }
  let packument;
  try {
    packument = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from npm registry for ${packageName}: ${e.message}`, { cause: e });
  }
  const result = selectMostRecentVersion(packument);
  if (!result) {
    return {
      version: '', tarball: null, unpackedSize: 0, scripts: {},
      homepage: '', description: '',
      latestTagVersion: null, recentVersions: [],
      age_days: null, version_count: 0,
    };
  }
  // A3: ledger burst versions dropped by the maxRecent enqueue cap — they are never scanned,
  // so record each as a 'dropped' coverage loss (source burst_extras_cap) for the coverage
  // audit. Best-effort; never throws. selectMostRecentVersion stays pure (it only collects).
  if (result.droppedBurstVersions && result.droppedBurstVersions.length) {
    for (const v of result.droppedBurstVersions) {
      try {
        appendScanLedger({ name: packageName, version: v, ecosystem: 'npm', outcome: 'dropped', source: 'burst_extras_cap' });
      } catch { /* ledger is best-effort */ }
    }
  }
  // Stage 2.1 — extract reputation signals from the packument we already have,
  // so triageRisk in queue.js doesn't have to refetch metadata via
  // getPackageMetadata. Two fields are derivable from the packument alone:
  //   - age_days   : time.created (package creation timestamp)
  //   - version_count : Object.keys(versions).length (excludes unpublished
  //                     tombstones kept only in `time`)
  // weekly_downloads requires a separate api.npmjs.org call and is fetched in
  // parallel by preResolveNpmBatch (it has its own cache + no semaphore).
  const createdAt = (packument && packument.time && packument.time.created) || null;
  result.age_days = createdAt
    ? Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000)
    : null;
  result.version_count = (packument && packument.versions)
    ? Object.keys(packument.versions).length : 0;
  return result;
}

// --- Pre-resolution helpers ---
//
// Resolve tarball URLs and metadata at ingestion time so scan workers do not
// each pay a separate registry round-trip. Best-effort: any failure leaves
// item.tarballUrl untouched (null) so resolveTarballAndScan() in queue.js
// falls back to its existing lazy-resolution path (zero scan loss).
//
// HTTP throttling: getNpmLatestTarball / getPyPITarballUrl already acquire
// the shared REGISTRY_SEMAPHORE_MAX=20 slot + 30 req/sec token bucket, so
// fan-out is naturally bounded — bursts queue up rather than overrun the
// registry. We still chunk explicitly below so the Promise closures don't
// pile up on a 1000-item catch-up batch (each waiting on the semaphore
// holds ~10KB of state; 1000 of them is a needless heap spike).
const PRE_RESOLVE_CHUNK_SIZE = 50;

// --- Load-aware pre-resolve shedding (2026-06-13) ---
// Under catch-up (deep scan queue) or active npm throttle (elevated brain
// level), prefetching up to CHANGES_LIMIT (1000) packuments per poll cycle
// through the SHARED registry rate budget starves the per-scan metadata fetches
// the workers actually need — and most prefetched items get spilled/shed before
// any worker scans them, so the fetch is wasted budget that also keeps npm
// 429-ing. When shedding, the batch skips the prefetch and enqueues items with
// tarballUrl=null; resolveTarballAndScan() lazily resolves ONLY the items a
// worker actually scans (the existing zero-scan-loss fallback path).
const PRE_RESOLVE_SHED_QUEUE = Math.max(0, parseInt(process.env.MUADDIB_PRERESOLVE_SHED_QUEUE, 10) || 2000);
const PRE_RESOLVE_SHED_LEVEL = Math.max(1, parseInt(process.env.MUADDIB_PRERESOLVE_SHED_LEVEL, 10) || 3);

function preResolveShouldShed(scanQueue) {
  // Kill-switch read live so it can be flipped via the systemd EnvironmentFile
  // + restart without a code change/rebuild.
  if (process.env.MUADDIB_PRERESOLVE_NO_SHED === '1') return false;
  if (scanQueue && scanQueue.length > PRE_RESOLVE_SHED_QUEUE) return true;
  try {
    // Lazy-require so the brain accessor is stubbable in tests (a top-level
    // destructure captures a frozen reference) and to dodge load-order cycles.
    // require() is cached — negligible on this per-chunk check.
    const { getBrainState, DEFAULT_HOST } = require('../shared/http-limiter.js');
    const brain = getBrainState(DEFAULT_HOST);
    if (brain && (brain.level || 0) >= PRE_RESOLVE_SHED_LEVEL) return true;
  } catch { /* observability seam — must never block ingestion */ }
  return false;
}

// If a scanQueue is provided, items are pushed onto it as soon as their chunk
// finishes resolution — so a crash mid-batch only loses the current chunk's
// in-flight work, not all the chunks that already completed. When scanQueue
// is omitted (unit tests, lib usage), items are only mutated in place and the
// caller decides when to push.
// Burst threshold for the capture-at-publish prefetch trigger. Mirrors
// BURST_PREALERT_MIN_VERSIONS (queue.js:212) and reads the SAME env var so ops tunes
// one knob. Per-name version count in the recent-publish window.
const BURST_MIN_VERSIONS_PREFETCH = (() => {
  const n = parseInt(process.env.MUADDIB_BURST_MIN_VERSIONS, 10);
  return Number.isFinite(n) && n >= 2 ? n : 10;
})();

// A prerelease publish (1.2.0-rc.1, 2.0.0-beta, ...-dev) is EXPECTED to differ
// from dist-tags.latest: npm semver resolution (^/~/x.y ranges) never selects a
// prerelease unless it is requested explicitly, so an account-takeover that wants
// victims to auto-resolve to the malicious version cannot use one. Excluding
// prereleases from the ATO *prefetch* signal drops the dominant false positive
// (CI/dev/rc/beta churn — ~17% of npm publishes per the 2026-06-28 backtest, which
// would otherwise balloon the bounded tarball cache) WITHOUT weakening the
// release-version ATO catch (Leo Platform: malicious leo-sdk@6.0.19, a plain
// release, still fires). Prefetch-only: queue.js keeps its own (more inclusive)
// atoSignal for fast-track / anti-eviction, and this never touches scoring.
function isPrereleaseVersion(v) {
  // semver: the prerelease lives after '-' in the version core, before any '+'
  // build metadata. Strip build metadata first so '1.0.0+build-7' is NOT flagged.
  return /-/.test(String(v == null ? '' : v).split('+')[0]);
}

async function preResolveNpmBatch(items, stats, scanQueue) {
  if (!items || items.length === 0) return;
  const start = Date.now();
  let resolved = 0;
  let alreadyResolved = 0;
  let failed = 0;
  let shed = 0;
  for (let i = 0; i < items.length; i += PRE_RESOLVE_CHUNK_SIZE) {
    const chunk = items.slice(i, i + PRE_RESOLVE_CHUNK_SIZE);
    if (preResolveShouldShed(scanQueue)) {
      // Load-aware shed: skip the packument prefetch; enqueue as-is so workers
      // lazy-resolve ONLY what they actually scan (resolveTarballAndScan handles
      // tarballUrl=null — zero scan loss). Re-checked per chunk so prefetch
      // resumes mid-batch the moment the queue drains below the threshold.
      shed += chunk.length;
      if (scanQueue) { for (const item of chunk) enqueueScan(scanQueue, item, stats); }
      continue;
    }
    await Promise.all(chunk.map(async (item) => {
      if (item.tarballUrl) { alreadyResolved++; return; }
      try {
        // Stage 2.1 — fetch downloads in parallel with the packument. The
        // downloads endpoint (api.npmjs.org) is not on the registry semaphore
        // and has its own internal cache, so this is effectively free in the
        // warm-cache case and adds at most one parallel HTTP otherwise.
        const [npmInfo, weeklyDownloads] = await Promise.all([
          getNpmLatestTarball(item.name),
          getWeeklyDownloads(item.name).catch(() => null)
        ]);
        if (npmInfo && npmInfo.tarball) {
          item.tarballUrl = npmInfo.tarball;
          if (!item.version) item.version = npmInfo.version || '';
          if (!item.unpackedSize) item.unpackedSize = npmInfo.unpackedSize || 0;
          if (!item.registryScripts) item.registryScripts = npmInfo.scripts || null;
          // weekly_downloads is best-effort. getWeeklyDownloads returns -1 on
          // failure; normalize that to null so triageRisk treats it as missing
          // (rather than silently biasing the reputation factor toward "suspect").
          npmInfo.weekly_downloads = (typeof weeklyDownloads === 'number' && weeklyDownloads >= 0)
            ? weeklyDownloads : null;
          // Stash full packument-derived metadata for resolveTarballAndScan so
          // the worker can run ATO-signature, burst-extras, and fast-track logic
          // without a second registry call. Stage 2.1 enriches this with
          // age_days / version_count (from getNpmLatestTarball) and
          // weekly_downloads (from getWeeklyDownloads) so the triage block in
          // queue.js can read meta directly without re-fetching.
          item._npmInfo = npmInfo;
          // Capture-at-publish trigger for the fast-takedown class (Leo Platform / Miasma,
          // June 2026). ATO (published version != dist-tags.latest) and per-name burst are
          // only knowable from the registry data fetched here, so the name-only
          // evaluateCacheTrigger at ingestion (change.doc is null post-2025) cannot set them.
          // Feed them in now so the burst/ATO subset is prefetched too — only when no
          // higher-priority (ioc/typosquat) trigger already fired. queue.js still computes
          // the same signals later for scan-queue protection + extras enqueue (idempotent).
          if (!item._cacheTrigger) {
            const atoSignal = !!(npmInfo.latestTagVersion && item.version &&
              item.version !== npmInfo.latestTagVersion &&
              !isPrereleaseVersion(item.version));
            const burstCount = Number.isFinite(npmInfo.recentWindowCount)
              ? npmInfo.recentWindowCount
              : ((Array.isArray(npmInfo.recentVersions) ? npmInfo.recentVersions.length : 0) + 1);
            const isBurst = burstCount >= BURST_MIN_VERSIONS_PREFETCH;
            if (atoSignal || isBurst) {
              const trig = evaluateCacheTrigger(item.name, null, null, { atoSignal, isBurst });
              if (trig.shouldCache) item._cacheTrigger = trig;
            }
          }
          resolved++;
        } else {
          failed++;
        }
      } catch {
        // Silent: worker will retry via lazy resolution. Logging here would
        // double-count errors that the worker already surfaces.
        failed++;
      }
    }));
    // Crash resilience: surface this chunk to the queue now, before the next
    // chunk starts. If the process dies between chunks we still keep the work
    // already done. Items keep their original order because chunks complete
    // sequentially.
    if (scanQueue) {
      for (const item of chunk) enqueueScan(scanQueue, item, stats);
    }
  }
  if (stats) {
    stats.npmPreResolved = (stats.npmPreResolved || 0) + resolved;
    stats.npmPreResolveFailed = (stats.npmPreResolveFailed || 0) + failed;
    if (shed) stats.npmPreResolveShed = (stats.npmPreResolveShed || 0) + shed;
  }
  if (items.length >= 5) {
    const elapsed = Date.now() - start;
    const shedNote = shed ? `, ${shed} shed (load-aware)` : '';
    console.log(`[MONITOR] PRE-RESOLVE npm: ${resolved}/${items.length} in ${elapsed}ms (${failed} → lazy fallback${alreadyResolved ? `, ${alreadyResolved} already resolved` : ''}${shedNote})`);
  }
}

async function preResolvePyPIBatch(items, stats, scanQueue) {
  if (!items || items.length === 0) return;
  const start = Date.now();
  let resolved = 0;
  let alreadyResolved = 0;
  let failed = 0;
  let shed = 0;
  for (let i = 0; i < items.length; i += PRE_RESOLVE_CHUNK_SIZE) {
    const chunk = items.slice(i, i + PRE_RESOLVE_CHUNK_SIZE);
    if (preResolveShouldShed(scanQueue)) {
      // Load-aware shed (shared gate): queue-depth dominates here; the prefetched
      // PyPI metadata would mostly be for items shed before any worker scans them.
      // Enqueue as-is — resolveTarballAndScan lazily resolves PyPI URLs too.
      shed += chunk.length;
      if (scanQueue) { for (const item of chunk) enqueueScan(scanQueue, item, stats); }
      continue;
    }
    await Promise.all(chunk.map(async (item) => {
      if (item.tarballUrl) { alreadyResolved++; return; }
      try {
        const pypiInfo = await getPyPITarballUrl(item.name, item.version || '');
        if (pypiInfo && pypiInfo.url) {
          item.tarballUrl = pypiInfo.url;
          if (!item.version && pypiInfo.version) item.version = pypiInfo.version;
          // Stage 2 triage signals: stash age_days + version_count for
          // triageRisk() to read in queue.js without a second registry call.
          item._pypiInfo = {
            age_days: pypiInfo.age_days,
            version_count: pypiInfo.version_count,
          };
          // First-publish parity with npm: derive the cache trigger + flag from the
          // version count (PyPI has no packument at ingest, so the count comes from
          // the registry fetch above). Feeds tarball retention, the scan-ledger
          // firstPublish field, and Phase 2b protected eviction. The first-publish
          // *sandbox* stays npm-only (runSandbox can't pip-install) — gated in queue.js.
          const trig = evaluateCacheTrigger(item.name, null, null, {
            ecosystem: 'pypi', versionCount: pypiInfo.version_count
          });
          item._cacheTrigger = trig.shouldCache ? trig : null;
          item.firstPublish = trig.reason === 'first_publish';
          resolved++;
        } else {
          failed++;
        }
      } catch {
        failed++;
      }
    }));
    if (scanQueue) {
      for (const item of chunk) enqueueScan(scanQueue, item, stats);
    }
  }
  if (stats) {
    stats.pypiPreResolved = (stats.pypiPreResolved || 0) + resolved;
    stats.pypiPreResolveFailed = (stats.pypiPreResolveFailed || 0) + failed;
    if (shed) stats.pypiPreResolveShed = (stats.pypiPreResolveShed || 0) + shed;
  }
  if (items.length >= 5) {
    const elapsed = Date.now() - start;
    const shedNote = shed ? `, ${shed} shed (load-aware)` : '';
    console.log(`[MONITOR] PRE-RESOLVE pypi: ${resolved}/${items.length} in ${elapsed}ms (${failed} → lazy fallback${alreadyResolved ? `, ${alreadyResolved} already resolved` : ''}${shedNote})`);
  }
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
      const infoBody = await _deps.httpsGet('https://replicate.npmjs.com/registry/', 10000);
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
      body = await _deps.httpsGet(url, 60000);
      data = JSON.parse(body);
    } catch (fetchErr) {
      // Invalid seq (stale from pre-migration CouchDB) or transient error — re-init to current seq
      console.warn(`[MONITOR] Changes stream fetch failed (${fetchErr.message}) — attempting seq re-init`);
      try {
        const reinitBody = await _deps.httpsGet('https://replicate.npmjs.com/registry/', 10000);
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
      const currentSeqBody = await _deps.httpsGet('https://replicate.npmjs.com/registry/', 10000);
      const currentSeqData = JSON.parse(currentSeqBody);
      const currentSeq = currentSeqData.update_seq;
      if (typeof currentSeq === 'number' && typeof data.last_seq === 'number' &&
          (currentSeq - data.last_seq) > CHANGES_CATCHUP_MAX) {
        const gap = currentSeq - lastSeq;
        console.warn(`[MONITOR] Changes stream too far behind (${gap} changes) — skipping to current`);
        stats.npmCatchupSkips = (stats.npmCatchupSkips || 0) + 1;
        stats.npmCatchupSkippedSeqs = (stats.npmCatchupSkippedSeqs || 0) + gap;
        // Catch-up gap = events we know happened but chose to skip. They must
        // appear in the coverage denominator so the daily report exposes the
        // gap as low coverage (and the catch-up line explains why).
        stats.npmPublishEventsSeen = (stats.npmPublishEventsSeen || 0) + gap;
        state.npmLastSeq = currentSeq;
        saveNpmSeq(currentSeq);
        return 0;
      }
    }

    // IMPORTANT: count raw events BEFORE filtering — otherwise the coverage
    // denominator is biased (matches "events we queued", not "events npm
    // emitted"). The filters below drop _design/self/@types/deleted, but
    // those were still real changes-stream events.
    stats.npmPublishEventsSeen = (stats.npmPublishEventsSeen || 0) + data.results.length;

    let queued = 0;
    // Collect items into a local batch so we can pre-resolve tarball URLs in
    // parallel before pushing to scanQueue. Items reach workers with metadata
    // already attached → workers skip the per-scan registry round-trip.
    const newItems = [];
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

      // Post-May 2025: change.doc is always null, so docMeta is null and tarballUrl
      // starts as null. preResolveNpmBatch below fills tarballUrl + metadata via
      // a parallel registry fetch so workers do not pay the round-trip per scan.
      newItems.push({
        name,
        version: docMeta ? docMeta.version : '',
        ecosystem: 'npm',
        tarballUrl: docMeta ? docMeta.tarball : null,
        unpackedSize: docMeta ? docMeta.unpackedSize : 0,
        registryScripts: docMeta ? docMeta.scripts : null,
        _cacheTrigger: cacheTrigger.shouldCache ? cacheTrigger : null,
        firstPublish: cacheTrigger.shouldCache && cacheTrigger.reason === 'first_publish',
        isIOCMatch: isKnownIOC
      });
      queued++;
    }

    // Parallel pre-resolution, pushed chunk by chunk for crash resilience.
    // Failures leave tarballUrl=null so the existing lazy-resolution path in
    // resolveTarballAndScan() picks up the slack — zero scan loss.
    await preResolveNpmBatch(newItems, stats, scanQueue);

    // Capture-at-publish (Miasma / Leo, June 2026): prefetch the high-value
    // subset's tarballs into the local cache NOW — before the (often backlogged)
    // scan downloads them — so we win the race against fast-takedown unpublishes.
    // Best-effort, bounded, non-blocking; the scan path consumes the cache
    // transparently (scanPackage cache-hit) or falls back to its own download.
    // See src/monitor/tarball-prefetch.js.
    try {
      require('./tarball-prefetch.js').schedulePrefetch(newItems, { stats });
    } catch (err) {
      console.warn(`[MONITOR] prefetch schedule failed: ${err.message}`);
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
      body = await _deps.httpsGet(url);
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

    // Mirror pollNpmChanges: count raw events BEFORE per-package filters
    // so the coverage denominator stays accurate when the changes stream
    // falls back to RSS.
    stats.npmPublishEventsSeen = (stats.npmPublishEventsSeen || 0) + newPackages.length;

    const newItems = [];
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

      newItems.push({
        name,
        version: '',
        ecosystem: 'npm',
        tarballUrl: null // pre-resolved below; lazy fallback preserved on failure
      });
    }

    // Parallel pre-resolution with per-chunk push → crash-resilient and saves
    // the worker's per-scan registry round-trip when it succeeds.
    await preResolveNpmBatch(newItems, stats, scanQueue);

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

// A normal 15-min poll is a few dozen events; a changelog_since_serial batch
// caps around ~50K. Anything this large means we are far behind — worth one
// extra changelog_last_serial call to measure the GLOBAL lag (see the global
// catch-up protection in pollPyPIChangelog).
const PYPI_CATCHUP_PROBE_MIN_EVENTS = 10000;

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

    // GLOBAL catch-up protection (2026-06-11 incident): the per-batch gap
    // below is bounded by one changelog_since_serial response (~50K events,
    // observed 33-43K), so it can NEVER exceed PYPI_CATCHUP_MAX (100K) — a
    // poller resumed from an ancient serial (a test-fixture serial leaked
    // into prod state) replayed YEARS of history, ~15K ancient packages per
    // poll, without ever tripping the skip. A full batch is the tell: probe
    // the registry's current serial and skip to it when the global lag is
    // beyond the cap. Costs one extra XML-RPC call only on full batches.
    if (events.length >= PYPI_CATCHUP_PROBE_MIN_EVENTS) {
      await acquireRegistrySlot();
      let curBody;
      try {
        curBody = await _deps.httpsPost(
          PYPI_XMLRPC_URL,
          buildXmlRpcCall('changelog_last_serial', []),
          { 'User-Agent': PYPI_USER_AGENT },
          10_000
        );
      } finally {
        releaseRegistrySlot();
      }
      const currentSerial = parseXmlRpcInt(curBody);
      if (currentSerial != null && currentSerial - lastSerial > PYPI_CATCHUP_MAX) {
        console.warn(`[MONITOR] PyPI changelog globally behind (${currentSerial - lastSerial} serials) — skipping to current ${currentSerial}`);
        stats.pypiCatchupSkips = (stats.pypiCatchupSkips || 0) + 1;
        stats.pypiCatchupSkippedEvents = (stats.pypiCatchupSkippedEvents || 0) + (currentSerial - lastSerial);
        state.pypiLastSerial = currentSerial;
        savePypiSerial(currentSerial);
        return 0;
      }
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
    const newItems = [];

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
          sendIOCPreAlert(ev.name, ev.version, 'pypi').catch(err => {
            console.error(`[MONITOR] IOC pre-alert webhook failed for ${ev.name}: ${err.message}`);
          });
        }
      } catch { /* IOC load failure is non-fatal */ }

      // Campaign pre-alert (mirror of the npm Layer 1b): fire on name-pattern
      // matches when the package isn't already a known IOC. Campaigns can target
      // PyPI too; matchCampaignPattern is a pure name match, ecosystem-agnostic.
      if (!isKnownIOC) {
        const campaign = matchCampaignPattern(ev.name);
        if (campaign) {
          console.log(`[MONITOR] CAMPAIGN PRE-ALERT (pypi): ${ev.name} — matches ${campaign}`);
          stats.campaignPreAlerts = (stats.campaignPreAlerts || 0) + 1;
          sendCampaignPreAlert(ev.name, campaign, 'pypi').catch(err => {
            console.error(`[MONITOR] campaign pre-alert webhook failed for ${ev.name}: ${err.message}`);
          });
        }
      }

      newItems.push({
        name: ev.name,
        version: ev.version,
        ecosystem: 'pypi',
        tarballUrl: null, // pre-resolved below; lazy fallback preserved
        isIOCMatch: isKnownIOC
      });
      queued++;
    }

    // Parallel pre-resolution with per-chunk push to scanQueue. Failures keep
    // tarballUrl=null so resolveTarballAndScan() falls back to lazy lookup.
    await preResolvePyPIBatch(newItems, stats, scanQueue);

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

    const newItems = [];
    for (const name of newPackages) {
      console.log(`[MONITOR] New pypi (rss): ${name}`);
      newItems.push({
        name,
        version: '',
        ecosystem: 'pypi',
        tarballUrl: null // pre-resolved below; lazy fallback preserved
      });
    }

    // pollPyPIRss does not have a stats arg today; pass {} so the helper still
    // runs but per-poll counters are dropped. The PRE-RESOLVE log line gives
    // operational visibility regardless. scanQueue is passed for per-chunk push.
    await preResolvePyPIBatch(newItems, {}, scanQueue);

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

  // Track consecutive poll failures. The backoff WAIT is applied by the
  // scheduler (daemon.js, via getPollBackoffMs()), NOT here: sleeping inside
  // poll() used to hold pollInProgress for up to POLL_MAX_BACKOFF (16min),
  // stalling ingestion and forcing the poll watchdog to be sized above the
  // backoff. poll() stays sleep-free so the watchdog bounds poll *work* only.
  if (npmCount === -1 && pypiCount === -1) {
    consecutivePollErrors++;
    if (consecutivePollErrors > 1) {
      console.log(`[MONITOR] Both registries failed (${consecutivePollErrors}x) — scheduler will back off ${(getPollBackoffMs() / 1000).toFixed(0)}s`);
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
  MAX_RESPONSE_BYTES,
  SOFT_BACKPRESSURE_THRESHOLD,

  // Mutable state
  getConsecutivePollErrors,
  setConsecutivePollErrors,
  getPollBackoffMs,

  // HTTP helpers
  httpsGet,
  httpsPost,
  getWeeklyDownloads,

  // Tarball URL helpers
  getNpmTarballUrl,
  getPyPITarballUrl,
  getNpmLatestTarball,
  preResolveNpmBatch,
  preResolvePyPIBatch,
  preResolveShouldShed,
  isPrereleaseVersion,

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
