'use strict';

/**
 * PyPI registry metadata fetcher — mirror of `src/scanner/npm-registry.js`
 * for the PyPI ecosystem. Closes the npm/PyPI asymmetry on the metadata axis.
 *
 * Created v2.11.47 to enable PyPI-side maintainer/email/release-zero
 * detections (port of MAINTAINER-005/006/PKG-022 to PyPI).
 *
 * Architecture parity with npm-registry.js :
 *  - built-in fetch (no external dep)
 *  - 10s timeout, 3 retries with exponential backoff
 *  - 429 backoff respecting Retry-After
 *  - throttle via http-limiter.js semaphore (shared with npm — same MUAD'DIB
 *    self-DoS protection ; rate budget is global, ok since target hosts differ)
 *  - 5min in-process cache keyed by package name
 *  - returns null on any failure (never throws — pipeline safety)
 *  - gated upstream by `MUADDIB_NO_REGISTRY_FETCH === '1'` (same master switch)
 *
 * URL : https://pypi.org/pypi/<package>/json (canonical PEP 691 JSON API)
 */

const { debugLog } = require('../utils.js');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');

const PYPI_REGISTRY_URL = 'https://pypi.org/pypi';
const REQUEST_TIMEOUT = 10000; // 10 seconds
const MAX_RETRIES = 3;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes — mirror npm-registry

// PEP 503 normalized package name: lowercase letters / digits / `-` `_` `.`
// Case-insensitive on input, server normalizes.
const PYPI_PACKAGE_REGEX = /^[A-Za-z0-9_.-]{1,214}$/;

// In-process cache : Map<packageName, { fetchedAt: number, data: object | null }>
// Negative caching (data === null) is honored too — avoids repeat 404 hammering.
const _pypiMetadataCache = new Map();

// AbortSignal.timeout polyfill — mirror npm-registry.js
function createTimeoutSignal(ms) {
  if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
    return { signal: AbortSignal.timeout(ms), cleanup: () => {} };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cleanup: () => clearTimeout(timer) };
}

async function fetchWithRetry(url) {
  let lastError = null;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    let response;
    const { signal, cleanup } = createTimeoutSignal(REQUEST_TIMEOUT);
    try {
      response = await fetch(url, { signal });
    } catch (err) {
      cleanup();
      lastError = err;
      if (attempt < MAX_RETRIES - 1) {
        const backoff = Math.min(1000 * Math.pow(2, attempt), 8000);
        await new Promise(r => setTimeout(r, backoff));
      }
      continue;
    }
    cleanup();

    if (response.status === 404) {
      try { await response.text(); } catch (e) { debugLog('pypi-registry: response drain failed:', e.message); }
      return null;
    }

    if (response.status === 429) {
      try { await response.text(); } catch (e) { debugLog('pypi-registry: response drain failed:', e.message); }
      const retryAfter = parseInt(response.headers.get('retry-after'), 10);
      const delay = Math.min(retryAfter && retryAfter > 0 ? retryAfter * 1000 : 2000, 30000);
      await new Promise(r => setTimeout(r, delay));
      continue;
    }

    if (!response.ok) {
      try { await response.text(); } catch (e) { debugLog('pypi-registry: response drain failed:', e.message); }
      return null;
    }

    try {
      return await response.json();
    } catch {
      return null;
    }
  }
  if (lastError) debugLog('pypi-registry: retries exhausted for ' + url + ': ' + lastError.message);
  return null;
}

/**
 * Extract a deduped, lowercased list of maintainer emails from PyPI metadata.
 * PyPI distinguishes `author_email` and `maintainer_email` (top-level strings,
 * not arrays). Either or both may be present. Some packages list multiple
 * addresses separated by commas — split on those.
 */
function extractMaintainerEmails(infoBlock) {
  const out = new Set();
  if (!infoBlock || typeof infoBlock !== 'object') return [];
  for (const field of ['author_email', 'maintainer_email']) {
    const raw = infoBlock[field];
    if (typeof raw !== 'string' || !raw.includes('@')) continue;
    // Split on commas (PEP 621-style multi-author) and on "Name <email>" wrappers
    const parts = raw.split(',');
    for (const part of parts) {
      const m = part.match(/<([^>]+@[^>]+)>/) || part.match(/([^\s<>]+@[^\s<>]+)/);
      if (m && m[1].includes('@')) out.add(m[1].toLowerCase().trim());
    }
  }
  return Array.from(out);
}

/**
 * Extract per-version publish timestamps from PyPI metadata.
 * `releases` is an object keyed by version string, each value is an array of
 * file entries with `upload_time_iso_8601`. Use the earliest upload time per
 * version (a release may have multiple files for sdist + wheels).
 */
function extractReleaseTimes(releases) {
  if (!releases || typeof releases !== 'object') return {};
  const out = {};
  for (const [version, files] of Object.entries(releases)) {
    if (!Array.isArray(files) || files.length === 0) continue;
    let earliest = null;
    for (const f of files) {
      const t = typeof f === 'object' && f ? (f.upload_time_iso_8601 || f.upload_time) : null;
      if (typeof t !== 'string') continue;
      if (earliest === null || t < earliest) earliest = t;
    }
    if (earliest) out[version] = earliest;
  }
  return out;
}

/**
 * Fetch + parse PyPI registry metadata. Returns null on validation fail,
 * cache hit of a previous null, network fail, or 404.
 *
 * Cached for 5 minutes (positive AND negative results).
 *
 * @param {string} packageName
 * @returns {Promise<{
 *   created_at: string | null,
 *   latest_release_at: string | null,
 *   age_days: number | null,
 *   latest_version: string | null,
 *   version_count: number,
 *   maintainer_emails: string[],
 *   yanked: boolean,
 *   description: string,
 *   home_page: string | null,
 *   project_urls: object | null,
 *   releases: { [version: string]: string }
 * } | null>}
 */
async function getPyPIPackageMetadata(packageName) {
  if (typeof packageName !== 'string' || !PYPI_PACKAGE_REGEX.test(packageName)) return null;
  const normalized = packageName.toLowerCase();

  // Cache check (honors negative cache)
  const cached = _pypiMetadataCache.get(normalized);
  if (cached && (Date.now() - cached.fetchedAt) < CACHE_TTL) {
    return cached.data;
  }

  const url = PYPI_REGISTRY_URL + '/' + encodeURIComponent(packageName) + '/json';
  let raw;
  await acquireRegistrySlot('pypi.org');
  try {
    raw = await fetchWithRetry(url);
  } finally {
    releaseRegistrySlot('pypi.org');
  }

  if (!raw || typeof raw !== 'object') {
    _pypiMetadataCache.set(normalized, { fetchedAt: Date.now(), data: null });
    return null;
  }

  const info = raw.info || {};
  const releases = raw.releases || {};
  const releaseTimes = extractReleaseTimes(releases);

  // earliest + latest publish dates across all release-versions
  let createdAt = null;
  let latestReleaseAt = null;
  for (const t of Object.values(releaseTimes)) {
    if (createdAt === null || t < createdAt) createdAt = t;
    if (latestReleaseAt === null || t > latestReleaseAt) latestReleaseAt = t;
  }

  const ageDays = createdAt
    ? Math.floor((Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60 * 24))
    : null;

  // Latest version: prefer info.version, fallback to highest key in releases
  const latestVersion = (typeof info.version === 'string' && info.version) || null;

  // Yanked status of the latest version (PyPI sets a "yanked" boolean on each file).
  let yanked = false;
  if (latestVersion && Array.isArray(releases[latestVersion])) {
    yanked = releases[latestVersion].every(f => f && f.yanked === true);
  }

  // P3 (provenance): PEP 740 digital attestations (Trusted Publishing, supported
  // since Nov 2024) surface as a `provenance` field on a release file. Same dual
  // signal as npm: present on the latest version → trust (downweight); regressed
  // from earlier versions → build-divergence / takeover suspicion (upweight).
  let latestHasProvenance = false;
  if (latestVersion && Array.isArray(releases[latestVersion])) {
    latestHasProvenance = releases[latestVersion].some(f => f && f.provenance);
  }
  let anyPriorHadProvenance = false;
  if (!latestHasProvenance) {
    for (const [v, files] of Object.entries(releases)) {
      if (v === latestVersion || !Array.isArray(files)) continue;
      if (files.some(f => f && f.provenance)) { anyPriorHadProvenance = true; break; }
    }
  }

  const data = {
    created_at: createdAt,
    latest_release_at: latestReleaseAt,
    age_days: ageDays,
    latest_version: latestVersion,
    version_count: Object.keys(releaseTimes).length,
    maintainer_emails: extractMaintainerEmails(info),
    yanked,
    description: typeof info.summary === 'string' ? info.summary
      : (typeof info.description === 'string' ? info.description.slice(0, 1000) : ''),
    home_page: typeof info.home_page === 'string' && info.home_page ? info.home_page : null,
    project_urls: (info.project_urls && typeof info.project_urls === 'object') ? info.project_urls : null,
    releases: releaseTimes,
    has_provenance: latestHasProvenance,
    provenance_regressed: !latestHasProvenance && anyPriorHadProvenance
  };

  _pypiMetadataCache.set(normalized, { fetchedAt: Date.now(), data });
  return data;
}

module.exports = {
  getPyPIPackageMetadata,
  // Exposed for unit tests
  _internal: {
    PYPI_PACKAGE_REGEX,
    extractMaintainerEmails,
    extractReleaseTimes,
    fetchWithRetry,
    _pypiMetadataCache,
    _resetCache: () => _pypiMetadataCache.clear()
  }
};
