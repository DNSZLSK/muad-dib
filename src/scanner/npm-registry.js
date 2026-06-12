const { NPM_PACKAGE_REGEX } = require('../shared/constants.js');
const { debugLog } = require('../utils.js');
const { acquireRegistrySlot, releaseRegistrySlot, awaitRateToken, signal429, hostForUrl } = require('../shared/http-limiter.js');
const { computeAdvancedRegistrySignals } = require('../integrations/registry-signals.js');

const REGISTRY_URL = 'https://registry.npmjs.org';
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week';
const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search';

// Env-tunable; defaults preserve prior behavior except MAX_RETRIES (3 → 5) for more headroom
// under sustained 429s during a large evaluate burst.
const REQUEST_TIMEOUT = Math.max(1000, parseInt(process.env.MUADDIB_REGISTRY_TIMEOUT_MS, 10) || 10000); // 10s default
const MAX_RETRIES = Math.max(1, parseInt(process.env.MUADDIB_REGISTRY_RETRIES, 10) || 5);

/**
 * Create a timeout signal, with fallback for older Node versions.
 * Returns { signal, cleanup } — call cleanup() after fetch to prevent timer leaks.
 */
function createTimeoutSignal(ms) {
  if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
    return { signal: AbortSignal.timeout(ms), cleanup: () => {} };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cleanup: () => clearTimeout(timer) };
}

async function fetchWithRetry(url) {
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    // The caller's acquireRegistrySlot paid the rate token for the FIRST
    // attempt only. Every retry is a new network request and must pay its own
    // token — otherwise retries bypass the bucket entirely, and during a 429
    // backoff pause they keep hammering the registry the limiter is trying to
    // back away from (the token wait also parks the retry until the pause ends).
    if (attempt > 0) {
      let granted = true;
      try { ({ granted } = await awaitRateToken(hostForUrl(url))); } catch { /* limiter is best-effort */ }
      // Denied (deadline elapsed — deep backoff pause or blocked main): treat
      // as retries exhausted. A missing metadata enrichment beats hammering a
      // registry that is telling us to back off.
      if (!granted) return null;
    }
    let response;
    const { signal, cleanup } = createTimeoutSignal(REQUEST_TIMEOUT);
    try {
      response = await fetch(url, { signal });
    } catch {
      cleanup();
      // REG-001: Retry on timeout/abort instead of returning null immediately.
      // Jittered exponential backoff avoids synchronized retry storms across the
      // (up to MUADDIB_REGISTRY_CONCURRENCY) concurrent fetches.
      if (attempt < MAX_RETRIES - 1) {
        const backoff = Math.min(1000 * Math.pow(2, attempt), 8000);
        await new Promise(r => setTimeout(r, Math.round(backoff * (0.5 + Math.random() * 0.5))));
      }
      continue;
    }

    cleanup();

    // 404 = package doesn't exist
    if (response.status === 404) {
      // Drain response body to free resources
      try { await response.text(); } catch (e) { debugLog('response drain failed:', e.message); }
      return null;
    }

    // 429 = rate limit. Drain the SHARED token bucket so EVERY in-flight request
    // (not just this one) backs off together — fixes the thundering-herd 429 storm
    // that left ~17% of packages metadata-less in a local evaluate run. Then honor
    // Retry-After (capped at 30s) with jitter so retries don't re-synchronize.
    if (response.status === 429) {
      try { await response.text(); } catch (e) { debugLog('response drain failed:', e.message); }
      try { signal429(); } catch { /* limiter is best-effort */ }
      const retryAfter = parseInt(response.headers.get('retry-after'), 10);
      const base = Math.min(retryAfter && retryAfter > 0 ? retryAfter * 1000 : 2000, 30000);
      await new Promise(r => setTimeout(r, Math.round(base * (0.5 + Math.random() * 0.5))));
      continue;
    }

    if (!response.ok) {
      // Drain response body on errors
      try { await response.text(); } catch (e) { debugLog('response drain failed:', e.message); }
      return null;
    }

    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  // Don't throw — return null to prevent crashing the scan pipeline (REG-02)
  return null;
}

async function getPackageMetadata(packageName) {
  // Validate package name before building URL
  if (!NPM_PACKAGE_REGEX.test(packageName)) return null;

  // 1. Registry metadata — read from temporal-analysis cache if warm (monitor pipeline
  // pre-fetches metadata for temporal checks). Only reads the Map, never fires HTTP.
  // Falls back to own fetchWithRetry (with retries + 429 handling) on cache miss.
  let meta = null;
  try {
    const { _metadataCache, METADATA_CACHE_TTL } = require('../temporal-analysis.js');
    const cached = _metadataCache.get(packageName);
    if (cached && (Date.now() - cached.fetchedAt) < METADATA_CACHE_TTL) {
      meta = cached.data;
    }
  } catch {
    // temporal-analysis not available — fall through to fetchWithRetry
  }
  if (!meta) {
    const registryUrl = REGISTRY_URL + '/' + encodeURIComponent(packageName);
    await acquireRegistrySlot();
    try {
      meta = await fetchWithRetry(registryUrl);
    } finally {
      releaseRegistrySlot();
    }
  }
  if (!meta) return null;

  const createdAt = meta.time?.created || null;
  const ageDays = createdAt
    ? Math.floor((Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60 * 24))
    : null;

  // Extract maintainer name from latest version
  const latestVersion = meta['dist-tags']?.latest;
  const latestMeta = latestVersion ? meta.versions?.[latestVersion] : null;
  const maintainer = latestMeta?.maintainers?.[0]?.name
    || meta.maintainers?.[0]?.name
    || null;

  // F3 — extract ALL maintainer emails (latest version + top-level merged,
  // deduped) for unclaimed-domain MX check downstream.
  const maintainerEmails = (() => {
    const out = new Set();
    const sources = [
      ...(Array.isArray(latestMeta?.maintainers) ? latestMeta.maintainers : []),
      ...(Array.isArray(meta.maintainers) ? meta.maintainers : [])
    ];
    for (const m of sources) {
      const e = m && typeof m === 'object' ? m.email : null;
      if (typeof e === 'string' && e.includes('@')) out.add(e.toLowerCase().trim());
    }
    return Array.from(out);
  })();

  const readmeText = meta.readme || '';
  const hasReadme = readmeText.length > 100;

  const hasRepository = !!(latestMeta?.repository || meta.repository);

  // P3 (provenance): npm publish provenance / attestations (npm `--provenance`,
  // Sigstore-backed, GA since 2023) appear as `dist.attestations` on the version.
  // Presence on the live latest version is a trust signal (downweight, fewer FP);
  // a mature package whose latest version LOST the provenance that earlier versions
  // carried is a build-divergence / takeover signal (Ultralytics shape — upweight).
  const latestHasProvenance = !!(latestMeta?.dist?.attestations);
  let anyPriorHadProvenance = false;
  if (!latestHasProvenance && meta.versions) {
    for (const [v, vm] of Object.entries(meta.versions)) {
      if (v === latestVersion) continue;
      if (vm?.dist?.attestations) { anyPriorHadProvenance = true; break; }
    }
  }
  const provenanceRegressed = !latestHasProvenance && anyPriorHadProvenance;

  // 2. Weekly downloads + author search (parallel)
  const downloadsUrl = DOWNLOADS_URL + '/' + encodeURIComponent(packageName);
  const authorUrl = maintainer
    ? SEARCH_URL + '?text=maintainer:' + encodeURIComponent(maintainer) + '&size=1'
    : null;

  async function fetchAuthorWithSlot() {
    if (!authorUrl) return null;
    await acquireRegistrySlot();
    try { return await fetchWithRetry(authorUrl); }
    finally { releaseRegistrySlot(); }
  }

  const [downloadsData, authorData] = await Promise.all([
    fetchWithRetry(downloadsUrl),    // api.npmjs.org — no semaphore needed
    fetchAuthorWithSlot()            // registry.npmjs.org — semaphore protected
  ]);

  const weeklyDownloads = downloadsData?.downloads ?? 0;
  const authorPackageCount = authorData?.total ?? 0;
  const versionCount = meta.versions ? Object.keys(meta.versions).length : 0;
  const description = (typeof latestMeta?.description === 'string' ? latestMeta.description
    : (typeof meta.description === 'string' ? meta.description : ''));

  let advancedSignals = {};
  try {
    advancedSignals = computeAdvancedRegistrySignals(meta);
  } catch (err) {
    debugLog('[registry-signals] failed for ' + packageName + ': ' + err.message);
  }

  // FPR plan Chantier 3 : the delta multiplier needs the per-version publish
  // timeline to pick the 3 versions immediately preceding the scanned one.
  // We export it as a compact { version : ISO string } map so consumers don't
  // have to re-fetch the packument. Skip the meta-keys "created" / "modified"
  // - those are top-level package timestamps, not version timestamps.
  const versionTimes = {};
  if (meta.time && typeof meta.time === 'object') {
    for (const [k, v] of Object.entries(meta.time)) {
      if (k === 'created' || k === 'modified') continue;
      if (typeof v !== 'string') continue;
      versionTimes[k] = v;
    }
  }

  return {
    created_at: createdAt,
    age_days: ageDays,
    weekly_downloads: weeklyDownloads,
    author_package_count: authorPackageCount,
    has_readme: hasReadme,
    has_repository: hasRepository,
    version_count: versionCount,
    readme_size: readmeText.length,
    description,
    // FPR plan : the "live latest" version for the package, used by the mature
    // stable cap to fire only when the scanned version IS this one. Historical
    // / pinned-old / vendored versions bypass the cap so we don't mask attacks
    // captured in static fixtures (e.g. eslint-scope 3.7.2, chalk 5.6.1).
    latest_version: latestVersion || null,
    // P4 : full dist-tags map ({ latest, next, canary, ... }) so scoring can tell a
    // maintainer-controlled pre-release channel version (inherits partial reputation)
    // from a historical / pinned-old version (no reputation).
    dist_tags: (meta['dist-tags'] && typeof meta['dist-tags'] === 'object') ? meta['dist-tags'] : null,
    // F3 : list of maintainer email addresses (lowercased, unique) for DNS
    // MX / RDAP downstream checks. Empty array if no emails published.
    maintainer_emails: maintainerEmails,
    // C3 : per-version publish timestamps for delta-mode selectPriorVersions.
    time: versionTimes,
    // P3 : Sigstore-backed publish provenance on the live latest version, and
    // whether it regressed (earlier versions had it, latest does not).
    has_provenance: latestHasProvenance,
    provenance_regressed: provenanceRegressed,
    ...advancedSignals
  };
}

module.exports = { getPackageMetadata };
