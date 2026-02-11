const REGISTRY_URL = 'https://registry.npmjs.org';
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week';
const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search';

const REQUEST_TIMEOUT = 10000; // 10 seconds
const MAX_RETRIES = 3;
const NPM_NAME_REGEX = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

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
  let lastError = null;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    let response;
    const { signal, cleanup } = createTimeoutSignal(REQUEST_TIMEOUT);
    try {
      response = await fetch(url, { signal });
    } catch (err) {
      cleanup();
      if (err.name === 'TimeoutError' || err.name === 'AbortError') return null;
      lastError = err;
      continue;
    }

    cleanup();

    // 404 = package doesn't exist
    if (response.status === 404) {
      // Drain response body to free resources
      try { await response.text(); } catch {}
      return null;
    }

    // 429 = rate limit, respect Retry-After header (capped at 30s)
    if (response.status === 429) {
      try { await response.text(); } catch {}
      const retryAfter = parseInt(response.headers.get('retry-after'), 10);
      const delay = Math.min(retryAfter && retryAfter > 0 ? retryAfter * 1000 : 2000, 30000);
      await new Promise(r => setTimeout(r, delay));
      continue;
    }

    if (!response.ok) {
      // Drain response body on errors
      try { await response.text(); } catch {}
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
  if (!NPM_NAME_REGEX.test(packageName)) return null;

  // 1. Registry metadata
  const registryUrl = REGISTRY_URL + '/' + encodeURIComponent(packageName);
  const meta = await fetchWithRetry(registryUrl);
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

  const readmeText = meta.readme || '';
  const hasReadme = readmeText.length > 100;

  const hasRepository = !!(latestMeta?.repository || meta.repository);

  // 2. Weekly downloads + author search (parallel)
  const downloadsUrl = DOWNLOADS_URL + '/' + encodeURIComponent(packageName);
  const authorUrl = maintainer
    ? SEARCH_URL + '?text=maintainer:' + encodeURIComponent(maintainer) + '&size=1'
    : null;

  const [downloadsData, authorData] = await Promise.all([
    fetchWithRetry(downloadsUrl),
    authorUrl ? fetchWithRetry(authorUrl) : Promise.resolve(null)
  ]);

  const weeklyDownloads = downloadsData?.downloads ?? 0;
  const authorPackageCount = authorData?.total ?? 0;

  return {
    created_at: createdAt,
    age_days: ageDays,
    weekly_downloads: weeklyDownloads,
    author_package_count: authorPackageCount,
    has_readme: hasReadme,
    has_repository: hasRepository
  };
}

module.exports = { getPackageMetadata };
