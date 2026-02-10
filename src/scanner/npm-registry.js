const REGISTRY_URL = 'https://registry.npmjs.org';
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week';
const SEARCH_URL = 'https://registry.npmjs.org/-/v1/search';

const REQUEST_TIMEOUT = 10000; // 10 seconds

async function fetchWithRetry(url) {
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(REQUEST_TIMEOUT) });
  } catch (err) {
    if (err.name === 'TimeoutError') return null;
    throw err;
  }

  // 404 = package doesn't exist
  if (response.status === 404) return null;

  // 429 = rate limit, retry once after 2s
  if (response.status === 429) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      response = await fetch(url, { signal: AbortSignal.timeout(REQUEST_TIMEOUT) });
    } catch {
      return null;
    }
    if (!response.ok) return null;
  }

  if (!response.ok) return null;
  return response.json();
}

async function getPackageMetadata(packageName) {
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
