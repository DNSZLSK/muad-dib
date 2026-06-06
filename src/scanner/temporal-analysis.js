const https = require('https');
const { acquireRegistrySlot, releaseRegistrySlot, resetLimiter, getActiveSemaphore, REGISTRY_SEMAPHORE_MAX } = require('../shared/http-limiter.js');

const REGISTRY_URL = 'https://registry.npmjs.org';
const TIMEOUT_MS = 10_000;
const MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50MB (some packages have lots of versions)

// Metadata cache: avoids duplicate HTTP requests when multiple temporal modules
// fetch the same package metadata within a short window (monitor pipeline).
// Entries with error=true are negative cache (shorter TTL) to avoid retry storms.
const _metadataCache = new Map(); // packageName → { data, fetchedAt, error? }
const _inflightRequests = new Map(); // packageName → Promise
const METADATA_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const NEGATIVE_CACHE_TTL = 60 * 1000; // 60 seconds for failed fetches
const METADATA_CACHE_MAX = 200;
// Heap-leak fix: how many of the newest versions keep their FULL body in the cached
// packument. Consumers (lifecycle/ast diff, maintainer-change) only diff the latest 2.
const META_KEEP_VERSIONS = Math.max(2, parseInt(process.env.MUADDIB_META_KEEP_VERSIONS, 10) || 3);

/**
 * Shrink a full npm packument to what _metadataCache consumers actually need, so the
 * cache never retains tens-of-MB packuments (packages with thousands of versions) —
 * the root cause of the monitor's old_space leak → OOM restarts.
 *
 * Kept: every root field (small), the FULL `time` map (publish timeline — required by
 * getLatestVersions + publish-anomaly), root `dist-tags`/`maintainers`, and the FULL
 * bodies of the newest META_KEEP_VERSIONS versions (+ dist-tags.latest). Older versions
 * are replaced by a truthy placeholder (1) so existence checks
 * (`if (!versions[v]) continue`) and totalVersions counts stay correct without the bulk.
 * The big optional blobs (`readme`, `_attachments`) are dropped.
 * @param {object} parsed - full registry packument
 * @returns {object} slimmed packument (safe drop-in for all current consumers)
 */
function projectPackument(parsed) {
  if (!parsed || typeof parsed !== 'object' || !parsed.versions || typeof parsed.versions !== 'object') {
    return parsed;
  }
  const versions = parsed.versions;
  const time = (parsed.time && typeof parsed.time === 'object') ? parsed.time : {};

  // Newest META_KEEP_VERSIONS versions by publish date (same ordering as getLatestVersions).
  const dated = [];
  for (const [v, t] of Object.entries(time)) {
    if (v === 'created' || v === 'modified') continue;
    if (!versions[v]) continue;
    dated.push([v, t]);
  }
  dated.sort((a, b) => new Date(b[1]) - new Date(a[1]));
  const keep = new Set(dated.slice(0, META_KEEP_VERSIONS).map(e => e[0]));
  const distTags = parsed['dist-tags'];
  if (distTags && distTags.latest && versions[distTags.latest]) keep.add(distTags.latest);

  const slimVersions = {};
  for (const v of Object.keys(versions)) {
    slimVersions[v] = keep.has(v) ? versions[v] : 1; // truthy placeholder for old versions
  }

  const slim = { ...parsed, versions: slimVersions };
  delete slim.readme;
  delete slim.readmeFilename;
  delete slim._attachments;
  return slim;
}

const LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
  'prepack',
  'postpack'
];

/**
 * Raw HTTP fetch — always hits the npm registry. Use fetchPackageMetadata() instead,
 * which adds caching, inflight dedup, and semaphore.
 * Acquires a shared HTTP semaphore slot before making the request.
 */
async function _fetchPackageMetadataImpl(packageName) {
  await acquireRegistrySlot();
  try {
    return await _fetchPackageMetadataHttp(packageName);
  } catch (err) {
    // Negative cache: store failure for 60s to prevent retry storms
    if (_metadataCache.size >= METADATA_CACHE_MAX) {
      const oldestKey = _metadataCache.keys().next().value;
      _metadataCache.delete(oldestKey);
    }
    _metadataCache.set(packageName, { data: null, error: true, fetchedAt: Date.now() });
    throw err;
  } finally {
    releaseRegistrySlot();
  }
}

/**
 * Low-level HTTP request to npm registry. No caching, no semaphore.
 */
function _fetchPackageMetadataHttp(packageName) {
  const encodedName = encodeURIComponent(packageName).replace('%40', '@');
  const url = `${REGISTRY_URL}/${encodedName}`;
  const urlObj = new URL(url);

  return new Promise((resolve, reject) => {
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/3.0',
        'Accept': 'application/json'
      }
    };

    const req = https.request(reqOptions, (res) => {
      if (res.statusCode === 404) {
        res.resume();
        reject(new Error(`Package not found: ${packageName}`));
        return;
      }

      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error(`Registry returned HTTP ${res.statusCode} for ${packageName}`));
        return;
      }

      let data = '';
      let dataSize = 0;
      let destroyed = false;

      res.on('data', chunk => {
        if (destroyed) return;
        dataSize += chunk.length;
        if (dataSize > MAX_RESPONSE_SIZE) {
          destroyed = true;
          res.destroy();
          reject(new Error(`Response exceeded maximum size for ${packageName}`));
          return;
        }
        data += chunk;
      });

      res.on('end', () => {
        if (destroyed) return;
        try {
          const parsed = JSON.parse(data);
          // Heap-leak fix: project to essentials BEFORE caching. A full packument can be
          // tens of MB (packages with thousands of versions); retaining it whole bloated
          // old_space → OOM restarts. Resolve the slim copy too so the full `parsed` is
          // freed immediately (consumers only need time + the latest few version bodies).
          const slim = projectPackument(parsed);
          // Store in cache on successful fetch
          if (_metadataCache.size >= METADATA_CACHE_MAX) {
            // Evict oldest entry
            const oldestKey = _metadataCache.keys().next().value;
            _metadataCache.delete(oldestKey);
          }
          _metadataCache.set(packageName, { data: slim, fetchedAt: Date.now() });
          resolve(slim);
        } catch (e) {
          reject(new Error(`Invalid JSON from registry for ${packageName}: ${e.message}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`Network error fetching ${packageName}: ${err.message}`));
    });

    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy();
      reject(new Error(`Timeout fetching metadata for ${packageName}`));
    });

    req.end();
  });
}

/**
 * Fetch full package metadata from the npm registry with caching, inflight dedup,
 * negative cache, and HTTP semaphore. Multiple callers requesting the same package
 * within 5 minutes share one HTTP request. Failed fetches are cached for 60s.
 * @param {string} packageName - npm package name (scoped or unscoped)
 * @returns {Promise<object>} Full registry metadata (versions, time, maintainers, etc.)
 */
function fetchPackageMetadata(packageName) {
  // Check cache first (TTL-based, positive + negative)
  const cached = _metadataCache.get(packageName);
  if (cached) {
    const ttl = cached.error ? NEGATIVE_CACHE_TTL : METADATA_CACHE_TTL;
    if ((Date.now() - cached.fetchedAt) < ttl) {
      if (cached.error) {
        return Promise.reject(new Error(`Negative cache hit for ${packageName} (failed ${Math.round((Date.now() - cached.fetchedAt) / 1000)}s ago)`));
      }
      return Promise.resolve(cached.data);
    }
  }

  // Dedup inflight requests — if the same package is already being fetched, reuse that Promise
  if (_inflightRequests.has(packageName)) {
    return _inflightRequests.get(packageName);
  }

  const promise = _fetchPackageMetadataImpl(packageName).finally(() => {
    _inflightRequests.delete(packageName);
  });
  _inflightRequests.set(packageName, promise);
  return promise;
}

/**
 * Clear the metadata cache and reset shared semaphore. Exported for tests and monitor reset.
 */
function clearMetadataCache() {
  _metadataCache.clear();
  _inflightRequests.clear();
  resetLimiter();
}

/**
 * Extract lifecycle scripts from a package.json object.
 * @param {object} packageJson - A package.json object (or a version entry from registry metadata)
 * @returns {object} Only the lifecycle scripts that are present, e.g. { postinstall: "node exploit.js" }
 */
function getLifecycleScripts(packageJson) {
  const scripts = packageJson && packageJson.scripts;
  if (!scripts || typeof scripts !== 'object') return {};

  const result = {};
  for (const name of LIFECYCLE_SCRIPTS) {
    if (typeof scripts[name] === 'string') {
      result[name] = scripts[name];
    }
  }
  return result;
}

/**
 * Compare lifecycle scripts between two versions of a package.
 * @param {string} versionA - The older version number (e.g. "1.2.0")
 * @param {string} versionB - The newer version number (e.g. "1.2.1")
 * @param {object} metadata - Full registry metadata from fetchPackageMetadata()
 * @returns {{ added: Array, removed: Array, modified: Array }}
 *   - added:    scripts present in versionB but not in versionA
 *   - removed:  scripts present in versionA but not in versionB
 *   - modified: scripts present in both but with different values
 */
function compareLifecycleScripts(versionA, versionB, metadata) {
  const versions = metadata && metadata.versions;
  if (!versions) {
    throw new Error('Invalid metadata: missing versions object');
  }

  const pkgA = versions[versionA];
  const pkgB = versions[versionB];

  if (!pkgA) throw new Error(`Version ${versionA} not found in metadata`);
  if (!pkgB) throw new Error(`Version ${versionB} not found in metadata`);

  const scriptsA = getLifecycleScripts(pkgA);
  const scriptsB = getLifecycleScripts(pkgB);

  const added = [];
  const removed = [];
  const modified = [];

  // Scripts in B but not in A → added
  // Scripts in both but different → modified
  for (const name of Object.keys(scriptsB)) {
    if (!(name in scriptsA)) {
      added.push({ script: name, value: scriptsB[name] });
    } else if (scriptsA[name] !== scriptsB[name]) {
      modified.push({ script: name, oldValue: scriptsA[name], newValue: scriptsB[name] });
    }
  }

  // Scripts in A but not in B → removed
  for (const name of Object.keys(scriptsA)) {
    if (!(name in scriptsB)) {
      removed.push({ script: name, value: scriptsA[name] });
    }
  }

  return { added, removed, modified };
}

const CRITICAL_SCRIPTS = ['preinstall', 'install', 'postinstall'];

/**
 * Get the N most recent versions of a package sorted by publish date.
 * @param {object} metadata - Full registry metadata from fetchPackageMetadata()
 * @param {number} count - Number of versions to return (default 2)
 * @returns {Array<{version: string, publishedAt: string}>} Most recent versions, newest first
 */
function getLatestVersions(metadata, count = 2) {
  const time = metadata && metadata.time;
  if (!time || typeof time !== 'object') return [];

  const versions = metadata.versions || {};
  const entries = [];
  for (const [version, publishedAt] of Object.entries(time)) {
    if (version === 'created' || version === 'modified') continue;
    if (!versions[version]) continue; // skip unpublished/yanked versions
    entries.push({ version, publishedAt });
  }

  entries.sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));
  return entries.slice(0, count);
}

/**
 * Detect sudden lifecycle script changes between the two most recent versions of an npm package.
 * @param {string} packageName - npm package name
 * @returns {Promise<object>} Detection result with suspicious flag, findings, and metadata
 */
async function detectSuddenLifecycleChange(packageName) {
  const metadata = await fetchPackageMetadata(packageName);
  const latest = getLatestVersions(metadata, 2);

  if (latest.length < 2) {
    return {
      packageName,
      latestVersion: latest.length > 0 ? latest[0].version : null,
      previousVersion: null,
      suspicious: false,
      findings: [],
      metadata: {
        latestPublishedAt: latest.length > 0 ? latest[0].publishedAt : null,
        previousPublishedAt: null,
        maintainers: metadata.maintainers || [],
        note: 'Package has fewer than 2 published versions'
      }
    };
  }

  const [newestEntry, previousEntry] = latest;
  const diff = compareLifecycleScripts(previousEntry.version, newestEntry.version, metadata);

  const findings = [];

  for (const item of diff.added) {
    findings.push({
      type: 'lifecycle_added',
      script: item.script,
      value: item.value,
      severity: CRITICAL_SCRIPTS.includes(item.script) ? 'CRITICAL' : 'HIGH'
    });
  }

  for (const item of diff.modified) {
    findings.push({
      type: 'lifecycle_modified',
      script: item.script,
      oldValue: item.oldValue,
      newValue: item.newValue,
      severity: CRITICAL_SCRIPTS.includes(item.script) ? 'CRITICAL' : 'HIGH'
    });
  }

  for (const item of diff.removed) {
    findings.push({
      type: 'lifecycle_removed',
      script: item.script,
      value: item.value,
      severity: 'LOW'
    });
  }

  return {
    packageName,
    latestVersion: newestEntry.version,
    previousVersion: previousEntry.version,
    suspicious: findings.length > 0,
    findings,
    metadata: {
      latestPublishedAt: newestEntry.publishedAt,
      previousPublishedAt: previousEntry.publishedAt,
      maintainers: metadata.maintainers || []
    }
  };
}

module.exports = {
  fetchPackageMetadata,
  clearMetadataCache,
  projectPackument,
  getLifecycleScripts,
  compareLifecycleScripts,
  getLatestVersions,
  detectSuddenLifecycleChange,
  // Exposed for tests only
  _metadataCache,
  _inflightRequests,
  METADATA_CACHE_TTL,
  METADATA_CACHE_MAX,
  NEGATIVE_CACHE_TTL,
  // Re-export shared semaphore for backward compat with existing tests
  _httpSemaphore: getActiveSemaphore(),
  HTTP_SEMAPHORE_MAX: REGISTRY_SEMAPHORE_MAX
};
