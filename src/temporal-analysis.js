const https = require('https');

const REGISTRY_URL = 'https://registry.npmjs.org';
const TIMEOUT_MS = 10_000;
const MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50MB (some packages have lots of versions)

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
 * Fetch full package metadata from the npm registry.
 * @param {string} packageName - npm package name (scoped or unscoped)
 * @returns {Promise<object>} Full registry metadata (versions, time, maintainers, etc.)
 */
function fetchPackageMetadata(packageName) {
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
          resolve(JSON.parse(data));
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
  getLifecycleScripts,
  compareLifecycleScripts,
  getLatestVersions,
  detectSuddenLifecycleChange
};
