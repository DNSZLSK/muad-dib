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
const { loadNpmSeq, saveNpmSeq, CHANGES_STREAM_URL, CHANGES_LIMIT, CHANGES_CATCHUP_MAX } = require('./state.js');
const { sendIOCPreAlert } = require('./webhook.js');
const { evaluateCacheTrigger, POPULAR_THRESHOLD, downloadsCache, DOWNLOADS_CACHE_TTL } = require('./classify.js');

const SELF_PACKAGE_NAME = require('../../package.json').name;

const POLL_INTERVAL = 60_000;
const POLL_MAX_BACKOFF = 960_000; // 16 minutes max backoff

// --- Mutable state ---
let consecutivePollErrors = 0;

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

// --- Trusted dependency diff check ---

const TRUSTED_DEP_AGE_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Check for new dependencies added to a TRUSTED (popular) package.
 * Detects supply-chain attacks where a compromised maintainer account adds a
 * malicious dependency in a patch bump (e.g., axios 1.14.0 → 1.14.1 adding
 * plain-crypto-js, 2026-03-30).
 *
 * @param {string} name - Package name
 * @param {string} newVersion - Newly published version
 * @returns {Array} Array of findings (empty if no new deps or on error)
 */
async function checkTrustedDepDiff(name, newVersion) {
  const findings = [];
  try {
    // Fetch packument to get version list and dependencies
    const body = await httpsGet(`https://registry.npmjs.org/${encodeURIComponent(name)}`, 10_000);
    const packument = JSON.parse(body);

    if (!packument.versions || !packument.time) return findings;

    // Sort versions by publish time (not semver — handles prereleases correctly)
    const timeMap = packument.time;
    const versionKeys = Object.keys(packument.versions)
      .filter(v => timeMap[v])
      .sort((a, b) => new Date(timeMap[a]) - new Date(timeMap[b]));

    const newIdx = versionKeys.indexOf(newVersion);
    if (newIdx <= 0) return findings; // First version or not found

    const prevVersion = versionKeys[newIdx - 1];

    const prevDeps = (packument.versions[prevVersion] && packument.versions[prevVersion].dependencies) || {};
    const newDeps = (packument.versions[newVersion] && packument.versions[newVersion].dependencies) || {};

    // Find newly added dependencies (name not present in previous version)
    const addedDeps = Object.keys(newDeps).filter(dep => !(dep in prevDeps));
    if (addedDeps.length === 0) return findings;

    console.log(`[MONITOR] TRUSTED dep diff: ${name} ${prevVersion} → ${newVersion}: +${addedDeps.length} new dep(s): ${addedDeps.join(', ')}`);

    for (const dep of addedDeps) {
      let ageMs = null;
      try {
        const depBody = await httpsGet(`https://registry.npmjs.org/${encodeURIComponent(dep)}`, 5_000);
        const depData = JSON.parse(depBody);
        const created = depData.time && depData.time.created;
        if (created) {
          ageMs = Date.now() - new Date(created).getTime();
        }
      } catch (err) {
        console.log(`[MONITOR] WARNING: could not check age of dependency ${dep}: ${err.message}`);
      }

      if (ageMs === null || ageMs < TRUSTED_DEP_AGE_THRESHOLD_MS) {
        // Unknown or < 7 days old — CRITICAL
        const ageDays = ageMs !== null ? Math.floor(ageMs / 86400000) : 'unknown';
        findings.push({
          type: 'trusted_new_unknown_dependency',
          severity: 'CRITICAL',
          confidence: ageMs === null ? 'medium' : 'high',
          file: 'package.json',
          message: `TRUSTED package ${name} added unknown dependency ${dep} (age: ${ageDays}d) in version ${prevVersion} → ${newVersion}`,
          rule_id: 'MUADDIB-TRUSTED-001',
          mitre: 'T1195.002',
          dep,
          depAgeDays: ageDays,
          prevVersion,
          newVersion
        });
      } else {
        // Known dependency (>= 7 days old) — HIGH
        const ageDays = Math.floor(ageMs / 86400000);
        findings.push({
          type: 'trusted_new_dependency',
          severity: 'HIGH',
          confidence: 'medium',
          file: 'package.json',
          message: `TRUSTED package ${name} added new dependency ${dep} (age: ${ageDays}d) in version ${prevVersion} → ${newVersion}`,
          rule_id: 'MUADDIB-TRUSTED-002',
          mitre: 'T1195.002',
          dep,
          depAgeDays: ageDays,
          prevVersion,
          newVersion
        });
      }
    }

    return findings;
  } catch (err) {
    // Graceful fallback — log warning, continue as TRUSTED
    console.log(`[MONITOR] WARNING: trusted dep diff check failed for ${name}@${newVersion}: ${err.message}`);
    return findings;
  }
}

// --- Tarball URL helpers ---

function getNpmTarballUrl(pkgData) {
  return (pkgData.dist && pkgData.dist.tarball) || null;
}

async function getPyPITarballUrl(packageName) {
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
  const body = await httpsGet(url);
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from PyPI for ${packageName}: ${e.message}`);
  }
  const version = (data.info && data.info.version) || '';
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

/**
 * Layer 2: Extract the latest version's tarball URL from a CouchDB changes document
 * (when using include_docs=true). Eliminates the separate registry roundtrip
 * that can 404 if the package is unpublished between detection and scan.
 *
 * @param {Object} doc - CouchDB document (change.doc)
 * @returns {{ version: string, tarball: string|null, unpackedSize: number, scripts: Object }|null}
 */
function extractTarballFromDoc(doc) {
  try {
    if (!doc || !doc.versions || !doc['dist-tags']) return null;

    const latestTag = doc['dist-tags'].latest;
    if (!latestTag) return null;

    const versionData = doc.versions[latestTag];
    if (!versionData) return null;

    const tarball = (versionData.dist && versionData.dist.tarball) || null;
    const unpackedSize = (versionData.dist && versionData.dist.unpackedSize) || 0;
    const version = versionData.version || latestTag;
    const scripts = versionData.scripts || {};

    return { version, tarball, unpackedSize, scripts };
  } catch {
    return null; // Parse failure -> fallback to lazy resolution
  }
}

/**
 * Fetch latest version metadata for an npm package.
 * Returns { version, tarball } or null on failure.
 */
async function getNpmLatestTarball(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
  await acquireRegistrySlot();
  let body;
  try {
    body = await httpsGet(url);
  } finally {
    releaseRegistrySlot();
  }
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    throw new Error(`Invalid JSON from npm registry for ${packageName}: ${e.message}`);
  }
  const version = data.version || '';
  const tarball = (data.dist && data.dist.tarball) || null;
  const unpackedSize = (data.dist && data.dist.unpackedSize) || 0;
  const scripts = (data.scripts) || {};
  return { version, tarball, unpackedSize, scripts };
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
        console.warn(`[MONITOR] Changes stream too far behind (${currentSeq - lastSeq} changes) — skipping to current`);
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

      // Layer 2: Extract tarball URL from CouchDB doc (eliminates lazy resolution 404 race)
      const docMeta = change.doc ? extractTarballFromDoc(change.doc) : null;

      // Layer 3: Evaluate if this package should be cached
      const cacheTrigger = evaluateCacheTrigger(name, docMeta, change.doc || null);

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

    // Persist new seq
    if (data.last_seq != null) {
      state.npmLastSeq = data.last_seq;
      saveNpmSeq(data.last_seq);
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
      try {
        const iocs = loadCachedIOCs();
        const isKnownIOC = iocs.wildcardPackages && iocs.wildcardPackages.has(name);
        if (isKnownIOC) {
          console.log(`[MONITOR] IOC PRE-ALERT: ${name} — known malicious package detected via RSS`);
          stats.iocPreAlerts = (stats.iocPreAlerts || 0) + 1;
          sendIOCPreAlert(name).catch(err => {
            console.error(`[MONITOR] IOC pre-alert webhook failed for ${name}: ${err.message}`);
          });
        }
      } catch { /* IOC load failure is non-fatal */ }

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

/**
 * Poll PyPI RSS feed for new packages.
 *
 * @param {Object} state - Monitor state object (pypiLastPackage)
 * @param {Array} scanQueue - Mutable scan queue array
 */
async function pollPyPI(state, scanQueue) {
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
      console.log(`[MONITOR] New pypi: ${name}`);
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
    console.error(`[MONITOR] PyPI poll error: ${err.message}`);
    return -1;
  }
}

// --- Main poll orchestrator ---

/**
 * Poll all registries (npm + PyPI) and manage backoff on consecutive failures.
 *
 * @param {Object} state - Monitor state object
 * @param {Array} scanQueue - Mutable scan queue array
 * @param {Object} stats - Mutable stats object
 */
async function poll(state, scanQueue, stats) {
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  console.log(`[MONITOR] ${timestamp} — polling registries...`);

  const [npmCount, pypiCount] = await Promise.all([
    pollNpm(state, scanQueue, stats),
    pollPyPI(state, scanQueue)
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
  getWeeklyDownloads,
  checkTrustedDepDiff,
  TRUSTED_DEP_AGE_THRESHOLD_MS,

  // Tarball URL helpers
  getNpmTarballUrl,
  getPyPITarballUrl,
  getNpmLatestTarball,

  // RSS parsing
  parseNpmRss,
  parsePyPIRss,

  // CouchDB doc extraction
  extractTarballFromDoc,

  // Polling functions
  pollNpmChanges,
  pollNpmRss,
  pollNpm,
  pollPyPI,
  poll
};
