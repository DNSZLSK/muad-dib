const fs = require('fs');
const path = require('path');
const https = require('https');

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const CACHE_IOC_FILE = path.join(CACHE_PATH, 'iocs.json');
const LOCAL_IOC_FILE = path.join(__dirname, 'data/iocs.json');
const LOCAL_COMPACT_FILE = path.join(__dirname, 'data/iocs-compact.json');
const { loadYAMLIOCs } = require('./yaml-loader.js');

// Remote feed - only used as fallback if local scrape doesn't exist
const REMOTE_FEED_URL = 'https://raw.githubusercontent.com/DNSZLSK/muad-dib/master/data/iocs.json';

async function updateIOCs() {
  console.log('[MUADDIB] Updating IOCs...\n');

  if (!fs.existsSync(CACHE_PATH)) {
    fs.mkdirSync(CACHE_PATH, { recursive: true });
  }

  // Priority 1: YAML files (builtin.yaml, etc.)
  const yamlIOCs = loadYAMLIOCs();
  
  const iocs = {
    packages: [...yamlIOCs.packages],
    hashes: yamlIOCs.hashes.map(function(h) { return h.sha256; }),
    markers: yamlIOCs.markers.map(function(m) { return m.pattern; }),
    files: yamlIOCs.files.map(function(f) { return f.name; })
  };

  console.log('[INFO] YAML IOCs: ' + yamlIOCs.packages.length + ' packages');

  // Priority 2: Local scraped IOCs (from muaddib scrape)
  let localScrapedCount = 0;
  if (fs.existsSync(LOCAL_IOC_FILE)) {
    try {
      const localIOCs = JSON.parse(fs.readFileSync(LOCAL_IOC_FILE, 'utf8'));
      localScrapedCount = mergeIOCs(iocs, localIOCs);
      console.log('[INFO] Local scraped IOCs: +' + localScrapedCount + ' packages');
    } catch (e) {
      console.log('[WARN] Error reading local IOCs: ' + e.message);
    }
  } else {
    console.log('[INFO] No local IOCs (run "muaddib scrape" to generate them)');
  }

  // Priority 3: Remote feed (fallback / additional source)
  let remoteCount = 0;
  try {
    console.log('[INFO] Downloading from GitHub...');
    const remoteData = await fetchUrl(REMOTE_FEED_URL);
    const remoteIOCs = JSON.parse(remoteData);
    remoteCount = mergeIOCs(iocs, remoteIOCs);
    console.log('[INFO] Remote IOCs: +' + remoteCount + ' packages');
  } catch (e) {
    console.log('[WARN] Remote download failed: ' + e.message);
    console.log('[INFO] Using local IOCs only');
  }

  // Update metadata
  iocs.updated = new Date().toISOString();

  // Save enriched to cache
  fs.writeFileSync(CACHE_IOC_FILE, JSON.stringify(iocs, null, 2));

  // Also save compact version to cache
  const compactCachePath = path.join(CACHE_PATH, 'iocs-compact.json');
  const compactIOCs = generateCompactIOCs(iocs);
  fs.writeFileSync(compactCachePath, JSON.stringify(compactIOCs));

  console.log('\n[OK] IOCs saved:');
  console.log('     - ' + iocs.packages.length + ' malicious packages');
  console.log('     - ' + iocs.files.length + ' suspicious files');
  console.log('     - ' + iocs.hashes.length + ' known hashes');
  console.log('     - ' + iocs.markers.length + ' markers\n');

  return iocs;
}

/**
 * Merge source IOCs into target without duplicates.
 * Uses Sets for O(1) dedup. Lazily initializes _sets on target.
 * Returns number of packages added.
 */
function mergeIOCs(target, source) {
  // Lazily initialize dedup sets on the target object
  if (!target._pkgKeys) {
    target._pkgKeys = new Set(target.packages.map(p => p.name + '@' + p.version));
    target._hashSet = new Set(target.hashes);
    target._markerSet = new Set(target.markers);
    target._fileSet = new Set(target.files);
  }

  let added = 0;

  // Merge packages
  for (const pkg of source.packages || []) {
    const key = pkg.name + '@' + pkg.version;
    if (!target._pkgKeys.has(key)) {
      target.packages.push(pkg);
      target._pkgKeys.add(key);
      added++;
    }
  }

  // Merge hashes
  for (const hash of source.hashes || []) {
    if (!target._hashSet.has(hash)) {
      target.hashes.push(hash);
      target._hashSet.add(hash);
    }
  }

  // Merge markers
  for (const marker of source.markers || []) {
    if (!target._markerSet.has(marker)) {
      target.markers.push(marker);
      target._markerSet.add(marker);
    }
  }

  // Merge files
  for (const file of source.files || []) {
    if (!target._fileSet.has(file)) {
      target.files.push(file);
      target._fileSet.add(file);
    }
  }

  return added;
}

// Allowed redirect domains for fetchUrl (SSRF protection)
const ALLOWED_FETCH_DOMAINS = [
  'raw.githubusercontent.com',
  'github.com',
  'objects.githubusercontent.com'
];

function isAllowedFetchRedirect(redirectUrl, originalUrl) {
  try {
    // Handle relative URLs by resolving against original
    const resolved = new URL(redirectUrl, originalUrl);
    return ALLOWED_FETCH_DOMAINS.includes(resolved.hostname);
  } catch {
    return false;
  }
}

function fetchUrl(url, redirectCount = 0) {
  const MAX_REDIRECTS = 5;
  return new Promise(function(resolve, reject) {
    https.get(url, function(res) {
      // Handle redirects with limit and domain validation
      if (res.statusCode === 301 || res.statusCode === 302) {
        if (redirectCount >= MAX_REDIRECTS) {
          reject(new Error('Too many redirects'));
          return;
        }
        const redirectTarget = res.headers.location;
        if (!isAllowedFetchRedirect(redirectTarget, url)) {
          reject(new Error('Redirect to unauthorized domain: ' + redirectTarget));
          return;
        }
        // Resolve relative URLs against original
        const resolvedUrl = new URL(redirectTarget, url).href;
        fetchUrl(resolvedUrl, redirectCount + 1).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error('HTTP ' + res.statusCode));
        return;
      }
      let data = '';
      res.on('data', function(chunk) { data += chunk; });
      res.on('end', function() { resolve(data); });
    }).on('error', reject);
  });
}

// Cache to avoid reloading IOCs on each call
let cachedIOCsResult = null;
let cachedIOCsTime = 0;
const CACHE_TTL = 60000; // 1 minute

function loadCachedIOCs() {
  // Return cache if still valid
  const now = Date.now();
  if (cachedIOCsResult && (now - cachedIOCsTime) < CACHE_TTL) {
    return cachedIOCsResult;
  }

  // Priority 1: YAML IOCs
  const yamlIOCs = loadYAMLIOCs();

  const merged = {
    packages: [...yamlIOCs.packages],
    hashes: yamlIOCs.hashes.map(function(h) { return h.sha256; }),
    markers: yamlIOCs.markers.map(function(m) { return m.pattern; }),
    files: yamlIOCs.files.map(function(f) { return f.name; })
  };

  // Priority 2: Local scraped IOCs (full enriched file)
  if (fs.existsSync(LOCAL_IOC_FILE)) {
    try {
      const localIOCs = JSON.parse(fs.readFileSync(LOCAL_IOC_FILE, 'utf8'));
      mergeIOCs(merged, localIOCs);
    } catch {
      // Ignore errors
    }
  } else if (fs.existsSync(LOCAL_COMPACT_FILE)) {
    // Priority 2b: Compact file (shipped in npm, lightweight)
    try {
      const compactData = JSON.parse(fs.readFileSync(LOCAL_COMPACT_FILE, 'utf8'));
      const expandedIOCs = expandCompactIOCs(compactData);
      mergeIOCs(merged, expandedIOCs);
    } catch {
      // Ignore errors
    }
  }

  // Priority 3: Cached IOCs (from previous update)
  if (fs.existsSync(CACHE_IOC_FILE)) {
    try {
      const cachedIOCs = JSON.parse(fs.readFileSync(CACHE_IOC_FILE, 'utf8'));
      mergeIOCs(merged, cachedIOCs);
    } catch {
      // Ignore errors
    }
  }

  // Create optimized structures for O(1) lookup
  const optimized = createOptimizedIOCs(merged);

  // Store in cache
  cachedIOCsResult = optimized;
  cachedIOCsTime = now;

  return optimized;
}

/**
 * Creates optimized structures for O(1) lookup
 * @param {Object} iocs - Raw IOCs
 * @returns {Object} IOCs with Map/Set for fast lookup
 */
function createOptimizedIOCs(iocs) {
  // Map for packages: "name" -> [{ version, source, ... }]
  const packagesMap = new Map();
  // Set for wildcard packages (all versions malicious)
  const wildcardPackages = new Set();

  for (const pkg of iocs.packages) {
    if (pkg.version === '*') {
      wildcardPackages.add(pkg.name);
    }

    if (!packagesMap.has(pkg.name)) {
      packagesMap.set(pkg.name, []);
    }
    packagesMap.get(pkg.name).push(pkg);
  }

  // Set for hashes (O(1) lookup)
  const hashesSet = new Set(iocs.hashes);

  // Set for markers
  const markersSet = new Set(iocs.markers);

  // Set for suspicious files
  const filesSet = new Set(iocs.files);

  return {
    // Optimized structures
    packagesMap,
    wildcardPackages,
    hashesSet,
    markersSet,
    filesSet,
    // Original arrays for compatibility
    packages: iocs.packages,
    hashes: iocs.hashes,
    markers: iocs.markers,
    files: iocs.files
  };
}

/**
 * Generates a compact version of IOCs for shipping in npm.
 * Format: wildcards as name array, versioned as name->versions map.
 * ~5MB instead of ~112MB.
 * @param {Object} fullIOCs - Full IOCs object with packages array
 * @returns {Object} Compact IOCs
 */
function generateCompactIOCs(fullIOCs) {
  const wildcards = [];
  const versioned = {};
  const severityOverrides = {};

  for (const p of fullIOCs.packages || []) {
    // Track non-critical severities as overrides
    if (p.severity && p.severity !== 'critical') {
      if (!severityOverrides[p.name]) severityOverrides[p.name] = {};
      severityOverrides[p.name][p.version] = p.severity;
    }

    if (p.version === '*') {
      wildcards.push(p.name);
    } else {
      if (!versioned[p.name]) versioned[p.name] = [];
      versioned[p.name].push(p.version);
    }
  }

  const compact = {
    defaultSeverity: 'critical',
    wildcards: wildcards,
    versioned: versioned,
    hashes: fullIOCs.hashes || [],
    markers: fullIOCs.markers || [],
    files: fullIOCs.files || [],
    updated: fullIOCs.updated,
    sources: fullIOCs.sources
  };

  if (Object.keys(severityOverrides).length > 0) {
    compact.severityOverrides = severityOverrides;
  }

  return compact;
}

/**
 * Expands compact IOCs back to standard packages array format.
 * Used when loading the compact file for scanning.
 * @param {Object} compact - Compact IOCs from generateCompactIOCs
 * @returns {Object} Standard IOCs with packages array
 */
function expandCompactIOCs(compact) {
  const packages = [];
  const defaultSev = compact.defaultSeverity || 'critical';
  const overrides = compact.severityOverrides || {};

  // Expand wildcards
  for (const name of compact.wildcards || []) {
    const severity = (overrides[name] && overrides[name]['*']) || defaultSev;
    packages.push({ name: name, version: '*', severity: severity });
  }

  // Expand versioned
  for (const name of Object.keys(compact.versioned || {})) {
    for (const version of compact.versioned[name]) {
      const severity = (overrides[name] && overrides[name][version]) || defaultSev;
      packages.push({ name: name, version: version, severity: severity });
    }
  }

  return {
    packages: packages,
    hashes: compact.hashes || [],
    markers: compact.markers || [],
    files: compact.files || [],
    updated: compact.updated,
    sources: compact.sources
  };
}

module.exports = { updateIOCs, loadCachedIOCs, generateCompactIOCs, expandCompactIOCs };