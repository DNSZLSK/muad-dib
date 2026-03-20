const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const HOME_DATA_PATH = path.join(os.homedir(), '.muaddib', 'data');
const CACHE_IOC_FILE = path.join(HOME_DATA_PATH, 'iocs.json');
const LOCAL_IOC_FILE = path.join(__dirname, 'data/iocs.json');
const LOCAL_COMPACT_FILE = path.join(__dirname, 'data/iocs-compact.json');
const { loadYAMLIOCs } = require('./yaml-loader.js');

async function updateIOCs() {
  console.log('[MUADDIB] Updating IOCs (fast mode)...\n');

  // Step 1: Load compact IOCs shipped in package (~225K IOCs)
  let baseIOCs = { packages: [], pypi_packages: [], hashes: [], markers: [], files: [] };

  if (fs.existsSync(LOCAL_COMPACT_FILE)) {
    try {
      const compactData = JSON.parse(fs.readFileSync(LOCAL_COMPACT_FILE, 'utf8'));
      baseIOCs = expandCompactIOCs(compactData);
      console.log('[1/4] Compact IOCs: ' + baseIOCs.packages.length + ' npm + ' + (baseIOCs.pypi_packages || []).length + ' PyPI');
    } catch (e) {
      console.log('[1/4] Error loading compact IOCs: ' + e.message);
    }
  } else {
    console.log('[1/4] Compact IOCs not found (run "muaddib scrape" first for full data)');
  }

  // Step 2: Load YAML IOCs (builtin.yaml, packages.yaml, hashes.yaml)
  const yamlIOCs = loadYAMLIOCs();
  const yamlStandard = {
    packages: yamlIOCs.packages || [],
    pypi_packages: [],
    hashes: (yamlIOCs.hashes || []).map(function(h) { return h.sha256; }),
    markers: (yamlIOCs.markers || []).map(function(m) { return m.pattern; }),
    files: (yamlIOCs.files || []).map(function(f) { return f.name; })
  };
  mergeIOCs(baseIOCs, yamlStandard);
  console.log('[2/4] YAML IOCs: ' + yamlStandard.packages.length + ' packages, ' + yamlStandard.hashes.length + ' hashes');

  // Step 3: Download additional IOCs from GitHub (GenSecAI + DataDog — small files, fast)
  const { scrapeShaiHuludDetector, scrapeDatadogIOCs } = require('./scraper.js');
  console.log('[3/4] Downloading GitHub IOCs...');

  const [shaiHulud, datadog] = await Promise.all([
    scrapeShaiHuludDetector(),
    scrapeDatadogIOCs()
  ]);

  const githubIOCs = {
    packages: [].concat(shaiHulud.packages, datadog.packages),
    pypi_packages: [],
    hashes: [].concat(shaiHulud.hashes || [], datadog.hashes || []),
    markers: [],
    files: []
  };
  mergeIOCs(baseIOCs, githubIOCs);
  console.log('     +' + shaiHulud.packages.length + ' GenSecAI, +' + datadog.packages.length + ' DataDog');

  // Step 3b: Load existing cache IOCs (from bootstrap download or previous update)
  if (fs.existsSync(CACHE_IOC_FILE)) {
    try {
      const existingCache = JSON.parse(fs.readFileSync(CACHE_IOC_FILE, 'utf8'));
      const before = baseIOCs.packages.length;
      const beforePyPI = (baseIOCs.pypi_packages || []).length;
      mergeIOCs(baseIOCs, existingCache);
      const addedNpm = baseIOCs.packages.length - before;
      const addedPyPI = (baseIOCs.pypi_packages || []).length - beforePyPI;
      if (addedNpm > 0 || addedPyPI > 0) {
        console.log('     +' + addedNpm + ' npm, +' + addedPyPI + ' PyPI from existing cache');
      }
    } catch (e) {
      console.log('[WARN] Failed to load existing cache: ' + e.message);
    }
  }

  // Step 4: Merge and save to cache (~/.muaddib/data/ — persists across npm updates)
  if (!fs.existsSync(HOME_DATA_PATH)) {
    fs.mkdirSync(HOME_DATA_PATH, { recursive: true });
  }

  // Verify write permission before attempting save (CROSS-001)
  try {
    fs.accessSync(HOME_DATA_PATH, fs.constants.W_OK);
  } catch {
    console.log('[WARN] Cache directory is not writable: ' + HOME_DATA_PATH);
    console.log('[WARN] IOCs loaded in memory but not persisted to disk.');
    return { total: baseIOCs.packages.length, totalPyPI: (baseIOCs.pypi_packages || []).length };
  }

  baseIOCs.updated = new Date().toISOString();
  baseIOCs.sources = ['compact', 'yaml', 'shai-hulud-detector', 'datadog', 'cache'];

  // Clean internal dedup sets before serialization
  delete baseIOCs._pkgKeys;
  delete baseIOCs._pypiPkgKeys;
  delete baseIOCs._hashSet;
  delete baseIOCs._markerSet;
  delete baseIOCs._fileSet;

  // Atomic write: write to .tmp then rename (UP-001)
  // HMAC written BEFORE rename to prevent race condition (crash between rename and HMAC write)
  const tmpFile = CACHE_IOC_FILE + '.tmp';
  const jsonData = JSON.stringify(baseIOCs);
  fs.writeFileSync(tmpFile, jsonData);
  const hmac = generateIOCHMAC(jsonData);
  fs.writeFileSync(CACHE_IOC_FILE + '.hmac', hmac);
  fs.renameSync(tmpFile, CACHE_IOC_FILE);

  // Mark HMAC as initialized — future loads require HMAC presence
  const hmacMarker = path.join(HOME_DATA_PATH, '.hmac-initialized');
  if (!fs.existsSync(hmacMarker)) {
    try { fs.writeFileSync(hmacMarker, new Date().toISOString()); } catch {}
  }

  const totalNpm = baseIOCs.packages.length;
  const totalPyPI = (baseIOCs.pypi_packages || []).length;
  console.log('[4/4] Saved to cache: ' + CACHE_IOC_FILE);
  console.log('\n[OK] IOCs updated: ' + totalNpm + ' npm + ' + totalPyPI + ' PyPI packages');

  return { total: totalNpm, totalPyPI: totalPyPI };
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
    target._pypiPkgKeys = new Set((target.pypi_packages || []).map(p => p.name + '@' + p.version));
    target._hashSet = new Set(target.hashes);
    target._markerSet = new Set(target.markers);
    target._fileSet = new Set(target.files);
  }

  let added = 0;

  // Merge packages (npm)
  for (const pkg of source.packages || []) {
    const key = pkg.name + '@' + pkg.version;
    if (!target._pkgKeys.has(key)) {
      target.packages.push(pkg);
      target._pkgKeys.add(key);
      added++;
    }
  }

  // Merge pypi_packages
  if (!target.pypi_packages) target.pypi_packages = [];
  for (const pkg of source.pypi_packages || []) {
    const key = pkg.name + '@' + pkg.version;
    if (!target._pypiPkgKeys.has(key)) {
      target.pypi_packages.push(pkg);
      target._pypiPkgKeys.add(key);
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

// Cache to avoid reloading IOCs on each call
let cachedIOCsResult = null;
let cachedIOCsTime = 0;
const CACHE_TTL = 10000; // 10 seconds

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
    pypi_packages: [],
    hashes: yamlIOCs.hashes.map(function(h) { return h.sha256; }),
    markers: yamlIOCs.markers.map(function(m) { return m.pattern; }),
    files: yamlIOCs.files.map(function(f) { return f.name; })
  };

  // Priority 2: Local scraped IOCs (full enriched file)
  if (fs.existsSync(LOCAL_IOC_FILE)) {
    try {
      const localIOCs = JSON.parse(fs.readFileSync(LOCAL_IOC_FILE, 'utf8'));
      mergeIOCs(merged, localIOCs);
    } catch (e) {
      console.log('[WARN] Failed to load IOC database (iocs.json): ' + e.message);
    }
  } else if (fs.existsSync(LOCAL_COMPACT_FILE)) {
    // Priority 2b: Compact file (shipped in npm, lightweight)
    try {
      const compactData = JSON.parse(fs.readFileSync(LOCAL_COMPACT_FILE, 'utf8'));
      const expandedIOCs = expandCompactIOCs(compactData);
      mergeIOCs(merged, expandedIOCs);
    } catch (e) {
      console.log('[WARN] Failed to load compact IOC database: ' + e.message);
    }
  }

  // Priority 3: Cached IOCs (from previous update) — verify HMAC integrity
  if (fs.existsSync(CACHE_IOC_FILE)) {
    try {
      const cachedData = fs.readFileSync(CACHE_IOC_FILE, 'utf8');
      const hmacFile = CACHE_IOC_FILE + '.hmac';
      if (fs.existsSync(hmacFile)) {
        const storedHmac = fs.readFileSync(hmacFile, 'utf8').trim();
        if (!verifyIOCHMAC(cachedData, storedHmac)) {
          console.log('[WARN] IOC cache HMAC verification failed — possible tampering. Skipping cache.');
        } else {
          mergeIOCs(merged, JSON.parse(cachedData));
        }
      } else {
        // No HMAC file — check if HMAC was previously initialized
        const hmacMarker = path.join(HOME_DATA_PATH, '.hmac-initialized');
        if (fs.existsSync(hmacMarker)) {
          // HMAC was initialized before but .hmac file is missing → possible tampering
          console.log('[WARN] IOC cache HMAC file missing but was previously initialized — skipping cache.');
        } else {
          // First run or pre-HMAC version — load but warn
          mergeIOCs(merged, JSON.parse(cachedData));
        }
      }
    } catch (e) {
      console.log('[WARN] Failed to load cached IOCs: ' + e.message);
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
  // Map for npm packages: "name" -> [{ version, source, ... }]
  const packagesMap = new Map();
  // Set for wildcard packages (all versions malicious)
  const wildcardPackages = new Set();

  for (const pkg of iocs.packages) {
    // Sanitize: split comma-separated version strings into individual entries
    if (pkg.version && pkg.version.includes(',')) {
      const versions = pkg.version.split(',').map(v => v.trim()).filter(Boolean);
      for (const ver of versions) {
        const entry = Object.assign({}, pkg, { version: ver });
        if (ver === '*' && !NEVER_WILDCARD.has(pkg.name)) {
          wildcardPackages.add(pkg.name);
        }
        if (!packagesMap.has(pkg.name)) packagesMap.set(pkg.name, []);
        packagesMap.get(pkg.name).push(entry);
      }
      continue;
    }

    if (pkg.version === '*') {
      // Defense-in-depth: NEVER_WILDCARD packages must not be wildcarded
      if (!NEVER_WILDCARD.has(pkg.name)) {
        wildcardPackages.add(pkg.name);
      }
    }

    if (!packagesMap.has(pkg.name)) {
      packagesMap.set(pkg.name, []);
    }
    packagesMap.get(pkg.name).push(pkg);
  }

  // Map for PyPI packages: "name" -> [{ version, source, ... }]
  const pypiPackagesMap = new Map();
  const pypiWildcardPackages = new Set();

  for (const pkg of iocs.pypi_packages || []) {
    // Sanitize: split comma-separated version strings
    if (pkg.version && pkg.version.includes(',')) {
      const versions = pkg.version.split(',').map(v => v.trim()).filter(Boolean);
      for (const ver of versions) {
        const entry = Object.assign({}, pkg, { version: ver });
        if (ver === '*') pypiWildcardPackages.add(pkg.name);
        if (!pypiPackagesMap.has(pkg.name)) pypiPackagesMap.set(pkg.name, []);
        pypiPackagesMap.get(pkg.name).push(entry);
      }
      continue;
    }

    if (pkg.version === '*') {
      pypiWildcardPackages.add(pkg.name);
    }

    if (!pypiPackagesMap.has(pkg.name)) {
      pypiPackagesMap.set(pkg.name, []);
    }
    pypiPackagesMap.get(pkg.name).push(pkg);
  }

  // Set for hashes (O(1) lookup)
  const hashesSet = new Set(iocs.hashes);

  // Set for markers
  const markersSet = new Set(iocs.markers);

  // Set for suspicious files
  const filesSet = new Set(iocs.files);

  return {
    // Optimized structures (npm)
    packagesMap,
    wildcardPackages,
    // Optimized structures (PyPI)
    pypiPackagesMap,
    pypiWildcardPackages,
    // Shared
    hashesSet,
    markersSet,
    filesSet,
    // Original arrays for compatibility
    packages: iocs.packages,
    pypi_packages: iocs.pypi_packages || [],
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
// Legitimate packages with version-specific compromises only.
// These must never become wildcards (all-version flags) because only
// specific versions were malicious — flagging all versions is a false positive.
const NEVER_WILDCARD = new Set([
  'event-stream', 'ua-parser-js', 'coa', 'rc',
  'colors', 'faker', 'node-ipc',
  'posthog-node', 'posthog-js', 'ngx-bootstrap', '@asyncapi/specs'
]);

function generateCompactIOCs(fullIOCs) {
  const wildcards = [];
  const versioned = Object.create(null);
  const severityOverrides = Object.create(null);
  const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

  for (const p of fullIOCs.packages || []) {
    if (p.severity && p.severity !== 'critical') {
      if (DANGEROUS_KEYS.has(p.name) || DANGEROUS_KEYS.has(p.version)) continue;
      if (!severityOverrides[p.name]) severityOverrides[p.name] = Object.create(null);
      severityOverrides[p.name][p.version] = p.severity;
    }

    if (p.version === '*') {
      if (NEVER_WILDCARD.has(p.name)) {
        // Legitimate package — skip wildcard, treat as version-unknown
        continue;
      }
      wildcards.push(p.name);
    } else {
      if (!versioned[p.name]) versioned[p.name] = [];
      // Sanitize: split comma-separated version strings into individual entries
      if (p.version && p.version.includes(',')) {
        const parts = p.version.split(',').map(v => v.trim()).filter(Boolean);
        for (const v of parts) {
          if (!versioned[p.name].includes(v)) versioned[p.name].push(v);
        }
      } else {
        versioned[p.name].push(p.version);
      }
    }
  }

  // PyPI compact (same structure, separate keys)
  const pypiWildcards = [];
  const pypiVersioned = Object.create(null);

  for (const p of fullIOCs.pypi_packages || []) {
    if (p.version === '*') {
      pypiWildcards.push(p.name);
    } else {
      if (!pypiVersioned[p.name]) pypiVersioned[p.name] = [];
      pypiVersioned[p.name].push(p.version);
    }
  }

  const compact = {
    defaultSeverity: 'critical',
    wildcards: wildcards,
    versioned: versioned,
    pypi_wildcards: pypiWildcards,
    pypi_versioned: pypiVersioned,
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

  // Expand npm wildcards (deduplicate via Set, enforce NEVER_WILDCARD)
  const seenWildcards = new Set();
  for (const name of compact.wildcards || []) {
    if (seenWildcards.has(name)) continue;
    if (NEVER_WILDCARD.has(name)) continue; // Defense-in-depth: skip wildcards for legitimate packages
    seenWildcards.add(name);
    const severity = (overrides[name] && overrides[name]['*']) || defaultSev;
    packages.push({ name: name, version: '*', severity: severity });
  }

  // Expand npm versioned
  for (const name of Object.keys(compact.versioned || {})) {
    for (const version of compact.versioned[name]) {
      // Sanitize: split comma-separated version strings into individual entries
      if (version && version.includes(',')) {
        const parts = version.split(',').map(function(v) { return v.trim(); }).filter(Boolean);
        for (const v of parts) {
          const severity = (overrides[name] && overrides[name][v]) || defaultSev;
          packages.push({ name: name, version: v, severity: severity });
        }
      } else {
        const severity = (overrides[name] && overrides[name][version]) || defaultSev;
        packages.push({ name: name, version: version, severity: severity });
      }
    }
  }

  // Expand PyPI wildcards
  const pypiPackages = [];
  for (const name of compact.pypi_wildcards || []) {
    pypiPackages.push({ name: name, version: '*', severity: defaultSev });
  }

  // Expand PyPI versioned
  for (const name of Object.keys(compact.pypi_versioned || {})) {
    for (const version of compact.pypi_versioned[name]) {
      // Sanitize: split comma-separated version strings
      if (version && version.includes(',')) {
        const parts = version.split(',').map(function(v) { return v.trim(); }).filter(Boolean);
        for (const v of parts) {
          pypiPackages.push({ name: name, version: v, severity: defaultSev });
        }
      } else {
        pypiPackages.push({ name: name, version: version, severity: defaultSev });
      }
    }
  }

  return {
    packages: packages,
    pypi_packages: pypiPackages,
    hashes: compact.hashes || [],
    markers: compact.markers || [],
    files: compact.files || [],
    updated: compact.updated,
    sources: compact.sources
  };
}

function invalidateCache() {
  cachedIOCsResult = null;
  cachedIOCsTime = 0;
}

/**
 * Check IOC freshness based on cached file mtime.
 * Returns a warning string if IOCs are older than maxAgeDays, null otherwise.
 * @param {number} maxAgeDays - Maximum acceptable age in days (default: 30)
 * @returns {string|null} Warning message or null
 */
function checkIOCStaleness(maxAgeDays = 30) {
  const filesToCheck = [CACHE_IOC_FILE, LOCAL_IOC_FILE, LOCAL_COMPACT_FILE];
  let newestMtime = 0;

  for (const f of filesToCheck) {
    try {
      const stat = fs.statSync(f);
      if (stat.mtimeMs > newestMtime) newestMtime = stat.mtimeMs;
    } catch {
      // File doesn't exist — skip
    }
  }

  if (newestMtime === 0) return null; // No IOC files found — bootstrap will handle

  const ageDays = (Date.now() - newestMtime) / (1000 * 60 * 60 * 24);
  if (ageDays > maxAgeDays) {
    return `IOC database is ${Math.floor(ageDays)} days old (threshold: ${maxAgeDays}d). Run "muaddib update" for latest threat data.`;
  }
  return null;
}

// ============================================
// IOC INTEGRITY: HMAC-SHA256 signing/verification
// ============================================
// Key is derived from a stable machine-specific seed + hardcoded salt.
// This protects against local file tampering by unauthorized processes.
//
// RISK ACCEPTED (v2.5.14): Full cryptographic signing of IOC updates (e.g., Ed25519
// signatures verified against a pinned public key) was evaluated but not implemented.
// Current mitigations: HTTPS-only downloads + domain allowlist in src/shared/download.js
// + HMAC-SHA256 integrity for cached data. The HMAC key is machine-local, so it does
// not protect against a compromised upstream source — that risk is accepted given the
// cost/benefit trade-off and the existing HTTPS + domain pinning controls.
const IOC_HMAC_SALT = 'muaddib-ioc-integrity-v1';

function getIOCHMACKey() {
  // Derive key from salt + hostname (machine-specific but stable)
  const seed = IOC_HMAC_SALT + ':' + os.hostname();
  return crypto.createHash('sha256').update(seed).digest();
}

/**
 * Generate HMAC-SHA256 for IOC data string.
 * @param {string} data - JSON string of IOC data
 * @returns {string} Hex-encoded HMAC
 */
function generateIOCHMAC(data) {
  const key = getIOCHMACKey();
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Verify HMAC-SHA256 of IOC data.
 * @param {string} data - JSON string of IOC data
 * @param {string} hmac - Expected HMAC hex string
 * @returns {boolean} True if HMAC matches
 */
function verifyIOCHMAC(data, hmac) {
  if (!hmac || typeof hmac !== 'string') return false;
  const expected = generateIOCHMAC(data);
  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(hmac, 'hex'));
  } catch {
    return false;
  }
}

module.exports = { updateIOCs, loadCachedIOCs, invalidateCache, generateCompactIOCs, expandCompactIOCs, mergeIOCs, createOptimizedIOCs, generateIOCHMAC, verifyIOCHMAC, checkIOCStaleness, NEVER_WILDCARD };