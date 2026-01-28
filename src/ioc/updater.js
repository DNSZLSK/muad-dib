const fs = require('fs');
const path = require('path');
const https = require('https');

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const CACHE_IOC_FILE = path.join(CACHE_PATH, 'iocs.json');
const LOCAL_IOC_FILE = path.join(__dirname, 'data/iocs.json');
const { loadYAMLIOCs } = require('./yaml-loader.js');

// Remote feed - only used as fallback if local scrape doesn't exist
const REMOTE_FEED_URL = 'https://raw.githubusercontent.com/DNSZLSK/muad-dib/master/data/iocs.json';

async function updateIOCs() {
  console.log('[MUADDIB] Mise a jour des IOCs...\n');

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
      console.log('[WARN] Erreur lecture IOCs locaux: ' + e.message);
    }
  } else {
    console.log('[INFO] Pas d\'IOCs locaux (lancez "muaddib scrape" pour en generer)');
  }

  // Priority 3: Remote feed (fallback / additional source)
  let remoteCount = 0;
  try {
    console.log('[INFO] Telechargement depuis GitHub...');
    const remoteData = await fetchUrl(REMOTE_FEED_URL);
    const remoteIOCs = JSON.parse(remoteData);
    remoteCount = mergeIOCs(iocs, remoteIOCs);
    console.log('[INFO] Remote IOCs: +' + remoteCount + ' packages');
  } catch (e) {
    console.log('[WARN] Echec telechargement distant: ' + e.message);
    console.log('[INFO] Utilisation des IOCs locaux uniquement');
  }

  // Update metadata
  iocs.updated = new Date().toISOString();

  // Save to cache
  fs.writeFileSync(CACHE_IOC_FILE, JSON.stringify(iocs, null, 2));
  
  console.log('\n[OK] IOCs sauvegardes:');
  console.log('     - ' + iocs.packages.length + ' packages malveillants');
  console.log('     - ' + iocs.files.length + ' fichiers suspects');
  console.log('     - ' + iocs.hashes.length + ' hashes connus');
  console.log('     - ' + iocs.markers.length + ' marqueurs\n');

  return iocs;
}

/**
 * Merge source IOCs into target without duplicates
 * Returns number of packages added
 */
function mergeIOCs(target, source) {
  let added = 0;
  
  // Merge packages
  for (const pkg of source.packages || []) {
    const exists = target.packages.find(function(p) {
      return p.name === pkg.name && p.version === pkg.version;
    });
    if (!exists) {
      target.packages.push(pkg);
      added++;
    }
  }
  
  // Merge hashes
  for (const hash of source.hashes || []) {
    if (!target.hashes.includes(hash)) {
      target.hashes.push(hash);
    }
  }
  
  // Merge markers
  for (const marker of source.markers || []) {
    if (!target.markers.includes(marker)) {
      target.markers.push(marker);
    }
  }
  
  // Merge files
  for (const file of source.files || []) {
    if (!target.files.includes(file)) {
      target.files.push(file);
    }
  }
  
  return added;
}

function fetchUrl(url) {
  return new Promise(function(resolve, reject) {
    https.get(url, function(res) {
      // Handle redirects
      if (res.statusCode === 301 || res.statusCode === 302) {
        fetchUrl(res.headers.location).then(resolve).catch(reject);
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

// Cache pour eviter de recharger les IOCs a chaque appel
let cachedIOCsResult = null;
let cachedIOCsTime = 0;
const CACHE_TTL = 60000; // 1 minute

function loadCachedIOCs() {
  // Retourner le cache si encore valide
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

  // Priority 2: Local scraped IOCs
  if (fs.existsSync(LOCAL_IOC_FILE)) {
    try {
      const localIOCs = JSON.parse(fs.readFileSync(LOCAL_IOC_FILE, 'utf8'));
      mergeIOCs(merged, localIOCs);
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

  // Creer structures optimisees pour lookup O(1)
  const optimized = createOptimizedIOCs(merged);

  // Mettre en cache
  cachedIOCsResult = optimized;
  cachedIOCsTime = now;

  return optimized;
}

/**
 * Cree des structures optimisees pour recherche O(1)
 * @param {Object} iocs - IOCs bruts
 * @returns {Object} IOCs avec Map/Set pour lookup rapide
 */
function createOptimizedIOCs(iocs) {
  // Map pour les packages: "name" -> [{ version, source, ... }]
  const packagesMap = new Map();
  // Set pour les packages wildcard (toutes versions malveillantes)
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

  // Set pour les hashes (lookup O(1))
  const hashesSet = new Set(iocs.hashes);

  // Set pour les markers
  const markersSet = new Set(iocs.markers);

  // Set pour les fichiers suspects
  const filesSet = new Set(iocs.files);

  return {
    // Structures optimisees
    packagesMap,
    wildcardPackages,
    hashesSet,
    markersSet,
    filesSet,
    // Arrays originaux pour compatibilite
    packages: iocs.packages,
    hashes: iocs.hashes,
    markers: iocs.markers,
    files: iocs.files
  };
}

module.exports = { updateIOCs, loadCachedIOCs };