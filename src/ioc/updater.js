const fs = require('fs');
const path = require('path');
const https = require('https');

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const IOC_FILE = path.join(CACHE_PATH, 'iocs.json');
const { loadYAMLIOCs } = require('./yaml-loader.js');

const EXTERNAL_FEEDS = [
  {
    name: 'muaddib-community',
    url: 'https://raw.githubusercontent.com/DNSZLSK/muad-dib/master/data/iocs.json',
    parser: parseMuaddibFeed
  }
];

async function updateIOCs() {
  console.log('[MUADDIB] Mise a jour des IOCs...\n');

  if (!fs.existsSync(CACHE_PATH)) {
    fs.mkdirSync(CACHE_PATH, { recursive: true });
  }

  // Charger les IOCs depuis les fichiers YAML (incluant builtin.yaml)
  const yamlIOCs = loadYAMLIOCs();
  
  const iocs = {
    packages: [...yamlIOCs.packages],
    hashes: yamlIOCs.hashes.map(h => h.sha256),
    markers: yamlIOCs.markers.map(m => m.pattern),
    files: yamlIOCs.files.map(f => f.name)
  };

  for (const feed of EXTERNAL_FEEDS) {
    try {
      console.log(`[INFO] Telechargement depuis ${feed.name}...`);
      const data = await fetchUrl(feed.url);
      const externalIOCs = feed.parser(data);
      
      // Merge packages
      for (const pkg of externalIOCs.packages || []) {
        if (!iocs.packages.find(p => p.name === pkg.name && p.version === pkg.version)) {
          iocs.packages.push(pkg);
        }
      }
      
      // Merge hashes
      for (const hash of externalIOCs.hashes || []) {
        if (!iocs.hashes.includes(hash)) {
          iocs.hashes.push(hash);
        }
      }
      
      // Merge markers
      for (const marker of externalIOCs.markers || []) {
        if (!iocs.markers.includes(marker)) {
          iocs.markers.push(marker);
        }
      }
      
      // Merge files
      for (const file of externalIOCs.files || []) {
        if (!iocs.files.includes(file)) {
          iocs.files.push(file);
        }
      }
      
      console.log(`[OK] IOCs externes merges depuis ${feed.name}`);
    } catch (err) {
      console.log(`[WARN] Echec ${feed.name}: ${err.message}`);
    }
  }

  iocs.updated = new Date().toISOString();

  fs.writeFileSync(IOC_FILE, JSON.stringify(iocs, null, 2));
  console.log(`\n[OK] IOCs sauvegardes:`);
  console.log(`     - ${iocs.packages.length} packages malveillants`);
  console.log(`     - ${iocs.files.length} fichiers suspects`);
  console.log(`     - ${iocs.hashes.length} hashes connus`);
  console.log(`     - ${iocs.markers.length} marqueurs\n`);

  return iocs;
}

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        fetchUrl(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function parseMuaddibFeed(data) {
  try {
    return JSON.parse(data);
  } catch {
    return { packages: [], hashes: [], markers: [], files: [] };
  }
}

function loadCachedIOCs() {
  // Priorite 1 : IOCs YAML locaux
  const yamlIOCs = loadYAMLIOCs();
  
  // Priorite 2 : Cache telecharge
  let cachedIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    cachedIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  
  // Merge : YAML + Cache
  const merged = {
    packages: [...yamlIOCs.packages],
    hashes: yamlIOCs.hashes.map(h => h.sha256),
    markers: yamlIOCs.markers.map(m => m.pattern),
    files: yamlIOCs.files.map(f => f.name)
  };
  
  // Ajouter les IOCs du cache sans doublons
  for (const pkg of cachedIOCs.packages || []) {
    if (!merged.packages.find(p => p.name === pkg.name)) {
      merged.packages.push(pkg);
    }
  }
  
  for (const hash of cachedIOCs.hashes || []) {
    if (!merged.hashes.includes(hash)) {
      merged.hashes.push(hash);
    }
  }
  
  for (const marker of cachedIOCs.markers || []) {
    if (!merged.markers.includes(marker)) {
      merged.markers.push(marker);
    }
  }
  
  for (const file of cachedIOCs.files || []) {
    if (!merged.files.includes(file)) {
      merged.files.push(file);
    }
  }
  
  return merged;
}

module.exports = { updateIOCs, loadCachedIOCs };