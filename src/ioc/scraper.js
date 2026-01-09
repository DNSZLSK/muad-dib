const https = require('https');
const fs = require('fs');
const path = require('path');

const IOC_FILE = path.join(__dirname, '../../data/iocs.json');
const STATIC_IOCS_FILE = path.join(__dirname, '../../data/static-iocs.json');

function loadStaticIOCs() {
  try {
    if (fs.existsSync(STATIC_IOCS_FILE)) {
      return JSON.parse(fs.readFileSync(STATIC_IOCS_FILE, 'utf8'));
    }
  } catch (e) {
    console.log(`[WARN] Erreur chargement static-iocs.json: ${e.message}`);
  }
  return { socket: [], phylum: [], npmRemoved: [] };
}

async function fetchJSON(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/1.0',
        'Accept': 'application/json',
        ...options.headers
      }
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, data: null, raw: data, error: e.message });
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
    
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

async function fetchText(url) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/1.0'
      }
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({ status: res.statusCode, data: data });
      });
    });

    req.on('error', reject);
    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
    
    req.end();
  });
}

// ============================================
// SOURCE 1: Shai-Hulud 2.0 Detector (795+ packages)
// ============================================
async function scrapeShaiHuludDetector() {
  console.log('[SCRAPER] Shai-Hulud 2.0 Detector (795+ packages)...');
  const packages = [];
  
  try {
    const url = 'https://raw.githubusercontent.com/gensecaihq/Shai-Hulud-2.0-Detector/main/compromised-packages.json';
    const { status, data } = await fetchJSON(url);
    
    if (status === 200 && Array.isArray(data)) {
      for (const pkg of data) {
        packages.push({
          id: `SHAI-HULUD-${pkg.name || pkg.package}`,
          name: pkg.name || pkg.package,
          version: pkg.version || pkg.versions || '*',
          severity: 'critical',
          confidence: 'high',
          source: 'shai-hulud-detector',
          description: pkg.description || 'Compromised by Shai-Hulud 2.0 supply chain attack',
          references: ['https://github.com/gensecaihq/Shai-Hulud-2.0-Detector'],
          mitre: 'T1195.002'
        });
      }
    } else if (status === 200 && data && typeof data === 'object') {
      // Si c'est un objet avec des packages dedans
      const pkgList = data.packages || data.compromised || Object.values(data);
      for (const pkg of pkgList) {
        if (typeof pkg === 'string') {
          packages.push({
            id: `SHAI-HULUD-${pkg}`,
            name: pkg,
            version: '*',
            severity: 'critical',
            confidence: 'high',
            source: 'shai-hulud-detector',
            description: 'Compromised by Shai-Hulud 2.0 supply chain attack',
            references: ['https://github.com/gensecaihq/Shai-Hulud-2.0-Detector'],
            mitre: 'T1195.002'
          });
        } else if (pkg && pkg.name) {
          packages.push({
            id: `SHAI-HULUD-${pkg.name}`,
            name: pkg.name,
            version: pkg.version || '*',
            severity: 'critical',
            confidence: 'high',
            source: 'shai-hulud-detector',
            description: pkg.description || 'Compromised by Shai-Hulud 2.0 supply chain attack',
            references: ['https://github.com/gensecaihq/Shai-Hulud-2.0-Detector'],
            mitre: 'T1195.002'
          });
        }
      }
    }
    
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  } catch (e) {
    console.log(`[SCRAPER]   -> Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 2: Datadog IOCs (packages + hashes)
// ============================================
async function scrapeDatadogIOCs() {
  console.log('[SCRAPER] Datadog Security Labs IOCs...');
  const packages = [];
  const hashes = [];
  
  try {
    // Fetch packages CSV
    const csvUrl = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/npm_packages.csv';
    const csvResponse = await fetchText(csvUrl);
    
    if (csvResponse.status === 200 && csvResponse.data) {
      const lines = csvResponse.data.split('\n').filter(l => l.trim());
      // Skip header
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 1) {
          const name = parts[0].trim().replace(/"/g, '');
          const version = parts[1] ? parts[1].trim().replace(/"/g, '') : '*';
          if (name && name !== 'package' && name !== 'name') {
            packages.push({
              id: `DATADOG-${name}`,
              name: name,
              version: version || '*',
              severity: 'critical',
              confidence: 'high',
              source: 'datadog-ioc',
              description: 'Compromised package identified by Datadog Security Labs',
              references: ['https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/'],
              mitre: 'T1195.002'
            });
          }
        }
      }
    }
    
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
    
    // Fetch SHA256 hashes
    const hashUrl = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/sha256_hashes.txt';
    const hashResponse = await fetchText(hashUrl);
    
    if (hashResponse.status === 200 && hashResponse.data) {
      const lines = hashResponse.data.split('\n').filter(l => l.trim());
      for (const line of lines) {
        const hash = line.trim();
        if (hash && hash.length === 64 && /^[a-f0-9]+$/i.test(hash)) {
          hashes.push(hash.toLowerCase());
        }
      }
      console.log(`[SCRAPER]   -> ${hashes.length} hashes trouves`);
    }
  } catch (e) {
    console.log(`[SCRAPER]   -> Erreur: ${e.message}`);
  }
  
  return { packages, hashes };
}

// ============================================
// SOURCE 3: OSV.dev (Open Source Vulnerabilities)
// ============================================
async function scrapeOSV() {
  console.log('[SCRAPER] OSV.dev...');
  const packages = [];
  
  try {
    const queries = ['malware', 'malicious', 'supply chain'];
    for (const query of queries) {
      const { status, data } = await fetchJSON('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { 
          package: { ecosystem: 'npm' },
          query: query
        }
      });
      if (status === 200 && data?.vulns) {
        for (const vuln of data.vulns) {
          for (const affected of vuln.affected || []) {
            if (affected.package?.ecosystem === 'npm') {
              packages.push({
                id: vuln.id,
                name: affected.package.name,
                version: '*',
                severity: 'high',
                confidence: 'high',
                source: 'osv',
                description: (vuln.summary || vuln.details || '').slice(0, 200),
                references: (vuln.references || []).map(r => r.url).slice(0, 2),
                mitre: 'T1195.002'
              });
            }
          }
        }
      }
    }
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  } catch (err) {
    console.log(`[SCRAPER]   -> Erreur: ${err.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 4: Socket.dev reports (from static file)
// ============================================
async function scrapeSocketReports() {
  console.log('[SCRAPER] Socket.dev reports...');
  const packages = [];
  const staticIOCs = loadStaticIOCs();
  
  for (const pkg of staticIOCs.socket || []) {
    packages.push({
      id: `SOCKET-${pkg.name}`,
      name: pkg.name,
      version: '*',
      severity: pkg.severity,
      confidence: 'high',
      source: pkg.source,
      description: 'Malicious package reported by Socket.dev',
      references: ['https://socket.dev/npm/package/' + pkg.name],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}

// ============================================
// SOURCE 5: Phylum Research (from static file)
// ============================================
async function scrapePhylum() {
  console.log('[SCRAPER] Phylum Research...');
  const packages = [];
  const staticIOCs = loadStaticIOCs();
  
  for (const pkg of staticIOCs.phylum || []) {
    packages.push({
      id: `PHYLUM-${pkg.name}`,
      name: pkg.name,
      version: '*',
      severity: pkg.severity,
      confidence: 'high',
      source: 'phylum',
      description: 'Malicious package reported by Phylum Research',
      references: ['https://blog.phylum.io'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}

// ============================================
// SOURCE 6: npm removed packages (from static file)
// ============================================
async function scrapeNpmRemoved() {
  console.log('[SCRAPER] npm removed packages...');
  const packages = [];
  const staticIOCs = loadStaticIOCs();
  
  for (const pkg of staticIOCs.npmRemoved || []) {
    packages.push({
      id: `NPM-REMOVED-${pkg.name}`,
      name: pkg.name,
      version: pkg.version,
      severity: 'critical',
      confidence: 'high',
      source: 'npm-removed',
      description: `Removed from npm: ${pkg.reason}`,
      references: ['https://www.npmjs.com/policies/security'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}


// ============================================
// SOURCE 7: AlienVault OTX
// ============================================
async function scrapeAlienVault() {
  console.log('[SCRAPER] AlienVault OTX...');
  const packages = [];
  
  try {
    const searches = ['npm%20malware', 'nodejs%20malware', 'supply%20chain%20npm'];
    
    for (const search of searches) {
      const url = `https://otx.alienvault.com/api/v1/search/pulses?q=${search}&limit=20`;
      const { status, data } = await fetchJSON(url);
      
      if (status === 200 && data?.results) {
        for (const pulse of data.results) {
          if (pulse.indicators) {
            for (const indicator of pulse.indicators) {
              if (indicator.type === 'hostname' || indicator.type === 'domain' || indicator.type === 'FileHash-SHA256') {
                const name = indicator.indicator;
                if (name && !name.includes('.') && !name.includes('/') && name.length > 2 && name.length < 50) {
                  packages.push({
                    id: `OTX-${pulse.id}-${name.slice(0, 20)}`,
                    name: name,
                    version: '*',
                    severity: 'high',
                    confidence: 'medium',
                    source: 'alienvault-otx',
                    description: (pulse.name || 'AlienVault OTX threat intelligence').slice(0, 200),
                    references: [`https://otx.alienvault.com/pulse/${pulse.id}`],
                    mitre: 'T1195.002'
                  });
                }
              }
            }
          }
        }
      }
    }
    
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  } catch (e) {
    console.log(`[SCRAPER]   -> Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 8: Aikido Intel
// ============================================
async function scrapeAikidoIntel() {
  console.log('[SCRAPER] Aikido Intel...');
  const packages = [];
  
  try {
    const url = 'https://intel.aikido.dev/api/v1/malware?ecosystem=npm&limit=100';
    const { status, data } = await fetchJSON(url);
    
    if (status === 200 && Array.isArray(data)) {
      for (const pkg of data) {
        packages.push({
          id: `AIKIDO-${pkg.name || pkg.id}`,
          name: pkg.name,
          version: pkg.version || '*',
          severity: pkg.severity || 'high',
          confidence: 'high',
          source: 'aikido-intel',
          description: (pkg.description || 'Malware detected by Aikido Intel').slice(0, 200),
          references: ['https://intel.aikido.dev'],
          mitre: 'T1195.002'
        });
      }
    }
    
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  } catch (e) {
    console.log(`[SCRAPER]   -> Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// MAIN SCRAPER
// ============================================
async function runScraper() {
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║      MUAD\'DIB IOC Scraper v2.0             ║');
  console.log('╚════════════════════════════════════════════╝\n');
  
  let existingIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    existingIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  
  const existingNames = new Set(existingIOCs.packages.map(p => p.name));
  const existingHashes = new Set(existingIOCs.hashes || []);
  const initialCount = existingIOCs.packages.length;
  const initialHashCount = existingIOCs.hashes?.length || 0;
  
  // Scrape all sources
const [
  shaiHuludPackages,
  datadogResult,
  osvPackages,
  socketPackages,
  phylumPackages,
  npmRemovedPackages,
  alienVaultPackages,
  aikidoPackages
] = await Promise.all([
  scrapeShaiHuludDetector(),
  scrapeDatadogIOCs(),
  scrapeOSV(),
  scrapeSocketReports(),
  scrapePhylum(),
  scrapeNpmRemoved(),
  scrapeAlienVault(),
  scrapeAikidoIntel()
]);

// Merge all packages
const allPackages = [
  ...shaiHuludPackages,
  ...datadogResult.packages,
  ...osvPackages,
  ...socketPackages,
  ...phylumPackages,
  ...npmRemovedPackages,
  ...alienVaultPackages,
  ...aikidoPackages
];
  
  let addedPackages = 0;
  for (const pkg of allPackages) {
    if (!existingNames.has(pkg.name)) {
      existingIOCs.packages.push(pkg);
      existingNames.add(pkg.name);
      addedPackages++;
    }
  }
  
  // Merge hashes from Datadog
  let addedHashes = 0;
  for (const hash of datadogResult.hashes || []) {
    if (!existingHashes.has(hash)) {
      existingIOCs.hashes = existingIOCs.hashes || [];
      existingIOCs.hashes.push(hash);
      existingHashes.add(hash);
      addedHashes++;
    }
  }
  
  // Save
  existingIOCs.updated = new Date().toISOString();
  fs.writeFileSync(IOC_FILE, JSON.stringify(existingIOCs, null, 2));
  
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║      Resultats                             ║');
  console.log('╚════════════════════════════════════════════╝');
  console.log(`  Packages avant:  ${initialCount}`);
  console.log(`  Packages apres:  ${existingIOCs.packages.length}`);
  console.log(`  Nouveaux:        +${addedPackages}`);
  console.log(`  Hashes avant:    ${initialHashCount}`);
  console.log(`  Hashes apres:    ${existingIOCs.hashes?.length || 0}`);
  console.log(`  Nouveaux:        +${addedHashes}`);
  console.log(`  Fichier:         ${IOC_FILE}\n`);
  
  return { 
    added: addedPackages, 
    total: existingIOCs.packages.length,
    addedHashes: addedHashes,
    totalHashes: existingIOCs.hashes?.length || 0
  };
}

module.exports = { runScraper };