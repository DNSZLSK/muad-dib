const https = require('https');
const fs = require('fs');
const path = require('path');

const IOC_FILE = path.join(__dirname, 'data/iocs.json');
const STATIC_IOCS_FILE = path.join(__dirname, 'data/static-iocs.json');

// ============================================
// UTILITY FUNCTIONS
// ============================================

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
        'User-Agent': 'MUADDIB-Scanner/2.0',
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
    req.setTimeout(30000, () => {
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
        'User-Agent': 'MUADDIB-Scanner/2.0'
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
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
    
    req.end();
  });
}

// ============================================
// SOURCE 1: GenSecAI Shai-Hulud 2.0 Detector
// La meilleure source consolidée (700+ packages)
// ============================================
async function scrapeShaiHuludDetector() {
  console.log('[SCRAPER] GenSecAI Shai-Hulud 2.0 Detector...');
  const packages = [];
  const hashes = [];
  
  try {
    const url = 'https://raw.githubusercontent.com/gensecaihq/Shai-Hulud-2.0-Detector/main/compromised-packages.json';
    const { status, data } = await fetchJSON(url);
    
    if (status === 200 && data) {
      // Extraire les packages
      const pkgList = data.packages || [];
      for (const pkg of pkgList) {
        const versions = pkg.affectedVersions || ['*'];
        packages.push({
          id: `SHAI-HULUD-${pkg.name}`,
          name: pkg.name,
          version: versions.join(', '),
          severity: pkg.severity || 'critical',
          confidence: 'high',
          source: 'shai-hulud-detector',
          description: `Compromised by Shai-Hulud 2.0 supply chain attack`,
          references: ['https://github.com/gensecaihq/Shai-Hulud-2.0-Detector'],
          mitre: 'T1195.002'
        });
      }
      
      // Extraire les hashes si disponibles
      if (data.indicators?.fileHashes) {
        const fileHashes = data.indicators.fileHashes;
        for (const [filename, hashData] of Object.entries(fileHashes)) {
          if (hashData.sha256) {
            const sha256List = Array.isArray(hashData.sha256) ? hashData.sha256 : [hashData.sha256];
            for (const hash of sha256List) {
              if (hash && hash.length === 64) {
                hashes.push(hash.toLowerCase());
              }
            }
          }
        }
      }
      
      console.log(`[SCRAPER]   ${packages.length} packages, ${hashes.length} hashes`);
    }
  } catch (e) {
    console.log(`[SCRAPER]   Erreur: ${e.message}`);
  }
  
  return { packages, hashes };
}

// ============================================
// SOURCE 2: DataDog Consolidated IOCs
// URL corrigée - consolidated_iocs.csv
// ============================================
async function scrapeDatadogIOCs() {
  console.log('[SCRAPER] DataDog Security Labs IOCs...');
  const packages = [];
  const hashes = [];
  
  try {
    // Fichier consolidé (plusieurs vendors)
    const consolidatedUrl = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv';
    const consolidatedResp = await fetchText(consolidatedUrl);
    
    if (consolidatedResp.status === 200 && consolidatedResp.data) {
      const lines = consolidatedResp.data.split('\n').filter(l => l.trim());
      // Format: package_name,versions,vendors
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 1) {
          const name = parts[0].trim().replace(/"/g, '');
          const versions = parts[1] ? parts[1].trim().replace(/"/g, '') : '*';
          const vendors = parts[2] ? parts[2].trim().replace(/"/g, '') : 'datadog';
          
          if (name && name !== 'package_name' && name !== 'name') {
            packages.push({
              id: `DATADOG-${name}`,
              name: name,
              version: versions || '*',
              severity: 'critical',
              confidence: 'high',
              source: 'datadog-consolidated',
              description: `Compromised package (sources: ${vendors})`,
              references: ['https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/'],
              mitre: 'T1195.002'
            });
          }
        }
      }
      console.log(`[SCRAPER]   ${packages.length} packages (consolidated)`);
    }
    
    // Fichier DataDog spécifique
    const ddUrl = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/shai-hulud-2.0.csv';
    const ddResp = await fetchText(ddUrl);
    
    if (ddResp.status === 200 && ddResp.data) {
      const lines = ddResp.data.split('\n').filter(l => l.trim());
      let ddCount = 0;
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 2) {
          const name = parts[0].trim().replace(/"/g, '');
          const version = parts[1].trim().replace(/"/g, '');
          
          if (name && name !== 'package_name') {
            // Vérifier si pas déjà ajouté
            if (!packages.find(p => p.name === name && p.version === version)) {
              packages.push({
                id: `DATADOG-DD-${name}-${version}`,
                name: name,
                version: version,
                severity: 'critical',
                confidence: 'high',
                source: 'datadog-direct',
                description: 'Manually confirmed by DataDog Security Labs',
                references: ['https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/'],
                mitre: 'T1195.002'
              });
              ddCount++;
            }
          }
        }
      }
      console.log(`[SCRAPER]   +${ddCount} packages (datadog direct)`);
    }
    
  } catch (e) {
    console.log(`[SCRAPER]   Erreur: ${e.message}`);
  }
  
  return { packages, hashes };
}

// ============================================
// SOURCE 3: OSSF Malicious Packages (via OSV API)
// La source la plus complète - 8000+ reports
// ============================================
async function scrapeOSSFMaliciousPackages() {
  console.log('[SCRAPER] OSSF Malicious Packages (via OSV.dev)...');
  const packages = [];
  
  try {
    // L'API OSV agrège les données OSSF malicious-packages
    // On requête par écosystème npm sans version pour tout récupérer
    // Malheureusement l'API OSV ne permet pas de lister tous les packages
    // On va donc utiliser des requêtes ciblées par préfixe commun
    
    // Liste des préfixes de packages malveillants connus
    const maliciousPrefixes = [
      'MAL-', // Prefix OSSF pour malware
    ];
    
    // Requête batch pour les vulns de type malware
    const { status, data } = await fetchJSON('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { 
        package: { ecosystem: 'npm' }
      }
    });
    
    // Note: Cette requête retourne TOUTES les vulns npm, pas juste malware
    // On va filtrer par ID commençant par MAL-
    if (status === 200 && data?.vulns) {
      for (const vuln of data.vulns) {
        // Filtrer uniquement les malware (ID commence par MAL-)
        if (vuln.id && vuln.id.startsWith('MAL-')) {
          for (const affected of vuln.affected || []) {
            if (affected.package?.ecosystem === 'npm') {
              packages.push({
                id: vuln.id,
                name: affected.package.name,
                version: '*',
                severity: 'critical',
                confidence: 'high',
                source: 'ossf-malicious',
                description: (vuln.summary || vuln.details || 'Malicious package').slice(0, 200),
                references: (vuln.references || []).map(r => r.url).slice(0, 3),
                mitre: 'T1195.002'
              });
            }
          }
        }
      }
    }
    
    // Requêtes supplémentaires pour packages spécifiques connus
    const knownMalwarePatterns = ['typosquat', 'cryptominer', 'backdoor', 'infostealer'];
    
    for (const pattern of knownMalwarePatterns) {
      try {
        const resp = await fetchJSON('https://api.osv.dev/v1/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: { query: pattern }
        });
        
        if (resp.status === 200 && resp.data?.vulns) {
          for (const vuln of resp.data.vulns) {
            if (vuln.id?.startsWith('MAL-')) {
              for (const affected of vuln.affected || []) {
                if (affected.package?.ecosystem === 'npm') {
                  const exists = packages.find(p => p.id === vuln.id && p.name === affected.package.name);
                  if (!exists) {
                    packages.push({
                      id: vuln.id,
                      name: affected.package.name,
                      version: '*',
                      severity: 'critical',
                      confidence: 'high',
                      source: 'ossf-malicious',
                      description: (vuln.summary || `${pattern} malware`).slice(0, 200),
                      references: (vuln.references || []).map(r => r.url).slice(0, 3),
                      mitre: 'T1195.002'
                    });
                  }
                }
              }
            }
          }
        }
      } catch (e) {
        // Continue with other patterns
      }
    }
    
    console.log(`[SCRAPER]   ${packages.length} packages`);
  } catch (e) {
    console.log(`[SCRAPER]   Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 4: GitHub Advisory Database (Malware)
// ============================================
async function scrapeGitHubAdvisory() {
  console.log('[SCRAPER] GitHub Advisory Database (malware)...');
  const packages = [];
  
  try {
    // L'API GitHub Advisory nécessite un token, on passe par OSV qui l'agrège
    const { status, data } = await fetchJSON('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { 
        package: { ecosystem: 'npm' }
      }
    });
    
    if (status === 200 && data?.vulns) {
      for (const vuln of data.vulns) {
        // Filtrer les GHSA avec mention de malware
        if (vuln.id?.startsWith('GHSA-')) {
          const summary = (vuln.summary || '').toLowerCase();
          const details = (vuln.details || '').toLowerCase();
          const isMalware = summary.includes('malware') || 
                          summary.includes('malicious') ||
                          details.includes('malware') ||
                          details.includes('malicious') ||
                          summary.includes('backdoor') ||
                          summary.includes('trojan');
          
          if (isMalware) {
            for (const affected of vuln.affected || []) {
              if (affected.package?.ecosystem === 'npm') {
                packages.push({
                  id: vuln.id,
                  name: affected.package.name,
                  version: '*',
                  severity: 'critical',
                  confidence: 'high',
                  source: 'github-advisory',
                  description: (vuln.summary || 'Malicious package').slice(0, 200),
                  references: [`https://github.com/advisories/${vuln.id}`],
                  mitre: 'T1195.002'
                });
              }
            }
          }
        }
      }
    }
    
    console.log(`[SCRAPER]   ${packages.length} packages`);
  } catch (e) {
    console.log(`[SCRAPER]   Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 5: Static IOCs (Socket, Phylum, npm removed)
// Fichier local maintenu manuellement
// ============================================
async function scrapeStaticIOCs() {
  console.log('[SCRAPER] Static IOCs (local file)...');
  const packages = [];
  const staticIOCs = loadStaticIOCs();
  
  // Socket.dev reports
  for (const pkg of staticIOCs.socket || []) {
    packages.push({
      id: `SOCKET-${pkg.name}`,
      name: pkg.name,
      version: pkg.version || '*',
      severity: pkg.severity || 'critical',
      confidence: 'high',
      source: 'socket-dev',
      description: pkg.description || 'Malicious package reported by Socket.dev',
      references: [`https://socket.dev/npm/package/${pkg.name}`],
      mitre: 'T1195.002'
    });
  }
  
  // Phylum Research
  for (const pkg of staticIOCs.phylum || []) {
    packages.push({
      id: `PHYLUM-${pkg.name}`,
      name: pkg.name,
      version: pkg.version || '*',
      severity: pkg.severity || 'critical',
      confidence: 'high',
      source: 'phylum',
      description: pkg.description || 'Malicious package reported by Phylum Research',
      references: ['https://blog.phylum.io'],
      mitre: 'T1195.002'
    });
  }
  
  // npm removed packages
  for (const pkg of staticIOCs.npmRemoved || []) {
    packages.push({
      id: `NPM-REMOVED-${pkg.name}`,
      name: pkg.name,
      version: pkg.version || '*',
      severity: 'critical',
      confidence: 'high',
      source: 'npm-removed',
      description: `Removed from npm: ${pkg.reason || 'security violation'}`,
      references: ['https://www.npmjs.com/policies/security'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   ${packages.length} packages`);
  return packages;
}

// ============================================
// SOURCE 6: Snyk Vulnerability DB (malware only)
// Via API publique limitée
// ============================================
async function scrapeSnykMalware() {
  console.log('[SCRAPER] Snyk Malware DB...');
  const packages = [];
  
  // Snyk n'a pas d'API publique pour lister les malwares
  // On utilise des packages connus documentés dans leurs blogs
  const knownSnykMalware = [
    { name: 'event-stream', version: '3.3.6', description: 'Flatmap-stream backdoor (2018)' },
    { name: 'flatmap-stream', version: '*', description: 'Malicious dependency of event-stream' },
    { name: 'eslint-scope', version: '3.7.2', description: 'Credential theft (2018)' },
    { name: 'eslint-config-eslint', version: '*', description: 'Credential theft (2018)' },
    { name: 'getcookies', version: '*', description: 'Backdoor malware' },
    { name: 'mailparser', version: '2.3.0', description: 'Compromised version' },
    { name: 'node-ipc', version: '10.1.1', description: 'Protestware - file deletion' },
    { name: 'node-ipc', version: '10.1.2', description: 'Protestware - file deletion' },
    { name: 'node-ipc', version: '10.1.3', description: 'Protestware - file deletion' },
    { name: 'colors', version: '1.4.1', description: 'Protestware - infinite loop' },
    { name: 'colors', version: '1.4.2', description: 'Protestware - infinite loop' },
    { name: 'faker', version: '6.6.6', description: 'Protestware - breaking change' },
    { name: 'ua-parser-js', version: '0.7.29', description: 'Cryptominer injection' },
    { name: 'ua-parser-js', version: '0.8.0', description: 'Cryptominer injection' },
    { name: 'ua-parser-js', version: '1.0.0', description: 'Cryptominer injection' },
    { name: 'coa', version: '2.0.3', description: 'Malicious version' },
    { name: 'coa', version: '2.0.4', description: 'Malicious version' },
    { name: 'coa', version: '2.1.1', description: 'Malicious version' },
    { name: 'coa', version: '2.1.3', description: 'Malicious version' },
    { name: 'coa', version: '3.0.1', description: 'Malicious version' },
    { name: 'coa', version: '3.1.3', description: 'Malicious version' },
    { name: 'rc', version: '1.2.9', description: 'Malicious version' },
    { name: 'rc', version: '1.3.9', description: 'Malicious version' },
    { name: 'rc', version: '2.3.9', description: 'Malicious version' },
  ];
  
  for (const pkg of knownSnykMalware) {
    packages.push({
      id: `SNYK-${pkg.name}-${pkg.version}`.replace(/[^a-zA-Z0-9-]/g, '-'),
      name: pkg.name,
      version: pkg.version,
      severity: 'critical',
      confidence: 'high',
      source: 'snyk-known',
      description: pkg.description,
      references: ['https://snyk.io/advisor'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   ${packages.length} packages`);
  return packages;
}

// ============================================
// MAIN SCRAPER
// ============================================
async function runScraper() {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║      MUAD\'DIB IOC Scraper v3.0                         ║');
  console.log('║      Optimized sources - No dead links                 ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');
  
  // Créer le dossier data si nécessaire
  const dataDir = path.dirname(IOC_FILE);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  
  // Charger les IOCs existants
  let existingIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    try {
      existingIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
    } catch (e) {
      console.log('[WARN] Fichier IOCs corrompu, réinitialisation...');
    }
  }
  
  const existingNames = new Set(existingIOCs.packages.map(p => `${p.name}@${p.version}`));
  const existingHashes = new Set(existingIOCs.hashes || []);
  const initialCount = existingIOCs.packages.length;
  const initialHashCount = existingIOCs.hashes?.length || 0;
  
  console.log(`[INFO] IOCs existants: ${initialCount} packages, ${initialHashCount} hashes\n`);
  
  // Scraper toutes les sources en parallèle
  const [
    shaiHuludResult,
    datadogResult,
    ossfPackages,
    githubPackages,
    staticPackages,
    snykPackages
  ] = await Promise.all([
    scrapeShaiHuludDetector(),
    scrapeDatadogIOCs(),
    scrapeOSSFMaliciousPackages(),
    scrapeGitHubAdvisory(),
    scrapeStaticIOCs(),
    scrapeSnykMalware()
  ]);
  
  // Merger tous les packages
  const allPackages = [
    ...shaiHuludResult.packages,
    ...datadogResult.packages,
    ...ossfPackages,
    ...githubPackages,
    ...staticPackages,
    ...snykPackages
  ];
  
  // Merger tous les hashes
  const allHashes = [
    ...(shaiHuludResult.hashes || []),
    ...(datadogResult.hashes || [])
  ];
  
  // Dédupliquer et ajouter les nouveaux packages
  let addedPackages = 0;
  for (const pkg of allPackages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (!existingNames.has(key)) {
      existingIOCs.packages.push(pkg);
      existingNames.add(key);
      addedPackages++;
    }
  }
  
  // Dédupliquer et ajouter les nouveaux hashes
  let addedHashes = 0;
  for (const hash of allHashes) {
    if (!existingHashes.has(hash)) {
      existingIOCs.hashes = existingIOCs.hashes || [];
      existingIOCs.hashes.push(hash);
      existingHashes.add(hash);
      addedHashes++;
    }
  }
  
  // Ajouter les marqueurs Shai-Hulud si pas présents
  if (!existingIOCs.markers || existingIOCs.markers.length === 0) {
    existingIOCs.markers = [
      'setup_bun.js',
      'bun_environment.js',
      'bun_installer.js',
      'environment_source.js',
      'cloud.json',
      'contents.json',
      'environment.json',
      'truffleSecrets.json',
      'actionsSecrets.json',
      'trufflehog_output.json',
      '3nvir0nm3nt.json',
      'cl0vd.json',
      'c9nt3nts.json',
      'pigS3cr3ts.json'
    ];
  }
  
  // Mettre à jour les métadonnées
  existingIOCs.updated = new Date().toISOString();
  existingIOCs.sources = [
    'shai-hulud-detector',
    'datadog-consolidated',
    'datadog-direct',
    'ossf-malicious',
    'github-advisory',
    'socket-dev',
    'phylum',
    'npm-removed',
    'snyk-known'
  ];
  
  // Sauvegarder
  fs.writeFileSync(IOC_FILE, JSON.stringify(existingIOCs, null, 2));
  
  // Afficher le résumé
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║      RÉSULTATS                                         ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log(`  Packages avant:   ${initialCount}`);
  console.log(`  Packages après:   ${existingIOCs.packages.length}`);
  console.log(`  Nouveaux:         +${addedPackages}`);
  console.log(`  Hashes avant:     ${initialHashCount}`);
  console.log(`  Hashes après:     ${existingIOCs.hashes?.length || 0}`);
  console.log(`  Nouveaux:         +${addedHashes}`);
  console.log(`  Fichier:          ${IOC_FILE}`);
  
  // Stats par source
  console.log('\n  Répartition par source:');
  const sourceCounts = {};
  for (const pkg of existingIOCs.packages) {
    sourceCounts[pkg.source] = (sourceCounts[pkg.source] || 0) + 1;
  }
  for (const [source, count] of Object.entries(sourceCounts).sort((a, b) => b[1] - a[1])) {
    console.log(`     - ${source}: ${count}`);
  }
  
  console.log('\n');
  
  return { 
    added: addedPackages, 
    total: existingIOCs.packages.length,
    addedHashes: addedHashes,
    totalHashes: existingIOCs.hashes?.length || 0
  };
}

// Export pour utilisation en module
module.exports = { runScraper };

// Exécution directe si appelé en CLI
if (require.main === module) {
  runScraper()
    .then(result => {
      console.log('Scraping terminé avec succès');
      process.exit(0);
    })
    .catch(err => {
      console.error('Erreur:', err.message);
      process.exit(1);
    });
}