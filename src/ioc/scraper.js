const https = require('https');
const fs = require('fs');
const path = require('path');

const IOC_FILE = path.join(__dirname, 'data/iocs.json');
const STATIC_IOCS_FILE = path.join(__dirname, 'data/static-iocs.json');

// Allowed domains for redirections (SSRF security)
const ALLOWED_REDIRECT_DOMAINS = [
  'raw.githubusercontent.com',
  'github.com',
  'api.github.com',
  'api.osv.dev',
  'osv.dev',
  'objects.githubusercontent.com'
];

/**
 * Checks if a redirect URL is allowed
 * @param {string} redirectUrl - Redirect URL
 * @returns {boolean} true if allowed
 */
function isAllowedRedirect(redirectUrl) {
  try {
    const urlObj = new URL(redirectUrl);
    return ALLOWED_REDIRECT_DOMAINS.includes(urlObj.hostname);
  } catch {
    return false;
  }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Parse a CSV line correctly handling commas within quoted fields
 * Supports: "field1","field, with comma","field3"
 * @param {string} line - CSV line to parse
 * @returns {string[]} Array of fields
 */
function parseCSVLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;
  let i = 0;

  while (i < line.length) {
    const char = line[i];

    if (char === '"') {
      // Handle escaped double quotes ("") within a field
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 2;
        continue;
      }
      // Toggle quote mode
      inQuotes = !inQuotes;
      i++;
      continue;
    }

    if (char === ',' && !inQuotes) {
      // End of field
      fields.push(current.trim());
      current = '';
      i++;
      continue;
    }

    current += char;
    i++;
  }

  // Add the last field
  fields.push(current.trim());

  return fields;
}

/**
 * Parse a complete CSV file
 * @param {string} csvContent - CSV content
 * @param {boolean} [hasHeader=true] - If true, skip the first line
 * @returns {string[][]} Array of parsed lines
 */
function parseCSV(csvContent, hasHeader = true) {
  const lines = csvContent.split('\n').filter(l => l.trim());
  const startIndex = hasHeader ? 1 : 0;
  const results = [];

  for (let i = startIndex; i < lines.length; i++) {
    const parsed = parseCSVLine(lines[i]);
    if (parsed.length > 0 && parsed[0]) {
      results.push(parsed);
    }
  }

  return results;
}

function loadStaticIOCs() {
  try {
    if (fs.existsSync(STATIC_IOCS_FILE)) {
      return JSON.parse(fs.readFileSync(STATIC_IOCS_FILE, 'utf8'));
    }
  } catch (e) {
    console.log(`[WARN] Error loading static-iocs.json: ${e.message}`);
  }
  return { socket: [], phylum: [], npmRemoved: [] };
}

const MAX_REDIRECTS = 5;

function fetchJSON(url, options = {}, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/3.0',
        'Accept': 'application/json',
        ...options.headers
      }
    };

    const req = https.request(reqOptions, (res) => {
      // Handle redirects (with security validation and limit)
      if (res.statusCode === 301 || res.statusCode === 302) {
        if (redirectCount >= MAX_REDIRECTS) {
          reject(new Error('Too many redirects'));
          return;
        }
        const redirectUrl = res.headers.location;
        if (!isAllowedRedirect(redirectUrl)) {
          reject(new Error(`Unauthorized redirect to: ${redirectUrl}`));
          return;
        }
        fetchJSON(redirectUrl, options, redirectCount + 1).then(resolve).catch(reject);
        return;
      }

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

function fetchText(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/3.0'
      }
    };

    const req = https.request(reqOptions, (res) => {
      // Handle redirects (with security validation and limit)
      if (res.statusCode === 301 || res.statusCode === 302) {
        if (redirectCount >= MAX_REDIRECTS) {
          reject(new Error('Too many redirects'));
          return;
        }
        const redirectUrl = res.headers.location;
        if (!isAllowedRedirect(redirectUrl)) {
          reject(new Error(`Unauthorized redirect to: ${redirectUrl}`));
          return;
        }
        fetchText(redirectUrl, redirectCount + 1).then(resolve).catch(reject);
        return;
      }

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
// Consolidated list (700+ packages)
// ============================================
async function scrapeShaiHuludDetector() {
  console.log('[SCRAPER] GenSecAI Shai-Hulud 2.0 Detector...');
  const packages = [];
  const hashes = [];
  
  try {
    const url = 'https://raw.githubusercontent.com/gensecaihq/Shai-Hulud-2.0-Detector/main/compromised-packages.json';
    const { status, data } = await fetchJSON(url);
    
    if (status === 200 && data) {
      // Extract packages — one IOC per version for correct matching
      const pkgList = data.packages || [];
      for (const pkg of pkgList) {
        const versions = pkg.affectedVersions || ['*'];
        for (const ver of versions) {
          packages.push({
            id: `SHAI-HULUD-${pkg.name}-${ver}`,
            name: pkg.name,
            version: ver,
            severity: pkg.severity || 'critical',
            confidence: 'high',
            source: 'shai-hulud-detector',
            description: 'Compromised by Shai-Hulud 2.0 supply chain attack',
            references: ['https://github.com/gensecaihq/Shai-Hulud-2.0-Detector'],
            mitre: 'T1195.002'
          });
        }
      }
      
      // Extract hashes
      if (data.indicators && data.indicators.fileHashes) {
        const fileHashes = data.indicators.fileHashes;
        for (const hashData of Object.values(fileHashes)) {
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
    console.log(`[SCRAPER]   Error: ${e.message}`);
  }
  
  return { packages, hashes };
}

// ============================================
// SOURCE 2: DataDog Consolidated IOCs
// Fixed URLs - consolidated_iocs.csv
// ============================================
async function scrapeDatadogIOCs() {
  console.log('[SCRAPER] DataDog Security Labs IOCs...');
  const packages = [];
  
  try {
    // Consolidated file (multiple vendors)
    const consolidatedUrl = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv';
    const consolidatedResp = await fetchText(consolidatedUrl);
    
    if (consolidatedResp.status === 200 && consolidatedResp.data) {
      // Format: package_name,versions,vendors (with comma handling in fields)
      const rows = parseCSV(consolidatedResp.data, true);

      for (const parts of rows) {
        const name = parts[0] || '';
        const versions = parts[1] || '*';
        const vendors = parts[2] || 'datadog';

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
      console.log(`[SCRAPER]   ${packages.length} packages (consolidated)`);
    }
    
    // DataDog specific file
    const ddUrl = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/shai-hulud-2.0.csv';
    const ddResp = await fetchText(ddUrl);
    
    if (ddResp.status === 200 && ddResp.data) {
      // Parse with comma handling in quoted fields
      const rows = parseCSV(ddResp.data, true);
      let ddCount = 0;

      for (const parts of rows) {
        if (parts.length >= 2) {
          const name = parts[0] || '';
          const version = parts[1] || '*';

          if (name && name !== 'package_name') {
            // Check if not already added
            if (!packages.find(p => p.name === name && p.version === version)) {
              packages.push({
                id: `DATADOG-DD-${name}-${version}`.replace(/[^a-zA-Z0-9-]/g, '-'),
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
    console.log(`[SCRAPER]   Error: ${e.message}`);
  }
  
  return { packages, hashes: [] };
}

// ============================================
// SOURCE 3: OSSF Malicious Packages
// Direct download from GitHub API
// ============================================
async function scrapeOSSFMaliciousPackages() {
  console.log('[SCRAPER] OSSF Malicious Packages...');
  const packages = [];
  
  try {
    // Use GitHub API to list files in the npm malware directory
    // We'll fetch the index file that lists all malware
    const indexUrl = 'https://raw.githubusercontent.com/ossf/malicious-packages/main/osv/malicious/npm/index.json';
    const indexResp = await fetchJSON(indexUrl);
    
    if (indexResp.status === 200 && indexResp.data) {
      // If index exists, parse it
      const entries = Array.isArray(indexResp.data) ? indexResp.data : [];
      for (const entry of entries) {
        if (entry.name) {
          packages.push({
            id: entry.id || `OSSF-${entry.name}`,
            name: entry.name,
            version: entry.version || '*',
            severity: 'critical',
            confidence: 'high',
            source: 'ossf-malicious',
            description: entry.summary || 'Malicious package from OSSF database',
            references: ['https://github.com/ossf/malicious-packages'],
            mitre: 'T1195.002'
          });
        }
      }
    } else {
      // Fallback: use OSV API to query for MAL- prefixed vulnerabilities
      // This is limited but better than nothing
      const ecosystems = ['npm'];
      
      for (const ecosystem of ecosystems) {
        try {
          const resp = await fetchJSON('https://api.osv.dev/v1/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: { package: { ecosystem } }
          });
          
          if (resp.status === 200 && resp.data && resp.data.vulns) {
            for (const vuln of resp.data.vulns) {
              // Filter only malware (ID starts with MAL-)
              if (vuln.id && vuln.id.startsWith('MAL-')) {
                for (const affected of vuln.affected || []) {
                  if (affected.package && affected.package.ecosystem === 'npm') {
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
        } catch {
          // Continue silently
        }
      }
    }
    
    console.log(`[SCRAPER]   ${packages.length} packages`);
  } catch (e) {
    console.log(`[SCRAPER]   Error: ${e.message}`);
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
    const resp = await fetchJSON('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { package: { ecosystem: 'npm' } }
    });
    
    if (resp.status === 200 && resp.data && resp.data.vulns) {
      for (const vuln of resp.data.vulns) {
        // Filter GHSA with malware mention
        if (vuln.id && vuln.id.startsWith('GHSA-')) {
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
              if (affected.package && affected.package.ecosystem === 'npm') {
                packages.push({
                  id: vuln.id,
                  name: affected.package.name,
                  version: '*',
                  severity: 'critical',
                  confidence: 'high',
                  source: 'github-advisory',
                  description: (vuln.summary || 'Malicious package').slice(0, 200),
                  references: ['https://github.com/advisories/' + vuln.id],
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
    console.log(`[SCRAPER]   Error: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 5: Static IOCs (Socket, Phylum, npm removed)
// Local file maintained manually
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
      references: ['https://socket.dev/npm/package/' + pkg.name],
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
      description: 'Removed from npm: ' + (pkg.reason || 'security violation'),
      references: ['https://www.npmjs.com/policies/security'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   ${packages.length} packages`);
  return packages;
}

// ============================================
// SOURCE 6: Snyk Known Malware
// Historical attacks database
// ============================================
async function scrapeSnykMalware() {
  console.log('[SCRAPER] Snyk Malware DB...');
  const packages = [];
  
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
      id: ('SNYK-' + pkg.name + '-' + pkg.version).replace(/[^a-zA-Z0-9-]/g, '-'),
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
  console.log('\n' + '='.repeat(60));
  console.log('  MUAD\'DIB IOC Scraper v3.0');
  console.log('  Optimized sources - No dead links');
  console.log('='.repeat(60) + '\n');
  
  // Create data directory if needed
  const dataDir = path.dirname(IOC_FILE);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  
  // Load existing IOCs
  let existingIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    try {
      existingIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
    } catch {
      console.log('[WARN] IOCs file corrupted, resetting...');
    }
  }
  
  const existingNames = new Set(existingIOCs.packages.map(p => p.name + '@' + p.version));
  const existingHashes = new Set(existingIOCs.hashes || []);
  const initialCount = existingIOCs.packages.length;
  const initialHashCount = existingIOCs.hashes ? existingIOCs.hashes.length : 0;
  
  console.log('[INFO] Existing IOCs: ' + initialCount + ' packages, ' + initialHashCount + ' hashes\n');
  
  // Scrape all sources in parallel
  const results = await Promise.all([
    scrapeShaiHuludDetector(),
    scrapeDatadogIOCs(),
    scrapeOSSFMaliciousPackages(),
    scrapeGitHubAdvisory(),
    scrapeStaticIOCs(),
    scrapeSnykMalware()
  ]);
  
  const shaiHuludResult = results[0];
  const datadogResult = results[1];
  const ossfPackages = results[2];
  const githubPackages = results[3];
  const staticPackages = results[4];
  const snykPackages = results[5];
  
  // Merge all packages
  const allPackages = [
    ...shaiHuludResult.packages,
    ...datadogResult.packages,
    ...ossfPackages,
    ...githubPackages,
    ...staticPackages,
    ...snykPackages
  ];
  
  // Merge all hashes
  const allHashes = [
    ...(shaiHuludResult.hashes || []),
    ...(datadogResult.hashes || [])
  ];
  
  // Deduplicate and add new packages
  let addedPackages = 0;
  for (const pkg of allPackages) {
    const key = pkg.name + '@' + pkg.version;
    if (!existingNames.has(key)) {
      existingIOCs.packages.push(pkg);
      existingNames.add(key);
      addedPackages++;
    }
  }
  
  // Deduplicate and add new hashes
  let addedHashes = 0;
  for (const hash of allHashes) {
    if (!existingHashes.has(hash)) {
      existingIOCs.hashes = existingIOCs.hashes || [];
      existingIOCs.hashes.push(hash);
      existingHashes.add(hash);
      addedHashes++;
    }
  }
  
  // Add Shai-Hulud markers if not present
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
  
  // Update metadata
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
  
  // Save
  fs.writeFileSync(IOC_FILE, JSON.stringify(existingIOCs, null, 2));
  
  // Display summary
  console.log('\n' + '='.repeat(60));
  console.log('  RESULTS');
  console.log('='.repeat(60));
  console.log('  Packages before:  ' + initialCount);
  console.log('  Packages after:   ' + existingIOCs.packages.length);
  console.log('  New:              +' + addedPackages);
  console.log('  Hashes before:    ' + initialHashCount);
  console.log('  Hashes after:     ' + (existingIOCs.hashes ? existingIOCs.hashes.length : 0));
  console.log('  New:              +' + addedHashes);
  console.log('  File:             ' + IOC_FILE);
  
  // Stats by source
  console.log('\n  Distribution by source:');
  const sourceCounts = {};
  for (const pkg of existingIOCs.packages) {
    sourceCounts[pkg.source] = (sourceCounts[pkg.source] || 0) + 1;
  }
  const sortedSources = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]);
  for (const [source, count] of sortedSources) {
    console.log('     - ' + source + ': ' + count);
  }
  
  console.log('\n');
  
  return { 
    added: addedPackages, 
    total: existingIOCs.packages.length,
    addedHashes: addedHashes,
    totalHashes: existingIOCs.hashes ? existingIOCs.hashes.length : 0
  };
}

module.exports = { runScraper };

// Direct execution if called as CLI
if (require.main === module) {
  runScraper()
    .then(function(result) {
      console.log('[OK] ' + result.added + ' new IOCs (total: ' + result.total + ')');
      process.exit(0);
    })
    .catch(function(err) {
      console.error('[ERROR] ' + err.message);
      process.exit(1);
    });
}