const https = require('https');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const IOC_FILE = path.join(__dirname, 'data/iocs.json');
const COMPACT_IOC_FILE = path.join(__dirname, 'data/iocs-compact.json');
const STATIC_IOCS_FILE = path.join(__dirname, 'data/static-iocs.json');
const { generateCompactIOCs } = require('./updater.js');
const { Spinner } = require('../utils.js');

// Allowed domains for redirections (SSRF security)
const ALLOWED_REDIRECT_DOMAINS = [
  'raw.githubusercontent.com',
  'github.com',
  'api.github.com',
  'api.osv.dev',
  'osv.dev',
  'objects.githubusercontent.com',
  'osv-vulnerabilities.storage.googleapis.com',
  'storage.googleapis.com'
];

/**
 * Checks if a redirect URL is allowed
 * @param {string} redirectUrl - Redirect URL
 * @returns {boolean} true if allowed
 */
function isAllowedRedirect(redirectUrl) {
  try {
    const urlObj = new URL(redirectUrl);
    if (urlObj.protocol !== 'https:') return false;
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
const MAX_RESPONSE_SIZE = 200 * 1024 * 1024; // 200MB

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
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume(); // Drain old response before following redirect
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
      let dataSize = 0;
      let destroyed = false;
      res.on('data', chunk => {
        if (destroyed) return;
        dataSize += chunk.length;
        if (dataSize > MAX_RESPONSE_SIZE) {
          destroyed = true;
          res.destroy();
          reject(new Error('Response exceeded maximum size'));
          return;
        }
        data += chunk;
      });
      res.on('end', () => {
        if (destroyed) return;
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
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume(); // Drain old response before following redirect
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
      let dataSize = 0;
      res.on('data', chunk => {
        dataSize += chunk.length;
        if (dataSize > MAX_RESPONSE_SIZE) {
          req.destroy();
          reject(new Error('Response exceeded maximum size'));
          return;
        }
        data += chunk;
      });
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

function fetchBuffer(url, redirectCount = 0) {
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
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume(); // Drain response body before following redirect
        if (redirectCount >= MAX_REDIRECTS) {
          reject(new Error('Too many redirects'));
          return;
        }
        const redirectUrl = res.headers.location;
        if (!isAllowedRedirect(redirectUrl)) {
          reject(new Error('Unauthorized redirect to: ' + redirectUrl));
          return;
        }
        fetchBuffer(redirectUrl, redirectCount + 1).then(resolve).catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        res.resume(); // Drain response body on error
        reject(new Error('HTTP ' + res.statusCode));
        return;
      }

      const chunks = [];
      let received = 0;
      res.on('data', chunk => {
        received += chunk.length;
        if (received > MAX_RESPONSE_SIZE) {
          req.destroy();
          reject(new Error('Response exceeded maximum size'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });

    req.on('error', reject);
    req.setTimeout(120000, () => {
      req.destroy();
      reject(new Error('Timeout'));
    });

    req.end();
  });
}

/**
 * Download a large file with spinner progress (npm/ora style).
 * Used for bulk zip downloads (OSV npm/PyPI ~50-100MB each).
 */
function fetchBufferWithProgress(url, label, redirectCount = 0) {
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
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume(); // Drain response body before following redirect
        if (redirectCount >= MAX_REDIRECTS) {
          reject(new Error('Too many redirects'));
          return;
        }
        const redirectUrl = res.headers.location;
        if (!isAllowedRedirect(redirectUrl)) {
          reject(new Error('Unauthorized redirect to: ' + redirectUrl));
          return;
        }
        fetchBufferWithProgress(redirectUrl, label, redirectCount + 1).then(resolve).catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        res.resume(); // Drain response body on error
        reject(new Error('HTTP ' + res.statusCode));
        return;
      }

      const totalSize = parseInt(res.headers['content-length'], 10) || 0;
      const totalMb = totalSize > 0 ? Math.round(totalSize / 1024 / 1024) : null;
      const chunks = [];
      let received = 0;

      const spinner = new Spinner();
      spinner.start('Downloading ' + label + '...');

      res.on('data', (chunk) => {
        chunks.push(chunk);
        received += chunk.length;
        if (received > MAX_RESPONSE_SIZE) {
          req.destroy();
          spinner.fail('Download exceeded maximum size');
          reject(new Error('Response exceeded maximum size'));
          return;
        }
        const mb = Math.round(received / 1024 / 1024);
        if (totalMb) {
          spinner.update('Downloading ' + label + '... ' + mb + 'MB/' + totalMb + 'MB');
        } else {
          spinner.update('Downloading ' + label + '... ' + mb + 'MB');
        }
      });

      res.on('end', () => {
        const mb = Math.round(received / 1024 / 1024);
        spinner.succeed('Downloaded ' + label + ' (' + mb + 'MB)');
        resolve(Buffer.concat(chunks));
      });
    });

    req.on('error', reject);
    req.setTimeout(300000, () => {
      req.destroy();
      reject(new Error('Timeout downloading ' + label));
    });

    req.end();
  });
}

// ============================================
// SHARED HELPERS
// ============================================

const CONFIDENCE_ORDER = { 'high': 3, 'medium': 2, 'low': 1 };

function createFreshness(source, confidence) {
  return {
    added_at: new Date().toISOString(),
    source: source,
    confidence: confidence || 'high'
  };
}

/**
 * Extract version list from an OSV affected entry.
 * Returns explicit versions if available, otherwise ['*'].
 */
function extractVersions(affected) {
  const versions = new Set();

  if (affected.versions && affected.versions.length > 0) {
    for (const v of affected.versions) {
      versions.add(v);
    }
  }

  if (affected.ranges) {
    for (const range of affected.ranges) {
      if (range.events) {
        for (const event of range.events) {
          if (event.introduced && event.introduced !== '0') {
            versions.add(event.introduced);
          }
        }
      }
    }
  }

  return versions.size > 0 ? [...versions] : ['*'];
}

/**
 * Parse an OSV-format vulnerability entry into IOC packages.
 * Shared by OSSF and OSV sources.
 * @param {Object} vuln - OSV vulnerability object
 * @param {string} source - Source identifier
 * @param {string} [ecosystem='npm'] - Target ecosystem ('npm' or 'PyPI')
 */
function parseOSVEntry(vuln, source, ecosystem) {
  if (!ecosystem) ecosystem = 'npm';
  const packages = [];
  if (!vuln || !vuln.affected) return packages;

  for (const affected of vuln.affected) {
    if (!affected.package || affected.package.ecosystem !== ecosystem) continue;

    const pkgVersions = extractVersions(affected);

    for (const ver of pkgVersions) {
      packages.push({
        id: vuln.id || source + '-' + affected.package.name,
        name: affected.package.name,
        version: ver,
        severity: 'critical',
        confidence: 'high',
        source: source,
        description: (vuln.summary || vuln.details || 'Malicious package').slice(0, 200),
        references: (vuln.references || []).map(r => r.url).slice(0, 3),
        mitre: 'T1195.002',
        published: vuln.published || vuln.modified || null,
        freshness: createFreshness(source, 'high')
      });
    }
  }

  return packages;
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
            mitre: 'T1195.002',
            freshness: createFreshness('gensecai', 'high')
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
            mitre: 'T1195.002',
            freshness: createFreshness('datadog', 'high')
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
                mitre: 'T1195.002',
                freshness: createFreshness('datadog', 'high')
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
// GitHub tree API + batch fetch with incremental SHA
// ============================================
async function scrapeOSSFMaliciousPackages(knownIds) {
  console.log('[SCRAPER] OSSF Malicious Packages (GitHub tree)...');
  const packages = [];
  const knownIdSet = knownIds || new Set();

  try {
    // Step 1: Get recursive tree
    const treeUrl = 'https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1';
    const { status, data } = await fetchJSON(treeUrl);

    if (status !== 200 || !data || !data.tree) {
      console.log('[SCRAPER]   Failed to get tree (HTTP ' + status + ')');
      return packages;
    }

    // Incremental: compare tree SHA
    const treeSha = data.sha;
    const dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    const shaFile = path.join(dataDir, '.ossf-tree-sha');
    let lastSha = null;
    try { lastSha = fs.readFileSync(shaFile, 'utf8').trim(); } catch {}

    if (lastSha === treeSha) {
      console.log('[SCRAPER]   Tree unchanged (SHA: ' + treeSha.slice(0, 8) + '...), skipping fetch');
      return packages;
    }

    // Step 2: Filter npm MAL-* entries
    const npmMalFiles = data.tree.filter(function(entry) {
      return entry.path.startsWith('osv/malicious/npm/')
        && entry.path.endsWith('.json')
        && entry.path.includes('/MAL-');
    });

    console.log('[SCRAPER]   Found ' + npmMalFiles.length + ' npm malware entries in tree');

    // Step 3: Skip entries already known from OSV dump
    const toFetch = npmMalFiles.filter(function(entry) {
      // Extract MAL-XXXX-XXXX from filename
      const filename = path.basename(entry.path, '.json');
      return !knownIdSet.has(filename);
    });

    console.log('[SCRAPER]   ' + (npmMalFiles.length - toFetch.length) + ' already known from OSV, fetching ' + toFetch.length + ' new entries');

    // Step 4: Batch fetch (50 concurrent, with small delay between batches for rate limit)
    const BATCH_SIZE = 50;
    let fetchSpinner = null;
    if (toFetch.length > 0) {
      fetchSpinner = new Spinner();
      fetchSpinner.start('Fetching OSSF entries... 0/' + toFetch.length);
    }

    for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
      const batch = toFetch.slice(i, i + BATCH_SIZE);
      const results = await Promise.all(batch.map(function(entry) {
        const rawUrl = 'https://raw.githubusercontent.com/ossf/malicious-packages/main/' + entry.path;
        return fetchJSON(rawUrl).catch(function() { return null; });
      }));

      for (const result of results) {
        if (!result || result.status !== 200 || !result.data) continue;
        const parsed = parseOSVEntry(result.data, 'ossf-malicious');
        for (const p of parsed) packages.push(p);
      }

      // Progress
      const progress = Math.min(i + BATCH_SIZE, toFetch.length);
      fetchSpinner.update('Fetching OSSF entries... ' + progress + '/' + toFetch.length);

      // Small delay between batches to respect rate limits
      if (i + BATCH_SIZE < toFetch.length) {
        await new Promise(function(r) { setTimeout(r, 100); });
      }
    }

    if (fetchSpinner) {
      fetchSpinner.succeed('Fetched OSSF entries: ' + packages.length + ' packages');
    }

    // Save tree SHA for next incremental run
    try { fs.writeFileSync(shaFile, treeSha); } catch {}
  } catch (e) {
    console.log('[SCRAPER]   Error: ' + e.message);
  }

  return packages;
}

// ============================================
// SOURCE 3b: OSV.dev npm data dump
// Bulk zip download — primary volume source
// ============================================
async function scrapeOSVDataDump() {
  const packages = [];
  const knownIds = new Set();

  try {
    // Download the full npm zip (~50-100MB)
    const zipUrl = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';
    const zipBuffer = await fetchBufferWithProgress(zipUrl, 'npm all.zip');

    // Extract using adm-zip
    const zip = new AdmZip(zipBuffer);
    const entries = zip.getEntries();
    const total = entries.length;

    let malCount = 0;
    let skippedCount = 0;

    const spinner = new Spinner();
    spinner.start('Parsing npm entries... 0/' + total);

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const name = entry.entryName;

      // Only process MAL-*.json files (malware), skip GHSA-*, CVE-*, PYSEC-* etc.
      if (!name.startsWith('MAL-') || !name.endsWith('.json')) {
        skippedCount++;
      } else {
        try {
          const content = entry.getData().toString('utf8');
          const vuln = JSON.parse(content);
          const parsed = parseOSVEntry(vuln, 'osv-malicious');
          for (const p of parsed) packages.push(p);

          // Track known IDs so OSSF can skip them
          knownIds.add(vuln.id || path.basename(name, '.json'));
          malCount++;
        } catch {
          // Skip unparseable entries
        }
      }

      if ((i + 1) % 1000 === 0 || i === entries.length - 1) {
        spinner.update('Parsing npm entries... ' + (i + 1) + '/' + total);
      }
    }

    spinner.succeed('Parsed npm entries: ' + malCount + ' MAL-* (' + skippedCount + ' skipped) \u2192 ' + packages.length + ' packages');
  } catch (e) {
    console.log('[SCRAPER]   Error: ' + e.message);
  }

  return { packages, knownIds };
}

// ============================================
// SOURCE 3c: OSV.dev PyPI data dump
// Bulk zip download — PyPI malicious packages
// ============================================
async function scrapeOSVPyPIDataDump() {
  const packages = [];

  try {
    const zipUrl = 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip';
    const zipBuffer = await fetchBufferWithProgress(zipUrl, 'PyPI all.zip');

    const zip = new AdmZip(zipBuffer);
    const entries = zip.getEntries();
    const total = entries.length;

    let malCount = 0;
    let skippedCount = 0;

    const spinner = new Spinner();
    spinner.start('Parsing PyPI entries... 0/' + total);

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const name = entry.entryName;

      // Only process MAL-*.json files (malware)
      if (!name.startsWith('MAL-') || !name.endsWith('.json')) {
        skippedCount++;
      } else {
        try {
          const content = entry.getData().toString('utf8');
          const vuln = JSON.parse(content);
          const parsed = parseOSVEntry(vuln, 'osv-malicious-pypi', 'PyPI');
          for (const p of parsed) packages.push(p);
          malCount++;
        } catch {
          // Skip unparseable entries
        }
      }

      if ((i + 1) % 1000 === 0 || i === entries.length - 1) {
        spinner.update('Parsing PyPI entries... ' + (i + 1) + '/' + total);
      }
    }

    spinner.succeed('Parsed PyPI entries: ' + malCount + ' MAL-* (' + skippedCount + ' skipped) \u2192 ' + packages.length + ' packages');
  } catch (e) {
    console.log('[SCRAPER]   Error: ' + e.message);
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
                  mitre: 'T1195.002',
                  freshness: createFreshness('github-advisory', 'high')
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
      mitre: 'T1195.002',
      freshness: createFreshness('socket', 'high')
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
      mitre: 'T1195.002',
      freshness: createFreshness('phylum', 'high')
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
      mitre: 'T1195.002',
      freshness: createFreshness('npm-removed', 'medium')
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
      mitre: 'T1195.002',
      freshness: createFreshness('snyk', 'high')
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
  console.log('  MUAD\'DIB IOC Scraper v4.0');
  console.log('  OSV + OSSF + GenSecAI + DataDog + Snyk');
  console.log('='.repeat(60) + '\n');

  // Create data directory if needed
  const dataDir = path.dirname(IOC_FILE);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Verify write permission (CROSS-001)
  try {
    fs.accessSync(dataDir, fs.constants.W_OK);
  } catch {
    throw new Error(`Data directory is not writable: ${dataDir}`);
  }

  // Load existing IOCs
  let existingIOCs = { packages: [], pypi_packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    try {
      existingIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
      if (!existingIOCs.pypi_packages) existingIOCs.pypi_packages = [];
    } catch {
      console.log('[WARN] IOCs file corrupted, resetting...');
    }
  }

  const initialCount = existingIOCs.packages.length;
  const initialPyPICount = existingIOCs.pypi_packages.length;
  const initialHashCount = existingIOCs.hashes ? existingIOCs.hashes.length : 0;

  console.log('[INFO] Existing IOCs: ' + initialCount + ' packages, ' + initialHashCount + ' hashes\n');

  // Phase 1: OSV data dump first (bulk, primary source)
  // This returns knownIds so OSSF can skip already-known entries
  const osvResult = await scrapeOSVDataDump();

  // Phase 2: All other sources in parallel (including PyPI dump)
  // OSSF receives knownIds from OSV to avoid redundant fetches
  const results = await Promise.all([
    scrapeShaiHuludDetector(),
    scrapeDatadogIOCs(),
    scrapeOSSFMaliciousPackages(osvResult.knownIds),
    scrapeGitHubAdvisory(),
    scrapeStaticIOCs(),
    scrapeSnykMalware(),
    scrapeOSVPyPIDataDump()
  ]);

  const shaiHuludResult = results[0];
  const datadogResult = results[1];
  const ossfPackages = results[2];
  const githubPackages = results[3];
  const staticPackages = results[4];
  const snykPackages = results[5];
  const pypiPackages = results[6];

  // Merge all scraped packages
  const allPackages = [
    ...osvResult.packages,
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

  // Smart deduplication: build map of best entry per key
  // For duplicates, keep the one with highest confidence, then most recent date
  const dedupMap = new Map();

  // Seed with existing IOCs
  for (const pkg of existingIOCs.packages) {
    const key = pkg.name + '@' + pkg.version;
    dedupMap.set(key, pkg);
  }

  // Merge new IOCs with smart replacement
  let addedPackages = 0;
  let upgradedPackages = 0;
  for (const pkg of allPackages) {
    const key = pkg.name + '@' + pkg.version;
    if (!dedupMap.has(key)) {
      dedupMap.set(key, pkg);
      addedPackages++;
    } else {
      const existing = dedupMap.get(key);
      const existingConf = CONFIDENCE_ORDER[existing.confidence] || 0;
      const newConf = CONFIDENCE_ORDER[pkg.confidence] || 0;
      if (newConf > existingConf) {
        dedupMap.set(key, pkg);
        upgradedPackages++;
      } else if (newConf === existingConf) {
        // Same confidence: keep most recent
        const existingDate = existing.published || (existing.freshness && existing.freshness.added_at) || '';
        const newDate = pkg.published || (pkg.freshness && pkg.freshness.added_at) || '';
        if (newDate > existingDate) {
          dedupMap.set(key, pkg);
          upgradedPackages++;
        }
      }
    }
  }

  // Rebuild packages array from dedup map
  existingIOCs.packages = [...dedupMap.values()];

  // PyPI deduplication (same logic, separate array)
  const pypiDedupMap = new Map();
  for (const pkg of existingIOCs.pypi_packages) {
    const key = pkg.name + '@' + pkg.version;
    pypiDedupMap.set(key, pkg);
  }
  let addedPyPIPackages = 0;
  for (const pkg of pypiPackages) {
    const key = pkg.name + '@' + pkg.version;
    if (!pypiDedupMap.has(key)) {
      pypiDedupMap.set(key, pkg);
      addedPyPIPackages++;
    } else {
      const existing = pypiDedupMap.get(key);
      const existingConf = CONFIDENCE_ORDER[existing.confidence] || 0;
      const newConf = CONFIDENCE_ORDER[pkg.confidence] || 0;
      if (newConf > existingConf) {
        pypiDedupMap.set(key, pkg);
      }
    }
  }
  existingIOCs.pypi_packages = [...pypiDedupMap.values()];

  // Deduplicate and add new hashes
  const existingHashes = new Set(existingIOCs.hashes || []);
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
    'osv-malicious',
    'osv-malicious-pypi',
    'ossf-malicious',
    'shai-hulud-detector',
    'datadog-consolidated',
    'datadog-direct',
    'github-advisory',
    'socket-dev',
    'phylum',
    'npm-removed',
    'snyk-known'
  ];

  // Save enriched (full) IOCs — atomic write via .tmp + rename
  const saveSpinner = new Spinner();
  saveSpinner.start('Saving IOCs...');
  const tmpIOCFile = IOC_FILE + '.tmp';
  fs.writeFileSync(tmpIOCFile, JSON.stringify(existingIOCs, null, 2));
  fs.renameSync(tmpIOCFile, IOC_FILE);

  // Save compact IOCs (lightweight, shipped in npm) — atomic write
  saveSpinner.update('Generating compact IOCs...');
  const compactIOCs = generateCompactIOCs(existingIOCs);
  const tmpCompactFile = COMPACT_IOC_FILE + '.tmp';
  fs.writeFileSync(tmpCompactFile, JSON.stringify(compactIOCs));
  fs.renameSync(tmpCompactFile, COMPACT_IOC_FILE);
  saveSpinner.succeed('Saved IOCs + compact format');

  // Display summary
  console.log('\n' + '='.repeat(60));
  console.log('  RESULTS');
  console.log('='.repeat(60));
  console.log('  npm packages before:  ' + initialCount);
  console.log('  npm packages after:   ' + existingIOCs.packages.length);
  console.log('  New npm:              +' + addedPackages);
  console.log('  Upgraded:             ' + upgradedPackages);
  console.log('  PyPI packages before: ' + initialPyPICount);
  console.log('  PyPI packages after:  ' + existingIOCs.pypi_packages.length);
  console.log('  New PyPI:             +' + addedPyPIPackages);
  console.log('  Hashes before:        ' + initialHashCount);
  console.log('  Hashes after:     ' + (existingIOCs.hashes ? existingIOCs.hashes.length : 0));
  console.log('  New hashes:       +' + addedHashes);
  console.log('  File:             ' + IOC_FILE);

  // Stats by source (npm + PyPI combined)
  console.log('\n  Distribution by source:');
  const sourceCounts = {};
  for (const pkg of existingIOCs.packages) {
    sourceCounts[pkg.source] = (sourceCounts[pkg.source] || 0) + 1;
  }
  for (const pkg of existingIOCs.pypi_packages) {
    sourceCounts[pkg.source] = (sourceCounts[pkg.source] || 0) + 1;
  }
  const sortedSources = Object.entries(sourceCounts).sort(function(a, b) { return b[1] - a[1]; });
  for (const [source, count] of sortedSources) {
    console.log('     - ' + source + ': ' + count);
  }

  // Target check
  const total = existingIOCs.packages.length;
  if (total >= 5000) {
    console.log('\n  [OK] Target reached: ' + total + ' IOCs (>= 5000)');
  } else {
    console.log('\n  [WARN] Target NOT reached: ' + total + ' IOCs (< 5000)');
  }

  console.log('\n');

  return {
    added: addedPackages,
    total: existingIOCs.packages.length,
    upgraded: upgradedPackages,
    addedHashes: addedHashes,
    totalHashes: existingIOCs.hashes ? existingIOCs.hashes.length : 0,
    addedPyPI: addedPyPIPackages,
    totalPyPI: existingIOCs.pypi_packages.length
  };
}

module.exports = { runScraper, scrapeShaiHuludDetector, scrapeDatadogIOCs };

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