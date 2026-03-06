const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const IOCS_DIR = path.join(__dirname, '../../iocs');

/**
 * Read a YAML file with optional HMAC verification.
 * If a sibling .hmac file exists, verify integrity. Warn on mismatch but still load
 * (backward-compatible for pre-HMAC installs).
 * Uses lazy require to avoid circular dependency with updater.js.
 * @param {string} filePath - Path to the YAML file
 * @returns {string} Raw YAML content
 */
function readVerifiedYAML(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const hmacPath = filePath + '.hmac';
  if (fs.existsSync(hmacPath)) {
    try {
      const { verifyIOCHMAC } = require('./updater.js');
      const storedHmac = fs.readFileSync(hmacPath, 'utf8').trim();
      if (!verifyIOCHMAC(content, storedHmac)) {
        console.error(`[WARN] HMAC verification failed for ${path.basename(filePath)} — possible tampering`);
      }
    } catch (e) {
      console.error(`[WARN] Could not read HMAC file for ${path.basename(filePath)}: ${e.message}`);
    }
  }
  return content;
}

function loadYAMLIOCs() {
  const iocs = {
    packages: [],
    hashes: [],
    markers: [],
    files: []
  };

  // Dedup sets for O(1) lookup during loading
  const seenPkgs = new Set();
  const seenHashes = new Set();
  const seenMarkers = new Set();
  const seenFiles = new Set();

  // Charger packages.yaml
  loadPackagesYAML(path.join(IOCS_DIR, 'packages.yaml'), iocs, seenPkgs);

  // Charger builtin.yaml (fallback)
  loadBuiltinYAML(path.join(IOCS_DIR, 'builtin.yaml'), iocs, seenPkgs, seenHashes, seenMarkers, seenFiles);

  // Charger hashes.yaml
  loadHashesYAML(path.join(IOCS_DIR, 'hashes.yaml'), iocs, seenHashes, seenMarkers, seenFiles);

  return iocs;
}

function loadPackagesYAML(filePath, iocs, seenPkgs) {
  if (!fs.existsSync(filePath)) return;

  try {
    const data = yaml.load(readVerifiedYAML(filePath), { schema: yaml.JSON_SCHEMA });
    if (data && data.packages) {
      for (const p of data.packages) {
        if (!p.name || typeof p.name !== 'string') continue;
        const key = p.name + '@' + p.version;
        if (!seenPkgs.has(key)) {
          seenPkgs.add(key);
          iocs.packages.push({
            id: p.id,
            name: p.name,
            version: p.version,
            severity: p.severity || 'critical',
            confidence: p.confidence || 'high',
            source: p.source,
            description: p.description,
            references: p.references || [],
            mitre: p.mitre || 'T1195.002'
          });
        }
      }
    }
  } catch (e) {
    console.error('[WARN] Erreur parsing packages.yaml:', e.message);
  }
}

function loadBuiltinYAML(filePath, iocs, seenPkgs, seenHashes, seenMarkers, seenFiles) {
  if (!fs.existsSync(filePath)) return;

  try {
    const data = yaml.load(readVerifiedYAML(filePath), { schema: yaml.JSON_SCHEMA });

    // Packages
    if (data && data.packages) {
      for (const p of data.packages) {
        if (!p.name || typeof p.name !== 'string') continue;
        const key = p.name + '@' + p.version;
        if (!seenPkgs.has(key)) {
          seenPkgs.add(key);
          iocs.packages.push({
            id: `BUILTIN-${p.name}`,
            name: p.name,
            version: p.version,
            severity: p.severity || 'critical',
            confidence: p.confidence || 'high',
            source: p.source,
            description: p.description || `Malicious package: ${p.name}`,
            references: p.references || [],
            mitre: p.mitre || 'T1195.002'
          });
        }
      }
    }

    // Files
    if (data && data.files) {
      for (const f of data.files) {
        const fileName = typeof f === 'string' ? f : f.name;
        if (!seenFiles.has(fileName)) {
          seenFiles.add(fileName);
          iocs.files.push({
            id: `BUILTIN-FILE-${fileName}`,
            name: fileName,
            severity: 'critical',
            confidence: 'high',
            source: 'builtin',
            description: `Suspicious file: ${fileName}`
          });
        }
      }
    }

    // Hashes
    if (data && data.hashes) {
      for (const h of data.hashes) {
        const hash = typeof h === 'string' ? h : h.sha256;
        if (!seenHashes.has(hash)) {
          seenHashes.add(hash);
          iocs.hashes.push({
            id: `BUILTIN-HASH-${hash.slice(0, 12)}`,
            sha256: hash,
            severity: 'critical',
            confidence: 'high',
            source: 'builtin',
            description: 'Known malicious hash'
          });
        }
      }
    }

    // Markers
    if (data && data.markers) {
      for (const m of data.markers) {
        const pattern = typeof m === 'string' ? m : m.pattern;
        if (!seenMarkers.has(pattern)) {
          seenMarkers.add(pattern);
          iocs.markers.push({
            id: `BUILTIN-MARKER-${pattern.slice(0, 10)}`,
            pattern: pattern,
            severity: 'critical',
            confidence: 'high',
            source: 'builtin',
            description: `Malware marker: ${pattern}`
          });
        }
      }
    }
  } catch (e) {
    console.error('[WARN] Erreur parsing builtin.yaml:', e.message);
  }
}

function loadHashesYAML(filePath, iocs, seenHashes, seenMarkers, seenFiles) {
  if (!fs.existsSync(filePath)) return;

  try {
    const data = yaml.load(readVerifiedYAML(filePath), { schema: yaml.JSON_SCHEMA });

    if (data && data.hashes) {
      for (const h of data.hashes) {
        if (!seenHashes.has(h.sha256)) {
          seenHashes.add(h.sha256);
          iocs.hashes.push({
            id: h.id,
            sha256: h.sha256,
            file: h.file,
            severity: h.severity || 'critical',
            confidence: h.confidence || 'high',
            source: h.source,
            description: h.description,
            references: h.references || []
          });
        }
      }
    }

    if (data && data.markers) {
      for (const m of data.markers) {
        if (!seenMarkers.has(m.pattern)) {
          seenMarkers.add(m.pattern);
          iocs.markers.push({
            id: m.id,
            pattern: m.pattern,
            severity: m.severity || 'critical',
            confidence: m.confidence || 'high',
            source: m.source,
            description: m.description
          });
        }
      }
    }

    if (data && data.files) {
      for (const f of data.files) {
        if (!seenFiles.has(f.name)) {
          seenFiles.add(f.name);
          iocs.files.push({
            id: f.id,
            name: f.name,
            severity: f.severity || 'critical',
            confidence: f.confidence || 'high',
            source: f.source,
            description: f.description
          });
        }
      }
    }
  } catch (e) {
    console.error('[WARN] Erreur parsing hashes.yaml:', e.message);
  }
}

let _cachedIOCStats = null;

function getIOCStats() {
  if (_cachedIOCStats) return _cachedIOCStats;
  const iocs = loadYAMLIOCs();
  _cachedIOCStats = {
    packages: iocs.packages.length,
    hashes: iocs.hashes.length,
    markers: iocs.markers.length,
    files: iocs.files.length
  };
  return _cachedIOCStats;
}

/**
 * Generate .hmac signature files for the 3 YAML IOC files.
 * Call after updating YAML IOCs to sign them for integrity verification.
 */
function signYAMLIOCs() {
  const { generateIOCHMAC } = require('./updater.js');
  const yamlFiles = ['packages.yaml', 'builtin.yaml', 'hashes.yaml'];
  for (const file of yamlFiles) {
    const filePath = path.join(IOCS_DIR, file);
    if (!fs.existsSync(filePath)) continue;
    const content = fs.readFileSync(filePath, 'utf8');
    const hmac = generateIOCHMAC(content);
    fs.writeFileSync(filePath + '.hmac', hmac);
  }
}

module.exports = { loadYAMLIOCs, getIOCStats, readVerifiedYAML, signYAMLIOCs };
