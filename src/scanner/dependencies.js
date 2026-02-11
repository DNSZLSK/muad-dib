const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { REHABILITATED_PACKAGES } = require('../shared/constants.js');

// Packages legitimes avec lifecycle scripts (ne pas alerter)
const TRUSTED_PACKAGES = [
  'esbuild', 'sharp', 'bcrypt', 'node-sass', 'puppeteer',
  'playwright', 'sqlite3', 'better-sqlite3', 'canvas',
  'grpc', 'fsevents', 'msgpackr-extract', 'lmdb', 'parcel',
  'electron', 'node-gyp', 'prebuild-install', 'nan'
];

// Fichiers legitimes qui ressemblent a des fichiers suspects
const SAFE_FILES = {
  'inject.js': ['async', 'awilix', 'inversify', 'bottlejs'],
  'install.js': ['esbuild', 'sharp', 'bcrypt', 'node-sass', 'puppeteer', 'playwright', 'electron']
};

/**
 * Verifie si un package est dans la whitelist des packages rehabilites
 * @returns {boolean|null} true = safe, false = compromis, null = pas dans whitelist
 */
function checkRehabilitatedPackage(pkgName, pkgVersion) {
  const rehab = REHABILITATED_PACKAGES[pkgName];
  if (!rehab) return null;  // Pas dans la whitelist
  
  // Si marque comme safe = toutes versions sont OK
  if (rehab.safe === true) return true;
  
  // Sinon, verifier si la version est dans la liste des compromises
  if (rehab.compromised && rehab.compromised.includes(pkgVersion)) {
    return false;  // Version specifiquement compromise
  }
  
  return true;  // Version pas dans la liste des compromises = safe
}

async function scanDependencies(targetPath) {
  const threats = [];
  const nodeModulesPath = path.join(targetPath, 'node_modules');
  const iocs = loadCachedIOCs();

  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  const packages = listPackages(nodeModulesPath);

  // Pre-compute files and markers lists once (outside the loop)
  const suspiciousFilesRaw = iocs.filesSet || iocs.files || [];
  const filesToCheck = suspiciousFilesRaw instanceof Set
    ? Array.from(suspiciousFilesRaw)
    : suspiciousFilesRaw;

  const markersRaw = iocs.markersSet || iocs.markers || [];
  const markersToCheck = markersRaw instanceof Set
    ? Array.from(markersRaw)
    : markersRaw;

  for (const pkg of packages) {
    // D'abord verifier la whitelist des packages rehabilites
    const rehabStatus = checkRehabilitatedPackage(pkg.name, pkg.version);
    
    if (rehabStatus === true) {
      // Package rehabilite et version safe, skip
      continue;
    }
    
    if (rehabStatus === false) {
      // Package rehabilite mais version specifiquement compromise
      const rehab = REHABILITATED_PACKAGES[pkg.name];
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Version compromise: ${pkg.name}@${pkg.version} (${rehab.note})`,
        file: `node_modules/${pkg.name}`,
        source: 'rehabilitated'
      });
      continue;
    }
    
    // rehabStatus === null : pas dans whitelist, continuer verification normale

    // Verifie si package connu malveillant (IOCs caches) AVEC VERSION
    // Utilise Map/Set pour lookup O(1) au lieu de O(n)
    let maliciousPkg = null;

    // Check 1: Package avec wildcard (toutes versions malveillantes)
    if (iocs.wildcardPackages && iocs.wildcardPackages.has(pkg.name)) {
      const pkgList = iocs.packagesMap.get(pkg.name);
      maliciousPkg = pkgList ? pkgList.find(p => p.version === '*') : null;
    }
    // Check 2: Version specifique via Map
    else if (iocs.packagesMap && iocs.packagesMap.has(pkg.name)) {
      const pkgList = iocs.packagesMap.get(pkg.name);
      maliciousPkg = pkgList ? pkgList.find(p => p.version === pkg.version) : null;
    }
    // Fallback: recherche lineaire (compatibilite ancienne API)
    else if (!iocs.packagesMap) {
      maliciousPkg = iocs.packages.find(p => {
        if (p.name !== pkg.name) return false;
        if (p.version === '*') return true;
        return p.version === pkg.version;
      });
    }

    if (maliciousPkg) {
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Package malveillant connu: ${pkg.name}@${maliciousPkg.version} (source: ${maliciousPkg.source})`,
        file: `node_modules/${pkg.name}`
      });
      continue;
    }

    // Skip trusted packages pour les checks suivants
    if (TRUSTED_PACKAGES.includes(pkg.name)) continue;

    // Verifie les fichiers suspects (IOCs caches) avec whitelist
    for (const suspFile of filesToCheck) {
      // Skip si fichier legitime pour ce package
      if (SAFE_FILES[suspFile] && SAFE_FILES[suspFile].includes(pkg.name)) {
        continue;
      }

      const filePath = path.join(pkg.path, suspFile);
      if (fs.existsSync(filePath)) {
        threats.push({
          type: 'suspicious_file',
          severity: 'HIGH',
          message: `Fichier suspect "${suspFile}" dans ${pkg.name}`,
          file: `node_modules/${pkg.name}/${suspFile}`
        });
      }
    }

    // Verifie les lifecycle scripts
    const pkgJsonPath = path.join(pkg.path, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      try {
        const pkgContent = fs.readFileSync(pkgJsonPath, 'utf8');

        // Verifie les marqueurs Shai-Hulud
        for (const marker of markersToCheck) {
          if (pkgContent.includes(marker)) {
            threats.push({
              type: 'shai_hulud_marker',
              severity: 'CRITICAL',
              message: `Marqueur "${marker}" detecte dans ${pkg.name}`,
              file: `node_modules/${pkg.name}/package.json`
            });
          }
        }
      } catch {
        // JSON parse error, skip
      }
    }
  }

  return threats;
}

function listPackages(nodeModulesPath) {
  const packages = [];
  const items = fs.readdirSync(nodeModulesPath);

  for (const item of items) {
    if (item.startsWith('.')) continue;

    const itemPath = path.join(nodeModulesPath, item);
    
    try {
      const stat = fs.lstatSync(itemPath);
      if (stat.isSymbolicLink()) continue;
      if (!stat.isDirectory()) continue;

      if (item.startsWith('@')) {
        const scopedItems = fs.readdirSync(itemPath);
        for (const scopedItem of scopedItems) {
          const scopedPath = path.join(itemPath, scopedItem);
          const scopedStat = fs.lstatSync(scopedPath);
          if (scopedStat.isSymbolicLink()) continue;
          if (scopedStat.isDirectory()) {
            const version = getPackageVersion(scopedPath);
            packages.push({
              name: `${item}/${scopedItem}`,
              path: scopedPath,
              version: version
            });
          }
        }
      } else {
        const version = getPackageVersion(itemPath);
        packages.push({
          name: item,
          path: itemPath,
          version: version
        });
      }
    } catch {
      // Skip inaccessible
    }
  }

  return packages;
}

function getPackageVersion(pkgPath) {
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgPath, 'package.json'), 'utf8'));
    return pkgJson.version || '*';
  } catch {
    return '*';
  }
}

module.exports = {
  scanDependencies,
  checkRehabilitatedPackage,
  TRUSTED_PACKAGES,
  SAFE_FILES
};