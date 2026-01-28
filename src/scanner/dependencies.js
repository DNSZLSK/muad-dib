const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');

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

// Packages qui ont ete compromis temporairement mais sont maintenant safe
// Format: { name: { safe_after: "version", compromised: ["version1", "version2"] } }
const REHABILITATED_PACKAGES = {
  // Septembre 2025 - Compromission massive via phishing, corrige en quelques heures
  'chalk': {
    compromised: [],  // Versions malveillantes retirees de npm
    safe: true,       // Toutes versions actuelles sont safe
    note: 'Compromis sept 2025, versions malveillantes retirees'
  },
  'debug': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'ansi-styles': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'strip-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'wrap-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'is-arrayish': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'simple-swizzle': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'color-convert': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'supports-color': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  'has-flag': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, corrige rapidement'
  },
  
  // Packages avec versions specifiques compromises (pas toutes)
  'ua-parser-js': {
    compromised: ['0.7.29', '0.8.0', '1.0.0'],
    safe: false,  // Seulement les versions non-compromised sont safe
    note: 'Versions specifiques compromises oct 2021'
  },
  'coa': {
    compromised: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
    safe: false,
    note: 'Versions specifiques compromises nov 2021'
  },
  'rc': {
    compromised: ['1.2.9', '1.3.9', '2.3.9'],
    safe: false,
    note: 'Versions specifiques compromises nov 2021'
  },
  
  // Notre propre package et dependances connues safe
  'muaddib-scanner': {
    compromised: [],
    safe: true,
    note: 'Notre package'
  },
  'acorn': {
    compromised: [],
    safe: true,
    note: 'Parser AST legitime'
  },
  'acorn-walk': {
    compromised: [],
    safe: true,
    note: 'Parser AST legitime'
  }
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
  if (rehab.compromised.includes(pkgVersion)) {
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
        file: `node_modules/${pkg.name}`
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
      maliciousPkg = pkgList.find(p => p.version === pkg.version);
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
    // Utilise Set ou Array selon la structure disponible
    const suspiciousFiles = iocs.filesSet || iocs.files || [];
    const filesToCheck = suspiciousFiles instanceof Set
      ? Array.from(suspiciousFiles)
      : suspiciousFiles;

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
        // Utilise Set ou Array selon la structure disponible
        const markers = iocs.markersSet || iocs.markers || [];
        const markersToCheck = markers instanceof Set
          ? Array.from(markers)
          : markers;

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
      const stat = fs.statSync(itemPath);
      if (!stat.isDirectory()) continue;

      if (item.startsWith('@')) {
        const scopedItems = fs.readdirSync(itemPath);
        for (const scopedItem of scopedItems) {
          const scopedPath = path.join(itemPath, scopedItem);
          if (fs.statSync(scopedPath).isDirectory()) {
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
  REHABILITATED_PACKAGES,
  TRUSTED_PACKAGES,
  SAFE_FILES
};