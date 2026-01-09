const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { loadCachedIOCs } = require('./ioc/updater.js');

// Packages connus sûrs qui utilisent des patterns "suspects" légitimement
const TRUSTED_PACKAGES = [
  'lodash', 'underscore', 'express', 'react', 'vue', 'angular',
  'webpack', 'babel', 'typescript', 'esbuild', 'vite', 'rollup',
  'jest', 'mocha', 'chai', 'sharp', 'bcrypt', 'argon2'
];

// Cache pour eviter de scanner deux fois le meme package
const scannedPackages = new Set();

// Verifier si un package est dans les IOCs
function checkIOCs(pkg, pkgName) {
  try {
    const iocs = loadCachedIOCs();
    return iocs.packages?.find(p => p.name === pkg || p.name === pkgName);
  } catch (e) {
    return null;
  }
}

// Scanner un package et ses dependances recursivement
async function scanPackageRecursive(pkg, depth = 0, maxDepth = 3) {
  const indent = '  '.repeat(depth);
  const pkgName = pkg.replace(/^@[^/]+\//, '').split('@')[0];
  
  // Eviter les boucles infinies
  if (scannedPackages.has(pkg) || scannedPackages.has(pkgName)) {
    return { safe: true };
  }
  scannedPackages.add(pkg);
  scannedPackages.add(pkgName);
  
  // Skip trusted packages
  if (TRUSTED_PACKAGES.includes(pkgName)) {
    if (depth === 0) console.log(`[OK] ${pkg} - Package de confiance`);
    return { safe: true };
  }
  
  // Limiter la profondeur
  if (depth > maxDepth) {
    return { safe: true };
  }
  
  if (depth === 0) {
    console.log(`[*] Analyse de ${pkg}...`);
  } else {
    console.log(`${indent}[*] Dependance: ${pkg}`);
  }
  
  // Verifier IOCs
  const malicious = checkIOCs(pkg, pkgName);
  if (malicious) {
    return {
      safe: false,
      package: pkg,
      reason: 'known_malicious',
      source: malicious.source || 'IOC Database',
      description: malicious.description || 'Package malveillant connu',
      depth
    };
  }
  
  // Recuperer les infos du package
  let pkgInfo;
  try {
    const infoRaw = execSync(`npm view ${pkg} --json 2>nul`, { encoding: 'utf8' });
    pkgInfo = JSON.parse(infoRaw);
  } catch (e) {
    if (depth === 0) console.log(`[!] Package ${pkg} introuvable sur npm`);
    return { safe: true };
  }
  
  // Scanner les dependances
  const dependencies = pkgInfo.dependencies || {};
  const depNames = Object.keys(dependencies);
  
  if (depNames.length > 0 && depth < maxDepth) {
    for (const depName of depNames) {
      const depVersion = dependencies[depName];
      const depPkg = depName; // On check juste le nom, pas la version specifique
      
      const result = await scanPackageRecursive(depPkg, depth + 1, maxDepth);
      if (!result.safe) {
        return result;
      }
    }
  }
  
  if (depth === 0) {
    console.log(`[OK] ${pkg} - Aucune menace (${depNames.length} dependances scannees)`);
  }
  
  return { safe: true };
}

async function safeInstall(packages, options = {}) {
  const { isDev, isGlobal, force } = options;
  
  console.log(`
╔══════════════════════════════════════════╗
║   MUAD'DIB Safe Install                  ║
║   Scanning packages + dependencies...    ║
╚══════════════════════════════════════════╝
`);

  // Reset le cache pour chaque install
  scannedPackages.clear();
  
  try {
    for (const pkg of packages) {
      const result = await scanPackageRecursive(pkg);
      
      if (!result.safe) {
        console.log(`
╔══════════════════════════════════════════╗
║   [!] PACKAGE MALVEILLANT DETECTE        ║
╚══════════════════════════════════════════╝
`);
        if (result.depth > 0) {
          console.log(`Package demande: ${pkg}`);
          console.log(`Dependance malveillante: ${result.package} (profondeur: ${result.depth})`);
        } else {
          console.log(`Package: ${result.package}`);
        }
        console.log(`Source: ${result.source}`);
        console.log(`Raison: ${result.description}`);
        console.log('');
        
        if (!force) {
          console.log('[!] Installation BLOQUEE.');
          return { blocked: true, package: result.package, threats: [{ type: 'known_malicious', severity: 'CRITICAL', message: result.description }] };
        } else {
          console.log('[!] --force active, installation malgre les menaces...');
        }
      }
    }

    // Tout est clean, installer pour de vrai
    console.log('');
    console.log('[*] Installation en cours...');
    
    let cmd = `npm install ${packages.join(' ')}`;
    if (isDev) cmd += ' --save-dev';
    if (isGlobal) cmd += ' -g';
    
    execSync(cmd, { stdio: 'inherit' });
    
    console.log('');
    console.log('[OK] Installation terminee.');
    
    return { blocked: false };

  } catch (e) {
    throw e;
  }
}

module.exports = { safeInstall };