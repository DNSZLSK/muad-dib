const { execSync } = require('child_process');
const { loadCachedIOCs } = require('./ioc/updater.js');

// Packages connus sûrs qui utilisent des patterns "suspects" légitimement
const TRUSTED_PACKAGES = [
  'lodash', 'underscore', 'express', 'react', 'vue', 'angular',
  'webpack', 'babel', 'typescript', 'esbuild', 'vite', 'rollup',
  'jest', 'mocha', 'chai', 'sharp', 'bcrypt', 'argon2'
];

// Packages qui ont ete compromis temporairement mais sont maintenant safe
// Ces packages ne seront PAS bloques (sauf versions specifiques compromises)
const REHABILITATED_PACKAGES = {
  // Septembre 2025 - Compromission massive via phishing, corrige en quelques heures
  'chalk': {
    compromised: [],
    safe: true,
    note: 'Compromis sept 2025, versions malveillantes retirees de npm'
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
    safe: false,
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
  
  // MUAD'DIB et dependances
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
  },
  '@inquirer/prompts': {
    compromised: [],
    safe: true,
    note: 'Dependance legitime'
  }
};

// Cache pour eviter de scanner deux fois le meme package
const scannedPackages = new Set();

/**
 * Verifie si un package est rehabilite (compromis temporairement puis corrige)
 * @returns {object|null} null si pas rehabilite, sinon {safe: bool, note: string}
 */
function checkRehabilitated(pkgName, pkgVersion) {
  const rehab = REHABILITATED_PACKAGES[pkgName];
  if (!rehab) return null;
  
  // Si marque comme safe = toutes versions actuelles sont OK
  if (rehab.safe === true) {
    return { safe: true, note: rehab.note };
  }
  
  // Sinon verifier si la version est dans la liste des compromises
  if (pkgVersion && rehab.compromised.includes(pkgVersion)) {
    return { safe: false, note: rehab.note };
  }
  
  // Version pas dans la liste des compromises = safe
  return { safe: true, note: rehab.note };
}

// Verifier si un package est dans les IOCs
function checkIOCs(pkg, pkgName, pkgVersion) {
  // D'abord verifier la whitelist des packages rehabilites
  const rehabStatus = checkRehabilitated(pkgName, pkgVersion);
  if (rehabStatus) {
    if (rehabStatus.safe) {
      return null; // Package rehabilite et safe, pas de menace
    } else {
      // Version specifiquement compromise d'un package rehabilite
      return {
        name: pkgName,
        source: 'rehabilitated-compromised',
        description: `Version compromise: ${rehabStatus.note}`
      };
    }
  }
  
  // Pas dans la whitelist, verifier les IOCs
  try {
    const iocs = loadCachedIOCs();
    const malicious = iocs.packages?.find(p => {
      if (p.name !== pkg && p.name !== pkgName) return false;
      // Si version "*" dans IOC = toutes versions malveillantes
      if (p.version === '*') return true;
      // Si on a une version, comparer
      if (pkgVersion && p.version === pkgVersion) return true;
      // Sinon, si pas de version specifiee et IOC a une version specifique, skip
      return false;
    });
    return malicious || null;
  } catch {
    return null;
  }
}

// Scanner un package et ses dependances recursivement
async function scanPackageRecursive(pkg, depth = 0, maxDepth = 3) {
  const indent = '  '.repeat(depth);
  
  // Extraire nom et version du package
  let pkgName = pkg;
  let pkgVersion = null;
  
  // Gerer les scoped packages (@scope/name) et versions (@scope/name@version ou name@version)
  if (pkg.startsWith('@')) {
    // Scoped package
    const parts = pkg.slice(1).split('@');
    if (parts.length >= 2 && parts[parts.length - 1].match(/^\d/)) {
      pkgVersion = parts.pop();
      pkgName = '@' + parts.join('@');
    }
  } else {
    const parts = pkg.split('@');
    if (parts.length >= 2 && parts[parts.length - 1].match(/^\d/)) {
      pkgVersion = parts.pop();
      pkgName = parts.join('@');
    }
  }
  
  const pkgBaseName = pkgName.replace(/^@[^/]+\//, '');
  
  // Eviter les boucles infinies
  if (scannedPackages.has(pkgName)) {
    return { safe: true };
  }
  scannedPackages.add(pkgName);
  
  // Skip trusted packages
  if (TRUSTED_PACKAGES.includes(pkgBaseName) || TRUSTED_PACKAGES.includes(pkgName)) {
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
    console.log(`${indent}[*] Dependance: ${pkgName}`);
  }
  
  // Verifier IOCs (avec whitelist)
  const malicious = checkIOCs(pkg, pkgName, pkgVersion);
  if (malicious) {
    return {
      safe: false,
      package: pkgName,
      reason: 'known_malicious',
      source: malicious.source || 'IOC Database',
      description: malicious.description || 'Package malveillant connu',
      depth
    };
  }
  
  // Recuperer les infos du package
  let pkgInfo;
  try {
    const infoRaw = execSync(`npm view ${pkgName} --json 2>nul`, { encoding: 'utf8' });
    pkgInfo = JSON.parse(infoRaw);
  } catch {
    if (depth === 0) console.log(`[!] Package ${pkgName} introuvable sur npm`);
    return { safe: true };
  }
  
  // Scanner les dependances
  const dependencies = pkgInfo.dependencies || {};
  const depNames = Object.keys(dependencies);
  
  if (depNames.length > 0 && depth < maxDepth) {
    for (const depName of depNames) {
      const result = await scanPackageRecursive(depName, depth + 1, maxDepth);
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
}

module.exports = { safeInstall, REHABILITATED_PACKAGES, checkRehabilitated };