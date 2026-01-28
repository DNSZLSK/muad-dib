const { spawnSync } = require('child_process');
const { loadCachedIOCs } = require('./ioc/updater.js');

// Regex to validate npm package names (prevents command injection)
const NPM_PACKAGE_REGEX = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

/**
 * Validates that a package name is safe (no command injection)
 * @param {string} pkgName - Package name
 * @returns {boolean} true if valid
 */
function isValidPackageName(pkgName) {
  // Remove version if present
  const nameOnly = pkgName.split('@').filter((p, i) => i === 0 || !p.match(/^\d/)).join('@');
  return NPM_PACKAGE_REGEX.test(nameOnly) || (nameOnly.startsWith('@') && NPM_PACKAGE_REGEX.test(nameOnly));
}

// Known safe packages that legitimately use "suspicious" patterns
const TRUSTED_PACKAGES = [
  'lodash', 'underscore', 'express', 'react', 'vue', 'angular',
  'webpack', 'babel', 'typescript', 'esbuild', 'vite', 'rollup',
  'jest', 'mocha', 'chai', 'sharp', 'bcrypt', 'argon2'
];

// Packages that were temporarily compromised but are now safe
// These packages will NOT be blocked (except specific compromised versions)
const REHABILITATED_PACKAGES = {
  // September 2025 - Massive compromise via phishing, fixed within hours
  'chalk': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, malicious versions removed from npm'
  },
  'debug': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'ansi-styles': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'strip-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'wrap-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'is-arrayish': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'simple-swizzle': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'color-convert': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'supports-color': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'has-flag': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },

  // Packages with specific compromised versions (not all)
  'ua-parser-js': {
    compromised: ['0.7.29', '0.8.0', '1.0.0'],
    safe: false,
    note: 'Specific versions compromised Oct 2021'
  },
  'coa': {
    compromised: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
    safe: false,
    note: 'Specific versions compromised Nov 2021'
  },
  'rc': {
    compromised: ['1.2.9', '1.3.9', '2.3.9'],
    safe: false,
    note: 'Specific versions compromised Nov 2021'
  },

  // MUAD'DIB and dependencies
  'muaddib-scanner': {
    compromised: [],
    safe: true,
    note: 'Our package'
  },
  'acorn': {
    compromised: [],
    safe: true,
    note: 'Legitimate AST parser'
  },
  'acorn-walk': {
    compromised: [],
    safe: true,
    note: 'Legitimate AST parser'
  },
  '@inquirer/prompts': {
    compromised: [],
    safe: true,
    note: 'Legitimate dependency'
  }
};

// Cache to avoid scanning the same package twice
const scannedPackages = new Set();

/**
 * Checks if a package is rehabilitated (temporarily compromised then fixed)
 * @returns {object|null} null if not rehabilitated, otherwise {safe: bool, note: string}
 */
function checkRehabilitated(pkgName, pkgVersion) {
  const rehab = REHABILITATED_PACKAGES[pkgName];
  if (!rehab) return null;

  // If marked as safe = all current versions are OK
  if (rehab.safe === true) {
    return { safe: true, note: rehab.note };
  }

  // Otherwise check if the version is in the compromised list
  if (pkgVersion && rehab.compromised.includes(pkgVersion)) {
    return { safe: false, note: rehab.note };
  }

  // Version not in the compromised list = safe
  return { safe: true, note: rehab.note };
}

// Check if a package is in the IOCs
function checkIOCs(pkg, pkgName, pkgVersion) {
  // First check the whitelist of rehabilitated packages
  const rehabStatus = checkRehabilitated(pkgName, pkgVersion);
  if (rehabStatus) {
    if (rehabStatus.safe) {
      return null; // Rehabilitated and safe package, no threat
    } else {
      // Specifically compromised version of a rehabilitated package
      return {
        name: pkgName,
        source: 'rehabilitated-compromised',
        description: `Compromised version: ${rehabStatus.note}`
      };
    }
  }

  // Not in the whitelist, check the IOCs
  try {
    const iocs = loadCachedIOCs();
    const malicious = iocs.packages?.find(p => {
      if (p.name !== pkg && p.name !== pkgName) return false;
      // If version "*" in IOC = all versions are malicious
      if (p.version === '*') return true;
      // If we have a version, compare
      if (pkgVersion && p.version === pkgVersion) return true;
      // Otherwise, if no version specified and IOC has a specific version, skip
      return false;
    });
    return malicious || null;
  } catch {
    return null;
  }
}

// Scan a package and its dependencies recursively
async function scanPackageRecursive(pkg, depth = 0, maxDepth = 3) {
  const indent = '  '.repeat(depth);

  // Extract name and version of the package
  let pkgName = pkg;
  let pkgVersion = null;

  // Handle scoped packages (@scope/name) and versions (@scope/name@version or name@version)
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
  
  // Avoid infinite loops
  if (scannedPackages.has(pkgName)) {
    return { safe: true };
  }
  scannedPackages.add(pkgName);
  
  // Skip trusted packages
  if (TRUSTED_PACKAGES.includes(pkgBaseName) || TRUSTED_PACKAGES.includes(pkgName)) {
    if (depth === 0) console.log(`[OK] ${pkg} - Trusted package`);
    return { safe: true };
  }
  
  // Limit the depth
  if (depth > maxDepth) {
    return { safe: true };
  }
  
  if (depth === 0) {
    console.log(`[*] Analyzing ${pkg}...`);
  } else {
    console.log(`${indent}[*] Dependency: ${pkgName}`);
  }
  
  // Check IOCs (with whitelist)
  const malicious = checkIOCs(pkg, pkgName, pkgVersion);
  if (malicious) {
    return {
      safe: false,
      package: pkgName,
      reason: 'known_malicious',
      source: malicious.source || 'IOC Database',
      description: malicious.description || 'Known malicious package',
      depth
    };
  }

  // Validate the package name (security: prevent command injection)
  if (!isValidPackageName(pkgName)) {
    console.log(`[!] Invalid package name: ${pkgName}`);
    return { safe: false, package: pkgName, reason: 'invalid_name', source: 'validation', description: 'Invalid or suspicious package name', depth };
  }

  // Get the package info (uses spawnSync to avoid injection)
  let pkgInfo;
  try {
    const result = spawnSync('npm', ['view', pkgName, '--json'], { encoding: 'utf8', shell: false });
    if (result.status !== 0 || !result.stdout) {
      if (depth === 0) console.log(`[!] Package ${pkgName} not found on npm`);
      return { safe: true };
    }
    pkgInfo = JSON.parse(result.stdout);
  } catch {
    if (depth === 0) console.log(`[!] Package ${pkgName} not found on npm`);
    return { safe: true };
  }
  
  // Scan the dependencies
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
    console.log(`[OK] ${pkg} - No threats (${depNames.length} dependencies scanned)`);
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

  // Reset the cache for each install
  scannedPackages.clear();
  
  for (const pkg of packages) {
    const result = await scanPackageRecursive(pkg);
    
    if (!result.safe) {
      console.log(`
╔══════════════════════════════════════════╗
║   [!] MALICIOUS PACKAGE DETECTED         ║
╚══════════════════════════════════════════╝
`);
      if (result.depth > 0) {
        console.log(`Requested package: ${pkg}`);
        console.log(`Malicious dependency: ${result.package} (depth: ${result.depth})`);
      } else {
        console.log(`Package: ${result.package}`);
      }
      console.log(`Source: ${result.source}`);
      console.log(`Reason: ${result.description}`);
      console.log('');

      if (!force) {
        console.log('[!] Installation BLOCKED.');
        return { blocked: true, package: result.package, threats: [{ type: 'known_malicious', severity: 'CRITICAL', message: result.description }] };
      } else {
        console.log('[!] --force enabled, installing despite threats...');
      }
    }
  }

  // Validate all package names before installation
  for (const pkg of packages) {
    const pkgNameOnly = pkg.split('@').filter((p, i) => i === 0 || !p.match(/^\d/)).join('@');
    if (!isValidPackageName(pkgNameOnly)) {
      console.log(`[!] Invalid package name: ${pkg}`);
      return { blocked: true, package: pkg, threats: [{ type: 'invalid_name', severity: 'HIGH', message: 'Invalid or suspicious package name' }] };
    }
  }

  // Everything is clean, install for real (uses spawnSync to avoid injection)
  console.log('');
  console.log('[*] Installation in progress...');

  const npmArgs = ['install', ...packages];
  if (isDev) npmArgs.push('--save-dev');
  if (isGlobal) npmArgs.push('-g');

  const result = spawnSync('npm', npmArgs, { stdio: 'inherit', shell: false });

  if (result.status !== 0) {
    console.log('');
    console.log('[!] Error during installation.');
    return { blocked: false, error: true };
  }

  console.log('');
  console.log('[OK] Installation complete.');

  return { blocked: false };
}

module.exports = { safeInstall, REHABILITATED_PACKAGES, checkRehabilitated, isValidPackageName };