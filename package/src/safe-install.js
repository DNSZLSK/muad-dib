const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadCachedIOCs } = require('./ioc/updater.js');
const { REHABILITATED_PACKAGES, NPM_PACKAGE_REGEX } = require('./shared/constants.js');

/**
 * Validates that a package name is safe (no command injection)
 * @param {string} pkgName - Package name
 * @returns {boolean} true if valid
 */
function isValidPackageName(pkgName) {
  // Remove version/tag suffix if present (e.g., pkg@1.0.0, @scope/pkg@latest)
  let nameOnly;
  if (pkgName.startsWith('@')) {
    // Scoped package: @scope/name or @scope/name@version
    const slashIdx = pkgName.indexOf('/');
    if (slashIdx === -1) return false;
    const afterSlash = pkgName.slice(slashIdx + 1);
    const atIdx = afterSlash.indexOf('@');
    nameOnly = atIdx === -1 ? pkgName : pkgName.slice(0, slashIdx + 1 + atIdx);
  } else {
    const atIdx = pkgName.indexOf('@');
    nameOnly = atIdx === -1 ? pkgName : pkgName.slice(0, atIdx);
  }
  return NPM_PACKAGE_REGEX.test(nameOnly);
}

// REHABILITATED_PACKAGES imported from src/shared/constants.js (single source of truth)

// Cache to avoid scanning the same package twice.
// IMPORTANT: safeInstall() calls scannedPackages.clear() before each install session.
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
  let iocs;
  try {
    iocs = loadCachedIOCs();
  } catch (e) {
    console.log('[WARN] IOC database unavailable: ' + e.message);
    console.log('[WARN] Blocking install as a precaution. Run "muaddib update" to fix.');
    return { name: pkgName, source: 'ioc-unavailable', description: 'IOC database could not be loaded' };
  }

  // Use optimized Map/Set for O(1) lookup when available
  let malicious = null;
  if (iocs.packagesMap) {
    if (iocs.wildcardPackages && iocs.wildcardPackages.has(pkgName)) {
      const pkgList = iocs.packagesMap.get(pkgName);
      malicious = pkgList ? pkgList.find(p => p.version === '*') : null;
    } else if (iocs.packagesMap.has(pkgName)) {
      const pkgList = iocs.packagesMap.get(pkgName);
      if (pkgVersion) {
        malicious = pkgList.find(p => p.version === pkgVersion || p.version === '*');
      } else {
        // SFI-003: No version specified — still check for wildcard IOCs
        malicious = pkgList.find(p => p.version === '*');
      }
    }
  } else {
    // Fallback: linear search
    malicious = iocs.packages?.find(p => {
      if (p.name !== pkg && p.name !== pkgName) return false;
      if (p.version === '*') return true;
      if (pkgVersion && p.version === pkgVersion) return true;
      return false;
    });
  }
  return malicious || null;
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
  
  // Limit the depth
  if (depth > maxDepth) {
    return { safe: true };
  }
  
  // Validate the package name first (security: prevent command injection)
  if (!isValidPackageName(pkgName)) {
    console.log(`[!] Invalid package name: ${pkgName}`);
    return { safe: false, package: pkgName, reason: 'invalid_name', source: 'validation', description: 'Invalid or suspicious package name', depth };
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

  // Get the package info (uses spawnSync to avoid injection)
  let pkgInfo;
  try {
    const result = spawnSync('npm', ['view', pkgName, '--json'], { encoding: 'utf8', shell: false });
    if (result.status !== 0 || !result.stdout) {
      if (depth === 0) console.log(`[!] Package ${pkgName} not found on npm`);
      return { safe: false, package: pkgName, reason: 'npm_unreachable', source: 'npm-registry', description: 'Package not found on npm registry', depth };
    }
    pkgInfo = JSON.parse(result.stdout);
  } catch {
    if (depth === 0) console.log(`[!] Invalid npm response for ${pkgName}`);
    return { safe: false, package: pkgName, reason: 'invalid_npm_response', source: 'npm-registry', description: 'Invalid or unparseable npm response', depth };
  }
  
  // Scan the dependencies
  const dependencies = pkgInfo.dependencies || {};
  const depNames = Object.keys(dependencies);
  
  if (depNames.length > 0 && depth < maxDepth) {
    for (const depName of depNames) {
      const depSpec = dependencies[depName] ? depName + '@' + dependencies[depName] : depName;
      const result = await scanPackageRecursive(depSpec, depth + 1, maxDepth);
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
        console.log('╔══════════════════════════════════════════╗');
        console.log('║   [!!!] WARNING: FORCE INSTALL ACTIVE    ║');
        console.log('║   Known malicious package detected!       ║');
        console.log('║   Installing despite security threats.    ║');
        console.log('╚══════════════════════════════════════════╝');
        console.log('[AUDIT] Force-install override for malicious package: ' + result.package);

        // SFI-004: Write audit log for force-install overrides
        try {
          const auditDir = path.join(process.cwd(), '.muaddib-cache');
          if (!fs.existsSync(auditDir)) fs.mkdirSync(auditDir, { recursive: true });
          const auditFile = path.join(auditDir, 'force-install-audit.log');
          const entry = new Date().toISOString() + ' FORCE_INSTALL pkg=' + result.package
            + ' source=' + result.source + ' reason=' + result.description + '\n';
          fs.appendFileSync(auditFile, entry);
        } catch { /* audit log write failure is non-fatal */ }
      }
    }
  }

  // Validate all package names before installation
  for (const pkg of packages) {
    if (!isValidPackageName(pkg)) {
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

module.exports = { safeInstall, scanPackageRecursive, REHABILITATED_PACKAGES, checkRehabilitated, isValidPackageName, checkIOCs };