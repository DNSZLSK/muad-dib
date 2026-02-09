const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');

const SUSPICIOUS_SCRIPTS = [
  'preinstall',
  'postinstall',
  'preuninstall',
  'postuninstall'
];

const DANGEROUS_PATTERNS = [
  { pattern: /curl\s+.*\|.*sh/, name: 'curl_pipe_sh' },
  { pattern: /wget\s+.*\|.*sh/, name: 'wget_pipe_sh' },
  { pattern: /eval\s*\(/, name: 'eval_usage' },
  { pattern: /child_process/, name: 'child_process' },
  { pattern: /\.npmrc/, name: 'npmrc_access' },
  { pattern: /GITHUB_TOKEN/, name: 'github_token_access' },
  { pattern: /AWS_/, name: 'aws_credential_access' },
  { pattern: /base64/, name: 'base64_encoding' }
];

async function scanPackageJson(targetPath) {
  const threats = [];
  const pkgPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    return threats;
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch {
    return threats;
  }
  const scripts = pkg.scripts || {};

  // Scan lifecycle scripts
  for (const scriptName of SUSPICIOUS_SCRIPTS) {
    if (scripts[scriptName]) {
      const scriptContent = scripts[scriptName];

      threats.push({
        type: 'lifecycle_script',
        severity: 'MEDIUM',
        message: `Script "${scriptName}" detected. Common attack vector.`,
        file: 'package.json'
      });

      for (const { pattern, name } of DANGEROUS_PATTERNS) {
        if (pattern.test(scriptContent)) {
          threats.push({
            type: name,
            severity: 'HIGH',
            message: `Dangerous pattern "${name}" in script "${scriptName}".`,
            file: 'package.json'
          });
        }
      }
    }
  }

  // Scan declared dependencies against IOCs
  const iocs = loadCachedIOCs();
  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.optionalDependencies,
    ...pkg.peerDependencies
  };

  for (const [depName, depVersion] of Object.entries(allDeps)) {
    let malicious = null;

    // Use optimized Map for O(1) lookup if available
    if (iocs.packagesMap) {
      if (iocs.wildcardPackages && iocs.wildcardPackages.has(depName)) {
        const pkgList = iocs.packagesMap.get(depName);
        malicious = pkgList ? pkgList.find(p => p.version === '*') : null;
      } else if (iocs.packagesMap.has(depName)) {
        const pkgList = iocs.packagesMap.get(depName);
        const cleanVersion = depVersion.replace(/^[^0-9]*/, '');
        malicious = pkgList.find(p => p.version === cleanVersion || p.version === depVersion);
      }
    } else {
      // Fallback: linear search for compatibility
      malicious = iocs.packages.find(p => {
        if (p.name !== depName) return false;
        if (p.version === '*') return true;
        const cleanVersion = depVersion.replace(/^[^0-9]*/, '');
        if (p.version === cleanVersion || p.version === depVersion) return true;
        return false;
      });
    }

    if (malicious) {
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Malicious dependency declared: ${depName}@${depVersion} (source: ${malicious.source || 'IOC'})`,
        file: 'package.json'
      });
    }
  }

  return threats;
}

module.exports = { scanPackageJson };