const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');

const SUSPICIOUS_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'postuninstall',
  'prepare',
  'prepack'
];

const DANGEROUS_PATTERNS = [
  { pattern: /curl\s+.*\|.*sh/, name: 'curl_pipe_sh' },
  { pattern: /wget\s+.*\|.*sh/, name: 'wget_pipe_sh' },
  { pattern: /eval\s*\(/, name: 'eval_usage' },
  { pattern: /child_process/, name: 'child_process' },
  { pattern: /\.npmrc/, name: 'npmrc_access' },
  { pattern: /GITHUB_TOKEN/, name: 'github_token_access' },
  { pattern: /AWS_/, name: 'aws_credential_access' },
  { pattern: /base64/, name: 'base64_encoding' },
  { pattern: /require\s*\(\s*['"]https?['"]\)/, name: 'network_require' },
  { pattern: /node\s+-e\s/, name: 'node_inline_exec' }
];

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']);
const DEP_FP_WHITELIST = new Set(['es5-ext', 'bootstrap-sass']);

/**
 * Clean a version specifier to extract the primary version number.
 * Handles: ^1.0.0, ~1.0.0, >=1.0.0, >=1.0.0,<2.0.0, git URLs, etc.
 * @param {string} versionSpec - Raw version from package.json
 * @returns {string} Cleaned version or original string
 */
function cleanVersionSpec(versionSpec) {
  if (!versionSpec || typeof versionSpec !== 'string') return '';
  // Skip git URLs, file paths, URLs entirely (not matchable to IOC versions)
  if (/^(git[+:]|github:|https?:|file:|\/)/.test(versionSpec)) return '';
  // Handle range specifiers like ">=1.0.0,<2.0.0" — extract the first version
  const rangeMatch = versionSpec.match(/[\^~>=<!\s]*(\d+\.\d+[.\d-a-zA-Z]*)/);
  return rangeMatch ? rangeMatch[1] : versionSpec.replace(/^[\^~>=<! ]+/, '');
}

async function scanPackageJson(targetPath) {
  const threats = [];
  const pkgPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    return threats;
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch (e) {
    console.log('[WARN] Failed to parse package.json: ' + e.message);
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

      // Escalate: lifecycle script (preinstall/install/postinstall) + shell pipe → CRITICAL
      if (['preinstall', 'install', 'postinstall'].includes(scriptName)) {
        if (/curl\s.*\|\s*(sh|bash)\b/.test(scriptContent) ||
            /wget\s.*\|\s*(sh|bash)\b/.test(scriptContent)) {
          threats.push({
            type: 'lifecycle_shell_pipe',
            severity: 'CRITICAL',
            message: `Critical: "${scriptName}" pipes remote code to shell — supply chain RCE.`,
            file: 'package.json'
          });
        }
      }
    }
  }

  // Check non-lifecycle scripts (test, start, etc.) for network exfil commands
  const NETWORK_SCRIPT_PATTERN = /\bcurl\b|\bwget\b|\bnc\s+-|\bncat\b|\bpowershell\b|\bnslookup\b/;
  for (const [scriptName, scriptContent] of Object.entries(scripts)) {
    if (SUSPICIOUS_SCRIPTS.includes(scriptName)) continue; // already checked above
    if (typeof scriptContent !== 'string') continue;
    if (NETWORK_SCRIPT_PATTERN.test(scriptContent)) {
      threats.push({
        type: 'lifecycle_script',
        severity: 'MEDIUM',
        message: `Script "${scriptName}" contains network command (curl/wget/nc/nslookup). Unusual for "${scriptName}".`,
        file: 'package.json'
      });
    }
  }

  // Scan declared dependencies against IOCs
  let iocs;
  try {
    iocs = loadCachedIOCs();
  } catch (e) {
    console.log('[WARN] Failed to load IOCs: ' + e.message);
    return threats;
  }
  const allDeps = {};
  const depSources = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies, pkg.peerDependencies];
  for (const src of depSources) {
    if (!src || typeof src !== 'object') continue;
    for (const [key, value] of Object.entries(src)) {
      if (!DANGEROUS_KEYS.has(key)) allDeps[key] = value;
    }
  }
  // bundledDependencies is an array of package names, not an object
  if (Array.isArray(pkg.bundledDependencies)) {
    for (const name of pkg.bundledDependencies) {
      if (typeof name === 'string' && !DANGEROUS_KEYS.has(name)) allDeps[name] = allDeps[name] || '*';
    }
  }

  for (const [depName, depVersion] of Object.entries(allDeps)) {
    if (DANGEROUS_KEYS.has(depName)) continue;
    // Skip local dependencies (link:, file:, workspace:) — they're local code, not npm packages
    if (typeof depVersion === 'string' && /^(link:|file:|workspace:)/.test(depVersion)) continue;
    // Skip npm alias syntax (e.g. "npm:typescript@^3.1.6") — alias name is virtual, not a real package
    if (typeof depVersion === 'string' && depVersion.startsWith('npm:')) continue;
    // Detect suspicious dependency URLs (HTTP/HTTPS instead of version)
    if (typeof depVersion === 'string' && /^https?:\/\//.test(depVersion)) {
      const urlLower = depVersion.toLowerCase();
      const isSuspicious = [
        /ngrok\.io/, /ngrok-free\.app/, /ngrok\.app/,
        /localtunnel\.me/, /loca\.lt/, /serveo\.net/, /bore\.digital/,
        /trycloudflare\.com/, /localhost\.run/,
        /\/\/localhost[:/]/, /\/\/127\.0\.0\.1[:/]/, /\/\/0\.0\.0\.0[:/]/,
        /\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]/,
        /\/\/192\.168\.\d{1,3}\.\d{1,3}[:/]/,
        /\/\/172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}[:/]/
      ].some(p => p.test(urlLower));
      threats.push({
        type: 'dependency_url_suspicious',
        severity: isSuspicious ? 'HIGH' : 'MEDIUM',
        message: `Dependency "${depName}" uses HTTP URL: ${depVersion}` +
          (isSuspicious ? ' (tunnel/private/localhost)' : ' (unusual, verify source)'),
        file: 'package.json'
      });
    }
    // Skip known FP packages that share names with malicious IOC entries
    if (DEP_FP_WHITELIST.has(depName)) continue;
    let malicious = null;

    // Use optimized Map for O(1) lookup if available
    if (iocs.packagesMap) {
      if (iocs.wildcardPackages && iocs.wildcardPackages.has(depName)) {
        const pkgList = iocs.packagesMap.get(depName);
        malicious = pkgList ? pkgList.find(p => p.version === '*') : null;
      } else if (iocs.packagesMap.has(depName)) {
        const pkgList = iocs.packagesMap.get(depName);
        const cleanVersion = cleanVersionSpec(depVersion);
        malicious = pkgList.find(p => p.version === cleanVersion || p.version === depVersion);
      }
    } else if (iocs.packages) {
      // Fallback: linear search for compatibility
      malicious = iocs.packages.find(p => {
        if (p.name !== depName) return false;
        if (p.version === '*') return true;
        const cleanVersion = cleanVersionSpec(depVersion);
        if (p.version === cleanVersion || p.version === depVersion) return true;
        return false;
      });
    }

    if (malicious) {
      // C1: Include triggering dependency metadata for diagnostic
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Malicious dependency declared: ${depName}@${depVersion} (source: ${malicious.source || 'IOC'})`,
        file: 'package.json',
        matchedDep: depName,
        matchedVersion: malicious.version,
        iocSource: malicious.source || 'IOC'
      });
    }
  }

  return threats;
}

module.exports = { scanPackageJson };