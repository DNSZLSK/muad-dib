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

// System commands that should never be shadowed via the "bin" field (PATH hijack)
const SHADOWED_COMMANDS = new Set([
  'node', 'npm', 'npx', 'git', 'sh', 'bash', 'zsh', 'python', 'python3',
  'curl', 'wget', 'ssh', 'scp', 'tar', 'make', 'gcc', 'go', 'ruby',
  'perl', 'php', 'java', 'javac', 'pip', 'pip3', 'yarn', 'pnpm', 'bun'
]);

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
        message: `Script "${scriptName}" detected: ${scriptContent.substring(0, 200)}`,
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

      // Escalate: lifecycle script targeting node_modules/ — payload hiding technique.
      // Legitimate postinstall scripts run from the package's own directory, not from node_modules/.
      // Lazarus/DPRK interview attacks hide payloads in node_modules/.cache/ or similar paths.
      if (['preinstall', 'install', 'postinstall'].includes(scriptName) &&
          /\bnode_modules[\/\\]/.test(scriptContent)) {
        threats.push({
          type: 'lifecycle_hidden_payload',
          severity: 'CRITICAL',
          message: `Critical: "${scriptName}" targets file inside node_modules/ — payload hiding technique to evade scanners.`,
          file: 'package.json'
        });
      }

      // Detect Bun runtime evasion in lifecycle scripts (Shai-Hulud 2.0)
      if (/\bbun\s+(run|exec|install|x)\b/.test(scriptContent) || /\bbunx\s+/.test(scriptContent)) {
        threats.push({
          type: 'bun_runtime_evasion',
          severity: 'HIGH',
          message: `Bun runtime invocation in lifecycle script "${scriptName}" — alternative runtime to evade Node.js monitoring/sandboxing.`,
          file: 'package.json'
        });
      }

      // Blue Team v8b (B8): Lifecycle script references non-existent file in package
      // Pattern: "node path/to/script.js" where the file does not exist — phantom install script
      // Strong signal: preinstall/install scripts pointing to missing files can't be build artifacts
      if (['preinstall', 'install', 'postinstall'].includes(scriptName)) {
        const nodeFileMatch = scriptContent.match(/^node\s+(\S+)/);
        if (nodeFileMatch) {
          const scriptFile = nodeFileMatch[1];
          const fullScriptPath = path.join(targetPath, scriptFile);
          if (!fs.existsSync(fullScriptPath) && !fs.existsSync(fullScriptPath + '.js')) {
            threats.push({
              type: 'lifecycle_missing_script',
              severity: scriptName === 'postinstall' ? 'HIGH' : 'CRITICAL',
              message: `Lifecycle "${scriptName}" references "${scriptFile}" which does not exist in the package — phantom install script, payload may be injected at publish time.`,
              file: 'package.json'
            });
          }
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

  // Detect bin field hijacking: shadowing system commands (node, npm, git, bash, etc.)
  if (pkg.bin) {
    const binEntries = typeof pkg.bin === 'string'
      ? { [pkg.name]: pkg.bin }
      : pkg.bin;
    for (const [cmdName, cmdPath] of Object.entries(binEntries || {})) {
      if (SHADOWED_COMMANDS.has(cmdName)) {
        // Skip when the package IS the legitimate provider of the command:
        // 1. Self-name: npm→bin.npm, yarn→bin.yarn
        // 2. Sibling commands: npm also provides npx → pkg.name in SHADOWED_COMMANDS
        // Typosquats still caught: 'nmp' declaring bin.npm → 'nmp' not in SHADOWED_COMMANDS → fires
        if (cmdName === pkg.name || SHADOWED_COMMANDS.has(pkg.name)) continue;
        threats.push({
          type: 'bin_field_hijack',
          severity: 'CRITICAL',
          message: `package.json "bin" field shadows system command "${cmdName}" → ${cmdPath}. PATH hijack: all npm scripts will execute this instead of the real ${cmdName}.`,
          file: 'package.json'
        });
      }
    }
  }

  // Detect .npmrc with git= override (PackageGate technique)
  const npmrcPath = path.join(targetPath, '.npmrc');
  if (fs.existsSync(npmrcPath)) {
    try {
      const npmrcContent = fs.readFileSync(npmrcPath, 'utf8');
      if (/^git\s*=/m.test(npmrcContent)) {
        threats.push({
          type: 'npmrc_git_override',
          severity: 'CRITICAL',
          message: '.npmrc contains git= override — PackageGate technique: replaces git binary with attacker-controlled script.',
          file: '.npmrc'
        });
      }
    } catch { /* permission error */ }
  }

  // Blue Team v8: binding.gyp + lifecycle script = native addon install risk
  // binding.gyp triggers node-gyp compilation during install. Combined with lifecycle scripts
  // that aren't standard node-gyp build tools, this indicates potentially malicious native code.
  const bindingGypPath = path.join(targetPath, 'binding.gyp');
  if (fs.existsSync(bindingGypPath)) {
    const hasInstallLifecycle = ['preinstall', 'install', 'postinstall'].some(s => scripts[s]);
    const installScript = scripts.install || scripts.postinstall || scripts.preinstall || '';
    // node-gyp rebuild / prebuild-install / cmake-js are legitimate native addon builders
    const isStandardBuild = /\b(node-gyp|prebuild|cmake-js|napi|prebuildify|neon)\b/i.test(installScript);

    // Blue Team v8b (C7): Check binding.gyp content for shell commands in actions
    let gypContent = '';
    try { gypContent = fs.readFileSync(bindingGypPath, 'utf8'); } catch {}
    const hasShellActions = /\baction\b.*\bsh\b/.test(gypContent) || /\bcurl\b/.test(gypContent) ||
      /\bwget\b/.test(gypContent) || /\$\(whoami\)/.test(gypContent) || /\$\(uname/.test(gypContent);
    // Check if binding.gyp references C/C++ source files
    const hasNativeSources = /\.(c|cc|cpp|cxx|h|hpp)\b/.test(gypContent);

    if (hasShellActions) {
      threats.push({
        type: 'native_addon_install',
        severity: 'CRITICAL',
        message: `binding.gyp contains shell commands in build actions (curl/sh/whoami) — build-time code execution and exfiltration.`,
        file: 'binding.gyp'
      });
    } else if (hasInstallLifecycle && !isStandardBuild) {
      threats.push({
        type: 'native_addon_install',
        severity: 'HIGH',
        message: `binding.gyp present with non-standard lifecycle script: "${installScript.substring(0, 100)}" — potential malicious native compilation.`,
        file: 'package.json'
      });
    } else if (hasInstallLifecycle && hasNativeSources) {
      // Standard build but with native C/C++ sources — HIGH (native code is opaque)
      threats.push({
        type: 'native_addon_install',
        severity: 'HIGH',
        message: `binding.gyp with C/C++ source files + lifecycle script — native addon compilation. Native code is opaque to static analysis.`,
        file: 'package.json'
      });
    } else if (hasInstallLifecycle) {
      // Standard build tool — informational only
      threats.push({
        type: 'native_addon_install',
        severity: 'LOW',
        message: 'binding.gyp with standard build tool (node-gyp/prebuild) in lifecycle script — legitimate native addon.',
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
        severity: isSuspicious ? 'CRITICAL' : 'HIGH',
        message: `Dependency "${depName}" uses HTTP URL: ${depVersion}` +
          (isSuspicious ? ' (tunnel/private/localhost)' : ' (unusual, verify source)'),
        file: 'package.json'
      });
    }
    // Detect git-based dependencies — potential PackageGate RCE vector
    if (typeof depVersion === 'string' && /^git[+:]/.test(depVersion)) {
      threats.push({
        type: 'git_dependency_rce',
        severity: 'HIGH',
        message: `Dependency "${depName}" uses git URL: ${depVersion} — potential PackageGate RCE vector (malicious .npmrc can override git binary).`,
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
      // Use distinct type for dependency-declared IOC matches (not the package itself)
      // so they don't bypass all downstream filtering via IOC_MATCH_TYPES
      threats.push({
        type: 'dependency_ioc_match',
        severity: 'HIGH',
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