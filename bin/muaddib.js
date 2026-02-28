#!/usr/bin/env node
const { exec } = require('child_process');
const { run } = require('../src/index.js');
const { updateIOCs } = require('../src/ioc/updater.js');
const { watch } = require('../src/watch.js');
const { runScraper } = require('../src/ioc/scraper.js');
const { safeInstall } = require('../src/safe-install.js');
const { buildSandboxImage, runSandbox, generateNetworkReport } = require('../src/sandbox.js');
const { diff, showRefs } = require('../src/diff.js');
const { initHooks, removeHooks } = require('../src/hooks-init.js');

const args = process.argv.slice(2);
const command = args[0];
const options = args.slice(1);

// Parse options
let target = '.';
let jsonOutput = false;
let htmlOutput = null;
let sarifOutput = null;
let explainMode = false;
let failLevel = 'high';
let webhookUrl = null;
let paranoidMode = false;
let excludeDirs = [];
let entropyThreshold = null;
let temporalMode = false;
let temporalAstMode = false;
let temporalPublishMode = false;
let temporalMaintainerMode = false;
let temporalFullMode = false;
let breakdownMode = false;
let noDeobfuscate = false;
let noModuleGraph = false;
let noReachability = false;
let feedLimit = null;
let feedSeverity = null;
let feedSince = null;
let servePort = null;

for (let i = 0; i < options.length; i++) {
  if (options[i] === '--json') {
    jsonOutput = true;
  } else if (options[i] === '--html') {
    const htmlPath = options[i + 1] || 'muaddib-report.html';
    // CLI-001: Block path traversal
    if (htmlPath.includes('..')) {
      console.error('[ERROR] --html path must not contain path traversal (..)');
      process.exit(1);
    }
    htmlOutput = htmlPath;
    i++;
  } else if (options[i] === '--sarif') {
    const sarifPath = options[i + 1] || 'muaddib-results.sarif';
    // CLI-001: Block path traversal
    if (sarifPath.includes('..')) {
      console.error('[ERROR] --sarif path must not contain path traversal (..)');
      process.exit(1);
    }
    sarifOutput = sarifPath;
    i++;
  } else if (options[i] === '--explain') {
    explainMode = true;
  } else if (options[i] === '--fail-on') {
    const val = (options[i + 1] || 'high').toLowerCase();
    const validLevels = ['critical', 'high', 'medium', 'low'];
    if (!validLevels.includes(val)) {
      console.error(`[ERROR] --fail-on must be one of: ${validLevels.join(', ')} (got: "${val}")`);
      process.exit(1);
    }
    failLevel = val;
    i++;
  } else if (options[i] === '--webhook') {
    const rawUrl = options[i + 1];
    // CLI-002: Validate webhook URL (HTTPS only, no private IPs)
    if (rawUrl) {
      try {
        const parsed = new URL(rawUrl);
        if (parsed.protocol !== 'https:') {
          console.error('[ERROR] --webhook URL must use HTTPS');
          process.exit(1);
        }
        const host = parsed.hostname.toLowerCase();
        if (/^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.|169\.254\.|localhost$|::1$)/.test(host)) {
          console.error('[ERROR] --webhook URL must not point to a private/local address');
          process.exit(1);
        }
      } catch {
        console.error('[ERROR] --webhook URL is invalid');
        process.exit(1);
      }
    }
    webhookUrl = rawUrl;
    i++;
  } else if (options[i] === '--exclude') {
    if (options[i + 1] && !options[i + 1].startsWith('-')) {
      excludeDirs.push(options[i + 1]);
      i++;
    }
  } else if (options[i] === '--entropy-threshold') {
    const val = parseFloat(options[i + 1]);
    if (!isNaN(val) && val > 0 && val <= 8) {
      entropyThreshold = val;
    } else {
      console.error('[ERROR] --entropy-threshold must be a number between 0 and 8');
      process.exit(1);
    }
    i++;
  } else if (options[i] === '--paranoid') {
    paranoidMode = true;
  } else if (options[i] === '--temporal-full') {
    temporalFullMode = true;
  } else if (options[i] === '--temporal-ast') {
    temporalAstMode = true;
  } else if (options[i] === '--temporal-publish') {
    temporalPublishMode = true;
  } else if (options[i] === '--temporal-maintainer') {
    temporalMaintainerMode = true;
  } else if (options[i] === '--breakdown') {
    breakdownMode = true;
  } else if (options[i] === '--no-deobfuscate') {
    noDeobfuscate = true;
  } else if (options[i] === '--no-module-graph') {
    noModuleGraph = true;
  } else if (options[i] === '--no-reachability') {
    noReachability = true;
  } else if (options[i] === '--temporal') {
    temporalMode = true;
  } else if (options[i] === '--limit') {
    const val = parseInt(options[i + 1], 10);
    if (!isNaN(val) && val > 0) {
      feedLimit = val;
    }
    i++;
  } else if (options[i] === '--severity') {
    feedSeverity = options[i + 1] || null;
    i++;
  } else if (options[i] === '--since') {
    feedSince = options[i + 1] || null;
    i++;
  } else if (options[i] === '--port') {
    const val = parseInt(options[i + 1], 10);
    if (!isNaN(val) && val >= 1 && val <= 65535) {
      servePort = val;
    } else {
      console.error('[ERROR] --port must be a number between 1 and 65535');
      process.exit(1);
    }
    i++;
  } else if (options[i] === '--strict') {
    // Sandbox strict mode flag (parsed here, used by sandbox commands)
  } else if (options[i] === '--no-canary') {
    // Sandbox canary disable flag (parsed here, used by sandbox commands)
  } else if (!options[i].startsWith('-')) {
    target = options[i];
  }
}

// Version check (truly non-blocking, skip for machine-readable output)
if (!jsonOutput && !sarifOutput && command !== 'feed' && command !== 'serve') {
  try {
    const currentVersion = require('../package.json').version;
    exec('npm view muaddib-scanner version', { timeout: 5000 }, (err, stdout) => {
      if (err) return; // No network or npm unavailable
      const latest = (stdout || '').toString().trim();
      if (!latest || latest === currentVersion) return;
      // Semver comparison: only notify if remote is strictly newer
      const parse = v => v.split('.').map(Number);
      const [cM, cm, cp] = parse(currentVersion);
      const [lM, lm, lp] = parse(latest);
      const isNewer = lM > cM || (lM === cM && (lm > cm || (lm === cm && lp > cp)));
      if (isNewer) {
        console.log(`\n[UPDATE] New version available: ${currentVersion} -> ${latest}`);
        console.log(`  Run: npm install -g muaddib-scanner@latest\n`);
      }
    });
  } catch {
    // Skip silently
  }
}

// Interactive menu
async function interactiveMenu() {
  const { select, input, confirm } = await import('@inquirer/prompts');

  console.log(`
  ╔═══════════════════════════════════════════════╗
  ║   MUAD'DIB - npm & PyPI Supply Chain Hunter  ║
  ║   "The worms must die."                      ║
  ╚═══════════════════════════════════════════════╝
  `);

  const action = await select({
    message: 'What do you want to do?',
    choices: [
      { name: 'Scan a project', value: 'scan' },
      { name: 'Scan with paranoid mode', value: 'scan-paranoid' },
      { name: 'Compare with previous version (diff)', value: 'diff' },
      { name: 'Install packages (safe)', value: 'install' },
      { name: 'Watch a project (real-time)', value: 'watch' },
      { name: 'Start daemon', value: 'daemon' },
      { name: 'Setup git hooks', value: 'init-hooks' },
      { name: 'Update IOCs', value: 'update' },
      { name: 'Scrape new IOCs', value: 'scrape' },
      { name: 'Sandbox analysis', value: 'sandbox' },
      { name: 'Threat feed (JSON)', value: 'feed' },
      { name: 'Threat feed server', value: 'serve' },
      { name: 'Quit', value: 'quit' }
    ]
  });

  if (action === 'quit') {
    console.log('Bye!');
    process.exit(0);
  }

  if (action === 'scan' || action === 'scan-paranoid') {
    const path = await input({
      message: 'Project path:',
      default: '.'
    });

    const outputFormat = await select({
      message: 'Output format:',
      choices: [
        { name: 'Console (default)', value: 'console' },
        { name: 'JSON', value: 'json' },
        { name: 'HTML', value: 'html' },
        { name: 'SARIF (GitHub Security)', value: 'sarif' }
      ]
    });

    const opts = {
      json: outputFormat === 'json',
      html: outputFormat === 'html' ? 'muaddib-report.html' : null,
      sarif: outputFormat === 'sarif' ? 'muaddib-results.sarif' : null,
      explain: true,
      failLevel: 'high',
      paranoid: action === 'scan-paranoid'
    };

    const exitCode = await run(path, opts);
    process.exit(exitCode);
  }

  if (action === 'install') {
    const pkgInput = await input({
      message: 'Package(s) to install (space-separated):'
    });
    
    const packages = pkgInput.split(' ').filter(p => p.trim());
    if (packages.length === 0) {
      console.log('No packages specified.');
      process.exit(1);
    }
    
    const result = await safeInstall(packages, {});
    process.exit(result.blocked ? 1 : 0);
  }

  if (action === 'watch') {
    const path = await input({
      message: 'Project path:',
      default: '.'
    });
    watch(path);
  }

  if (action === 'daemon') {
    const useWebhook = await confirm({
      message: 'Configure Discord/Slack webhook?',
      default: false
    });

    let webhook = null;
    if (useWebhook) {
      webhook = await input({
        message: 'Webhook URL:'
      });
    }
    const { startDaemon } = require('../src/daemon.js');
    startDaemon({ webhook });
  }

  if (action === 'update') {
    await updateIOCs();
    process.exit(0);
  }

  if (action === 'scrape') {
    const result = await runScraper();
    console.log(`[OK] ${result.added} new IOCs (total: ${result.total})`);
    process.exit(0);
  }

  if (action === 'sandbox') {
    const packageName = await input({
      message: 'Package name to analyze:'
    });

    if (!packageName.trim()) {
      console.log('No package specified.');
      process.exit(1);
    }

    const useStrict = await confirm({
      message: 'Enable strict mode? (blocks non-essential network)',
      default: false
    });

    await buildSandboxImage();
    const results = await runSandbox(packageName.trim(), { strict: useStrict });
    if (results.raw_report) {
      console.log(generateNetworkReport(results.raw_report));
    }
    process.exit(results.suspicious ? 1 : 0);
  }

  if (action === 'feed') {
    const { getFeed } = require('../src/threat-feed.js');
    const result = getFeed();
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  }

  if (action === 'serve') {
    const { startServer } = require('../src/serve.js');
    startServer({ port: 3000 });
    // Server runs indefinitely
  }

  if (action === 'diff') {
    const baseRef = await input({
      message: 'Compare with (commit/tag/branch):',
      default: 'HEAD~1'
    });

    const projectPath = await input({
      message: 'Project path:',
      default: '.'
    });

    const exitCode = await diff(projectPath, baseRef, { explain: true });
    process.exit(exitCode);
  }

  if (action === 'init-hooks') {
    const hookMode = await select({
      message: 'Hook mode:',
      choices: [
        { name: 'Scan all threats', value: 'scan' },
        { name: 'Diff only (block only NEW threats)', value: 'diff' }
      ]
    });

    const hookType = await select({
      message: 'Hook system:',
      choices: [
        { name: 'Auto-detect', value: 'auto' },
        { name: 'Husky', value: 'husky' },
        { name: 'pre-commit framework', value: 'pre-commit' },
        { name: 'Native git hooks', value: 'git' }
      ]
    });

    await initHooks('.', { type: hookType, mode: hookMode });
    process.exit(0);
  }
}

const helpText = `
  MUAD'DIB - npm & PyPI Supply Chain Threat Hunter

  Usage:
    muaddib                          Interactive mode
    muaddib scan [path] [options]    Scan a project
    muaddib diff <ref> [path]        Compare threats with a previous version
    muaddib install <pkg> [options]  Safe install (scan before install)
    muaddib watch [path]             Watch in real-time
    muaddib daemon [options]         Start daemon
    muaddib init-hooks [options]     Setup git pre-commit hooks
    muaddib remove-hooks [path]      Remove MUAD'DIB git hooks
    muaddib update                   Update IOCs
    muaddib scrape                   Scrape new IOCs
    muaddib sandbox <pkg> [--strict] [--no-canary]  Analyze in isolated Docker container
    muaddib sandbox-report <pkg>     Sandbox + detailed network report
    muaddib version                  Show version

  Replay Options:
    --verbose           Show detailed findings per attack
    --json              Machine-readable JSON output
    GT-NNN              Replay single attack by ID

  Diff Examples:
    muaddib diff HEAD~1              Compare with previous commit
    muaddib diff v1.2.0              Compare with tag
    muaddib diff main                Compare with branch
    muaddib diff abc1234 ./myproject Compare specific commit

  Init-hooks Options:
    --type [auto|husky|pre-commit|git]  Hook system (default: auto)
    --mode [scan|diff]                  scan=all threats, diff=new only

  Options:
    --json              JSON output
    --html [file]       HTML report
    --sarif [file]      SARIF report (GitHub Security)
    --explain           Detailed explanations
    --breakdown         Show score breakdown by threat
    --fail-on [level]   Fail level (critical|high|medium|low)
    --webhook [url]     Discord/Slack webhook
    --paranoid          Ultra-strict mode
    --temporal          Detect sudden lifecycle script changes (network requests per package)
    --temporal-ast      Detect sudden dangerous API additions via AST diff (downloads tarballs)
    --temporal-publish  Detect publish frequency anomalies (bursts, dormant spikes)
    --temporal-maintainer  Detect maintainer changes (new maintainer, account takeover)
    --temporal-full     All temporal analyses (lifecycle + AST + publish + maintainer)
    --no-canary         Disable honey token injection in sandbox
    --no-deobfuscate    Disable deobfuscation pre-processing
    --no-module-graph   Disable cross-file dataflow analysis
    --no-reachability   Disable entry-point reachability analysis
    --exclude [dir]     Exclude directory from scan (repeatable)
    --limit [n]         Limit feed entries (default: 50)
    --severity [level]  Filter by severity (CRITICAL|HIGH|MEDIUM|LOW)
    --since [date]      Filter detections after date (ISO 8601)
    --port [n]          HTTP server port (default: 3000, serve only)
    --entropy-threshold [n]  Custom string-level entropy threshold (default: 5.5)
    --save-dev, -D      Install as dev dependency
    -g, --global        Install globally
    --force             Force install despite threats
`;

// Main
if (command === 'version' || command === '--version' || command === '-v') {
  const pkg = require('../package.json');
  console.log(`muaddib-scanner v${pkg.version}`);
  process.exit(0);
} else if (!command || command === '--help' || command === '-h') {
  if (command === '--help' || command === '-h') {
    console.log(helpText);
    process.exit(0);
  }
  interactiveMenu().catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'scan') {
  if (options.includes('--help') || options.includes('-h')) {
    console.log(helpText);
    process.exit(0);
  }
  run(target, {
    json: jsonOutput,
    html: htmlOutput,
    sarif: sarifOutput,
    explain: explainMode,
    failLevel: failLevel,
    webhook: webhookUrl,
    paranoid: paranoidMode,
    temporal: temporalMode || temporalFullMode,
    temporalAst: temporalAstMode || temporalFullMode,
    temporalPublish: temporalPublishMode || temporalFullMode,
    temporalMaintainer: temporalMaintainerMode || temporalFullMode,
    exclude: excludeDirs,
    entropyThreshold: entropyThreshold,
    breakdown: breakdownMode,
    noDeobfuscate: noDeobfuscate,
    noModuleGraph: noModuleGraph,
    noReachability: noReachability
  }).then(exitCode => {
    process.exit(exitCode);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'feed') {
  const { getFeed } = require('../src/threat-feed.js');
  const feedOpts = {};
  if (feedLimit) feedOpts.limit = feedLimit;
  if (feedSeverity) feedOpts.severity = feedSeverity;
  if (feedSince) feedOpts.since = feedSince;
  const result = getFeed(feedOpts);
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
} else if (command === 'serve') {
  const { startServer } = require('../src/serve.js');
  startServer({ port: servePort || 3000 });
  // Server runs indefinitely — no process.exit
} else if (command === 'watch') {
  watch(target);
} else if (command === 'update') {
  updateIOCs().then(() => {
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'scrape') {
  runScraper().then(result => {
    console.log(`[OK] ${result.added} new IOCs (total: ${result.total})`);
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'monitor') {
  const testPkg = options.filter(o => !o.startsWith('-'));
  const isTemporal = options.includes('--temporal');
  const isTemporalAst = options.includes('--temporal-ast');
  const isTest = options.includes('--test');

  if (isTemporalAst && isTest) {
    const actualPkg = options.filter(o => !o.startsWith('-')).pop();
    if (!actualPkg) {
      console.log('Usage: muaddib monitor --temporal-ast --test <package-name>');
      process.exit(1);
    }
    const { detectSuddenAstChanges } = require('../src/temporal-ast-diff.js');
    console.log(`[TEMPORAL-AST] Analyzing ${actualPkg}...\n`);
    detectSuddenAstChanges(actualPkg).then(result => {
      console.log(`Package:          ${result.packageName}`);
      console.log(`Latest version:   ${result.latestVersion || 'N/A'}`);
      console.log(`Previous version: ${result.previousVersion || 'N/A'}`);
      console.log(`Suspicious:       ${result.suspicious ? 'YES' : 'NO'}`);
      if (result.metadata.latestPublishedAt) {
        console.log(`Published:        ${result.metadata.latestPublishedAt}`);
      }
      if (result.findings.length > 0) {
        console.log(`\nFindings:`);
        for (const f of result.findings) {
          console.log(`  [${f.severity}] ${f.pattern}: ${f.description}`);
        }
      } else {
        console.log(`\nNo dangerous API changes detected between the last two versions.`);
      }
      process.exit(result.suspicious ? 1 : 0);
    }).catch(err => {
      console.error(`[ERROR] ${err.message}`);
      process.exit(1);
    });
  } else if (isTemporal && isTest && testPkg.length > 0) {
    const { detectSuddenLifecycleChange } = require('../src/temporal-analysis.js');
    const pkgName = testPkg[testPkg.indexOf('--test') !== -1 ? testPkg.length - 1 : 0] || testPkg[0];
    // Find the package name: it's the non-flag argument
    const actualPkg = options.filter(o => !o.startsWith('-')).pop();
    if (!actualPkg) {
      console.log('Usage: muaddib monitor --temporal --test <package-name>');
      process.exit(1);
    }
    console.log(`[TEMPORAL] Analyzing ${actualPkg}...\n`);
    detectSuddenLifecycleChange(actualPkg).then(result => {
      console.log(`Package:          ${result.packageName}`);
      console.log(`Latest version:   ${result.latestVersion || 'N/A'}`);
      console.log(`Previous version: ${result.previousVersion || 'N/A'}`);
      console.log(`Suspicious:       ${result.suspicious ? 'YES' : 'NO'}`);
      if (result.metadata.note) {
        console.log(`Note:             ${result.metadata.note}`);
      }
      if (result.metadata.latestPublishedAt) {
        console.log(`Published:        ${result.metadata.latestPublishedAt}`);
      }
      if (result.metadata.maintainers && result.metadata.maintainers.length > 0) {
        const names = result.metadata.maintainers.map(m => m.name || m.email).join(', ');
        console.log(`Maintainers:      ${names}`);
      }
      if (result.findings.length > 0) {
        console.log(`\nFindings:`);
        for (const f of result.findings) {
          const action = f.type === 'lifecycle_added' ? 'ADDED' : f.type === 'lifecycle_modified' ? 'MODIFIED' : 'REMOVED';
          const value = f.type === 'lifecycle_modified' ? f.newValue : f.value;
          console.log(`  [${f.severity}] ${f.script} script ${action}: "${value}"`);
        }
      } else {
        console.log(`\nNo lifecycle script changes detected between the last two versions.`);
      }
      process.exit(result.suspicious ? 1 : 0);
    }).catch(err => {
      console.error(`[ERROR] ${err.message}`);
      process.exit(1);
    });
  } else if (isTemporal && isTest) {
    console.log('Usage: muaddib monitor --temporal --test <package-name>');
    process.exit(1);
  } else {
    // Start full monitor
    const { startMonitor } = require('../src/monitor.js');
    const monitorOpts = {
      verbose: options.includes('--verbose')
    };
    startMonitor(monitorOpts).catch(err => {
      console.error('[ERROR]', err.message);
      process.exit(1);
    });
  }
} else if (command === 'daemon') {
  const { startDaemon } = require('../src/daemon.js');
  startDaemon({ webhook: webhookUrl });
} else if (command === 'install' || command === 'i') {
  const packages = options.filter(o => !o.startsWith('-'));
  const isDev = options.includes('--save-dev') || options.includes('-D');
  const isGlobal = options.includes('-g') || options.includes('--global');
  const force = options.includes('--force');
  
  if (packages.length === 0) {
    console.log('Usage: muaddib install <package> [<package>...] [--save-dev] [-g] [--force]');
    process.exit(1);
  }
  
  safeInstall(packages, { isDev, isGlobal, force }).then(result => {
    if (result.blocked && !force) {
      process.exit(1);
    }
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'sandbox') {
  const sandboxOpts = options.filter(o => !o.startsWith('-'));
  const packageName = sandboxOpts[0];
  const strict = options.includes('--strict');
  const canary = !options.includes('--no-canary');
  const local = options.includes('--local');
  if (!packageName) {
    console.log('Usage: muaddib sandbox <package-name|path> [--local] [--strict] [--no-canary]');
    process.exit(1);
  }

  buildSandboxImage()
    .then(() => runSandbox(packageName, { strict, canary, local }))
    .then((results) => {
      process.exit(results.suspicious ? 1 : 0);
    })
    .catch((err) => {
      console.error('[ERROR]', err.message);
      process.exit(1);
    });
} else if (command === 'sandbox-report') {
  const sandboxOpts = options.filter(o => !o.startsWith('-'));
  const packageName = sandboxOpts[0];
  const strict = options.includes('--strict');
  const canary = !options.includes('--no-canary');
  const local = options.includes('--local');
  if (!packageName) {
    console.log('Usage: muaddib sandbox-report <package-name|path> [--local] [--strict] [--no-canary]');
    process.exit(1);
  }

  buildSandboxImage()
    .then(() => runSandbox(packageName, { strict, canary, local }))
    .then((results) => {
      if (results.raw_report) {
        console.log(generateNetworkReport(results.raw_report));
      }
      process.exit(results.suspicious ? 1 : 0);
    })
    .catch((err) => {
      console.error('[ERROR]', err.message);
      process.exit(1);
    });
} else if (command === 'diff') {
  // Parse diff arguments: muaddib diff <ref> [path] [options]
  const diffArgs = options.filter(o => !o.startsWith('-'));
  const baseRef = diffArgs[0];
  const diffTarget = diffArgs[1] || '.';

  if (!baseRef) {
    showRefs('.');
    process.exit(0);
  }

  diff(diffTarget, baseRef, {
    json: jsonOutput,
    explain: explainMode,
    failLevel: failLevel,
    paranoid: paranoidMode
  }).then(exitCode => {
    process.exit(exitCode);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'detections') {
  const { loadDetections, getDetectionStats } = require('../src/monitor.js');
  const wantStats = options.includes('--stats');
  const wantJson = options.includes('--json');

  if (wantJson) {
    const data = loadDetections();
    console.log(JSON.stringify(data, null, 2));
    process.exit(0);
  }

  if (wantStats) {
    const s = getDetectionStats();
    console.log('\n  MUAD\'DIB Detection Stats\n');
    console.log(`  Total detections: ${s.total}`);
    if (Object.keys(s.bySeverity).length > 0) {
      console.log('  By severity:');
      for (const [sev, count] of Object.entries(s.bySeverity)) {
        console.log(`    ${sev}: ${count}`);
      }
    }
    if (Object.keys(s.byEcosystem).length > 0) {
      console.log('  By ecosystem:');
      for (const [eco, count] of Object.entries(s.byEcosystem)) {
        console.log(`    ${eco}: ${count}`);
      }
    }
    if (s.leadTime) {
      console.log(`  Lead time (hours): avg=${s.leadTime.avg.toFixed(1)}, min=${s.leadTime.min.toFixed(1)}, max=${s.leadTime.max.toFixed(1)} (${s.leadTime.count} entries)`);
    } else {
      console.log('  Lead time: no advisory data yet');
    }
    console.log('');
    process.exit(0);
  }

  // Default: list recent detections
  const data = loadDetections();
  const recent = data.detections.slice(-20).reverse();
  if (recent.length === 0) {
    console.log('\n  No detections recorded yet.\n');
    process.exit(0);
  }
  console.log(`\n  MUAD'DIB Recent Detections (${recent.length} of ${data.detections.length})\n`);
  for (const d of recent) {
    const lead = d.lead_time_hours != null ? ` | lead: ${d.lead_time_hours.toFixed(1)}h` : '';
    console.log(`  [${d.severity}] ${d.ecosystem}/${d.package}@${d.version} — ${d.first_seen_at}${lead}`);
    console.log(`         findings: ${d.findings.join(', ')}`);
  }
  console.log('');
  process.exit(0);
} else if (command === 'stats') {
  const { loadScanStats } = require('../src/monitor.js');
  const wantDaily = options.includes('--daily');
  const wantJson = options.includes('--json');

  const data = loadScanStats();

  if (wantJson) {
    console.log(JSON.stringify(data, null, 2));
    process.exit(0);
  }

  if (wantDaily) {
    const last7 = data.daily.slice(-7);
    console.log('\n  MUAD\'DIB Scan Stats — Daily Breakdown\n');
    if (last7.length === 0) {
      console.log('  No daily data recorded yet.\n');
      process.exit(0);
    }
    console.log('  Date         Scanned  Clean  Suspect  FP  Confirmed  FP Rate');
    console.log('  ' + '-'.repeat(60));
    for (const d of last7) {
      const fpRate = (d.fp_rate * 100).toFixed(1) + '%';
      console.log(`  ${d.date}   ${String(d.scanned).padStart(5)}  ${String(d.clean).padStart(5)}  ${String(d.suspect).padStart(7)}  ${String(d.false_positive).padStart(2)}  ${String(d.confirmed).padStart(9)}  ${fpRate.padStart(7)}`);
    }
    console.log('');
    process.exit(0);
  }

  // Default: global stats
  const s = data.stats;
  const globalDenom = s.false_positive + s.confirmed_malicious;
  const globalFpRate = globalDenom > 0 ? ((s.false_positive / globalDenom) * 100).toFixed(1) + '%' : 'N/A';

  console.log('\n  MUAD\'DIB Scan Stats\n');
  console.log(`  Total scanned:      ${s.total_scanned}`);
  console.log(`  Clean:              ${s.clean}`);
  console.log(`  Suspect:            ${s.suspect}`);
  console.log(`  False positives:    ${s.false_positive}`);
  console.log(`  Confirmed malicious: ${s.confirmed_malicious}`);
  console.log(`  FP rate:            ${globalFpRate}`);
  console.log('');
  process.exit(0);
} else if (command === 'evaluate') {
  const { evaluate } = require('../src/commands/evaluate.js');
  const evalOpts = { json: jsonOutput };
  for (let i = 0; i < options.length; i++) {
    if (options[i] === '--benign-limit' && options[i + 1]) {
      evalOpts.benignLimit = parseInt(options[i + 1], 10);
      i++;
    } else if (options[i] === '--refresh-benign') {
      evalOpts.refreshBenign = true;
    }
  }
  evaluate(evalOpts).then(() => {
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'init-hooks') {
  // Parse init-hooks arguments
  let hookType = 'auto';
  let hookMode = 'scan';

  for (let i = 0; i < options.length; i++) {
    if (options[i] === '--type' && options[i + 1]) {
      hookType = options[i + 1];
      i++;
    } else if (options[i] === '--mode' && options[i + 1]) {
      hookMode = options[i + 1];
      i++;
    }
  }

  initHooks(target, { type: hookType, mode: hookMode }).then(success => {
    process.exit(success ? 0 : 1);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'remove-hooks') {
  removeHooks(target).then(success => {
    process.exit(success ? 0 : 1);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'replay' || command === 'ground-truth') {
  const { replay } = require('../tests/ground-truth/replay.js');
  const replayOpts = {};
  for (const o of options) {
    if (o === '--verbose' || o === '-v') replayOpts.verbose = true;
    else if (o === '--json') replayOpts.json = true;
    else if (o.startsWith('GT-')) replayOpts.filterId = o;
  }
  replay(replayOpts).then(result => {
    if (!replayOpts.json) {
      process.exit(result.missed > 0 ? 1 : 0);
    }
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'report') {
  // Hidden/internal — not in --help
  if (options.includes('--now')) {
    const { sendReportNow } = require('../src/monitor.js');
    sendReportNow().then(result => {
      const color = process.stdout.isTTY;
      if (result.sent) {
        const check = color ? '\x1b[32m\u2713\x1b[0m' : '\u2713';
        console.log(`\n  ${check} ${result.message}\n`);
      } else {
        const warn = color ? '\x1b[33m!\x1b[0m' : '!';
        console.log(`\n  ${warn} ${result.message}\n`);
      }
      process.exit(result.sent ? 0 : 1);
    }).catch(err => {
      console.error('[ERROR]', err.message);
      process.exit(1);
    });
  } else if (options.includes('--status')) {
    const { getReportStatus } = require('../src/monitor.js');
    const status = getReportStatus();
    console.log('\n  MUAD\'DIB Report Status\n');
    console.log(`  Last report sent:     ${status.lastDailyReportDate || 'Never'}`);
    console.log(`  Packages scanned since: ${status.scannedSince}`);
    console.log(`  Next scheduled report:  ${status.nextReport}`);
    console.log('');
    process.exit(0);
  } else {
    console.log('Usage: muaddib report --now | --status');
    process.exit(1);
  }
} else if (command === 'help') {
  console.log(helpText);
  process.exit(0);
} else {
  console.log(`Unknown command: ${String(command).replace(/[\x00-\x1f\x7f-\x9f]/g, '')}`);
  console.log('Type "muaddib help" to see available commands.');
  process.exit(1);
}