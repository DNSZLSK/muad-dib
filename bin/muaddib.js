#!/usr/bin/env node
const { execSync } = require('child_process');
const { run } = require('../src/index.js');
const { updateIOCs } = require('../src/ioc/updater.js');
const { watch } = require('../src/watch.js');
const { startDaemon } = require('../src/daemon.js');
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

for (let i = 0; i < options.length; i++) {
  if (options[i] === '--json') {
    jsonOutput = true;
  } else if (options[i] === '--html') {
    htmlOutput = options[i + 1] || 'muaddib-report.html';
    i++;
  } else if (options[i] === '--sarif') {
    sarifOutput = options[i + 1] || 'muaddib-results.sarif';
    i++;
  } else if (options[i] === '--explain') {
    explainMode = true;
  } else if (options[i] === '--fail-on') {
    failLevel = options[i + 1] || 'high';
    i++;
  } else if (options[i] === '--webhook') {
    webhookUrl = options[i + 1];
    i++;
  } else if (options[i] === '--paranoid') {
    paranoidMode = true;
  } else if (options[i] === '--strict') {
    // Sandbox strict mode flag (parsed here, used by sandbox commands)
  } else if (!options[i].startsWith('-')) {
    target = options[i];
  }
}

// Version check (non-blocking, skip for machine-readable output)
if (!jsonOutput && !sarifOutput) {
  try {
    const currentVersion = require('../package.json').version;
    const latest = execSync('npm view muaddib-scanner version', { timeout: 5000 }).toString().trim();
    if (latest !== currentVersion) {
      console.log(`\n[UPDATE] New version available: ${currentVersion} -> ${latest}`);
      console.log(`  Run: npm install -g muaddib-scanner@latest\n`);
    }
  } catch {
    // No network or npm unavailable, skip silently
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
    muaddib sandbox <pkg> [--strict]  Analyze in isolated Docker container
    muaddib sandbox-report <pkg>     Sandbox + detailed network report
    muaddib version                  Show version

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
    --fail-on [level]   Fail level (critical|high|medium|low)
    --webhook [url]     Discord/Slack webhook
    --paranoid          Ultra-strict mode
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
  run(target, {
    json: jsonOutput,
    html: htmlOutput,
    sarif: sarifOutput,
    explain: explainMode,
    failLevel: failLevel,
    webhook: webhookUrl,
    paranoid: paranoidMode
  }).then(exitCode => {
    process.exit(exitCode);
  });
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
} else if (command === 'daemon') {
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
  if (!packageName) {
    console.log('Usage: muaddib sandbox <package-name> [--strict]');
    process.exit(1);
  }

  buildSandboxImage()
    .then(() => runSandbox(packageName, { strict }))
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
  if (!packageName) {
    console.log('Usage: muaddib sandbox-report <package-name> [--strict]');
    process.exit(1);
  }

  buildSandboxImage()
    .then(() => runSandbox(packageName, { strict }))
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
} else if (command === 'help') {
  console.log(helpText);
  process.exit(0);
} else {
  console.log(`Unknown command: ${command}`);
  console.log('Type "muaddib help" to see available commands.');
  process.exit(1);
}