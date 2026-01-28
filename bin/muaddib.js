#!/usr/bin/env node
const { run } = require('../src/index.js');
const { updateIOCs } = require('../src/ioc/updater.js');
const { watch } = require('../src/watch.js');
const { startDaemon } = require('../src/daemon.js');
const { runScraper } = require('../src/ioc/scraper.js');
const { safeInstall } = require('../src/safe-install.js');
const { buildSandboxImage, runSandbox } = require('../src/sandbox.js');

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
  } else if (!options[i].startsWith('-')) {
    target = options[i];
  }
}

// Interactive menu
async function interactiveMenu() {
  const { select, input, confirm } = await import('@inquirer/prompts');
  
  console.log(`
  ╔══════════════════════════════════════════╗
  ║   MUAD'DIB - npm Supply Chain Hunter     ║
  ║   "The worms must die."                  ║
  ╚══════════════════════════════════════════╝
  `);

  const action = await select({
    message: 'What do you want to do?',
    choices: [
      { name: 'Scan a project', value: 'scan' },
      { name: 'Scan with paranoid mode', value: 'scan-paranoid' },
      { name: 'Install packages (safe)', value: 'install' },
      { name: 'Watch a project (real-time)', value: 'watch' },
      { name: 'Start daemon', value: 'daemon' },
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
    
    await buildSandboxImage();
    const results = await runSandbox(packageName.trim());
    process.exit(results.suspicious ? 1 : 0);
  }
}

const helpText = `
  MUAD'DIB - npm Supply Chain Threat Hunter
  
  Usage:
    muaddib                          Interactive mode
    muaddib scan [path] [options]    Scan a project
    muaddib install <pkg> [options]  Safe install (scan before install)
    muaddib watch [path]             Watch in real-time
    muaddib daemon [options]         Start daemon
    muaddib update                   Update IOCs
    muaddib scrape                   Scrape new IOCs
    muaddib sandbox <pkg>            Analyze a package in an isolated Docker container
    
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
if (!command || command === '--help' || command === '-h') {
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
  const packageName = options[0];
  if (!packageName) {
    console.log('Usage: muaddib sandbox <package-name>');
    process.exit(1);
  }
  
  buildSandboxImage()
    .then(() => runSandbox(packageName))
    .then((results) => {
      process.exit(results.suspicious ? 1 : 0);
    })
    .catch((err) => {
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