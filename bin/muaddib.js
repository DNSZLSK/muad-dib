#!/usr/bin/env node
const { run } = require('../src/index.js');
const { updateIOCs } = require('../src/ioc/updater.js');
const { watch } = require('../src/watch.js');
const { startDaemon } = require('../src/daemon.js');
const { runScraper } = require('../src/ioc/scraper.js');
const { safeInstall } = require('../src/safe-install.js');

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

// Menu interactif si pas de commande
async function interactiveMenu() {
  const { select, input, confirm } = await import('@inquirer/prompts');
  
  console.log(`
  ╔══════════════════════════════════════════╗
  ║   MUAD'DIB - npm Supply Chain Hunter     ║
  ║   "The worms must die."                  ║
  ╚══════════════════════════════════════════╝
  `);

  const action = await select({
    message: 'Que veux-tu faire ?',
    choices: [
      { name: 'Scanner un projet', value: 'scan' },
      { name: 'Scanner avec mode paranoid', value: 'scan-paranoid' },
      { name: 'Surveiller un projet (watch)', value: 'watch' },
      { name: 'Lancer le daemon', value: 'daemon' },
      { name: 'Mettre a jour les IOCs', value: 'update' },
      { name: 'Scraper nouveaux IOCs', value: 'scrape' },
      { name: 'Quitter', value: 'quit' }
    ]
  });

  if (action === 'quit') {
    console.log('Bye!');
    process.exit(0);
  }

  if (action === 'scan' || action === 'scan-paranoid') {
    const path = await input({
      message: 'Chemin du projet :',
      default: '.'
    });

    const outputFormat = await select({
      message: 'Format de sortie :',
      choices: [
        { name: 'Console (defaut)', value: 'console' },
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

  if (action === 'watch') {
    const path = await input({
      message: 'Chemin du projet :',
      default: '.'
    });
    watch(path);
  }

  if (action === 'daemon') {
    const useWebhook = await confirm({
      message: 'Configurer un webhook Discord/Slack ?',
      default: false
    });

    let webhook = null;
    if (useWebhook) {
      webhook = await input({
        message: 'URL du webhook :'
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
    console.log(`[OK] ${result.added} nouveaux IOCs (total: ${result.total})`);
    process.exit(0);
  }
}

// Main
if (!command || command === '--help' || command === '-h') {
  if (command === '--help' || command === '-h') {
    console.log(`
  MUAD'DIB - npm Supply Chain Threat Hunter
  
  Usage:
    muaddib                          Mode interactif
    muaddib scan [path] [options]    Scanner un projet
    muaddib watch [path]             Surveiller en temps reel
    muaddib daemon [options]         Lancer le daemon
    muaddib update                   Mettre a jour les IOCs
    muaddib scrape                   Scraper nouveaux IOCs
    muaddib install <pkg>            Installer apres scan (safe)
    
  Options:
    --json              Sortie JSON
    --html [file]       Rapport HTML
    --sarif [file]      Rapport SARIF (GitHub Security)
    --explain           Explications detaillees
    --fail-on [level]   Niveau d'echec (critical|high|medium|low)
    --webhook [url]     Webhook Discord/Slack
    --paranoid          Mode ultra-strict
    `);
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
    console.log(`[OK] ${result.added} nouveaux IOCs (total: ${result.total})`);
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
} else if (command === 'help') {
  console.log(`
  MUAD'DIB - npm Supply Chain Threat Hunter
  
  Usage:
    muaddib                          Mode interactif
    muaddib scan [path] [options]    Scanner un projet
    muaddib watch [path]             Surveiller en temps reel
    muaddib daemon [options]         Lancer le daemon
    muaddib update                   Mettre a jour les IOCs
    muaddib scrape                   Scraper nouveaux IOCs
    
  Options:
    --json              Sortie JSON
    --html [file]       Rapport HTML
    --sarif [file]      Rapport SARIF (GitHub Security)
    --explain           Explications detaillees
    --fail-on [level]   Niveau d'echec (critical|high|medium|low)
    --webhook [url]     Webhook Discord/Slack
    --paranoid          Mode ultra-strict
  `);
  process.exit(0);
} else {
  console.log(`Commande inconnue: ${command}`);
  console.log('Tape "muaddib help" pour voir les commandes.');
  process.exit(1);
}