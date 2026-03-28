'use strict';

const { run } = require('../index.js');
const { updateIOCs } = require('../ioc/updater.js');
const { watch } = require('../watch.js');
const { runScraper } = require('../ioc/scraper.js');
const { safeInstall } = require('../safe-install.js');
const { buildSandboxImage, runSandbox, generateNetworkReport } = require('../sandbox/index.js');
const { diff } = require('../diff.js');
const { initHooks } = require('../hooks-init.js');

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

module.exports = { interactiveMenu };
