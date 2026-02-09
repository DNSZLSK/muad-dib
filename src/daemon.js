const fs = require('fs');
const path = require('path');
const { run } = require('./index.js');

let webhookUrl = null;
let isRunning = false;

async function startDaemon(options = {}) {
  webhookUrl = options.webhook || null;
  isRunning = true;

  console.log(`
╔════════════════════════════════════════════╗
║         MUAD'DIB Security Daemon           ║
║      Surveillance npm install active       ║
╚════════════════════════════════════════════╝
  `);

  console.log('[DAEMON] Demarrage...');
  console.log(`[DAEMON] Webhook: ${webhookUrl ? 'Configure' : 'Non configure'}`);
  console.log('[DAEMON] Ctrl+C pour arreter\n');

  // Surveille le dossier courant
  const cwd = process.cwd();
  const watchers = watchDirectory(cwd);

  // Cleanup function to close all watchers
  function cleanup() {
    for (const w of watchers) {
      try { w.close(); } catch { /* ignore */ }
    }
  }

  // Keep process alive until SIGINT
  await new Promise((resolve) => {
    process.on('SIGINT', () => {
      console.log('\n[DAEMON] Arret...');
      isRunning = false;
      cleanup();
      resolve();
    });
  });

  process.exit(0);
}

function watchDirectory(dir) {
  const watchers = [];
  const nodeModulesPath = path.join(dir, 'node_modules');
  const packageLockPath = path.join(dir, 'package-lock.json');
  const yarnLockPath = path.join(dir, 'yarn.lock');

  console.log(`[DAEMON] Surveillance de ${dir}`);

  // Surveille package-lock.json
  if (fs.existsSync(packageLockPath)) {
    const w = watchFile(packageLockPath, dir);
    if (w) watchers.push(w);
  }

  // Surveille yarn.lock
  if (fs.existsSync(yarnLockPath)) {
    const w = watchFile(yarnLockPath, dir);
    if (w) watchers.push(w);
  }

  // Surveille node_modules
  if (fs.existsSync(nodeModulesPath)) {
    watchers.push(watchNodeModules(nodeModulesPath, dir));
  }

  // Surveille la creation de node_modules
  const dirWatcher = fs.watch(dir, (eventType, filename) => {
    if (filename === 'node_modules' && eventType === 'rename') {
      const nmPath = path.join(dir, 'node_modules');
      if (fs.existsSync(nmPath)) {
        console.log('[DAEMON] node_modules detecte, scan en cours...');
        triggerScan(dir);
      }
    }
    if (filename === 'package-lock.json' || filename === 'yarn.lock') {
      console.log(`[DAEMON] ${filename} modifie, scan en cours...`);
      triggerScan(dir);
    }
  });
  watchers.push(dirWatcher);

  return watchers;
}

function watchFile(filePath, projectDir) {
  let lastMtime;
  try {
    lastMtime = fs.statSync(filePath).mtime.getTime();
  } catch {
    return null; // File deleted between existsSync and statSync
  }

  return fs.watch(filePath, (eventType) => {
    if (eventType === 'change') {
      try {
        const currentMtime = fs.statSync(filePath).mtime.getTime();
        if (currentMtime !== lastMtime) {
          lastMtime = currentMtime;
          console.log(`[DAEMON] ${path.basename(filePath)} modifie`);
          triggerScan(projectDir);
        }
      } catch {
        // File may have been deleted between watch trigger and stat
      }
    }
  });
}

function watchNodeModules(nodeModulesPath, projectDir) {
  return fs.watch(nodeModulesPath, { recursive: true }, (eventType, filename) => {
    if (filename && filename.includes('package.json')) {
      console.log(`[DAEMON] Nouveau package detecte: ${filename}`);
      triggerScan(projectDir);
    }
  });
}

let scanTimeout = null;
let lastScanTime = 0;

function triggerScan(dir) {
  const now = Date.now();
  
  // Debounce: attend 3 secondes avant de scanner
  if (scanTimeout) {
    clearTimeout(scanTimeout);
  }

  // Evite les scans trop frequents (minimum 10 secondes entre chaque)
  if (now - lastScanTime < 10000) {
    scanTimeout = setTimeout(() => triggerScan(dir), 10000 - (now - lastScanTime));
    return;
  }

  scanTimeout = setTimeout(async () => {
    lastScanTime = Date.now();
    console.log(`\n[DAEMON] ========== SCAN AUTOMATIQUE ==========`);
    console.log(`[DAEMON] Cible: ${dir}`);
    console.log(`[DAEMON] Heure: ${new Date().toLocaleTimeString()}\n`);

    try {
      await run(dir, { webhook: webhookUrl });
    } catch (err) {
      console.log(`[DAEMON] Erreur scan: ${err.message}`);
    }

    console.log(`\n[DAEMON] ======================================\n`);
    console.log('[DAEMON] En attente de modifications...');
  }, 3000);
}

module.exports = { startDaemon };