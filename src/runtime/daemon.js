const fs = require('fs');
const path = require('path');
const { run } = require('../index.js');
const { banner } = require('../utils.js');

let webhookUrl = null;

async function startDaemon(options = {}) {
  webhookUrl = options.webhook || null;

  console.log('\n' + banner([
    "MUAD'DIB Security Daemon",
    'Monitoring npm installs'
  ]) + '\n');

  console.log('[DAEMON] Starting...');
  console.log(`[DAEMON] Webhook: ${webhookUrl ? 'Configured' : 'Not configured'}`);
  console.log('[DAEMON] Press Ctrl+C to stop\n');

  // Watch the current directory
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
    process.once('SIGINT', () => {
      console.log('\n[DAEMON] Stopping...');
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

  console.log(`[DAEMON] Watching ${dir}`);

  // Watch package-lock.json
  if (fs.existsSync(packageLockPath)) {
    const w = watchFile(packageLockPath, dir);
    if (w) watchers.push(w);
  }

  // Watch yarn.lock
  if (fs.existsSync(yarnLockPath)) {
    const w = watchFile(yarnLockPath, dir);
    if (w) watchers.push(w);
  }

  // Watch node_modules
  if (fs.existsSync(nodeModulesPath)) {
    watchers.push(watchNodeModules(nodeModulesPath, dir));
  }

  // Watch for node_modules creation
  if (process.platform === 'linux') {
    console.log('[DAEMON] Note: recursive fs.watch may not work on Linux');
  }

  const dirWatcher = fs.watch(dir, (eventType, filename) => {
    if (filename === 'node_modules' && eventType === 'rename') {
      const nmPath = path.join(dir, 'node_modules');
      if (fs.existsSync(nmPath)) {
        console.log('[DAEMON] node_modules detected, scanning...');
        triggerScan(dir);
      }
    }
    if (filename === 'package-lock.json' || filename === 'yarn.lock') {
      console.log(`[DAEMON] ${filename} modified, scanning...`);
      triggerScan(dir);
    }
  });
  dirWatcher.on('error', (err) => {
    console.log(`[DAEMON] Watcher error on ${dir}: ${err.message}`);
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

  const watcher = fs.watch(filePath, (eventType) => {
    if (eventType === 'change') {
      try {
        const currentMtime = fs.statSync(filePath).mtime.getTime();
        if (currentMtime !== lastMtime) {
          lastMtime = currentMtime;
          console.log(`[DAEMON] ${path.basename(filePath)} modified`);
          triggerScan(projectDir);
        }
      } catch {
        // File may have been deleted between watch trigger and stat
      }
    }
  });
  watcher.on('error', (err) => {
    console.log(`[DAEMON] Watcher error on ${filePath}: ${err.message}`);
  });
  return watcher;
}

function watchNodeModules(nodeModulesPath, projectDir) {
  const watcher = fs.watch(nodeModulesPath, { recursive: true }, (eventType, filename) => {
    if (filename && filename.includes('package.json')) {
      console.log(`[DAEMON] New package detected: ${filename}`);
      triggerScan(projectDir);
    }
  });
  watcher.on('error', (err) => {
    console.log(`[DAEMON] Watcher error on ${nodeModulesPath}: ${err.message}`);
  });
  return watcher;
}

// Per-directory scan state to prevent cross-directory scan suppression
const scanState = new Map();

function getScanState(dir) {
  if (!scanState.has(dir)) {
    scanState.set(dir, { timeout: null, lastScanTime: 0 });
  }
  return scanState.get(dir);
}

function triggerScan(dir) {
  const now = Date.now();
  const state = getScanState(dir);

  // Debounce: wait 3 seconds before scanning
  if (state.timeout) {
    clearTimeout(state.timeout);
  }

  // Avoid over-frequent scans (minimum 10 seconds between each)
  if (now - state.lastScanTime < 10000) {
    state.timeout = setTimeout(() => triggerScan(dir), 10000 - (now - state.lastScanTime));
    return;
  }

  state.timeout = setTimeout(async () => {
    state.lastScanTime = Date.now();
    console.log(`\n[DAEMON] ========== AUTOMATIC SCAN ==========`);
    console.log(`[DAEMON] Target: ${dir}`);
    console.log(`[DAEMON] Time: ${new Date().toLocaleTimeString()}\n`);

    try {
      await run(dir, { webhook: webhookUrl });
    } catch (err) {
      console.log(`[DAEMON] Scan error: ${err.message}`);
    }

    console.log(`\n[DAEMON] ======================================\n`);
    console.log('[DAEMON] Waiting for changes...');
  }, 3000);
}

module.exports = { startDaemon, watchDirectory, watchFile, watchNodeModules, triggerScan, getScanState };
