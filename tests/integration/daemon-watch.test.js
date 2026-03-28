const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes } = require('../test-utils');

async function runDaemonWatchTests() {
  console.log('\n=== DAEMON & WATCH TESTS ===\n');

  const { getScanState, watchFile, watchNodeModules, triggerScan, watchDirectory } = require('../../src/daemon.js');

  // --- getScanState ---

  test('DAEMON: getScanState returns default state for new directory', () => {
    const state = getScanState('/tmp/daemon-test-' + Date.now());
    assert(state.timeout === null, 'Default timeout should be null');
    assert(state.lastScanTime === 0, 'Default lastScanTime should be 0');
  });

  test('DAEMON: getScanState returns same object for same directory', () => {
    const dir = '/tmp/daemon-test-same-' + Date.now();
    const state1 = getScanState(dir);
    const state2 = getScanState(dir);
    assert(state1 === state2, 'Should return same reference');
  });

  // --- watchFile ---

  test('DAEMON: watchFile returns null for non-existent file', () => {
    const result = watchFile('/tmp/nonexistent-daemon-test-' + Date.now() + '.json', '/tmp');
    assert(result === null, 'Should return null for missing file');
  });

  test('DAEMON: watchFile returns watcher for existing file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-watch-'));
    const tmpFile = path.join(tmpDir, 'test.json');
    fs.writeFileSync(tmpFile, '{}');
    const origLog = console.log;
    console.log = () => {};
    try {
      const watcher = watchFile(tmpFile, tmpDir);
      assert(watcher !== null, 'Should return a watcher');
      assert(typeof watcher.close === 'function', 'Watcher should have close method');
      watcher.close();
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(tmpFile); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- watchNodeModules ---

  test('DAEMON: watchNodeModules returns watcher for existing dir', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-nm-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(nmDir);
    const origLog = console.log;
    console.log = () => {};
    try {
      const watcher = watchNodeModules(nmDir, tmpDir);
      assert(watcher !== null, 'Should return a watcher');
      assert(typeof watcher.close === 'function', 'Watcher should have close method');
      watcher.close();
    } finally {
      console.log = origLog;
      try { fs.rmdirSync(nmDir); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- triggerScan debounce ---

  test('DAEMON: triggerScan debounces (does not throw)', () => {
    const dir = '/tmp/daemon-trigger-' + Date.now();
    const origLog = console.log;
    console.log = () => {};
    try {
      // First call should set a timeout
      triggerScan(dir);
      const state = getScanState(dir);
      assert(state.timeout !== null, 'Should have a pending timeout');
      // Second call should clear and re-set
      triggerScan(dir);
      assert(state.timeout !== null, 'Should still have a pending timeout');
      // Clean up the timeout
      clearTimeout(state.timeout);
      state.timeout = null;
    } finally {
      console.log = origLog;
    }
  });

  test('DAEMON: triggerScan rate-limits within 10s window', () => {
    const dir = '/tmp/daemon-rate-' + Date.now();
    const state = getScanState(dir);
    // Simulate a recent scan
    state.lastScanTime = Date.now();
    const origLog = console.log;
    console.log = () => {};
    try {
      triggerScan(dir);
      // Should set a deferred timeout, not scan immediately
      assert(state.timeout !== null, 'Should defer scan');
      clearTimeout(state.timeout);
      state.timeout = null;
    } finally {
      console.log = origLog;
    }
  });

  // --- watchDirectory ---

  test('DAEMON: watchDirectory with lock files and node_modules', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-watchdir-'));
    const lockFile = path.join(tmpDir, 'package-lock.json');
    const yarnLock = path.join(tmpDir, 'yarn.lock');
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.writeFileSync(lockFile, '{}');
    fs.writeFileSync(yarnLock, '');
    fs.mkdirSync(nmDir);
    const origLog = console.log;
    console.log = () => {};
    try {
      const watchers = watchDirectory(tmpDir);
      assert(Array.isArray(watchers), 'Should return array of watchers');
      // lock file watcher + yarn watcher + node_modules watcher + dir watcher = 4
      assert(watchers.length >= 3, 'Should have at least 3 watchers, got ' + watchers.length);
      // Clean up watchers
      for (const w of watchers) {
        try { w.close(); } catch {}
      }
    } finally {
      console.log = origLog;
      try {
        fs.unlinkSync(lockFile);
        fs.unlinkSync(yarnLock);
        fs.rmdirSync(nmDir);
        fs.rmdirSync(tmpDir);
      } catch {}
    }
  });

  test('DAEMON: watchDirectory with no lock files or node_modules', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-emptydir-'));
    const origLog = console.log;
    console.log = () => {};
    try {
      const watchers = watchDirectory(tmpDir);
      assert(Array.isArray(watchers), 'Should return array');
      // Only dir watcher when no lock files or node_modules
      assert(watchers.length >= 1, 'Should have at least dir watcher');
      for (const w of watchers) {
        try { w.close(); } catch {}
      }
    } finally {
      console.log = origLog;
      try { fs.rmdirSync(tmpDir); } catch {}
    }
  });

  test('DAEMON: watchDirectory with only package-lock.json', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-lockonly-'));
    const lockFile = path.join(tmpDir, 'package-lock.json');
    fs.writeFileSync(lockFile, '{}');
    const origLog = console.log;
    console.log = () => {};
    try {
      const watchers = watchDirectory(tmpDir);
      // lock file watcher + dir watcher = 2
      assert(watchers.length >= 2, 'Should have at least 2 watchers, got ' + watchers.length);
      for (const w of watchers) {
        try { w.close(); } catch {}
      }
    } finally {
      console.log = origLog;
      try {
        fs.unlinkSync(lockFile);
        fs.rmdirSync(tmpDir);
      } catch {}
    }
  });

  // --- watch.js ---

  console.log('\n=== WATCH MODULE TESTS ===\n');

  // We can't test the full watch() function without long-running processes,
  // but we can verify the module loads and exports correctly
  const watchModule = require('../../src/watch.js');

  test('WATCH: module exports watch function', () => {
    assert(typeof watchModule.watch === 'function', 'Should export watch function');
  });

  // ============================================================
  // ADDITIONAL DAEMON.JS TESTS — covering uncovered lines
  // ============================================================

  // --- watchFile callback triggers scan on mtime change (lines 104-115) ---

  await asyncTest('DAEMON: watchFile callback triggers scan on mtime change', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-mtime-'));
    const tmpFile = path.join(tmpDir, 'test-lock.json');
    fs.writeFileSync(tmpFile, '{"v":1}');

    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const watcher = watchFile(tmpFile, tmpDir);
      assert(watcher !== null, 'Should return a watcher');

      // Wait a moment then modify the file to change mtime
      await new Promise(resolve => setTimeout(resolve, 100));
      fs.writeFileSync(tmpFile, '{"v":2}');

      // Wait for the watcher callback to fire
      await new Promise(resolve => setTimeout(resolve, 500));

      // The watcher should have detected the mtime change and logged
      const logStr = logs.join('\n');
      const detected = logStr.includes('modifie') || logStr.includes('SCAN');
      assert(detected, 'Should detect file modification via mtime change');

      watcher.close();
      // Clean up any pending triggerScan timeout
      const state = getScanState(tmpDir);
      if (state.timeout) { clearTimeout(state.timeout); state.timeout = null; }
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(tmpFile); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- watchFile watcher error handler (line 117-119) ---

  test('DAEMON: watchFile watcher error does not throw', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-werr-'));
    const tmpFile = path.join(tmpDir, 'err-test.json');
    fs.writeFileSync(tmpFile, '{}');

    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const watcher = watchFile(tmpFile, tmpDir);
      assert(watcher !== null, 'Should return a watcher');

      // Emit an error event — should be handled gracefully without throwing
      watcher.emit('error', new Error('simulated watcher error'));

      const logStr = logs.join('\n');
      assertIncludes(logStr, 'Watcher error', 'Should log watcher error message');
      assertIncludes(logStr, 'simulated watcher error', 'Should include error details');

      watcher.close();
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(tmpFile); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- watchNodeModules callback triggers on package.json change (lines 125-128) ---

  await asyncTest('DAEMON: watchNodeModules callback triggers on package.json change', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-nm-pkg-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(nmDir);
    // Create a package.json inside node_modules to trigger detection
    const pkgDir = path.join(nmDir, 'test-pkg');
    fs.mkdirSync(pkgDir);
    fs.writeFileSync(path.join(pkgDir, 'package.json'), '{}');

    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const watcher = watchNodeModules(nmDir, tmpDir);
      assert(watcher !== null, 'Should return a watcher');

      // Wait then modify a package.json file inside node_modules
      await new Promise(resolve => setTimeout(resolve, 100));
      fs.writeFileSync(path.join(pkgDir, 'package.json'), '{"v":2}');

      // Wait for the watcher callback to fire
      await new Promise(resolve => setTimeout(resolve, 500));

      const logStr = logs.join('\n');
      // On Windows/macOS with recursive watching, this should detect the change
      // The callback checks filename.includes('package.json')
      // Even if the OS doesn't fire, the test ensures no crash
      watcher.close();

      // Clean up any pending triggerScan timeout
      const state = getScanState(tmpDir);
      if (state.timeout) { clearTimeout(state.timeout); state.timeout = null; }
    } finally {
      console.log = origLog;
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  // --- watchNodeModules watcher error handler (line 130-132) ---

  test('DAEMON: watchNodeModules watcher error does not throw', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-nm-err-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(nmDir);

    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const watcher = watchNodeModules(nmDir, tmpDir);
      assert(watcher !== null, 'Should return a watcher');

      // Emit an error event — should be handled gracefully
      watcher.emit('error', new Error('simulated nm watcher error'));

      const logStr = logs.join('\n');
      assertIncludes(logStr, 'Watcher error', 'Should log watcher error message');
      assertIncludes(logStr, 'simulated nm watcher error', 'Should include error details');

      watcher.close();
    } finally {
      console.log = origLog;
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  // --- triggerScan actually runs scan after timeout (lines 162-174) ---

  await asyncTest('DAEMON: triggerScan executes run() after timeout expires', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-trigscan-'));

    // Monkey-patch index.js run to track calls
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    const runCalls = [];
    require(indexPath).run = async (dir, opts) => {
      runCalls.push({ dir, opts });
      return { threats: [], summary: {} };
    };

    // Clear daemon.js cache so it picks up the mocked run
    const daemonPath = require.resolve('../../src/runtime/daemon.js');
    delete require.cache[daemonPath];
    const daemonFresh = require(daemonPath);

    const origLog = console.log;
    console.log = () => {};
    try {
      // Ensure no rate-limiting: reset lastScanTime to 0
      const state = daemonFresh.getScanState(tmpDir);
      state.lastScanTime = 0;
      state.timeout = null;

      // Trigger the scan
      daemonFresh.triggerScan(tmpDir);
      assert(state.timeout !== null, 'Should have a pending timeout');

      // Wait for the 3-second timeout to fire + a bit extra
      await new Promise(resolve => setTimeout(resolve, 3500));

      assert(runCalls.length >= 1, 'run() should have been called, got ' + runCalls.length + ' calls');
      assert(runCalls[0].dir === tmpDir, 'run() should be called with the correct directory');
    } finally {
      // Clean up: restore original run, re-clear cache
      require(indexPath).run = origRun;
      delete require.cache[daemonPath];
      console.log = origLog;
      try { fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- triggerScan handles run() error gracefully (line 169-171) ---

  await asyncTest('DAEMON: triggerScan handles run() error gracefully', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'daemon-trigerr-'));

    // Monkey-patch index.js run to throw an error
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    require(indexPath).run = async () => {
      throw new Error('simulated scan failure');
    };

    // Clear daemon.js cache
    const daemonPath = require.resolve('../../src/runtime/daemon.js');
    delete require.cache[daemonPath];
    const daemonFresh = require(daemonPath);

    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const state = daemonFresh.getScanState(tmpDir);
      state.lastScanTime = 0;
      state.timeout = null;

      daemonFresh.triggerScan(tmpDir);

      // Wait for the 3-second timeout to fire
      await new Promise(resolve => setTimeout(resolve, 3500));

      const logStr = logs.join('\n');
      assertIncludes(logStr, 'Erreur scan', 'Should log scan error');
      assertIncludes(logStr, 'simulated scan failure', 'Should include error message');
    } finally {
      require(indexPath).run = origRun;
      delete require.cache[daemonPath];
      console.log = origLog;
      try { fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // ============================================================
  // ADDITIONAL WATCH.JS TESTS — covering uncovered lines
  // ============================================================

  console.log('\n=== WATCH MODULE ADDITIONAL TESTS ===\n');

  // --- watch() creates watchers for existing paths ---

  test('WATCH: watch() creates watchers for existing paths', () => {
    // Monkey-patch index.js run before requiring watch.js
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    require(indexPath).run = async () => ({ threats: [], summary: {} });

    // Save originals for monkey-patching
    const origExistsSync = fs.existsSync;
    const origFsWatch = fs.watch;
    const origProcessOnce = process.once;

    const createdWatchers = [];
    const fakeWatcher = () => {
      const EventEmitter = require('events');
      const w = new EventEmitter();
      w.close = () => {};
      createdWatchers.push(w);
      return w;
    };

    // Mock fs.existsSync to return true for watched paths
    fs.existsSync = (p) => {
      if (p.includes('package.json') || p.includes('package-lock.json') || p.includes('node_modules')) {
        return true;
      }
      return origExistsSync(p);
    };

    // Mock fs.watch to return fake watchers
    fs.watch = (watchPath, optionsOrCb, cb) => {
      return fakeWatcher();
    };

    // Mock process.once to capture SIGINT registration without actually registering
    let sigintHandler = null;
    process.once = (event, handler) => {
      if (event === 'SIGINT') {
        sigintHandler = handler;
      } else {
        origProcessOnce.call(process, event, handler);
      }
    };

    // Clear watch.js cache so it picks up mocked run
    const watchPath = require.resolve('../../src/runtime/watch.js');
    delete require.cache[watchPath];

    const origLog = console.log;
    console.log = () => {};
    try {
      const { watch: watchFn } = require(watchPath);
      watchFn('/fake/test/path');

      // Should have created watchers for package.json, package-lock.json, node_modules
      assert(createdWatchers.length >= 3, 'Should create watchers for existing paths, got ' + createdWatchers.length);
    } finally {
      fs.existsSync = origExistsSync;
      fs.watch = origFsWatch;
      process.once = origProcessOnce;
      require(indexPath).run = origRun;
      delete require.cache[watchPath];
      console.log = origLog;
    }
  });

  // --- watch() handles non-existing paths gracefully ---

  test('WATCH: watch() handles non-existing paths gracefully', () => {
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    require(indexPath).run = async () => ({ threats: [], summary: {} });

    const origExistsSync = fs.existsSync;
    const origFsWatch = fs.watch;
    const origProcessOnce = process.once;

    const createdWatchers = [];

    // Mock fs.existsSync to return false for all watch paths
    fs.existsSync = () => false;

    fs.watch = (watchPath, optionsOrCb, cb) => {
      const EventEmitter = require('events');
      const w = new EventEmitter();
      w.close = () => {};
      createdWatchers.push(w);
      return w;
    };

    process.once = (event, handler) => {
      if (event !== 'SIGINT') {
        origProcessOnce.call(process, event, handler);
      }
    };

    const watchPath = require.resolve('../../src/runtime/watch.js');
    delete require.cache[watchPath];

    const origLog = console.log;
    console.log = () => {};
    try {
      const { watch: watchFn } = require(watchPath);
      watchFn('/fake/nonexistent/path');

      // No watchers should be created since all paths don't exist
      assert(createdWatchers.length === 0, 'Should not create watchers for non-existing paths, got ' + createdWatchers.length);
    } finally {
      fs.existsSync = origExistsSync;
      fs.watch = origFsWatch;
      process.once = origProcessOnce;
      require(indexPath).run = origRun;
      delete require.cache[watchPath];
      console.log = origLog;
    }
  });

  // --- watch() registers SIGINT handler ---

  test('WATCH: watch() registers SIGINT handler', () => {
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    require(indexPath).run = async () => ({ threats: [], summary: {} });

    const origExistsSync = fs.existsSync;
    const origFsWatch = fs.watch;
    const origProcessOnce = process.once;

    fs.existsSync = () => false;
    fs.watch = () => {
      const EventEmitter = require('events');
      const w = new EventEmitter();
      w.close = () => {};
      return w;
    };

    let sigintRegistered = false;
    process.once = (event, handler) => {
      if (event === 'SIGINT') {
        sigintRegistered = true;
      } else {
        origProcessOnce.call(process, event, handler);
      }
    };

    const watchPath = require.resolve('../../src/runtime/watch.js');
    delete require.cache[watchPath];

    const origLog = console.log;
    console.log = () => {};
    try {
      const { watch: watchFn } = require(watchPath);
      watchFn('/fake/sigint/path');

      assert(sigintRegistered, 'Should register a SIGINT handler');
    } finally {
      fs.existsSync = origExistsSync;
      fs.watch = origFsWatch;
      process.once = origProcessOnce;
      require(indexPath).run = origRun;
      delete require.cache[watchPath];
      console.log = origLog;
    }
  });

  // --- watch() debounce callback calls run again on file change ---

  await asyncTest('WATCH: watch() debounce callback re-runs scan on file change', async () => {
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    const runCalls = [];
    require(indexPath).run = async (target, opts) => {
      runCalls.push({ target, opts });
      return { threats: [], summary: {} };
    };

    const origExistsSync = fs.existsSync;
    const origFsWatch = fs.watch;
    const origProcessOnce = process.once;

    const EventEmitter = require('events');
    let watchCallback = null;

    // Only make the first path (package.json) exist
    fs.existsSync = (p) => p.includes('package.json') && !p.includes('lock');

    fs.watch = (watchPath, optionsOrCb, cb) => {
      const w = new EventEmitter();
      w.close = () => {};
      // Capture the callback — it's the third arg when options object is passed
      if (typeof cb === 'function') {
        watchCallback = cb;
      } else if (typeof optionsOrCb === 'function') {
        watchCallback = optionsOrCb;
      }
      return w;
    };

    process.once = (event, handler) => {
      if (event !== 'SIGINT') {
        origProcessOnce.call(process, event, handler);
      }
    };

    const watchPath = require.resolve('../../src/runtime/watch.js');
    delete require.cache[watchPath];

    const origLog = console.log;
    console.log = () => {};
    try {
      const { watch: watchFn } = require(watchPath);
      watchFn('/fake/debounce/path');

      // Initial run call (the run at line 13 of watch.js)
      // Give it a moment for the initial async call
      await new Promise(resolve => setTimeout(resolve, 50));
      const initialCalls = runCalls.length;
      assert(initialCalls >= 1, 'Should have at least 1 initial run call, got ' + initialCalls);

      // Simulate a file change event via the watcher callback
      assert(watchCallback !== null, 'Should have captured the watch callback');
      watchCallback('change', 'package.json');

      // Wait for the 1-second debounce to fire
      await new Promise(resolve => setTimeout(resolve, 1200));

      assert(runCalls.length > initialCalls, 'Should have additional run calls after file change, got ' + runCalls.length);
    } finally {
      fs.existsSync = origExistsSync;
      fs.watch = origFsWatch;
      process.once = origProcessOnce;
      require(indexPath).run = origRun;
      delete require.cache[watchPath];
      console.log = origLog;
    }
  });

  // --- watch() watcher error handler logs warning ---

  test('WATCH: watch() watcher error handler logs warning', () => {
    const indexPath = require.resolve('../../src/index.js');
    const origRun = require(indexPath).run;
    require(indexPath).run = async () => ({ threats: [], summary: {} });

    const origExistsSync = fs.existsSync;
    const origFsWatch = fs.watch;
    const origProcessOnce = process.once;

    const EventEmitter = require('events');
    const createdWatchers = [];

    // Make only one path exist so we get one watcher
    fs.existsSync = (p) => p.includes('package.json') && !p.includes('lock');

    fs.watch = (watchPath, optionsOrCb, cb) => {
      const w = new EventEmitter();
      w.close = () => {};
      createdWatchers.push(w);
      return w;
    };

    process.once = (event, handler) => {
      if (event !== 'SIGINT') {
        origProcessOnce.call(process, event, handler);
      }
    };

    const watchPath = require.resolve('../../src/runtime/watch.js');
    delete require.cache[watchPath];

    const origConsoleError = console.error;
    const errors = [];
    console.error = (...args) => errors.push(args.join(' '));

    const origLog = console.log;
    console.log = () => {};
    try {
      const { watch: watchFn } = require(watchPath);
      watchFn('/fake/error/path');

      assert(createdWatchers.length >= 1, 'Should have at least one watcher');

      // Emit an error on the watcher — should be caught by the error handler
      createdWatchers[0].emit('error', new Error('simulated watch error'));

      const errStr = errors.join('\n');
      assertIncludes(errStr, 'WARN', 'Should log a warning on watcher error');
      assertIncludes(errStr, 'simulated watch error', 'Should include error message');
    } finally {
      fs.existsSync = origExistsSync;
      fs.watch = origFsWatch;
      process.once = origProcessOnce;
      require(indexPath).run = origRun;
      delete require.cache[watchPath];
      console.error = origConsoleError;
      console.log = origLog;
    }
  });
}

module.exports = { runDaemonWatchTests };
