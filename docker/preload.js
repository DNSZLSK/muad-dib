/**
 * MUAD'DIB Sandbox Preload — Runtime Monkey-Patching
 *
 * Injected via NODE_OPTIONS="--require /opt/preload.js" in the Docker sandbox.
 * Patches time, timers, network, filesystem, and process APIs to:
 *   1. Simulate time passage (trigger time-bomb malware)
 *   2. Accelerate timers (delayed payloads execute immediately)
 *   3. Log sensitive API calls for behavioral analysis
 *
 * All patches are wrapped in an IIFE — originals are closure-scoped and
 * unreachable by the target package. Every patch is try/catch guarded
 * to never break the target package.
 */
(function () {
  'use strict';

  // ═══════════════════════════════════════════════════════
  // 1. SAVE ALL ORIGINALS (closure-scoped, unreachable)
  // ═══════════════════════════════════════════════════════

  const _fs = require('fs');
  const _path = require('path');
  const _appendFileSync = _fs.appendFileSync;
  const _readFileSync = _fs.readFileSync;
  const _readFile = _fs.readFile;
  const _writeFileSync = _fs.writeFileSync;
  const _writeFile = _fs.writeFile;

  const _DateNow = Date.now;
  const _DateParse = Date.parse;
  const _OrigDate = Date;
  const _DateGetTime = Date.prototype.getTime;
  const _DateGetFullYear = Date.prototype.getFullYear;
  const _DateGetMonth = Date.prototype.getMonth;
  const _DateGetDate = Date.prototype.getDate;
  const _DateGetHours = Date.prototype.getHours;
  const _DateGetMinutes = Date.prototype.getMinutes;
  const _DateGetSeconds = Date.prototype.getSeconds;
  const _DateGetMilliseconds = Date.prototype.getMilliseconds;
  const _DateToString = Date.prototype.toString;
  const _DateToISOString = Date.prototype.toISOString;

  let _perfNow;
  try { _perfNow = performance.now.bind(performance); } catch (e) { _perfNow = null; }

  const _hrtime = process.hrtime;
  const _hrtimeBigint = process.hrtime.bigint;
  const _uptime = process.uptime;

  const _setTimeout = global.setTimeout;
  const _setInterval = global.setInterval;
  const _clearTimeout = global.clearTimeout;
  const _clearInterval = global.clearInterval;

  // ═══════════════════════════════════════════════════════
  // 2. CONFIGURATION
  // ═══════════════════════════════════════════════════════

  const TIME_OFFSET = parseInt(process.env.MUADDIB_TIME_OFFSET_MS || '0', 10);
  const LOG_FILE = '/tmp/preload.log';
  const realStart = _DateNow.call(Date);

  // Sensitive file patterns for FS interception
  const SENSITIVE_RE = /\.(npmrc|env|ssh|aws|gitconfig|bash_history)|id_rsa|credentials|\.gnupg|known_hosts|\.netrc/i;

  // Dangerous commands for process interception
  const DANGEROUS_CMD_RE = /\b(curl|wget|nc|netcat|python|python3|bash|sh|powershell|cmd\.exe)\b/i;

  // Sensitive env var patterns
  const SENSITIVE_ENV_RE = /TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|PRIVATE|API_KEY/i;

  // ═══════════════════════════════════════════════════════
  // 3. LOGGER (uses saved originals, silent on error)
  // ═══════════════════════════════════════════════════════

  function log(category, msg) {
    try {
      const ts = _DateNow.call(Date) - realStart;
      // Sanitize msg to prevent log injection (attacker injecting \n[PRELOAD] EXEC: DANGEROUS)
      const safeMsg = String(msg).replace(/\r/g, '\\r').replace(/\n/g, '\\n').substring(0, 1000);
      const safeCat = String(category).replace(/[\r\n]/g, '');
      _appendFileSync.call(_fs, LOG_FILE, `[PRELOAD] ${safeCat}: ${safeMsg} (t+${ts}ms)\n`);
    } catch (e) {
      // Silent — never break the target
    }
  }

  // ═══════════════════════════════════════════════════════
  // 4. TIME PATCHES — simulate time passage
  // ═══════════════════════════════════════════════════════

  if (TIME_OFFSET > 0) {
    try {
      Date.now = function () {
        return _DateNow.call(Date) + TIME_OFFSET;
      };
    } catch (e) { /* ignore */ }

    try {
      Date.prototype.getTime = function () {
        return _DateGetTime.call(this) + TIME_OFFSET;
      };
    } catch (e) { /* ignore */ }

    // Patch new Date() without arguments to return offset time
    try {
      const PatchedDate = function (...args) {
        if (new.target) {
          if (args.length === 0) {
            return new _OrigDate(_DateNow.call(Date) + TIME_OFFSET);
          }
          return new _OrigDate(...args);
        }
        // Called without new — returns string
        return new _OrigDate(_DateNow.call(Date) + TIME_OFFSET).toString();
      };

      // Preserve static methods
      PatchedDate.now = Date.now;
      PatchedDate.parse = _DateParse;
      PatchedDate.UTC = _OrigDate.UTC;
      PatchedDate.prototype = _OrigDate.prototype;
      PatchedDate.prototype.constructor = PatchedDate;

      global.Date = PatchedDate;
    } catch (e) { /* ignore */ }

    // performance.now — offset in ms
    if (_perfNow) {
      try {
        const perfOffset = TIME_OFFSET;
        Object.defineProperty(performance, 'now', {
          value: function () { return _perfNow() + perfOffset; },
          writable: true,
          configurable: true
        });
      } catch (e) { /* ignore */ }
    }

    // process.hrtime — offset in seconds+nanoseconds
    try {
      const offsetSec = Math.floor(TIME_OFFSET / 1000);
      const offsetNano = (TIME_OFFSET % 1000) * 1e6;

      process.hrtime = function (prev) {
        const real = _hrtime.call(process, prev);
        if (!prev) {
          real[0] += offsetSec;
          real[1] += offsetNano;
          if (real[1] >= 1e9) {
            real[0] += 1;
            real[1] -= 1e9;
          }
        }
        return real;
      };

      process.hrtime.bigint = function () {
        return _hrtimeBigint.call(process) + BigInt(TIME_OFFSET) * 1000000n;
      };
    } catch (e) { /* ignore */ }

    // process.uptime — offset in seconds
    try {
      const uptimeOffset = TIME_OFFSET / 1000;
      process.uptime = function () {
        return _uptime.call(process) + uptimeOffset;
      };
    } catch (e) { /* ignore */ }

    log('TIME', `Time offset applied: +${TIME_OFFSET}ms (${(TIME_OFFSET / 3600000).toFixed(1)}h)`);
  }

  // ═══════════════════════════════════════════════════════
  // 5. TIMER PATCHES — accelerate delays
  // ═══════════════════════════════════════════════════════

  try {
    global.setTimeout = function (fn, delay, ...args) {
      if (typeof fn !== 'function' && typeof fn !== 'string') {
        return _setTimeout(fn, delay, ...args);
      }
      const origDelay = typeof delay === 'number' ? delay : 0;
      if (origDelay > 1000) {
        log('TIMER', `setTimeout delay=${origDelay}ms (${(origDelay / 3600000).toFixed(1)}h) forced to 0`);
      }
      return _setTimeout(fn, 0, ...args);
    };
    // Preserve toString for detection evasion
    global.setTimeout.toString = function () { return 'function setTimeout() { [native code] }'; };
  } catch (e) { /* ignore */ }

  try {
    global.setInterval = function (fn, delay, ...args) {
      if (typeof fn !== 'function' && typeof fn !== 'string') {
        return _setInterval(fn, delay, ...args);
      }
      const origDelay = typeof delay === 'number' ? delay : 0;
      if (origDelay > 1000) {
        log('TIMER', `setInterval delay=${origDelay}ms (${(origDelay / 3600000).toFixed(1)}h) first exec immediate`);
        // Execute immediately, then keep the real interval
        try { fn(); } catch (e) { /* ignore callback errors */ }
      }
      return _setInterval(fn, delay, ...args);
    };
    global.setInterval.toString = function () { return 'function setInterval() { [native code] }'; };
  } catch (e) { /* ignore */ }

  // Preserve clearTimeout/clearInterval (not patched, but ensure they exist)
  global.clearTimeout = _clearTimeout;
  global.clearInterval = _clearInterval;

  // ═══════════════════════════════════════════════════════
  // 6. NETWORK PATCHES (log only, don't block)
  // ═══════════════════════════════════════════════════════

  // Patch https.request / http.request
  function patchHttpModule(modName) {
    try {
      const mod = require(modName);
      const _origRequest = mod.request;
      const _origGet = mod.get;

      mod.request = function (opts, cb) {
        try {
          const host = typeof opts === 'string' ? new URL(opts).hostname :
            (opts && (opts.hostname || opts.host)) || 'unknown';
          const method = (opts && opts.method) || 'GET';
          const path = typeof opts === 'string' ? new URL(opts).pathname :
            (opts && opts.path) || '/';
          log('NETWORK', `${modName}.request ${method} ${host}${path}`);
        } catch (e) { /* ignore logging errors */ }
        return _origRequest.apply(mod, arguments);
      };

      mod.get = function (opts, cb) {
        try {
          const host = typeof opts === 'string' ? new URL(opts).hostname :
            (opts && (opts.hostname || opts.host)) || 'unknown';
          const path = typeof opts === 'string' ? new URL(opts).pathname :
            (opts && opts.path) || '/';
          log('NETWORK', `${modName}.get GET ${host}${path}`);
        } catch (e) { /* ignore logging errors */ }
        return _origGet.apply(mod, arguments);
      };
    } catch (e) { /* module not available */ }
  }

  patchHttpModule('https');
  patchHttpModule('http');

  // Patch global fetch (Node 18+)
  if (typeof global.fetch === 'function') {
    try {
      const _origFetch = global.fetch;
      global.fetch = function (input, init) {
        try {
          const url = typeof input === 'string' ? input :
            (input && input.url) ? input.url : String(input);
          const method = (init && init.method) || 'GET';
          log('NETWORK', `fetch ${method} ${url}`);
        } catch (e) { /* ignore */ }
        return _origFetch.apply(global, arguments);
      };
      global.fetch.toString = function () { return 'function fetch() { [native code] }'; };
    } catch (e) { /* ignore */ }
  }

  // Patch dns.resolve / dns.lookup
  try {
    const dns = require('dns');
    const _origResolve = dns.resolve;
    const _origLookup = dns.lookup;

    if (_origResolve) {
      dns.resolve = function (hostname) {
        try { log('NETWORK', `dns.resolve ${hostname}`); } catch (e) { /* ignore */ }
        return _origResolve.apply(dns, arguments);
      };
    }

    if (_origLookup) {
      dns.lookup = function (hostname) {
        try { log('NETWORK', `dns.lookup ${hostname}`); } catch (e) { /* ignore */ }
        return _origLookup.apply(dns, arguments);
      };
    }
  } catch (e) { /* ignore */ }

  // Patch net.connect / net.createConnection
  try {
    const net = require('net');
    const _origConnect = net.connect;
    const _origCreateConnection = net.createConnection;

    net.connect = function (opts) {
      try {
        const host = (opts && opts.host) || 'unknown';
        const port = (opts && opts.port) || 0;
        log('NETWORK', `net.connect ${host}:${port}`);
      } catch (e) { /* ignore */ }
      return _origConnect.apply(net, arguments);
    };

    net.createConnection = function (opts) {
      try {
        const host = (opts && opts.host) || 'unknown';
        const port = (opts && opts.port) || 0;
        log('NETWORK', `net.createConnection ${host}:${port}`);
      } catch (e) { /* ignore */ }
      return _origCreateConnection.apply(net, arguments);
    };
  } catch (e) { /* ignore */ }

  // ═══════════════════════════════════════════════════════
  // 7. FILESYSTEM PATCHES (log sensitive reads, all writes)
  // ═══════════════════════════════════════════════════════

  try {
    const origReadFileSync = _fs.readFileSync;
    _fs.readFileSync = function (filePath) {
      try {
        const p = String(filePath);
        if (SENSITIVE_RE.test(p)) {
          log('FS_READ', `SENSITIVE ${p}`);
        }
      } catch (e) { /* ignore */ }
      return origReadFileSync.apply(_fs, arguments);
    };
  } catch (e) { /* ignore */ }

  try {
    const origReadFile = _fs.readFile;
    _fs.readFile = function (filePath) {
      try {
        const p = String(filePath);
        if (SENSITIVE_RE.test(p)) {
          log('FS_READ', `SENSITIVE ${p}`);
        }
      } catch (e) { /* ignore */ }
      return origReadFile.apply(_fs, arguments);
    };
  } catch (e) { /* ignore */ }

  try {
    const origWriteFileSync = _fs.writeFileSync;
    _fs.writeFileSync = function (filePath) {
      try {
        const p = String(filePath);
        const isSensitive = SENSITIVE_RE.test(p);
        log('FS_WRITE', `${isSensitive ? 'SENSITIVE ' : ''}${p}`);
      } catch (e) { /* ignore */ }
      return origWriteFileSync.apply(_fs, arguments);
    };
  } catch (e) { /* ignore */ }

  try {
    const origWriteFile = _fs.writeFile;
    _fs.writeFile = function (filePath) {
      try {
        const p = String(filePath);
        const isSensitive = SENSITIVE_RE.test(p);
        log('FS_WRITE', `${isSensitive ? 'SENSITIVE ' : ''}${p}`);
      } catch (e) { /* ignore */ }
      return origWriteFile.apply(_fs, arguments);
    };
  } catch (e) { /* ignore */ }

  // ═══════════════════════════════════════════════════════
  // 8. PROCESS PATCHES — command execution logging
  // ═══════════════════════════════════════════════════════

  try {
    const cp = require('child_process');

    const _origExec = cp.exec;
    const _origExecSync = cp.execSync;
    const _origSpawn = cp.spawn;
    const _origSpawnSync = cp.spawnSync;
    const _origExecFile = cp.execFile;
    const _origExecFileSync = cp.execFileSync;

    cp.exec = function (cmd) {
      try {
        const cmdStr = String(cmd);
        const isDangerous = DANGEROUS_CMD_RE.test(cmdStr);
        log('EXEC', `${isDangerous ? 'DANGEROUS ' : ''}exec: ${cmdStr.substring(0, 200)}`);
      } catch (e) { /* ignore */ }
      return _origExec.apply(cp, arguments);
    };

    cp.execSync = function (cmd) {
      try {
        const cmdStr = String(cmd);
        const isDangerous = DANGEROUS_CMD_RE.test(cmdStr);
        log('EXEC', `${isDangerous ? 'DANGEROUS ' : ''}execSync: ${cmdStr.substring(0, 200)}`);
      } catch (e) { /* ignore */ }
      return _origExecSync.apply(cp, arguments);
    };

    cp.spawn = function (cmd, args) {
      try {
        const cmdStr = String(cmd);
        const argsStr = Array.isArray(args) ? args.join(' ') : '';
        const full = `${cmdStr} ${argsStr}`.trim();
        const isDangerous = DANGEROUS_CMD_RE.test(full);
        log('EXEC', `${isDangerous ? 'DANGEROUS ' : ''}spawn: ${full.substring(0, 200)}`);
      } catch (e) { /* ignore */ }
      return _origSpawn.apply(cp, arguments);
    };

    cp.spawnSync = function (cmd, args) {
      try {
        const cmdStr = String(cmd);
        const argsStr = Array.isArray(args) ? args.join(' ') : '';
        const full = `${cmdStr} ${argsStr}`.trim();
        const isDangerous = DANGEROUS_CMD_RE.test(full);
        log('EXEC', `${isDangerous ? 'DANGEROUS ' : ''}spawnSync: ${full.substring(0, 200)}`);
      } catch (e) { /* ignore */ }
      return _origSpawnSync.apply(cp, arguments);
    };

    cp.execFile = function (file) {
      try {
        const fileStr = String(file);
        const isDangerous = DANGEROUS_CMD_RE.test(fileStr);
        log('EXEC', `${isDangerous ? 'DANGEROUS ' : ''}execFile: ${fileStr.substring(0, 200)}`);
      } catch (e) { /* ignore */ }
      return _origExecFile.apply(cp, arguments);
    };

    cp.execFileSync = function (file) {
      try {
        const fileStr = String(file);
        const isDangerous = DANGEROUS_CMD_RE.test(fileStr);
        log('EXEC', `${isDangerous ? 'DANGEROUS ' : ''}execFileSync: ${fileStr.substring(0, 200)}`);
      } catch (e) { /* ignore */ }
      return _origExecFileSync.apply(cp, arguments);
    };
  } catch (e) { /* child_process not available */ }

  // ═══════════════════════════════════════════════════════
  // 9. ENVIRONMENT VARIABLE ACCESS LOGGING
  // ═══════════════════════════════════════════════════════

  try {
    const _origEnv = process.env;
    const envProxy = new Proxy(_origEnv, {
      get: function (target, prop) {
        try {
          if (typeof prop === 'string' && SENSITIVE_ENV_RE.test(prop)) {
            log('ENV_ACCESS', `${prop}`);
          }
        } catch (e) { /* ignore */ }
        return target[prop];
      },
      set: function (target, prop, value) {
        target[prop] = value;
        return true;
      }
    });
    process.env = envProxy;
  } catch (e) { /* Proxy not supported or env not writable */ }

  // ═══════════════════════════════════════════════════════
  // 10. NATIVE ADDON DETECTION (process.dlopen)
  // ═══════════════════════════════════════════════════════

  // Native addons (.node files) can call syscalls like clock_gettime() directly,
  // bypassing all JavaScript monkey-patches. We can't prevent this, but we CAN
  // detect the loading of native addons and flag it for the analyzer.
  try {
    const _origDlopen = process.dlopen;
    process.dlopen = function (module, filename) {
      try {
        const f = String(filename || '');
        log('NATIVE_ADDON', `process.dlopen: ${f}`);
      } catch (e) { /* ignore */ }
      return _origDlopen.apply(process, arguments);
    };
  } catch (e) { /* ignore — process.dlopen may not be writable */ }

  // ═══════════════════════════════════════════════════════
  // 11. /proc/uptime SPOOFING
  // ═══════════════════════════════════════════════════════

  // Malware reads /proc/uptime to detect sandboxes (low uptime = fresh sandbox).
  // We intercept readFileSync('/proc/uptime') to return a realistic high uptime.
  // This complements the time API patches in section 4.
  try {
    const _origReadFileSyncForUptime = _fs.readFileSync;
    const _currentReadFileSync = _fs.readFileSync; // may already be patched by section 7
    _fs.readFileSync = function (filePath) {
      try {
        const p = String(filePath);
        if (p === '/proc/uptime') {
          // Return fake uptime: ~30 days + idle time (realistic for a production server)
          const fakeUptime = 2592000 + Math.floor(TIME_OFFSET / 1000) + Math.random() * 100;
          const fakeIdle = fakeUptime * 0.95;
          log('FS_READ', `SPOOFED /proc/uptime (real read intercepted)`);
          return `${fakeUptime.toFixed(2)} ${fakeIdle.toFixed(2)}\n`;
        }
      } catch (e) { /* ignore */ }
      return _currentReadFileSync.apply(_fs, arguments);
    };
  } catch (e) { /* ignore */ }

  // ═══════════════════════════════════════════════════════
  // 12. WORKER THREADS INTERCEPTION
  // ═══════════════════════════════════════════════════════

  // Workers spawned via new Worker() don't inherit NODE_OPTIONS preload.
  // Intercept the Worker constructor to inject preload and time offset.
  try {
    const wt = require('worker_threads');
    if (wt && wt.Worker) {
      const _OrigWorker = wt.Worker;
      wt.Worker = function (filename, options) {
        options = options || {};
        // Propagate time offset to worker
        options.env = Object.assign({}, process.env, options.env || {}, {
          MUADDIB_TIME_OFFSET_MS: String(TIME_OFFSET)
        });
        // Inject preload script into worker
        if (!options.execArgv) options.execArgv = [];
        options.execArgv = options.execArgv.concat(['--require', '/opt/preload.js']);
        log('WORKER', `Worker spawned: ${String(filename).substring(0, 200)}`);
        return new _OrigWorker(filename, options);
      };
      // Preserve prototype chain
      wt.Worker.prototype = _OrigWorker.prototype;
    }
  } catch (e) { /* worker_threads not available or not writable */ }

  // ═══════════════════════════════════════════════════════
  // 13. STARTUP LOG
  // ═══════════════════════════════════════════════════════

  log('INIT', `Preload active. TIME_OFFSET=${TIME_OFFSET}ms (${(TIME_OFFSET / 3600000).toFixed(1)}h). PID=${process.pid}`);

})();
