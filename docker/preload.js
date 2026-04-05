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

  // When libfaketime is active (C-level time shift), set JS TIME_OFFSET=0
  // to avoid double acceleration (libfaketime already shifts clock_gettime).
  const FAKETIME_ACTIVE = process.env.MUADDIB_FAKETIME_ACTIVE === '1';
  const TIME_OFFSET = FAKETIME_ACTIVE ? 0 : parseInt(process.env.NODE_TIMING_OFFSET || '0', 10);
  delete process.env.NODE_TIMING_OFFSET;
  delete process.env.MUADDIB_FAKETIME_ACTIVE;
  const LOG_FILE = '/tmp/preload.log';
  const realStart = _DateNow.call(Date);

  // ── Hide sandbox env vars from target package ──
  // libfaketime is already loaded in memory; env vars are no longer needed.
  // Prevents malware from detecting sandbox via process.env.LD_PRELOAD.
  const HIDDEN_ENV_VARS = new Set([
    'LD_PRELOAD', 'FAKETIME', 'DONT_FAKE_MONOTONIC',
    'FAKETIME_NO_CACHE', 'MUADDIB_FAKETIME', 'MUADDIB_FAKETIME_ACTIVE',
    'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS', 'MUADDIB_UPSTREAM_DNS'
  ]);
  for (const v of HIDDEN_ENV_VARS) { try { delete process.env[v]; } catch(e) { /* ignore */ } }

  // Lock NODE_OPTIONS to prevent target package from disabling preload in child processes
  try {
    const _nodeOpts = process.env.NODE_OPTIONS;
    Object.defineProperty(process.env, 'NODE_OPTIONS', {
      value: _nodeOpts, writable: false, configurable: false, enumerable: true
    });
  } catch (e) { /* env may not support defineProperty */ }

  // Sensitive file patterns for FS interception
  const SENSITIVE_RE = /\.(npmrc|env|ssh|aws|gitconfig|bash_history)|id_rsa|credentials|\.gnupg|known_hosts|\.netrc/i;

  // Dangerous commands for process interception
  const DANGEROUS_CMD_RE = /\b(curl|wget|nc|netcat|python|python3|bash|sh|powershell|cmd\.exe)\b/i;

  // Sensitive env var patterns
  const SENSITIVE_ENV_RE = /TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|PRIVATE|API_KEY/i;

  // Safe domains: pass through to real network (npm install, CDN downloads)
  // Must match the list in mock-network.js
  const MOCK_SAFE_DOMAINS = [
    'registry.npmjs.org', 'npmjs.com', 'npmjs.org',
    'registry.yarnpkg.com', 'yarnpkg.com',
    'github.com', 'api.github.com', 'objects.githubusercontent.com',
    'raw.githubusercontent.com', 'codeload.github.com', 'github.githubassets.com',
    'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'cloudflare.com',
    'amazonaws.com', 'googleapis.com', 'storage.googleapis.com',
    'nodejs.org', 'gitlab.com', 'bitbucket.org',
    'fastly.net', 'fastly.com'
  ];

  function isSafeDomain(host) {
    if (!host) return true; // unknown host → pass through (safe default)
    var d = String(host).toLowerCase().replace(/:\d+$/, '');
    if (d === 'localhost' || d === '127.0.0.1' || d === '::1') return true;
    return MOCK_SAFE_DOMAINS.some(function (s) { return d === s || d.endsWith('.' + s); });
  }

  // Per-session realistic mock IP — generated once, used for all dns.lookup mocks.
  // Range 104.16.0.0 – 104.31.255.255 (Cloudflare) to resist loopback/private-range checks.
  const MOCK_IP_OCTETS = [104, 16 + Math.floor(Math.random() * 16),
    Math.floor(Math.random() * 256), 1 + Math.floor(Math.random() * 254)];
  const MOCK_IP = MOCK_IP_OCTETS.join('.');

  // Plausible mock response bodies (indexed by content type hint)
  const MOCK_RESPONSE_JSON = '{"status":"ok","data":{}}';
  const MOCK_RESPONSE_HTML = '<html><body></body></html>';
  const MOCK_RESPONSE_JS = '""'; // eval('""') is a no-op

  // ═══════════════════════════════════════════════════════
  // 3. LOGGER (uses saved originals, silent on error)
  // ═══════════════════════════════════════════════════════

  function log(category, msg) {
    try {
      const ts = _DateNow.call(Date) - realStart;
      // Sanitize msg to prevent log injection (attacker injecting \n[PRELOAD] EXEC: DANGEROUS)
      const safeMsg = String(msg).replace(/\r/g, '\\r').replace(/\n/g, '\\n').substring(0, 1000);
      const safeCat = String(category).replace(/[\r\n\[\]]/g, '');
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
    const _patchedSetTimeout = function (fn, delay, ...args) {
      if (typeof fn !== 'function' && typeof fn !== 'string') {
        return _setTimeout(fn, delay, ...args);
      }
      const origDelay = typeof delay === 'number' ? delay : 0;
      if (origDelay > 1000) {
        log('TIMER', `setTimeout delay=${origDelay}ms (${(origDelay / 3600000).toFixed(1)}h) forced to 0`);
      }
      return _setTimeout(fn, 0, ...args);
    };
    _patchedSetTimeout.toString = function () { return 'function setTimeout() { [native code] }'; };
    Object.defineProperty(global, 'setTimeout', {
      value: _patchedSetTimeout,
      writable: false,
      configurable: false,
      enumerable: true
    });
  } catch (e) { /* ignore */ }

  try {
    const _patchedSetInterval = function (fn, delay, ...args) {
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
    _patchedSetInterval.toString = function () { return 'function setInterval() { [native code] }'; };
    Object.defineProperty(global, 'setInterval', {
      value: _patchedSetInterval,
      writable: false,
      configurable: false,
      enumerable: true
    });
  } catch (e) { /* ignore */ }

  // Preserve clearTimeout/clearInterval (not patched, but ensure they exist)
  global.clearTimeout = _clearTimeout;
  global.clearInterval = _clearInterval;

  // ═══════════════════════════════════════════════════════
  // 6. NETWORK PATCHES — Mock non-safe domains, pass through safe
  //
  // Safe domains (npm, GitHub, CDNs): real network call + log
  // Non-safe domains: mock response + log full request details
  //
  // This lets the sandbox observe network INTENT (which domains,
  // what data is sent) without real outbound traffic to C2 servers.
  // The system-level mock-network.js handles DNS + HTTP for non-Node
  // processes; this handles Node.js APIs (including HTTPS bodies).
  // ═══════════════════════════════════════════════════════

  /**
   * Create a mock http.ClientRequest that captures the request body
   * and emits a mock 200 OK response. Compatible with the common
   * malware patterns: callback-based, event-based, and piped.
   */
  function createMockClientRequest(host, method, reqPath, callback) {
    const EventEmitter = require('events');
    const req = new EventEmitter();
    const bodyChunks = [];
    req.writable = true;
    req.finished = false;
    req.headersSent = false;

    req.write = function (data) {
      try { if (data) bodyChunks.push(String(data)); } catch (e) { /* ignore */ }
      return true;
    };

    req.end = function (data, enc, cb) {
      if (typeof data === 'function') { cb = data; data = null; }
      else if (typeof enc === 'function') { cb = enc; }
      try { if (data) bodyChunks.push(String(data)); } catch (e) { /* ignore */ }
      req.finished = true;

      var body = bodyChunks.join('');
      if (body) {
        log('MOCK_HTTP_BODY', 'OUT ' + method + ' ' + host + reqPath + ' ' + body.substring(0, 2000));
      }

      // Build mock IncomingMessage (response) with plausible body
      var mockBody = MOCK_RESPONSE_JSON;
      var mockCT = 'application/json';
      if (/\.js($|\?)/.test(reqPath)) { mockBody = MOCK_RESPONSE_JS; mockCT = 'application/javascript'; }
      else if (/\.html?($|\?)/.test(reqPath)) { mockBody = MOCK_RESPONSE_HTML; mockCT = 'text/html'; }

      var res = new EventEmitter();
      res.statusCode = 200;
      res.statusMessage = 'OK';
      res.headers = { 'content-type': mockCT, 'content-length': String(Buffer.byteLength(mockBody)) };
      res.rawHeaders = ['Content-Type', mockCT, 'Content-Length', String(Buffer.byteLength(mockBody))];
      res.httpVersion = '1.1';
      res.readable = true;
      res.setEncoding = function () { return res; };
      res.resume = function () { return res; };
      res.read = function () { return null; };
      res.pipe = function (dest) { try { dest.end(mockBody); } catch (e) { /* ignore */ } return dest; };
      res.destroy = function () {};

      process.nextTick(function () {
        try {
          if (callback) callback(res);
          req.emit('response', res);
          res.emit('data', Buffer.from(mockBody));
          res.emit('end');
          if (cb) cb();
        } catch (e) { /* ignore callback errors */ }
      });

      return req;
    };

    req.setTimeout = function (ms, cb) { if (cb) req.on('timeout', cb); return req; };
    req.abort = function () { req.emit('close'); };
    req.destroy = function () { req.emit('close'); return req; };
    req.flushHeaders = function () {};
    req.setNoDelay = function () { return req; };
    req.setSocketKeepAlive = function () { return req; };
    req.setHeader = function () { return req; };
    req.getHeader = function () { return undefined; };
    req.removeHeader = function () {};
    return req;
  }

  /**
   * Extract hostname from http.request / https.request arguments.
   * Handles: request(url, cb), request(url, opts, cb), request(opts, cb)
   */
  function extractRequestInfo(args) {
    var urlOrOpts = args[0];
    var optsOrCb = args[1];
    var cb = args[2];
    var host = 'unknown', method = 'GET', reqPath = '/', callback;

    try {
      if (typeof urlOrOpts === 'string') {
        var u = new URL(urlOrOpts);
        host = u.hostname;
        reqPath = u.pathname + u.search;
        method = (typeof optsOrCb === 'object' && optsOrCb ? optsOrCb.method : null) || 'GET';
        callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
      } else if (urlOrOpts instanceof URL) {
        host = urlOrOpts.hostname;
        reqPath = urlOrOpts.pathname + urlOrOpts.search;
        method = (typeof optsOrCb === 'object' && optsOrCb ? optsOrCb.method : null) || 'GET';
        callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
      } else if (urlOrOpts && typeof urlOrOpts === 'object') {
        host = urlOrOpts.hostname || urlOrOpts.host || 'unknown';
        method = urlOrOpts.method || 'GET';
        reqPath = urlOrOpts.path || '/';
        callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
      }
    } catch (e) { /* ignore parse errors */ }

    // Strip port from host
    host = String(host).replace(/:\d+$/, '');
    return { host: host, method: method, path: reqPath, callback: callback };
  }

  // Patch https.request / http.request — mock non-safe, pass through safe
  function patchHttpModule(modName) {
    try {
      const mod = require(modName);
      const _origRequest = mod.request;
      const _origGet = mod.get;

      mod.request = function () {
        var info;
        try { info = extractRequestInfo(arguments); } catch (e) { return _origRequest.apply(mod, arguments); }

        log('NETWORK', modName + '.request ' + info.method + ' ' + info.host + info.path);

        if (!isSafeDomain(info.host)) {
          log('MOCK_HTTP', modName + ' ' + info.method + ' ' + info.host + info.path);
          return createMockClientRequest(info.host, info.method, info.path, info.callback);
        }

        return _origRequest.apply(mod, arguments);
      };

      mod.get = function () {
        var info;
        try { info = extractRequestInfo(arguments); } catch (e) { return _origGet.apply(mod, arguments); }

        log('NETWORK', modName + '.get GET ' + info.host + info.path);

        if (!isSafeDomain(info.host)) {
          log('MOCK_HTTP', modName + ' GET ' + info.host + info.path);
          var req = createMockClientRequest(info.host, 'GET', info.path, info.callback);
          process.nextTick(function () { req.end(); });
          return req;
        }

        return _origGet.apply(mod, arguments);
      };
    } catch (e) { /* module not available */ }
  }

  patchHttpModule('https');
  patchHttpModule('http');

  // Patch global fetch (Node 18+) — mock non-safe domains
  if (typeof global.fetch === 'function') {
    try {
      const _origFetch = global.fetch;
      global.fetch = function (input, init) {
        var url, method, hostname;
        try {
          url = typeof input === 'string' ? input :
            (input && input.url) ? input.url : String(input);
          method = (init && init.method) || 'GET';
          hostname = new URL(url).hostname;
          log('NETWORK', 'fetch ' + method + ' ' + url);
        } catch (e) {
          return _origFetch.apply(global, arguments);
        }

        if (!isSafeDomain(hostname)) {
          var body = '';
          try { body = init && init.body ? String(init.body).substring(0, 2000) : ''; } catch (e) { /* ignore */ }
          log('MOCK_HTTP', 'fetch ' + method + ' ' + url);
          if (body) log('MOCK_HTTP_BODY', 'OUT ' + method + ' ' + hostname + ' ' + body);
          // Choose plausible response body based on URL hint
          var mockBody = MOCK_RESPONSE_JSON;
          var mockCT = 'application/json';
          if (/\.js($|\?)/.test(url)) { mockBody = MOCK_RESPONSE_JS; mockCT = 'application/javascript'; }
          else if (/\.html?($|\?)/.test(url)) { mockBody = MOCK_RESPONSE_HTML; mockCT = 'text/html'; }
          return Promise.resolve(new Response(mockBody, { status: 200, headers: { 'content-type': mockCT } }));
        }

        return _origFetch.apply(global, arguments);
      };
      global.fetch.toString = function () { return 'function fetch() { [native code] }'; };
    } catch (e) { /* ignore */ }
  }

  // Patch dns.resolve / dns.lookup — mock non-safe domains
  try {
    const dns = require('dns');
    const _origResolve = dns.resolve;
    const _origLookup = dns.lookup;

    if (_origLookup) {
      dns.lookup = function (hostname, options, callback) {
        try { log('NETWORK', 'dns.lookup ' + hostname); } catch (e) { /* ignore */ }

        // Normalize args: lookup(hostname, callback) or lookup(hostname, options, callback)
        if (typeof options === 'function') { callback = options; options = {}; }

        if (hostname && !isSafeDomain(hostname)) {
          log('MOCK_DNS', hostname + ' -> ' + MOCK_IP);
          if (typeof callback === 'function') {
            process.nextTick(function () { callback(null, MOCK_IP, 4); });
            return;
          }
        }

        return _origLookup.apply(dns, arguments);
      };
    }

    if (_origResolve) {
      dns.resolve = function (hostname, rrtype, callback) {
        try { log('NETWORK', 'dns.resolve ' + hostname); } catch (e) { /* ignore */ }

        if (typeof rrtype === 'function') { callback = rrtype; rrtype = 'A'; }

        if (hostname && !isSafeDomain(hostname)) {
          log('MOCK_DNS', hostname + ' -> ' + MOCK_IP);
          if (typeof callback === 'function') {
            process.nextTick(function () { callback(null, [MOCK_IP]); });
            return;
          }
        }

        return _origResolve.apply(dns, arguments);
      };
    }
  } catch (e) { /* ignore */ }

  // Patch net.connect / net.createConnection — log and pass through
  // (mock DNS already redirects non-safe domains to 127.0.0.2 where
  // mock-network.js HTTP/TLS honeypot captures the traffic)
  try {
    const net = require('net');
    const _origConnect = net.connect;
    const _origCreateConnection = net.createConnection;

    net.connect = function (opts) {
      try {
        const host = (opts && opts.host) || 'unknown';
        const port = (opts && opts.port) || 0;
        log('NETWORK', 'net.connect ' + host + ':' + port);
      } catch (e) { /* ignore */ }
      return _origConnect.apply(net, arguments);
    };

    net.createConnection = function (opts) {
      try {
        const host = (opts && opts.host) || 'unknown';
        const port = (opts && opts.port) || 0;
        log('NETWORK', 'net.createConnection ' + host + ':' + port);
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

  // fs.promises patches (malware may use async API to avoid sync patches)
  try {
    const fsp = _fs.promises;
    if (fsp) {
      const origFspReadFile = fsp.readFile;
      fsp.readFile = function (filePath) {
        try {
          const p = String(filePath);
          if (SENSITIVE_RE.test(p)) {
            log('FS_READ', `SENSITIVE ${p}`);
          }
        } catch (e) { /* ignore */ }
        return origFspReadFile.apply(fsp, arguments);
      };

      const origFspWriteFile = fsp.writeFile;
      fsp.writeFile = function (filePath) {
        try {
          const p = String(filePath);
          const isSensitive = SENSITIVE_RE.test(p);
          log('FS_WRITE', `${isSensitive ? 'SENSITIVE ' : ''}${p}`);
        } catch (e) { /* ignore */ }
        return origFspWriteFile.apply(fsp, arguments);
      };
    }
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
        // Hide sandbox env vars (libfaketime, etc.) from target package
        if (typeof prop === 'string' && HIDDEN_ENV_VARS.has(prop)) return undefined;
        try {
          if (typeof prop === 'string' && SENSITIVE_ENV_RE.test(prop)) {
            log('ENV_ACCESS', `${prop}`);
          }
        } catch (e) { /* ignore */ }
        return target[prop];
      },
      has: function (target, prop) {
        if (typeof prop === 'string' && HIDDEN_ENV_VARS.has(prop)) return false;
        return prop in target;
      },
      ownKeys: function (target) {
        return Reflect.ownKeys(target).filter(k => !HIDDEN_ENV_VARS.has(k));
      },
      getOwnPropertyDescriptor: function (target, prop) {
        if (typeof prop === 'string' && HIDDEN_ENV_VARS.has(prop)) return undefined;
        return Object.getOwnPropertyDescriptor(target, prop);
      },
      set: function (target, prop, value) {
        try { target[prop] = value; } catch (e) { /* NODE_OPTIONS is locked */ }
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
        // 11b. /proc/1/cgroup SPOOFING (Docker detection evasion)
        // Malware reads /proc/1/cgroup looking for "docker" or "containerd" to detect sandbox.
        // Return realistic non-Docker cgroup content (systemd init.scope).
        if (p === '/proc/1/cgroup') {
          log('FS_READ', `SPOOFED /proc/1/cgroup (real read intercepted)`);
          return '0::/init.scope\n';
        }
        // 11c. /etc/resolv.conf SPOOFING (mock DNS detection evasion)
        // Mock network overrides resolv.conf to 127.0.0.1. Malware can detect this.
        // Return realistic resolv.conf pointing to Docker bridge DNS or Cloudflare.
        if (p === '/etc/resolv.conf') {
          log('FS_READ', 'SPOOFED /etc/resolv.conf (mock DNS hidden)');
          return 'nameserver 172.17.0.1\nnameserver 1.1.1.1\nsearch localdomain\n';
        }
        // 11d. /proc/self/environ SPOOFING (libfaketime detection evasion)
        // Malware reads /proc/self/environ or /proc/<pid>/environ to detect
        // LD_PRELOAD=libfaketime (sandbox fingerprint). Strip hidden vars.
        if (p === '/proc/self/environ' || /\/proc\/\d+\/environ/.test(p)) {
          log('FS_READ', `SPOOFED ${p} (sandbox vars stripped)`);
          try {
            const real = _currentReadFileSync.apply(_fs, arguments);
            const str = (Buffer.isBuffer(real) ? real : Buffer.from(String(real))).toString();
            const filtered = str.split('\0')
              .filter(function (e) { return !HIDDEN_ENV_VARS.has(e.split('=')[0]); })
              .join('\0');
            return Buffer.from(filtered);
          } catch (e) {
            // If real read fails, return empty (better than exposing LD_PRELOAD)
            return Buffer.from('');
          }
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
        // Propagate time offset to worker (FAKETIME_ACTIVE prevents double-accel)
        const workerEnvExtra = { NODE_TIMING_OFFSET: String(TIME_OFFSET) };
        if (FAKETIME_ACTIVE) workerEnvExtra.MUADDIB_FAKETIME_ACTIVE = '1';
        options.env = Object.assign({}, process.env, options.env || {}, workerEnvExtra);
        // Inject preload script into worker
        if (!options.execArgv) options.execArgv = [];
        options.execArgv = options.execArgv.concat(['--require', '/opt/node_setup.js']);
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
