/**
 * MUAD'DIB Mock Network — DNS Proxy + HTTP Honeypot
 *
 * Runs inside the Docker sandbox as a background service.
 * Intercepts non-safe network traffic at the system level:
 *   - DNS (UDP 53): forwards safe domains to upstream, returns mock IP for others
 *   - HTTP (TCP 80 on 127.0.0.2): captures full requests, returns 200 OK
 *   - TLS trap (TCP 443 on 127.0.0.2): accepts connections, logs the attempt
 *
 * Safe domains (npm registry, GitHub, CDNs) are proxied transparently
 * so npm install works. Everything else is redirected to the local
 * honeypot for behavioral analysis.
 *
 * Logs: /tmp/mock-dns.log, /tmp/mock-http.log (JSONL)
 */

'use strict';

const dgram = require('dgram');
const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');

// ── Config ──
const MOCK_IP = '127.0.0.2';
const UPSTREAM_DNS = process.env.MUADDIB_UPSTREAM_DNS || '8.8.8.8';
const DNS_LOG = '/tmp/mock-dns.log';
const HTTP_LOG = '/tmp/mock-http.log';

// Safe domains: forwarded to real DNS (npm install needs these)
const SAFE_DOMAINS = [
  'registry.npmjs.org', 'npmjs.com', 'npmjs.org',
  'registry.yarnpkg.com', 'yarnpkg.com',
  'github.com', 'api.github.com', 'objects.githubusercontent.com',
  'raw.githubusercontent.com', 'codeload.github.com', 'github.githubassets.com',
  'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'cloudflare.com',
  'amazonaws.com', 'googleapis.com', 'storage.googleapis.com',
  'nodejs.org', 'gitlab.com', 'bitbucket.org',
  'fastly.net', 'fastly.com'
];

function isSafe(domain) {
  const d = (domain || '').toLowerCase().replace(/\.$/, '');
  return SAFE_DOMAINS.some(function (s) { return d === s || d.endsWith('.' + s); });
}

function logDns(entry) {
  try { fs.appendFileSync(DNS_LOG, JSON.stringify(entry) + '\n'); } catch (e) { /* ignore */ }
}

function logHttp(entry) {
  try { fs.appendFileSync(HTTP_LOG, JSON.stringify(entry) + '\n'); } catch (e) { /* ignore */ }
}

// ═══════════════════════════════════════════════════════
// DNS PROXY (UDP 53)
// ═══════════════════════════════════════════════════════

/**
 * Extract domain name from DNS query buffer.
 * DNS names: [len][label][len][label]...[0x00] starting at offset 12.
 */
function extractDomain(buf) {
  if (buf.length < 13) return '';
  var offset = 12;
  var labels = [];
  var safety = 0;
  while (offset < buf.length && safety++ < 128) {
    var len = buf[offset];
    if (len === 0) { offset++; break; }
    if ((len & 0xC0) === 0xC0) { offset += 2; break; } // pointer (shouldn't appear in query)
    if (offset + 1 + len > buf.length) break;
    labels.push(buf.slice(offset + 1, offset + 1 + len).toString('ascii'));
    offset += 1 + len;
  }
  return labels.join('.');
}

/**
 * Build a mock DNS A response returning the mock IP.
 * Copies the query, flips QR bit, appends one A answer.
 */
function buildMockAResponse(queryBuf, ip) {
  var ipParts = ip.split('.').map(Number);
  var header = Buffer.from(queryBuf);
  header[2] = (header[2] | 0x80) | 0x04; // QR=1, AA=1
  header[3] = header[3] | 0x80;          // RA=1
  header[6] = 0; header[7] = 1;          // ANCOUNT = 1

  var answer = Buffer.from([
    0xC0, 0x0C,                                         // pointer → offset 12
    0x00, 0x01,                                         // type A
    0x00, 0x01,                                         // class IN
    0x00, 0x00, 0x00, 0x3C,                             // TTL 60s
    0x00, 0x04,                                         // rdlength 4
    ipParts[0], ipParts[1], ipParts[2], ipParts[3]
  ]);

  return Buffer.concat([header, answer]);
}

/**
 * Forward DNS query to upstream resolver and relay the response.
 */
function forwardToUpstream(queryBuf, callback) {
  var client = dgram.createSocket('udp4');
  var done = false;

  function finish(err, resp) {
    if (done) return;
    done = true;
    try { client.close(); } catch (e) { /* ignore */ }
    callback(err, resp);
  }

  client.send(queryBuf, 0, queryBuf.length, 53, UPSTREAM_DNS, function (err) {
    if (err) finish(err);
  });
  client.on('message', function (resp) { finish(null, resp); });
  client.on('error', function (err) { finish(err); });
  setTimeout(function () { finish(new Error('timeout')); }, 3000);
}

var dnsServer = dgram.createSocket('udp4');

dnsServer.on('message', function (msg, rinfo) {
  try {
    var domain = extractDomain(msg);
    if (!domain) {
      forwardToUpstream(msg, function (err, resp) {
        if (resp) dnsServer.send(resp, 0, resp.length, rinfo.port, rinfo.address);
      });
      return;
    }

    var safe = isSafe(domain);
    logDns({ ts: Date.now(), domain: domain, safe: safe, mock_ip: safe ? null : MOCK_IP });

    if (safe) {
      forwardToUpstream(msg, function (err, resp) {
        if (resp) {
          dnsServer.send(resp, 0, resp.length, rinfo.port, rinfo.address);
        } else {
          // Upstream failed → SERVFAIL (don't mock safe domains)
          var fail = Buffer.from(msg);
          fail[2] = 0x81; fail[3] = 0x82;
          dnsServer.send(fail, 0, fail.length, rinfo.port, rinfo.address);
        }
      });
    } else {
      var resp = buildMockAResponse(msg, MOCK_IP);
      dnsServer.send(resp, 0, resp.length, rinfo.port, rinfo.address);
    }
  } catch (e) {
    forwardToUpstream(msg, function (err, resp) {
      if (resp) try { dnsServer.send(resp, 0, resp.length, rinfo.port, rinfo.address); } catch (e2) { /* ignore */ }
    });
  }
});

dnsServer.on('error', function (e) {
  console.error('[MOCK-NET] DNS error: ' + e.message);
});

// ═══════════════════════════════════════════════════════
// SHARED: plausible response bodies + request handler
// ═══════════════════════════════════════════════════════

/**
 * Choose a plausible response based on Accept header and URL.
 * Returns { contentType, body } that won't crash common malware patterns:
 *   fetch(url).then(r => r.json())  → needs valid JSON
 *   fetch(url).then(r => r.text())  → any text works
 *   curl url | bash                 → empty is fine (no-op)
 */
function chooseMockResponse(req) {
  var accept = (req.headers.accept || '').toLowerCase();
  var urlPath = (req.url || '').toLowerCase();

  if (accept.includes('application/json') || urlPath.endsWith('.json')) {
    return { contentType: 'application/json', body: '{"status":"ok","data":{}}' };
  }
  if (accept.includes('text/html') || urlPath.endsWith('.html') || urlPath.endsWith('.htm')) {
    return { contentType: 'text/html', body: '<html><body></body></html>' };
  }
  if (accept.includes('javascript') || urlPath.endsWith('.js')) {
    return { contentType: 'application/javascript', body: '""' };
  }
  // Default: valid JSON (safest — works with both .json() and .text())
  return { contentType: 'application/json', body: '{"status":"ok","data":{}}' };
}

/**
 * Shared request handler for both HTTP and HTTPS honeypots.
 * Captures full request, responds with plausible body after realistic delay.
 */
function handleMockRequest(req, res, isTls) {
  var body = '';
  req.on('data', function (chunk) { if (body.length < 10000) body += chunk; });
  req.on('end', function () {
    logHttp({
      ts: Date.now(),
      method: req.method,
      host: (req.headers.host || 'unknown').split(':')[0],
      path: req.url,
      headers: req.headers,
      body: body.substring(0, 5000),
      tls: isTls
    });
    // Delay 50-200ms to simulate real network latency (0ms is detectable)
    var delay = 50 + Math.floor(Math.random() * 150);
    setTimeout(function () {
      var mock = chooseMockResponse(req);
      res.writeHead(200, {
        'Content-Type': mock.contentType,
        'Content-Length': String(Buffer.byteLength(mock.body)),
        'Server': 'nginx/1.24.0',
        'X-Request-Id': crypto.randomBytes(8).toString('hex')
      });
      res.end(mock.body);
    }, delay);
  });
  req.on('error', function () {
    try { res.writeHead(200); res.end(''); } catch (e) { /* ignore */ }
  });
}

// ═══════════════════════════════════════════════════════
// HTTP HONEYPOT (TCP 80 on MOCK_IP)
// ═══════════════════════════════════════════════════════

var httpServer = http.createServer(function (req, res) {
  handleMockRequest(req, res, false);
});

httpServer.on('error', function (e) {
  console.error('[MOCK-NET] HTTP error: ' + e.message);
});

// ═══════════════════════════════════════════════════════
// HTTPS HONEYPOT (TCP 443 on MOCK_IP)
// Dynamic per-hostname cert generation via SNICallback.
// CA + server key generated by sandbox-runner.sh per session.
// curl/wget/python trust the CA via SSL_CERT_FILE bundle.
// ═══════════════════════════════════════════════════════

var CA_CERT_PATH = '/tmp/mock-ca.pem';
var CA_KEY_PATH = '/tmp/mock-ca-key.pem';
var SERVER_KEY_PATH = '/tmp/mock-server-key.pem';
var DEFAULT_CERT_PATH = '/tmp/mock-cert-default.pem';
var certCache = {};

/**
 * Generate a TLS certificate for a given hostname, signed by our mock CA.
 * Uses openssl CLI (available in container via apk add openssl).
 * Caches results — each hostname is generated once per sandbox session.
 */
function generateCertForHost(hostname) {
  // Strict validation: prevent command injection via attacker-controlled SNI
  if (!hostname || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$/.test(hostname)) return null;
  if (certCache[hostname]) return certCache[hostname];

  try {
    var safeName = hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
    var certPath = '/tmp/mock-cert-' + safeName + '.pem';
    var extPath = '/tmp/mock-ext-' + safeName + '.cnf';

    fs.writeFileSync(extPath, 'subjectAltName=DNS:' + hostname + '\n');
    execSync(
      'openssl req -new -key ' + SERVER_KEY_PATH +
      ' -subj "/CN=' + hostname + '" 2>/dev/null | ' +
      'openssl x509 -req -CA ' + CA_CERT_PATH + ' -CAkey ' + CA_KEY_PATH +
      ' -CAcreateserial -days 1 -extfile ' + extPath +
      ' -out ' + certPath + ' 2>/dev/null',
      { stdio: 'pipe', timeout: 5000 }
    );

    var result = { cert: fs.readFileSync(certPath), key: fs.readFileSync(SERVER_KEY_PATH) };
    certCache[hostname] = result;
    return result;
  } catch (e) {
    return null;
  }
}

var httpsServer;
try {
  var defaultCert = fs.readFileSync(DEFAULT_CERT_PATH);
  var serverKey = fs.readFileSync(SERVER_KEY_PATH);

  httpsServer = https.createServer({
    SNICallback: function (hostname, cb) {
      var certData = generateCertForHost(hostname);
      if (certData) {
        cb(null, tls.createSecureContext({ cert: certData.cert, key: certData.key }));
      } else {
        cb(null); // fall back to default cert
      }
    },
    cert: defaultCert,
    key: serverKey
  }, function (req, res) {
    handleMockRequest(req, res, true);
  });
} catch (e) {
  // Fallback: if CA/cert files not generated, use TCP trap (log-only)
  console.error('[MOCK-NET] HTTPS setup failed (' + e.message + '), falling back to TCP trap.');
  httpsServer = net.createServer(function (socket) {
    logHttp({ ts: Date.now(), type: 'tls_attempt', host: MOCK_IP, port: 443 });
    socket.setTimeout(500, function () { socket.destroy(); });
    socket.on('error', function () { /* ignore */ });
  });
}

httpsServer.on('error', function (e) {
  console.error('[MOCK-NET] HTTPS error: ' + e.message);
});

// ═══════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════

var readyCount = 0;
function checkReady() {
  if (++readyCount === 3) {
    try { fs.writeFileSync('/tmp/mock-network-ready', '1'); } catch (e) { /* ignore */ }
    console.log('[MOCK-NET] All servers ready.');
  }
}

dnsServer.bind(53, '127.0.0.1', function () {
  console.log('[MOCK-NET] DNS on 127.0.0.1:53 (upstream: ' + UPSTREAM_DNS + ')');
  checkReady();
});

httpServer.listen(80, MOCK_IP, function () {
  console.log('[MOCK-NET] HTTP on ' + MOCK_IP + ':80');
  checkReady();
});

httpsServer.listen(443, MOCK_IP, function () {
  console.log('[MOCK-NET] HTTPS on ' + MOCK_IP + ':443 (SNI dynamic certs)');
  checkReady();
});

process.on('SIGTERM', function () {
  try { dnsServer.close(); } catch (e) { /* ignore */ }
  try { httpServer.close(); } catch (e) { /* ignore */ }
  try { httpsServer.close(); } catch (e) { /* ignore */ }
  process.exit(0);
});
