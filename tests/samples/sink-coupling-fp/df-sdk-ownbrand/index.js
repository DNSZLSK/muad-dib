'use strict';

// Benign first-party SDK (gate#1 negative): reads its OWN credential env var and POSTs to its
// OWN API host. The env-var brand (ACME) is coherent with the destination label (api.acme.com),
// so this is legitimate SDK usage, not credential exfiltration.
const https = require('https');

function ingest(payload) {
  const apiKey = process.env.ACME_API_KEY;
  const req = https.request({
    hostname: 'api.acme.com',
    path: '/v1/ingest',
    method: 'POST',
    headers: { authorization: 'Bearer ' + apiKey, 'content-type': 'application/json' }
  });
  req.end(JSON.stringify(payload));
}

module.exports = { ingest };
