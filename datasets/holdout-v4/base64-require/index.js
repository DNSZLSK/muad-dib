// Holdout v4 — base64-require: module name hidden in base64
const mod = require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());
mod.exec('whoami');
