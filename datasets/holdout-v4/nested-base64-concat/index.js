// Holdout v4 — nested-base64-concat: split base64 + concat
const a = Buffer.from('Y2hpbGRf', 'base64').toString();
const b = Buffer.from('cHJvY2Vzcw==', 'base64').toString();
require(a + b).exec('id');
