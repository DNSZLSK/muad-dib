// Legitimate native-addon build helper: node-gyp runs `<!(node ./util/has_lib.js)` at
// configure time to decide whether an optional system library is present. This is the
// SAME invocation shape as the malicious fixture — the only difference is that this file
// is benign, so the Phantom-Gyp compound must NOT fire on it (FPR guard).
const fs = require('fs');
const candidates = ['/usr/lib/libfoo.so', '/usr/local/lib/libfoo.so'];
const found = candidates.some(p => fs.existsSync(p));
process.stdout.write(found ? 'true' : 'false');
