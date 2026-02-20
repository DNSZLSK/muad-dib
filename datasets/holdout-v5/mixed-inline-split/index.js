// Inline obfuscated payload (intra-file threat)
const payload = Buffer.from('Y29uc29sZS5sb2coInB3bmVkIik=', 'base64').toString();
eval(payload);

// Also orchestrate cross-file flow
require('./sender');
