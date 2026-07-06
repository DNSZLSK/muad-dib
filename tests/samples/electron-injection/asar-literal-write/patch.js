// POSITIVE (HIGH tier): overwrites a home-rooted Electron app.asar with an opaque buffer.
// The injected payload is not statically resolvable (built by an external helper), so the rule
// cannot confirm the content is code — but writing into an installed app's .asar under the user's
// home is app tampering → HIGH.
const fs = require('fs');
const os = require('os');
const path = require('path');

function buildPatchedAsar() {
  // opaque — returns bytes assembled at runtime
  return Buffer.from([0x04, 0x00, 0x00, 0x00]);
}

const target = path.join(os.homedir(), '.config', 'discord', 'resources', 'app.asar');
if (fs.existsSync(target)) {
  const patched = buildPatchedAsar();
  fs.writeFileSync(target, patched);
}
