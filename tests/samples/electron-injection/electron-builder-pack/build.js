// NEGATIVE: an electron-builder-style packer. It writes an app.asar (a .asar signature) into the
// project's OWN dist/ output — no os.homedir(), no existsSync probe of a foreign install. The
// target is not home-rooted, so neither the CRITICAL nor the HIGH tier fires.
const fs = require('fs');
const path = require('path');

function pack(asarBuffer) {
  const outDir = path.join(__dirname, 'dist', 'win-unpacked', 'resources');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'app.asar'), asarBuffer);
}

pack(Buffer.from([0x00, 0x00, 0x00, 0x00]));
