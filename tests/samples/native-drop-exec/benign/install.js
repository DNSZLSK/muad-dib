// FIXTURE ONLY — legitimate prebuilt-binary installer (esbuild/prebuild-install shape):
// the bytes come from the NETWORK (https), not from a package-bundled blob. This is the
// FPR guard: install_native_drop_exec must NOT fire here (download-and-execute is a
// different, network-visible pattern). The scanner never runs this file.
'use strict';

const https = require('https');
const fs = require('fs');
const cp = require('child_process');
const path = require('path');

const bin = path.join(__dirname, 'bin', 'tool');
https.get('https://registry.npmjs.org/@scope/tool-linux-x64/-/tool-1.0.0.tgz', (res) => {
  const out = fs.createWriteStream(bin);
  res.pipe(out);
  out.on('finish', () => {
    fs.chmodSync(bin, 0o755);
    cp.spawnSync(bin, ['--version'], { stdio: 'inherit' });
  });
});
