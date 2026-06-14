'use strict';

// node-pre-gyp install flow: use a prebuilt binary from the package's own
// GitHub release if present, otherwise compile from source locally.
// This is a LOCAL build toolchain invocation — no remote code load, no exfil.
const { execSync } = require('node:child_process');
const path = require('node:path');

const root = path.join(__dirname, '..');

function run(cmd) {
  execSync(cmd, { cwd: root, stdio: 'inherit' });
}

function hasBinding() {
  try {
    require('../build/Release/bignum.node');
    return true;
  } catch {
    return false;
  }
}

if (!hasBinding()) {
  try {
    run('node-pre-gyp install --fallback-to-build=false');
  } catch {
    run('node-pre-gyp rebuild');
  }
}
