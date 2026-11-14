#!/usr/bin/env node
'use strict';

// The npm tarball may only hold runtime files. Run on every PR (product-smoke job) and before
// publishing (publish.yml): a stray file (2.12.0 shipped audit-data/, a self-scan, .githooks/,
// zizmor.yml, stats.json; the first 2.12.3 attempt carried .c8rc.json) fails here, not at release.

const { execSync } = require('child_process');
const path = require('path');

const ALLOWED = /^(bin\/|src\/|LICENSE$|NOTICE$|README\.md$|package\.json$)/;

const root = path.join(__dirname, '..');
// Constant command string (no user input): works with npm.cmd on Windows without passing
// arguments through a shell.
const out = execSync('npm pack --dry-run --json --ignore-scripts', {
  cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024
});
const files = JSON.parse(out)[0].files.map(f => f.path);
const bad = files.filter(p => !ALLOWED.test(p));
if (bad.length) {
  console.error('::error::unexpected files in the npm tarball: ' + bad.join(', '));
  process.exit(1);
}
console.log(files.length + ' files, all within the allowlist');
