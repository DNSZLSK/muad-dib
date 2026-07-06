#!/usr/bin/env node
'use strict';

// CI guard: fail the PR if `node_modules` (or anything under it) is tracked in git.
//
// Rationale: a self-referential `node_modules` symlink (points at itself → ELOOP)
// was accidentally re-added in commit 07d45dc8 and merged to master. Because a
// trailing-slash .gitignore pattern is directory-only, it did NOT re-ignore the
// symlink, so a stray `git add` slipped it back in. On every fresh deploy
// (`deploy/setup.sh` git clone → npm install, `deploy/auto-update.sh` git merge
// → npm ci) the ELOOP link is materialized and dependency resolution breaks.
// .gitignore alone cannot prevent recurrence — this gate makes the invariant
// explicit and fails loudly at PR time, mirroring scripts/check-deps-typosquats.js.

const path = require('path');
const { execFileSync } = require('child_process');

let tracked = '';
try {
  tracked = execFileSync('git', ['ls-files', '-z', 'node_modules'], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
} catch (e) {
  // No git available / unusual CI checkout — don't block the pipeline on an
  // unrelated git failure. The gate is a safety net, not a hard dependency.
  console.error(`check-no-tracked-node-modules: git ls-files failed (${e.message}); skipping`);
  process.exit(0);
}

const entries = tracked.split('\0').filter(Boolean);

if (entries.length > 0) {
  console.error('::error::node_modules is tracked in git — it must never be committed (a self-referential symlink ELOOP breaks every deploy)');
  for (const e of entries.slice(0, 20)) console.error(`  tracked: ${e}`);
  if (entries.length > 20) console.error(`  … and ${entries.length - 20} more`);
  console.error('Fix: git rm -r --cached node_modules && commit');
  process.exit(1);
}

console.log('node_modules: not tracked (clean)');
