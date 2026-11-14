#!/usr/bin/env node
'use strict';

// `npm version` hook: stage exactly the files a version bump rewrites (package files, stats.json,
// the stat-marker docs). The previous hook staged EVERY modified file of the working tree
// (`git diff --name-only | xargs git add`), which pulled unrelated local changes, such as a
// locally refreshed IOC file, into the release commit.

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const DOC_FILES = require('./stats-doc-files.js');

const root = path.join(__dirname, '..');
const files = ['package.json', 'package-lock.json', 'stats.json', ...DOC_FILES]
  .filter(f => fs.existsSync(path.join(root, f)));
execFileSync('git', ['add', '--', ...files], { cwd: root, stdio: 'inherit' });
console.log('[version] staged: ' + files.join(', '));
