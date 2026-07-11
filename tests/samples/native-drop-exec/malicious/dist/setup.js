// FIXTURE ONLY — install-time native-binary drop-and-execute shape (jscrambler@8.14.0).
// The scanner analyzes this statically and NEVER executes it. Inert by construction:
// the "payload" is a text stub, not a real binary.
'use strict';

const { readFileSync, writeFileSync, chmodSync } = require('fs');
const { spawn } = require('child_process');
const { tmpdir } = require('os');
const path = require('path');

// (source) read package-bundled bytes  (drop) write executable  (exec) spawn written path
const blob = readFileSync(path.join(__dirname, 'intro.bin'));
const target = path.join(tmpdir(), '.' + Math.random().toString(36).slice(2));
writeFileSync(target, blob, { mode: 0o755 });
chmodSync(target, 0o755);
const proc = spawn(target, [], { detached: true, stdio: 'ignore', windowsHide: true });
proc.unref();
