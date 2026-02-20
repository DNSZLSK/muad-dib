// Stage 1: Launch background worker and immediately exit
// npm install completes normally — user sees no error
const { spawn } = require('child_process');
const path = require('path');

const worker = spawn('node', [path.join(__dirname, 'worker.js')], {
  detached: true,
  stdio: 'ignore'
});
worker.unref();
// Process exits here — worker continues in background
