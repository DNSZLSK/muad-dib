const fs = require('fs');
const path = require('path');

const YAML_EXTENSIONS = ['.yml', '.yaml'];

function scanGitHubActions(targetPath) {
  const threats = [];

  // Scan both workflows and custom actions directories
  const dirsToScan = [
    path.join(targetPath, '.github', 'workflows'),
    path.join(targetPath, '.github', 'actions')
  ];

  for (const dirPath of dirsToScan) {
    if (!fs.existsSync(dirPath)) continue;

    const files = fs.readdirSync(dirPath);
    const relDir = path.relative(targetPath, dirPath).replace(/\\/g, '/');

    for (const file of files) {
      // Only process YAML files
      if (!YAML_EXTENSIONS.some(ext => file.endsWith(ext))) continue;

      const filePath = path.join(dirPath, file);

      try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile()) continue;
      } catch {
        continue;
      }

      let content;
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch {
        continue;
      }

      const relFile = `${relDir}/${file}`;
      let reported = false;

      // Détection du backdoor Shai-Hulud discussion.yaml
      if (file === 'discussion.yaml' || file === 'discussion.yml') {
        if (content.includes('runs-on: self-hosted') && content.includes('github.event.discussion.body')) {
          threats.push({
            type: 'shai_hulud_backdoor',
            severity: 'CRITICAL',
            message: 'Backdoor Shai-Hulud détecté: workflow discussion.yaml avec injection via self-hosted runner',
            file: relFile
          });
          reported = true;
        }
      }

      // Détection générique de workflows suspects (use else if to prevent duplicates)
      if (!reported && content.includes('runs-on: self-hosted')) {
        if (content.includes('${{ github.event.') && (content.includes('.body') || content.includes('.title'))) {
          threats.push({
            type: 'workflow_injection',
            severity: 'HIGH',
            message: 'Injection potentielle dans GitHub Actions: input non sanitisé sur self-hosted runner',
            file: relFile
          });
          reported = true;
        }
      }

      // Detect github.head_ref injection vector (can be attacker-controlled)
      if (!reported && content.includes('${{ github.head_ref')) {
        threats.push({
          type: 'workflow_injection',
          severity: 'HIGH',
          message: 'Potential injection: github.head_ref is attacker-controlled in pull_request workflows',
          file: relFile
        });
        reported = true;
      }

      // Detect comment.body injection vector
      if (!reported && content.includes('${{ github.event.comment.body')) {
        threats.push({
          type: 'workflow_injection',
          severity: 'HIGH',
          message: 'Potential injection: github.event.comment.body is attacker-controlled',
          file: relFile
        });
      }
    }
  }

  return threats;
}

module.exports = { scanGitHubActions };
