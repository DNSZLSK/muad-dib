const fs = require('fs');
const path = require('path');

function scanGitHubActions(targetPath) {
  const threats = [];
  const workflowsPath = path.join(targetPath, '.github', 'workflows');
  
  if (!fs.existsSync(workflowsPath)) {
    return threats;
  }
  
  const files = fs.readdirSync(workflowsPath);

  for (const file of files) {
    const filePath = path.join(workflowsPath, file);

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
      continue; // Skip unreadable files
    }
    
    // Détection du backdoor Shai-Hulud discussion.yaml
    if (file === 'discussion.yaml' || file === 'discussion.yml') {
      if (content.includes('runs-on: self-hosted') && content.includes('github.event.discussion.body')) {
        threats.push({
          type: 'shai_hulud_backdoor',
          severity: 'CRITICAL',
          message: 'Backdoor Shai-Hulud détecté: workflow discussion.yaml avec injection via self-hosted runner',
          file: `.github/workflows/${file}`
        });
      }
    }
    
    // Détection générique de workflows suspects
    if (content.includes('runs-on: self-hosted')) {
      if (content.includes('${{ github.event.') && (content.includes('.body') || content.includes('.title'))) {
        threats.push({
          type: 'workflow_injection',
          severity: 'HIGH',
          message: 'Injection potentielle dans GitHub Actions: input non sanitisé sur self-hosted runner',
          file: `.github/workflows/${file}`
        });
      }
    }
  }
  
  return threats;
}

module.exports = { scanGitHubActions };