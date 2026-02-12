const fs = require('fs');
const path = require('path');

const YAML_EXTENSIONS = ['.yml', '.yaml'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_DEPTH = 10;

function scanGitHubActions(targetPath) {
  const threats = [];

  // Scan both workflows and custom actions directories
  const dirsToScan = [
    path.join(targetPath, '.github', 'workflows'),
    path.join(targetPath, '.github', 'actions')
  ];

  for (const dirPath of dirsToScan) {
    if (!fs.existsSync(dirPath)) continue;
    scanDirRecursive(dirPath, targetPath, threats);
  }

  return threats;
}

function scanDirRecursive(dirPath, targetPath, threats, depth = 0) {
  if (depth > MAX_DEPTH) return;
  let files;
  try { files = fs.readdirSync(dirPath); } catch { return; }
  const relDir = path.relative(targetPath, dirPath).replace(/\\/g, '/');

  for (const file of files) {
    const filePath = path.join(dirPath, file);

    try {
      const stat = fs.lstatSync(filePath);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        scanDirRecursive(filePath, targetPath, threats, depth + 1);
        continue;
      }
      if (!stat.isFile()) continue;
      if (stat.size > MAX_FILE_SIZE) continue;
    } catch {
      continue;
    }

    // Only process YAML files
    if (!YAML_EXTENSIONS.some(ext => file.endsWith(ext))) continue;

      let content;
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch {
        continue;
      }

      const relFile = `${relDir}/${file}`;

      // GHA-001: Line-by-line YAML-aware parsing (skip comments)
      const yamlLines = content.split('\n');
      const activeLines = yamlLines.filter(l => !l.trim().startsWith('#'));
      const activeContent = activeLines.join('\n');

      // Détection du backdoor Shai-Hulud discussion.yaml
      if (file === 'discussion.yaml' || file === 'discussion.yml') {
        if (activeContent.includes('github.event.discussion.body')) {
          threats.push({
            type: 'shai_hulud_backdoor',
            severity: 'CRITICAL',
            message: 'Backdoor Shai-Hulud détecté: workflow discussion.yaml avec injection via discussion body',
            file: relFile
          });
        }
      }

      // GHA-002: Detect attacker-controlled context injection on ALL runners (not just self-hosted)
      const injectionPatterns = [
        { regex: /\$\{\{\s*github\.event\.(comment\.body|issue\.body|issue\.title|pull_request\.body|pull_request\.title|discussion\.body|discussion\.title)/, msg: 'Attacker-controlled GitHub event context used in workflow' },
        { regex: /\$\{\{\s*github\.head_ref/, msg: 'github.head_ref is attacker-controlled in pull_request workflows' }
      ];

      for (const { regex, msg } of injectionPatterns) {
        if (regex.test(activeContent)) {
          threats.push({
            type: 'workflow_injection',
            severity: 'HIGH',
            message: 'Potential injection: ' + msg,
            file: relFile
          });
        }
      }
    }
}

module.exports = { scanGitHubActions };
