const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');

const SHELL_EXCLUDED_DIRS = ['node_modules', '.git', 'test', 'tests', 'src', 'docker'];

const MALICIOUS_PATTERNS = [
  { pattern: /curl.*\|.*sh/, name: 'curl_pipe_shell', severity: 'HIGH' },
  { pattern: /wget.*&&.*chmod.*\+x/, name: 'wget_chmod_exec', severity: 'HIGH' },
  { pattern: /bash\s+-i\s+>&\s+\/dev\/tcp/, name: 'reverse_shell', severity: 'CRITICAL' },
  { pattern: /nc\s+-e\s+\/bin\/(ba)?sh/, name: 'netcat_shell', severity: 'CRITICAL' },
  { pattern: /rm\s+-rf\s+(~\/|\$HOME|\/home)/, name: 'home_deletion', severity: 'CRITICAL' },
  { pattern: /shred.*\$HOME/, name: 'shred_home', severity: 'CRITICAL' },
  { pattern: /curl.*-X\s*POST.*-d/, name: 'curl_exfiltration', severity: 'HIGH' },
  { pattern: /\.npmrc/, name: 'npmrc_access', severity: 'HIGH' },
  { pattern: /\.ssh/, name: 'ssh_access', severity: 'HIGH' }
];

async function scanShellScripts(targetPath) {
  const threats = [];
  
  // Cherche les fichiers .sh
  const files = findFiles(targetPath, { extensions: ['.sh'], excludedDirs: SHELL_EXCLUDED_DIRS });
  
  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    
    for (const { pattern, name, severity } of MALICIOUS_PATTERNS) {
      if (pattern.test(content)) {
        threats.push({
          type: name,
          severity: severity,
          message: `Pattern malveillant "${name}" detecte.`,
          file: path.relative(targetPath, file)
        });
      }
    }
  }

  return threats;
}

module.exports = { scanShellScripts };