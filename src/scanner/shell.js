const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');

const SHELL_EXCLUDED_DIRS = ['node_modules', '.git', '.muaddib-cache'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const MALICIOUS_PATTERNS = [
  { pattern: /curl.*\|.*sh/m, name: 'curl_pipe_shell', severity: 'HIGH' },
  { pattern: /wget.*&&.*chmod.*\+x/m, name: 'wget_chmod_exec', severity: 'HIGH' },
  { pattern: /bash\s+-i\s+>&\s+\/dev\/tcp/m, name: 'reverse_shell', severity: 'CRITICAL' },
  { pattern: /nc\s+-e\s+\/bin\/(ba)?sh/m, name: 'netcat_shell', severity: 'CRITICAL' },
  { pattern: /rm\s+-rf\s+(~\/|\$HOME|\/home)/m, name: 'home_deletion', severity: 'CRITICAL' },
  { pattern: /shred.*\$HOME/m, name: 'shred_home', severity: 'CRITICAL' },
  { pattern: /curl.*-X\s*POST.*-d/m, name: 'curl_exfiltration', severity: 'HIGH' },
  { pattern: /\.npmrc/m, name: 'npmrc_access', severity: 'HIGH' },
  { pattern: /\.ssh/m, name: 'ssh_access', severity: 'HIGH' },
  { pattern: /python\s+-c.*import\s+socket/m, name: 'python_reverse_shell', severity: 'CRITICAL' },
  { pattern: /perl\s+-e.*socket/m, name: 'perl_reverse_shell', severity: 'CRITICAL' },
  { pattern: /mkfifo.*\/dev\/tcp/m, name: 'fifo_reverse_shell', severity: 'CRITICAL' }
];

async function scanShellScripts(targetPath) {
  const threats = [];
  
  // Cherche les fichiers shell
  const files = findFiles(targetPath, { extensions: ['.sh', '.bash', '.zsh', '.command'], excludedDirs: SHELL_EXCLUDED_DIRS });

  for (const file of files) {
    let content;
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_SIZE) continue;
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue; // Skip unreadable files
    }
    
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