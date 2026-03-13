const fs = require('fs');
const path = require('path');
const { findFiles, forEachSafeFile } = require('../utils.js');
const { MAX_FILE_SIZE } = require('../shared/constants.js');

const SHELL_EXCLUDED_DIRS = ['node_modules', '.git', '.muaddib-cache'];

const MALICIOUS_PATTERNS = [
  { pattern: /curl.*\|.*sh/m, name: 'curl_pipe_shell', severity: 'HIGH' },
  { pattern: /wget.*&&.*chmod.*\+x/m, name: 'wget_chmod_exec', severity: 'HIGH' },
  { pattern: /bash\s+-i\s+>&\s+\/dev\/tcp/m, name: 'reverse_shell', severity: 'CRITICAL' },
  { pattern: /nc\s+-e\s+\/bin\/(ba)?sh/m, name: 'netcat_shell', severity: 'CRITICAL' },
  { pattern: /rm\s+-rf\s+(~\/|\$HOME|\/home)/m, name: 'home_deletion', severity: 'CRITICAL' },
  { pattern: /shred.*\$HOME/m, name: 'shred_home', severity: 'CRITICAL' },
  { pattern: /curl.*-X\s*POST.*-d/m, name: 'curl_exfiltration', severity: 'HIGH' },
  { pattern: /(?:cat|readFile|cp|mv|curl\s+file:\/\/|tar\s+.*|scp\s+).*\.npmrc/m, name: 'npmrc_access', severity: 'HIGH' },
  { pattern: /(?:cat|readFile|cp|mv|curl\s+file:\/\/|tar\s+.*|scp\s+).*\.ssh/m, name: 'ssh_access', severity: 'HIGH' },
  { pattern: /python\s+-c.*import\s+socket/m, name: 'python_reverse_shell', severity: 'CRITICAL' },
  { pattern: /perl\s+-e.*socket/m, name: 'perl_reverse_shell', severity: 'CRITICAL' },
  { pattern: /mkfifo.*\/dev\/tcp/m, name: 'fifo_reverse_shell', severity: 'CRITICAL' },
  { pattern: /mkfifo\s+\S+.*(?:\|\s*nc\s|nc\s+\S+.*>\s*\/tmp\/)/m, name: 'fifo_nc_reverse_shell', severity: 'CRITICAL' },
  { pattern: /base64\s+-d\b.*\|\s*(ba)?sh/m, name: 'base64_decode_exec', severity: 'CRITICAL' },
  { pattern: /wget\s+\S+.*&&.*base64\s+-d/m, name: 'wget_base64_decode', severity: 'HIGH' }
];

const SHEBANG_RE = /^#!.*\b(?:ba)?sh\b/;

function scanFileContent(file, content, targetPath, threats) {
  // Strip comment lines to avoid false positives on documentation
  const activeContent = content.split(/\r?\n/)
    .filter(line => !line.trimStart().startsWith('#'))
    .join('\n');

  for (const { pattern, name, severity } of MALICIOUS_PATTERNS) {
    if (pattern.test(activeContent)) {
      threats.push({
        type: name,
        severity: severity,
        message: `Pattern malveillant "${name}" detecte.`,
        file: path.relative(targetPath, file)
      });
    }
  }
}

/**
 * Find extensionless files in a directory (non-recursive into excluded dirs).
 * Used for shebang-based shell script detection.
 */
function findExtensionlessFiles(dir, excludedDirs, results = [], depth = 0) {
  if (depth > 20) return results;
  let items;
  try { items = fs.readdirSync(dir); } catch { return results; }

  for (const item of items) {
    if (excludedDirs.includes(item)) continue;
    const fullPath = path.join(dir, item);
    try {
      const lstat = fs.lstatSync(fullPath);
      if (lstat.isSymbolicLink()) continue;
      if (lstat.isDirectory()) {
        findExtensionlessFiles(fullPath, excludedDirs, results, depth + 1);
      } else if (lstat.isFile() && !path.extname(item) && lstat.size <= MAX_FILE_SIZE) {
        results.push(fullPath);
      }
    } catch { /* permission error */ }
  }
  return results;
}

async function scanShellScripts(targetPath) {
  const threats = [];

  // Pass 1: files with shell extensions
  const files = findFiles(targetPath, { extensions: ['.sh', '.bash', '.zsh', '.command'], excludedDirs: SHELL_EXCLUDED_DIRS });

  forEachSafeFile(files, (file, content) => {
    scanFileContent(file, content, targetPath, threats);
  });

  // Pass 2: extensionless files with sh/bash shebang
  const extensionless = findExtensionlessFiles(targetPath, SHELL_EXCLUDED_DIRS);

  for (const file of extensionless) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const firstLine = content.split(/\r?\n/, 1)[0];
      if (SHEBANG_RE.test(firstLine)) {
        scanFileContent(file, content, targetPath, threats);
      }
    } catch { /* ignore unreadable files */ }
  }

  return threats;
}

module.exports = { scanShellScripts };
