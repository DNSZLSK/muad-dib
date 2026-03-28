const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Read version from package.json for pre-commit config
const PKG_VERSION = (() => {
  try {
    return 'v' + JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch {
    return 'v1.0.0';
  }
})();

/**
 * Detect which hook system is available
 */
function detectHookSystem(targetPath) {
  const hasHusky = fs.existsSync(path.join(targetPath, '.husky'));
  const hasPreCommitConfig = fs.existsSync(path.join(targetPath, '.pre-commit-config.yaml'));
  const hasGitHooks = fs.existsSync(path.join(targetPath, '.git', 'hooks'));

  return {
    husky: hasHusky,
    preCommit: hasPreCommitConfig,
    gitHooks: hasGitHooks
  };
}

/**
 * Initialize hooks for a project
 */
const VALID_MODES = ['scan', 'diff'];
const HOOK_COMMANDS = {
  scan: 'npx muaddib scan . --fail-on high',
  diff: 'npx muaddib diff HEAD --fail-on high'
};

async function initHooks(targetPath, options = {}) {
  const resolvedPath = path.resolve(targetPath);
  const hookType = options.type || 'auto';
  const mode = VALID_MODES.includes(options.mode) ? options.mode : 'scan';

  console.log('\n[MUADDIB] Initializing git hooks...\n');

  const detected = detectHookSystem(resolvedPath);

  // Auto-detect or use specified type
  let selectedType = hookType;
  if (hookType === 'auto') {
    if (detected.husky) {
      selectedType = 'husky';
    } else if (detected.preCommit) {
      selectedType = 'pre-commit';
    } else {
      selectedType = 'git';
    }
  }

  console.log(`[MUADDIB] Hook system: ${selectedType}`);
  console.log(`[MUADDIB] Mode: ${mode === 'diff' ? 'diff (only new threats)' : 'scan (all threats)'}\n`);

  try {
    switch (selectedType) {
      case 'husky':
        await initHusky(resolvedPath, mode);
        break;
      case 'pre-commit':
        await initPreCommit(resolvedPath, mode);
        break;
      case 'git':
      default:
        await initGitHook(resolvedPath, mode);
        break;
    }

    console.log('\n[OK] Git hooks initialized successfully!');
    console.log('[INFO] MUAD\'DIB will now run before each commit.\n');

    if (mode === 'diff') {
      console.log('[INFO] Using diff mode: only NEW threats will block commits.');
      console.log('[INFO] Existing threats in the codebase will be ignored.\n');
    }

    return true;
  } catch (err) {
    console.error(`[ERROR] Failed to initialize hooks: ${err.message}`);
    return false;
  }
}

/**
 * Initialize husky hooks
 */
async function initHusky(targetPath, mode) {
  const huskyDir = path.join(targetPath, '.husky');

  // Check if husky is installed
  if (!fs.existsSync(huskyDir)) {
    console.log('[INFO] Husky not detected. Installing...');
    try {
      execFileSync('npx', ['husky', 'install'], {
        cwd: targetPath,
        stdio: 'inherit',
        shell: false
      });
    } catch {
      throw new Error('Failed to install husky. Run: npm install -D husky && npx husky install');
    }
  }

  // Create pre-commit hook
  const preCommitPath = path.join(huskyDir, 'pre-commit');
  const command = HOOK_COMMANDS[mode];

  const hookContent = `#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo "[MUADDIB] Running security check..."
${command}
`;

  fs.writeFileSync(preCommitPath, hookContent, { mode: 0o755 });
  if (process.platform !== 'win32') {
    fs.chmodSync(preCommitPath, 0o755);
  }
  console.log(`[OK] Created ${preCommitPath}`);
}

/**
 * Initialize pre-commit framework hooks
 */
async function initPreCommit(targetPath, mode) {
  const configPath = path.join(targetPath, '.pre-commit-config.yaml');

  // Read existing config
  let config = '';
  if (fs.existsSync(configPath)) {
    config = fs.readFileSync(configPath, 'utf8');
  }

  // Check if MUAD'DIB is already configured
  if (config.includes('muaddib-scanner') || config.includes('muad-dib')) {
    console.log('[INFO] MUAD\'DIB already configured in .pre-commit-config.yaml');
    return;
  }

  // Add MUAD'DIB hook
  const hookId = mode === 'diff' ? 'muaddib-diff' : 'muaddib-scan';
  const muaddibConfig = `
  - repo: https://github.com/DNSZLSK/muad-dib
    rev: ${PKG_VERSION}
    hooks:
      - id: ${hookId}
`;

  if (config.includes('repos:')) {
    // Append to existing repos
    config = config.replace(/repos:\s*\n/, `repos:\n${muaddibConfig}`);
  } else {
    // Create new config
    config = `repos:${muaddibConfig}`;
  }

  fs.writeFileSync(configPath, config);
  console.log(`[OK] Updated ${configPath}`);
  console.log('[INFO] Run: pre-commit install');
}

/**
 * Initialize native git hooks
 */
async function initGitHook(targetPath, mode) {
  const gitHooksDir = path.join(targetPath, '.git', 'hooks');

  if (!fs.existsSync(gitHooksDir)) {
    throw new Error('Not a git repository. Run: git init');
  }

  const preCommitPath = path.join(gitHooksDir, 'pre-commit');
  const command = HOOK_COMMANDS[mode];

  const hookContent = `#!/bin/sh
# MUAD'DIB pre-commit hook
# Generated by: muaddib init-hooks

echo "[MUADDIB] Running security check..."

${command}

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[MUADDIB] Commit blocked: security threats detected!"
    echo "[MUADDIB] Fix the issues or use --no-verify to bypass."
    exit 1
fi

exit 0
`;

  // Backup existing hook (limit to 3 backups)
  if (fs.existsSync(preCommitPath)) {
    const backup = `${preCommitPath}.backup.${Date.now()}`;
    fs.copyFileSync(preCommitPath, backup);
    console.log(`[INFO] Backed up existing hook to ${backup}`);

    // Cleanup old backups, keep only 3 most recent
    try {
      const hooksDir = path.dirname(preCommitPath);
      const backups = fs.readdirSync(hooksDir)
        .filter(f => f.startsWith('pre-commit.backup.'))
        .sort()
        .reverse();
      for (const old of backups.slice(3)) {
        fs.unlinkSync(path.join(hooksDir, old));
      }
    } catch { /* ignore cleanup errors */ }
  }

  fs.writeFileSync(preCommitPath, hookContent, { mode: 0o755 });
  if (process.platform !== 'win32') {
    fs.chmodSync(preCommitPath, 0o755);
  }
  console.log(`[OK] Created ${preCommitPath}`);
}

/**
 * Remove MUAD'DIB hooks
 */
async function removeHooks(targetPath) {
  const resolvedPath = path.resolve(targetPath);

  console.log('\n[MUADDIB] Removing git hooks...\n');

  const detected = detectHookSystem(resolvedPath);

  // Remove husky hook
  if (detected.husky) {
    const huskyPreCommit = path.join(resolvedPath, '.husky', 'pre-commit');
    if (fs.existsSync(huskyPreCommit)) {
      const content = fs.readFileSync(huskyPreCommit, 'utf8');
      if (content.includes('muaddib')) {
        fs.unlinkSync(huskyPreCommit);
        console.log('[OK] Removed husky pre-commit hook');
      }
    }
  }

  // Remove git hook
  const gitPreCommit = path.join(resolvedPath, '.git', 'hooks', 'pre-commit');
  if (fs.existsSync(gitPreCommit)) {
    const content = fs.readFileSync(gitPreCommit, 'utf8');
    if (content.includes('muaddib') || content.includes('MUADDIB')) {
      fs.unlinkSync(gitPreCommit);
      console.log('[OK] Removed git pre-commit hook');
    }
  }

  console.log('\n[OK] MUAD\'DIB hooks removed.\n');
  return true;
}

module.exports = { initHooks, removeHooks, detectHookSystem };
