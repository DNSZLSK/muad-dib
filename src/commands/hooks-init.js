/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

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
 * Hooks directory of the repository rooted at targetPath, or null if targetPath is not the
 * root of a git checkout. In a linked worktree or a submodule, `.git` is a file
 * (`gitdir: ...`), not a directory, and the hooks live in the common git directory: asking
 * git (`rev-parse --git-path hooks`) resolves both, and `core.hooksPath` too. Only a
 * checkout root counts (its own `.git` entry), so a subdirectory of a repository never
 * installs into the parent's hooks. Falls back to `.git/hooks` when git cannot run.
 */
function resolveGitHooksDir(targetPath) {
  if (!fs.existsSync(path.join(targetPath, '.git'))) return null;
  try {
    const [top, hooks] = execFileSync('git', ['rev-parse', '--show-toplevel', '--git-path', 'hooks'], {
      cwd: targetPath, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000
    }).trim().split(/\r?\n/);
    // An invalid `.git` makes git keep searching upwards: only trust an answer about
    // targetPath itself, never about a parent repository.
    const same = (a, b) => (process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);
    if (top && hooks && same(fs.realpathSync(top), fs.realpathSync(targetPath))) {
      return path.resolve(targetPath, hooks);
    }
  } catch { /* git missing or not a repository: plain layout below */ }
  return path.join(targetPath, '.git', 'hooks');
}

/**
 * Detect which hook system is available
 */
function detectHookSystem(targetPath) {
  const hasHusky = fs.existsSync(path.join(targetPath, '.husky'));
  const hasPreCommitConfig = fs.existsSync(path.join(targetPath, '.pre-commit-config.yaml'));
  const hooksDir = resolveGitHooksDir(targetPath);
  const hasGitHooks = hooksDir !== null && fs.existsSync(hooksDir);

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

/**
 * Back up an existing pre-commit hook before overwriting it, keeping the 3 most recent
 * timestamped backups. Shared by the husky and native-git hook writers so neither silently
 * destroys a user's existing hook (lint-staged, tests, etc.).
 * @param {string} hookPath - Absolute path to the pre-commit hook to be written
 */
function backupExistingHook(hookPath) {
  if (!fs.existsSync(hookPath)) return;
  const backup = `${hookPath}.backup.${Date.now()}`;
  fs.copyFileSync(hookPath, backup);
  console.log(`[INFO] Backed up existing hook to ${backup}`);

  // Cleanup old backups, keep only 3 most recent
  try {
    const hooksDir = path.dirname(hookPath);
    const base = path.basename(hookPath);
    const backups = fs.readdirSync(hooksDir)
      .filter(f => f.startsWith(base + '.backup.'))
      .sort()
      .reverse();
    for (const old of backups.slice(3)) {
      fs.unlinkSync(path.join(hooksDir, old));
    }
  } catch { /* ignore cleanup errors */ }
}

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

  // Back up any existing hook before overwriting (same policy as initGitHook): a project may
  // already have a husky pre-commit (lint-staged, tests…) — clobbering it silently loses config.
  backupExistingHook(preCommitPath);
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
  const gitHooksDir = resolveGitHooksDir(targetPath);

  if (!gitHooksDir || !fs.existsSync(gitHooksDir)) {
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
  backupExistingHook(preCommitPath);

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
  const hooksDir = resolveGitHooksDir(resolvedPath);
  const gitPreCommit = hooksDir ? path.join(hooksDir, 'pre-commit') : null;
  if (gitPreCommit && fs.existsSync(gitPreCommit)) {
    const content = fs.readFileSync(gitPreCommit, 'utf8');
    if (content.includes('muaddib') || content.includes('MUADDIB')) {
      fs.unlinkSync(gitPreCommit);
      console.log('[OK] Removed git pre-commit hook');
    }
  }

  console.log('\n[OK] MUAD\'DIB hooks removed.\n');
  return true;
}

module.exports = { initHooks, removeHooks, detectHookSystem, resolveGitHooksDir };
