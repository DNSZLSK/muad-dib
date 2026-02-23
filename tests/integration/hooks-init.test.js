const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes } = require('../test-utils');

async function runHooksInitTests() {
  console.log('\n=== HOOKS INIT TESTS ===\n');

  const { detectHookSystem, initHooks, removeHooks } = require('../../src/hooks-init.js');

  // --- detectHookSystem ---

  test('HOOKS: detectHookSystem returns all false for empty dir', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-detect-'));
    try {
      const result = detectHookSystem(tmpDir);
      assert(result.husky === false, 'No .husky should be false');
      assert(result.preCommit === false, 'No .pre-commit-config.yaml should be false');
      assert(result.gitHooks === false, 'No .git/hooks should be false');
    } finally {
      try { fs.rmdirSync(tmpDir); } catch {}
    }
  });

  test('HOOKS: detectHookSystem detects .husky', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-husky-'));
    const huskyDir = path.join(tmpDir, '.husky');
    fs.mkdirSync(huskyDir);
    try {
      const result = detectHookSystem(tmpDir);
      assert(result.husky === true, 'Should detect .husky');
      assert(result.preCommit === false, 'No .pre-commit-config.yaml');
    } finally {
      try { fs.rmdirSync(huskyDir); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  test('HOOKS: detectHookSystem detects .pre-commit-config.yaml', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-pc-'));
    fs.writeFileSync(path.join(tmpDir, '.pre-commit-config.yaml'), 'repos: []');
    try {
      const result = detectHookSystem(tmpDir);
      assert(result.preCommit === true, 'Should detect .pre-commit-config.yaml');
    } finally {
      try { fs.unlinkSync(path.join(tmpDir, '.pre-commit-config.yaml')); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  test('HOOKS: detectHookSystem detects .git/hooks', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-git-'));
    const gitDir = path.join(tmpDir, '.git');
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(gitDir);
    fs.mkdirSync(hooksDir);
    try {
      const result = detectHookSystem(tmpDir);
      assert(result.gitHooks === true, 'Should detect .git/hooks');
    } finally {
      try { fs.rmdirSync(hooksDir); fs.rmdirSync(gitDir); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- initHooks with git type ---

  await asyncTest('HOOKS: initHooks creates git pre-commit hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-init-'));
    const gitDir = path.join(tmpDir, '.git');
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(gitDir);
    fs.mkdirSync(hooksDir);
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await initHooks(tmpDir, { type: 'git', mode: 'scan' });
      assert(result === true, 'Should return true');
      const hookPath = path.join(hooksDir, 'pre-commit');
      assert(fs.existsSync(hookPath), 'pre-commit hook should exist');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib scan', 'Should contain scan command');
    } finally {
      console.log = origLog;
      try {
        const files = fs.readdirSync(hooksDir);
        for (const f of files) fs.unlinkSync(path.join(hooksDir, f));
        fs.rmdirSync(hooksDir); fs.rmdirSync(gitDir); fs.rmdirSync(tmpDir);
      } catch {}
    }
  });

  await asyncTest('HOOKS: initHooks with diff mode', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-diff-'));
    const gitDir = path.join(tmpDir, '.git');
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(gitDir);
    fs.mkdirSync(hooksDir);
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await initHooks(tmpDir, { type: 'git', mode: 'diff' });
      assert(result === true, 'Should return true');
      const content = fs.readFileSync(path.join(hooksDir, 'pre-commit'), 'utf8');
      assertIncludes(content, 'muaddib diff', 'Should contain diff command');
    } finally {
      console.log = origLog;
      try {
        const files = fs.readdirSync(hooksDir);
        for (const f of files) fs.unlinkSync(path.join(hooksDir, f));
        fs.rmdirSync(hooksDir); fs.rmdirSync(gitDir); fs.rmdirSync(tmpDir);
      } catch {}
    }
  });

  await asyncTest('HOOKS: initHooks fails for non-git repo', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-nogit-'));
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};
    try {
      const result = await initHooks(tmpDir, { type: 'git' });
      assert(result === false, 'Should return false for non-git repo');
    } finally {
      console.log = origLog;
      console.error = origErr;
      try { fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- initHooks with pre-commit type ---

  await asyncTest('HOOKS: initHooks creates pre-commit config', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-precommit-'));
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await initHooks(tmpDir, { type: 'pre-commit', mode: 'scan' });
      assert(result === true, 'Should return true');
      const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
      assert(fs.existsSync(configPath), 'Config file should exist');
      const content = fs.readFileSync(configPath, 'utf8');
      assertIncludes(content, 'muaddib-scan', 'Should contain muaddib-scan hook id');
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(path.join(tmpDir, '.pre-commit-config.yaml')); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  await asyncTest('HOOKS: initHooks appends to existing pre-commit config', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-pcexist-'));
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    fs.writeFileSync(configPath, 'repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v4.0.0\n');
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await initHooks(tmpDir, { type: 'pre-commit', mode: 'diff' });
      assert(result === true, 'Should return true');
      const content = fs.readFileSync(configPath, 'utf8');
      assertIncludes(content, 'muaddib-diff', 'Should contain muaddib-diff hook id');
      assertIncludes(content, 'pre-commit-hooks', 'Should preserve existing config');
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(configPath); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  await asyncTest('HOOKS: initHooks skips already-configured pre-commit', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-pcskip-'));
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    fs.writeFileSync(configPath, 'repos:\n  - repo: https://github.com/DNSZLSK/muad-dib\n');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      const result = await initHooks(tmpDir, { type: 'pre-commit' });
      assert(result === true, 'Should return true');
      assert(logs.some(l => l.includes('already configured')), 'Should log already configured');
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(configPath); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- initHooks auto-detect ---

  await asyncTest('HOOKS: initHooks auto-detects husky', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-auto-'));
    const huskyDir = path.join(tmpDir, '.husky');
    fs.mkdirSync(huskyDir);
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await initHooks(tmpDir, { type: 'auto' });
      assert(result === true, 'Should return true');
      const hookPath = path.join(huskyDir, 'pre-commit');
      assert(fs.existsSync(hookPath), 'Should create husky pre-commit hook');
    } finally {
      console.log = origLog;
      try {
        const files = fs.readdirSync(huskyDir);
        for (const f of files) fs.unlinkSync(path.join(huskyDir, f));
        fs.rmdirSync(huskyDir); fs.rmdirSync(tmpDir);
      } catch {}
    }
  });

  // --- removeHooks ---

  await asyncTest('HOOKS: removeHooks removes git pre-commit hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-rm-'));
    const gitDir = path.join(tmpDir, '.git');
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(gitDir);
    fs.mkdirSync(hooksDir);
    const hookPath = path.join(hooksDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\nmuaddib scan .\n');
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await removeHooks(tmpDir);
      assert(result === true, 'Should return true');
      assert(!fs.existsSync(hookPath), 'Hook should be removed');
    } finally {
      console.log = origLog;
      try {
        const files = fs.readdirSync(hooksDir);
        for (const f of files) fs.unlinkSync(path.join(hooksDir, f));
        fs.rmdirSync(hooksDir); fs.rmdirSync(gitDir); fs.rmdirSync(tmpDir);
      } catch {}
    }
  });

  await asyncTest('HOOKS: removeHooks leaves non-muaddib hook intact', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-rmother-'));
    const gitDir = path.join(tmpDir, '.git');
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(gitDir);
    fs.mkdirSync(hooksDir);
    const hookPath = path.join(hooksDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\nnpm test\n');
    const origLog = console.log;
    console.log = () => {};
    try {
      await removeHooks(tmpDir);
      assert(fs.existsSync(hookPath), 'Non-muaddib hook should remain');
    } finally {
      console.log = origLog;
      try { fs.unlinkSync(hookPath); fs.rmdirSync(hooksDir); fs.rmdirSync(gitDir); fs.rmdirSync(tmpDir); } catch {}
    }
  });

  // --- initHooks backup ---

  await asyncTest('HOOKS: initHooks backs up existing git hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hooks-backup-'));
    const gitDir = path.join(tmpDir, '.git');
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(gitDir);
    fs.mkdirSync(hooksDir);
    const hookPath = path.join(hooksDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\nold hook\n');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initHooks(tmpDir, { type: 'git' });
      const files = fs.readdirSync(hooksDir);
      const backups = files.filter(f => f.startsWith('pre-commit.backup.'));
      assert(backups.length >= 1, 'Should create at least 1 backup');
    } finally {
      console.log = origLog;
      try {
        const files = fs.readdirSync(hooksDir);
        for (const f of files) fs.unlinkSync(path.join(hooksDir, f));
        fs.rmdirSync(hooksDir); fs.rmdirSync(gitDir); fs.rmdirSync(tmpDir);
      } catch {}
    }
  });
}

module.exports = { runHooksInitTests };
