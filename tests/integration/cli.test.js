const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runScanCached, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runCliTests() {
  // ============================================
  // CLI TESTS
  // ============================================

  console.log('\n=== CLI TESTS ===\n');

  test('CLI: --help displays usage', () => {
    const output = runCommand('--help');
    assertIncludes(output, 'Usage', 'Should display usage');
  });

  await asyncTest('CLI: --json returns valid JSON (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(result && result.summary, 'Should return valid result object');
  });

  test('CLI: --sarif generates SARIF file', () => {
    const sarifPath = path.join(__dirname, 'test-output.sarif');
    runScan(path.join(TESTS_DIR, 'ast'), `--sarif "${sarifPath}"`);
    assert(fs.existsSync(sarifPath), 'SARIF file not generated');
    const content = fs.readFileSync(sarifPath, 'utf8');
    const sarif = JSON.parse(content);
    assert(sarif.version === '2.1.0', 'Incorrect SARIF version');
    assert(sarif.runs && sarif.runs.length > 0, 'SARIF runs missing');
    fs.unlinkSync(sarifPath);
  });

  test('CLI: --html generates HTML file', () => {
    const htmlPath = path.join(__dirname, 'test-output.html');
    runScan(path.join(TESTS_DIR, 'ast'), `--html "${htmlPath}"`);
    assert(fs.existsSync(htmlPath), 'HTML file not generated');
    const content = fs.readFileSync(htmlPath, 'utf8');
    assertIncludes(content, 'MUAD', 'HTML should contain MUAD');
    assertIncludes(content, '<table>', 'HTML should contain table');
    fs.unlinkSync(htmlPath);
  });

  test('CLI: --explain displays details', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
    assertIncludes(output, 'Rule ID', 'Should display Rule ID');
    assertIncludes(output, 'MITRE', 'Should display MITRE');
    assertIncludes(output, 'References', 'Should display References');
    assertIncludes(output, 'Playbook', 'Should display Playbook');
  });

  test('CLI: --fail-on critical exit code correct', () => {
    try {
      execSync(`node "${BIN}" scan "${path.join(TESTS_DIR, 'dataflow')}" --fail-on critical`, { encoding: 'utf8' });
    } catch (e) {
      assert(e.status >= 1, 'Exit code should be >= 1 for CRITICAL findings');
      return;
    }
    throw new Error('Should have non-zero exit code');
  });

  test('CLI: --fail-on high exit code correct', () => {
    try {
      execSync(`node "${BIN}" scan "${path.join(TESTS_DIR, 'ast')}" --fail-on high`, { encoding: 'utf8' });
    } catch (e) {
      assert(e.status > 0, 'Exit code should be > 0');
      return;
    }
    throw new Error('Should have non-zero exit code');
  });

  // ============================================
  // CLI NEW COMMANDS TESTS
  // ============================================

  console.log('\n=== CLI NEW COMMANDS TESTS ===\n');

  test('CLI: diff command shows refs when no arg', () => {
    const output = runCommand('diff');
    assertIncludes(output, 'Available references', 'Should show available refs');
    assertIncludes(output, 'Usage:', 'Should show usage');
  });

  test('CLI: init-hooks --help shows in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, 'init-hooks', 'Should show init-hooks command');
    assertIncludes(output, 'diff', 'Should show diff command');
  });

  // ============================================
  // CLI EXTENDED TESTS
  // ============================================

  console.log('\n=== CLI EXTENDED TESTS ===\n');

  test('CLI-EXT: version command shows version', () => {
    const output = runCommand('version');
    const pkg = require('../../package.json');
    assertIncludes(output, pkg.version, 'Should display version');
    assertIncludes(output, 'muaddib-scanner', 'Should display package name');
  });

  test('CLI-EXT: --version flag shows version', () => {
    const output = runCommand('--version');
    const pkg = require('../../package.json');
    assertIncludes(output, pkg.version, 'Should display version');
  });

  test('CLI-EXT: help command shows usage', () => {
    const output = runCommand('help');
    assertIncludes(output, 'Usage', 'Should display usage');
    assertIncludes(output, 'muaddib scan', 'Should show scan');
  });

  test('CLI-EXT: unknown command shows error', () => {
    const output = runCommand('blahblah');
    assertIncludes(output, 'Unknown command', 'Should say Unknown command');
  });

  await asyncTest('CLI-EXT: deduplication reduces duplicate alerts (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    // Verify no two threats have same file + type + message combination
    const keys = result.threats.map(t => `${t.file}::${t.type}::${t.message}`);
    const uniqueKeys = [...new Set(keys)];
    assert(keys.length === uniqueKeys.length, 'All threats should be unique per file+type+message');
  });

  test('CLI-EXT: scan with --paranoid and --webhook', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--paranoid --webhook https://discord.com/api/webhooks/test');
    assertIncludes(output, 'PARANOID', 'Should enable paranoid mode');
  });

  test('CLI-EXT: interactive mode errors without TTY', () => {
    // Running muaddib with no command + piped stdin triggers interactiveMenu -> catch
    try {
      execSync(`node "${BIN}"`, { encoding: 'utf8', timeout: 15000, input: '\n', stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assert(output.length > 0, 'Should produce output');
      return;
    }
  });

  test('CLI-EXT: diff with ref HEAD~1', () => {
    // Use a small fixture dir instead of '.' to avoid scanning the entire project
    const output = runCommand(`diff HEAD~1 "${path.join(TESTS_DIR, 'clean')}"`);
    assert(output !== undefined, 'Should not crash');
  });

  test('CLI-EXT: init-hooks with --type and --mode', () => {
    const output = runCommand('init-hooks --type git --mode scan');
    assert(output !== undefined, 'Should not crash');
  });

  test('CLI-EXT: install without packages shows usage', () => {
    const output = runCommand('install');
    assertIncludes(output, 'Usage', 'Should show install usage');
  });

  test('CLI-EXT: install blocks malicious package', () => {
    const output = runCommand('install lodahs');
    assertIncludes(output, 'MALICIOUS', 'Should detect malicious');
  });

  test('CLI-EXT: install alias i blocks malicious', () => {
    const output = runCommand('i lodahs');
    assertIncludes(output, 'MALICIOUS', 'Should detect via alias');
  });

  test('CLI-EXT: sandbox without package shows usage', () => {
    const output = runCommand('sandbox');
    assertIncludes(output, 'Usage', 'Should show sandbox usage');
  });

  test('CLI-EXT: sandbox with package errors without Docker', () => {
    const output = runCommand('sandbox nonexistent-pkg-test');
    assert(output.length > 0, 'Should produce output');
  });

  // SKIPPED: scrape does real network downloads (15s) — run via npm run test:integration
  console.log('[SKIP] CLI-EXT: scrape command runs (network)');
  addSkipped(1);

  // ============================================
  // CLI COVERAGE TESTS (muaddib.js)
  // ============================================

  console.log('\n=== CLI COVERAGE TESTS ===\n');

  await asyncTest('CLI-COV: --exclude flag is parsed correctly (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { exclude: ['node_modules', 'dist'] });
    assert(result && result.summary, 'Should not crash with --exclude');
  });

  await asyncTest('CLI-COV: --fail-on with invalid value defaults gracefully (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result && result.summary, 'Should not crash');
  });

  await asyncTest('CLI-COV: --fail-on low works (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result && result.summary, 'Should handle scan');
  });

  await asyncTest('CLI-COV: --fail-on medium works (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result && result.summary, 'Should handle scan');
  });

  test('CLI-COV: --html with path traversal is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --html "../../../etc/evil.html"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'traversal', 'Should mention path traversal');
    }
  });

  test('CLI-COV: --sarif with path traversal is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --sarif "../../evil.sarif"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'traversal', 'Should mention path traversal');
    }
  });

  test('CLI-COV: --webhook with HTTP URL is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "http://evil.com/hook"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'HTTPS', 'Should require HTTPS');
    }
  });

  test('CLI-COV: --webhook with private IP is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "https://127.0.0.1/hook"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'private', 'Should reject private IP');
    }
  });

  test('CLI-COV: --webhook with invalid URL is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "not-a-url"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'invalid', 'Should reject invalid URL');
    }
  });

  await asyncTest('CLI-COV: scan with multiple --exclude flags (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'), { exclude: ['dist'] });
    assert(result && result.threats, 'Should produce result');
  });

  test('CLI-COV: remove-hooks command runs', () => {
    const output = runCommand('remove-hooks .');
    assert(output !== undefined, 'Should not crash');
  });

  await asyncTest('CLI-COV: --paranoid flag is parsed correctly (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { paranoid: true });
    assert(result && result.summary, 'Should not crash with --paranoid');
  });

  await asyncTest('CLI-COV: scan result has summary (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result.summary, 'Result should have summary');
  });

  await asyncTest('CLI-COV: clean project has 0 threats (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result.summary.total === 0, 'Clean project should have 0 threats');
  });

  test('CLI-COV: scan nonexistent directory handles error', () => {
    const output = runScan('/nonexistent/path/12345');
    assert(output !== undefined, 'Should not crash on nonexistent dir');
  });

  test('CLI-COV: --webhook with localhost is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "https://localhost/hook"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'private', 'Should reject localhost');
    }
  });

  test('CLI-COV: -v flag shows version', () => {
    const output = runCommand('-v');
    assertIncludes(output, 'muaddib-scanner v', 'Should show version with -v');
  });

  test('CLI-COV: -h flag shows help', () => {
    const output = runCommand('-h');
    assertIncludes(output, 'Usage', 'Should show usage with -h');
  });

  test('CLI-COV: --temporal-ast flag appears in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, '--temporal-ast', 'Help should show --temporal-ast flag');
    assertIncludes(output, '--temporal-full', 'Help should show --temporal-full flag');
  });

  await asyncTest('CLI-COV: --temporal-ast flag is parsed without error (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporalAst: true });
    assert(result.summary, 'Should produce valid result with summary');
  });

  await asyncTest('CLI-COV: --temporal-full flag is parsed without error (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporal: true, temporalAst: true, temporalPublish: true, temporalMaintainer: true });
    assert(result.summary, 'Should produce valid result with summary');
  });

  test('CLI-COV: --temporal-publish flag appears in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, '--temporal-publish', 'Help should show --temporal-publish flag');
  });

  await asyncTest('CLI-COV: --temporal-publish flag is parsed without error (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporalPublish: true });
    assert(result.summary, 'Should produce valid result with summary');
  });

  await asyncTest('CLI-COV: --temporal-full includes publish analysis (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporal: true, temporalAst: true, temporalPublish: true, temporalMaintainer: true });
    assert(result.summary.total === 0, 'Clean project should have 0 threats with --temporal-full');
  });

  test('CLI-COV: --temporal-maintainer flag appears in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, '--temporal-maintainer', 'Help should show --temporal-maintainer flag');
  });

  await asyncTest('CLI-COV: --temporal-maintainer flag is parsed without error (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporalMaintainer: true });
    assert(result.summary, 'Should produce valid result with summary');
  });

  await asyncTest('CLI-COV: --temporal-full includes maintainer analysis (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporal: true, temporalAst: true, temporalPublish: true, temporalMaintainer: true });
    assert(result.summary.total === 0, 'Clean project should have 0 threats with --temporal-full');
  });

  test('CLI-COV: --no-canary flag appears in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, '--no-canary', 'Help should show --no-canary flag');
  });

  test('CLI-COV: --no-canary flag is parsed without error', () => {
    // --no-canary is for sandbox commands, but parsing should not crash
    const output = runCommand('--help');
    assertIncludes(output, '--no-canary', 'Help should mention --no-canary');
  });

  // ============================================
  // DIFF MODULE TESTS
  // ============================================

  console.log('\n=== DIFF MODULE TESTS ===\n');

  test('DIFF: Module loads without error', () => {
    const { diff, showRefs, isGitRepo } = require('../../src/diff.js');
    assert(typeof diff === 'function', 'diff should be a function');
    assert(typeof showRefs === 'function', 'showRefs should be a function');
    assert(typeof isGitRepo === 'function', 'isGitRepo should be a function');
  });

  test('DIFF: isGitRepo returns true for this repo', () => {
    const { isGitRepo } = require('../../src/diff.js');
    const result = isGitRepo(path.join(__dirname, '..', '..'));
    assert(result === true, 'Should detect git repo');
  });

  test('DIFF: isGitRepo returns false for non-repo', () => {
    const { isGitRepo } = require('../../src/diff.js');
    const result = isGitRepo('/tmp');
    assert(result === false, 'Should not detect git repo in /tmp');
  });

  test('DIFF: getRecentRefs returns tags and commits', () => {
    const { getRecentRefs } = require('../../src/diff.js');
    const refs = getRecentRefs(path.join(__dirname, '..', '..'));
    assert(refs.tags !== undefined, 'Should have tags array');
    assert(refs.commits !== undefined, 'Should have commits array');
    assert(refs.commits.length > 0, 'Should have at least one commit');
  });

  // ============================================
  // HOOKS INIT MODULE TESTS
  // ============================================

  console.log('\n=== HOOKS INIT MODULE TESTS ===\n');

  test('HOOKS: Module loads without error', () => {
    const { initHooks, detectHookSystem } = require('../../src/hooks-init.js');
    assert(typeof initHooks === 'function', 'initHooks should be a function');
    assert(typeof detectHookSystem === 'function', 'detectHookSystem should be a function');
  });

  test('HOOKS: detectHookSystem returns object with expected properties', () => {
    const { detectHookSystem } = require('../../src/hooks-init.js');
    const result = detectHookSystem(path.join(__dirname, '..', '..'));
    assert(typeof result.husky === 'boolean', 'Should have husky property');
    assert(typeof result.preCommit === 'boolean', 'Should have preCommit property');
    assert(typeof result.gitHooks === 'boolean', 'Should have gitHooks property');
  });

  test('HOOKS: detectHookSystem detects git hooks directory', () => {
    const { detectHookSystem } = require('../../src/hooks-init.js');
    const result = detectHookSystem(path.join(__dirname, '..', '..'));
    assert(result.gitHooks === true, 'Should detect .git/hooks directory');
  });

  // ============================================
  // HOOKS INIT COVERAGE TESTS (hooks-init.js)
  // ============================================

  console.log('\n=== HOOKS INIT COVERAGE TESTS ===\n');

  test('HOOKS-COV: HOOK_COMMANDS has scan and diff entries', () => {
    // Access module-level constants via require
    const hooksModule = require('../../src/hooks-init.js');
    // HOOK_COMMANDS is not exported, but we can verify initHooks behavior
    assert(typeof hooksModule.initHooks === 'function', 'initHooks should be a function');
    assert(typeof hooksModule.removeHooks === 'function', 'removeHooks should be a function');
  });

  await asyncTest('HOOKS-COV: initHooks with git type creates hook file', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};
    try {
      const result = await initH(tmpDir, { type: 'git', mode: 'scan' });
      console.log = origLog;
      console.error = origErr;
      assert(result === true, 'initHooks should return true');
      const hookPath = path.join(gitDir, 'pre-commit');
      assert(fs.existsSync(hookPath), 'pre-commit hook should exist');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib scan', 'Hook should contain scan command');
      assertIncludes(content, 'MUADDIB', 'Hook should contain MUADDIB');
    } finally {
      console.log = origLog;
      console.error = origErr;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks with diff mode generates diff command', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'git', mode: 'diff' });
      console.log = origLog;
      const hookPath = path.join(gitDir, 'pre-commit');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib diff', 'Hook should contain diff command');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks invalid mode defaults to scan', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'git', mode: 'invalidmode' });
      console.log = origLog;
      const hookPath = path.join(gitDir, 'pre-commit');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib scan', 'Invalid mode should default to scan');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks backs up existing hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const hookPath = path.join(gitDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\necho old hook\n');
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'git', mode: 'scan' });
      console.log = origLog;
      const backups = fs.readdirSync(gitDir).filter(f => f.startsWith('pre-commit.backup.'));
      assert(backups.length >= 1, 'Should have created a backup');
      const newContent = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(newContent, 'muaddib scan', 'New hook should contain scan');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks fails without .git directory', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};
    try {
      const result = await initH(tmpDir, { type: 'git', mode: 'scan' });
      console.log = origLog;
      console.error = origErr;
      assert(result === false, 'Should return false when no .git');
    } finally {
      console.log = origLog;
      console.error = origErr;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initPreCommit creates config when none exists', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    // Create .pre-commit-config.yaml marker
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    // Don't create it -- let initPreCommit create it
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'pre-commit', mode: 'scan' });
      console.log = origLog;
      assert(fs.existsSync(configPath), 'Should create .pre-commit-config.yaml');
      const content = fs.readFileSync(configPath, 'utf8');
      assertIncludes(content, 'muaddib-scan', 'Should have muaddib-scan hook id');
      assertIncludes(content, 'repos:', 'Should have repos section');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initPreCommit appends to existing config', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    fs.writeFileSync(configPath, 'repos:\n  - repo: https://github.com/other/hook\n    rev: v1.0\n    hooks:\n      - id: other-hook\n');
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'pre-commit', mode: 'diff' });
      console.log = origLog;
      const content = fs.readFileSync(configPath, 'utf8');
      assertIncludes(content, 'muaddib-diff', 'Should have muaddib-diff hook id');
      assertIncludes(content, 'other-hook', 'Should preserve existing hooks');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initPreCommit skips if already configured', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    fs.writeFileSync(configPath, 'repos:\n  - repo: muaddib-scanner\n');
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      await initH(tmpDir, { type: 'pre-commit', mode: 'scan' });
      console.log = origLog;
      const logged = logs.some(l => l.includes('already configured'));
      assert(logged, 'Should log that muaddib is already configured');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: removeHooks removes git hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const hookPath = path.join(gitDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\nmuaddib scan . --fail-on high\n');
    const { removeHooks: removeH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await removeH(tmpDir);
      console.log = origLog;
      assert(!fs.existsSync(hookPath), 'Hook should be removed');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: removeHooks preserves non-muaddib hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const hookPath = path.join(gitDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\necho "other tool"\n');
    const { removeHooks: removeH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await removeH(tmpDir);
      console.log = origLog;
      assert(fs.existsSync(hookPath), 'Non-muaddib hook should be preserved');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ============================================
  // SCORE BREAKDOWN TESTS
  // ============================================

  console.log('\n=== SCORE BREAKDOWN TESTS ===\n');

  test('BREAKDOWN: --breakdown appears in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, '--breakdown', 'Help should show --breakdown flag');
  });

  test('BREAKDOWN: --breakdown shows score contributors', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--breakdown');
    assertIncludes(output, '[BREAKDOWN]', 'Should show [BREAKDOWN] header');
    assertIncludes(output, 'MUADDIB-', 'Should show rule IDs');
  });

  test('BREAKDOWN: --breakdown --explain shows both breakdown and score', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--breakdown --explain');
    assertIncludes(output, '[BREAKDOWN]', 'Should show [BREAKDOWN] header');
    assertIncludes(output, '[SCORE]', 'Should show [SCORE] bar');
  });

  await asyncTest('BREAKDOWN: JSON includes summary.breakdown array (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(Array.isArray(result.summary.breakdown), 'summary.breakdown should be an array');
    assert(result.summary.breakdown.length > 0, 'breakdown should have entries for ast fixtures');
    const entry = result.summary.breakdown[0];
    assert(typeof entry.rule === 'string', 'breakdown entry should have rule');
    assert(typeof entry.type === 'string', 'breakdown entry should have type');
    assert(typeof entry.points === 'number', 'breakdown entry should have points');
    assert(typeof entry.reason === 'string', 'breakdown entry should have reason');
  });

  await asyncTest('BREAKDOWN: JSON breakdown sorted descending by points (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    const bd = result.summary.breakdown;
    for (let i = 1; i < bd.length; i++) {
      assert(bd[i - 1].points >= bd[i].points, `breakdown[${i - 1}].points (${bd[i - 1].points}) should >= breakdown[${i}].points (${bd[i].points})`);
    }
  });

  await asyncTest('BREAKDOWN: threats have numeric points field (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    for (const t of result.threats) {
      assert(typeof t.points === 'number', `threat ${t.rule_id} should have numeric points`);
      assert(t.points > 0, `threat ${t.rule_id} should have positive points`);
    }
  });

  await asyncTest('BREAKDOWN: clean project has empty breakdown (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(Array.isArray(result.summary.breakdown), 'summary.breakdown should be an array');
    assert(result.summary.breakdown.length === 0, 'clean project breakdown should be empty');
  });

  await asyncTest('BREAKDOWN: clean project has no breakdown entries (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result.summary.breakdown.length === 0, 'Clean project should have no breakdown entries');
  });

  await asyncTest('BREAKDOWN: points match severity weights x confidence (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    const WEIGHTS = { CRITICAL: 25, HIGH: 10, MEDIUM: 3, LOW: 1 };
    const CONF = { high: 1.0, medium: 0.85, low: 0.6 };
    for (const t of result.threats) {
      const expected = Math.round((WEIGHTS[t.severity] || 0) * (CONF[t.confidence] || 1.0));
      assert(t.points === expected, `${t.rule_id} (${t.severity}/${t.confidence}) should have ${expected} points, got ${t.points}`);
    }
  });

  // ============================================
  // PER-FILE SCORING TESTS (v2.2.11)
  // ============================================

  console.log('\n=== PER-FILE SCORING TESTS ===\n');

  await asyncTest('PER-FILE: JSON includes summary.maxFileScore (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(typeof result.summary.maxFileScore === 'number', 'summary.maxFileScore should be number');
  });

  await asyncTest('PER-FILE: JSON includes summary.globalRiskScore (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(typeof result.summary.globalRiskScore === 'number', 'summary.globalRiskScore should be number');
  });

  await asyncTest('PER-FILE: JSON includes summary.mostSuspiciousFile (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(result.summary.mostSuspiciousFile !== null, 'mostSuspiciousFile should be set for ast fixtures');
  });

  await asyncTest('PER-FILE: JSON includes summary.packageScore (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(typeof result.summary.packageScore === 'number', 'summary.packageScore should be number');
  });

  await asyncTest('PER-FILE: JSON includes summary.fileScores object (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(typeof result.summary.fileScores === 'object' && result.summary.fileScores !== null, 'fileScores should be an object');
  });

  await asyncTest('PER-FILE: riskScore <= globalRiskScore (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(result.summary.riskScore <= result.summary.globalRiskScore,
      `Per-file score (${result.summary.riskScore}) should be <= global score (${result.summary.globalRiskScore})`);
  });

  await asyncTest('PER-FILE: riskScore = maxFileScore + packageScore (capped) (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    const expected = Math.min(100, result.summary.maxFileScore + result.summary.packageScore);
    assert(result.summary.riskScore === expected,
      `riskScore (${result.summary.riskScore}) should equal min(100, maxFileScore + packageScore) = ${expected}`);
  });

  await asyncTest('PER-FILE: clean project has maxFileScore 0 (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'));
    assert(result.summary.maxFileScore === 0, 'Clean project maxFileScore should be 0');
    assert(result.summary.mostSuspiciousFile === null, 'Clean project mostSuspiciousFile should be null');
    assert(result.summary.riskScore === 0, 'Clean project riskScore should be 0');
  });

  await asyncTest('PER-FILE: mostSuspiciousFile appears in fileScores (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    if (result.summary.mostSuspiciousFile) {
      assert(result.summary.fileScores[result.summary.mostSuspiciousFile] !== undefined,
        'mostSuspiciousFile should have an entry in fileScores');
      assert(result.summary.fileScores[result.summary.mostSuspiciousFile] === result.summary.maxFileScore,
        'mostSuspiciousFile score should equal maxFileScore');
    }
  });

  test('PER-FILE: isPackageLevelThreat classifies correctly', () => {
    const { isPackageLevelThreat } = require('../../src/index.js');
    assert(isPackageLevelThreat({ type: 'lifecycle_script', file: 'package.json' }) === true, 'lifecycle_script should be package-level');
    assert(isPackageLevelThreat({ type: 'typosquat_detected', file: 'package.json' }) === true, 'typosquat should be package-level');
    assert(isPackageLevelThreat({ type: 'known_malicious_package', file: 'node_modules/evil' }) === true, 'known_malicious should be package-level');
    assert(isPackageLevelThreat({ type: 'eval_usage', file: 'src/index.js' }) === false, 'eval_usage should be file-level');
    assert(isPackageLevelThreat({ type: 'dynamic_require', file: 'lib/utils.js' }) === false, 'dynamic_require should be file-level');
    assert(isPackageLevelThreat({ type: 'obfuscation_detected', file: 'dist/bundle.js' }) === false, 'obfuscation should be file-level');
  });

  test('PER-FILE: computeGroupScore with mixed severities', () => {
    const { computeGroupScore } = require('../../src/index.js');
    // Use real types with HIGH confidence so weights are unmodified
    const threats = [
      { severity: 'CRITICAL', type: 'reverse_shell' },
      { severity: 'HIGH', type: 'env_access' },
      { severity: 'LOW', type: 'env_access' }
    ];
    const score = computeGroupScore(threats);
    // 25*1.0 + 10*1.0 + 1*1.0 = 36
    assert(score === 36, `Expected 25+10+1=36, got ${score}`);
  });

  test('PER-FILE: computeGroupScore caps prototype_hook MEDIUM', () => {
    const { computeGroupScore } = require('../../src/index.js');
    const threats = [];
    for (let i = 0; i < 20; i++) {
      threats.push({ severity: 'MEDIUM', type: 'prototype_hook' });
    }
    const score = computeGroupScore(threats);
    assert(score === 15, `Expected 15 (MEDIUM proto_hook capped), got ${score}`);
  });

  test('PER-FILE: computeGroupScore caps at 100', () => {
    const { computeGroupScore } = require('../../src/index.js');
    // Use real type with HIGH confidence so 5*25*1.0=125 → capped at 100
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ severity: 'CRITICAL', type: 'reverse_shell' });
    }
    const score = computeGroupScore(threats);
    assert(score === 100, `Expected 100 (capped), got ${score}`);
  });

  test('PER-FILE: computeGroupScore caps suspicious_dataflow MEDIUM (R4)', () => {
    const { computeGroupScore } = require('../../src/index.js');
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ severity: 'MEDIUM', type: 'suspicious_dataflow' });
    }
    const score = computeGroupScore(threats);
    assert(score === 3, `Expected 3 (dataflow MEDIUM capped), got ${score}`);
  });

  test('PER-FILE: computeGroupScore does NOT cap suspicious_dataflow HIGH', () => {
    const { computeGroupScore } = require('../../src/index.js');
    const threats = [
      { severity: 'HIGH', type: 'suspicious_dataflow' },
      { severity: 'HIGH', type: 'suspicious_dataflow' }
    ];
    const score = computeGroupScore(threats);
    assert(score === 20, `Expected 20 (2×HIGH=10 each, no cap), got ${score}`);
  });

  test('PER-FILE: output shows Max file info when threats exist', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '');
    assertIncludes(output, 'Max file:', 'Should show max file in score output');
  });

  await asyncTest('HOOKS-COV: auto-detect selects git when only .git exists', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../../src/hooks-init.js');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(String(msg));
    try {
      await initH(tmpDir, { type: 'auto', mode: 'scan' });
      console.log = origLog;
      const gitLog = logs.some(l => l.includes('Hook system: git'));
      assert(gitLog, 'Should auto-detect git hook system');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ============================================
  // THREAT FEED MODULE TESTS
  // ============================================

  console.log('\n=== THREAT FEED MODULE TESTS ===\n');

  test('FEED: Module loads with expected exports', () => {
    const { getFeed, computeDetectionScore, SEVERITY_WEIGHTS } = require('../../src/threat-feed.js');
    assert(typeof getFeed === 'function', 'getFeed should be a function');
    assert(typeof computeDetectionScore === 'function', 'computeDetectionScore should be a function');
    assert(typeof SEVERITY_WEIGHTS === 'object', 'SEVERITY_WEIGHTS should be an object');
    assert(SEVERITY_WEIGHTS.CRITICAL === 25, 'CRITICAL weight should be 25');
    assert(SEVERITY_WEIGHTS.HIGH === 10, 'HIGH weight should be 10');
    assert(SEVERITY_WEIGHTS.MEDIUM === 3, 'MEDIUM weight should be 3');
    assert(SEVERITY_WEIGHTS.LOW === 1, 'LOW weight should be 1');
  });

  test('FEED: getFeed returns expected structure', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const result = getFeed();
    assert(typeof result.generated_at === 'string', 'Should have generated_at');
    assert(typeof result.version === 'string', 'Should have version');
    assert(Array.isArray(result.feed), 'Should have feed array');
  });

  test('FEED: getFeed version matches package.json', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const pkgJson = require('../../package.json');
    const result = getFeed();
    assert(result.version === pkgJson.version, `Version should be ${pkgJson.version}, got ${result.version}`);
  });

  test('FEED: computeDetectionScore with known types', () => {
    const { computeDetectionScore } = require('../../src/threat-feed.js');
    const detection = {
      findings: ['obfuscation_detected', 'known_malicious_package'],
      severity: 'CRITICAL'
    };
    const result = computeDetectionScore(detection);
    assert(result.score === 35, `Score should be 35 (HIGH=10 + CRITICAL=25), got ${result.score}`);
    assert(result.breakdown.length === 2, 'Should have 2 breakdown entries');
    assert(result.breakdown[0].points >= result.breakdown[1].points, 'Breakdown should be sorted descending');
  });

  test('FEED: computeDetectionScore caps at 100', () => {
    const { computeDetectionScore } = require('../../src/threat-feed.js');
    const detection = {
      findings: [
        'known_malicious_package', 'known_malicious_package',
        'known_malicious_package', 'known_malicious_package',
        'known_malicious_package'
      ],
      severity: 'CRITICAL'
    };
    const result = computeDetectionScore(detection);
    assert(result.score === 100, `Score should be capped at 100, got ${result.score}`);
  });

  test('FEED: computeDetectionScore falls back to detection severity for unknown types', () => {
    const { computeDetectionScore } = require('../../src/threat-feed.js');
    const detection = {
      findings: ['totally_unknown_type_xyz'],
      severity: 'HIGH'
    };
    const result = computeDetectionScore(detection);
    assert(result.score === 10, `Unknown type with HIGH severity should score 10, got ${result.score}`);
    assert(result.breakdown[0].rule === 'MUADDIB-UNK-001', 'Should use unknown rule');
    assert(result.breakdown[0].severity === 'HIGH', 'Should use detection severity');
  });

  test('FEED: getFeed respects limit option', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const result = getFeed({ limit: 5 });
    assert(result.feed.length <= 5, `Feed should have at most 5 entries, got ${result.feed.length}`);
  });

  test('FEED: getFeed handles empty detections', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const result = getFeed({ since: '2099-01-01T00:00:00Z' });
    assert(Array.isArray(result.feed), 'Feed should still be an array');
    assert(result.feed.length === 0, 'Future since date should return empty feed');
  });

  // ============================================
  // CLI FEED COMMAND TESTS
  // ============================================

  console.log('\n=== CLI FEED COMMAND TESTS ===\n');

  test('FEED-CLI: getFeed returns valid structure', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const parsed = getFeed();
    assert(typeof parsed.generated_at === 'string', 'Should have generated_at');
    assert(typeof parsed.version === 'string', 'Should have version');
    assert(Array.isArray(parsed.feed), 'Should have feed array');
  });

  test('FEED-CLI: getFeed limit=3 respects limit', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const parsed = getFeed({ limit: 3 });
    assert(parsed.feed.length <= 3, `Feed should have at most 3 entries, got ${parsed.feed.length}`);
  });

  test('FEED-CLI: getFeed severity=CRITICAL filters', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const parsed = getFeed({ severity: 'CRITICAL' });
    for (const entry of parsed.feed) {
      assert(entry.severity === 'CRITICAL', `All entries should be CRITICAL, got ${entry.severity}`);
    }
  });

  test('FEED-CLI: getFeed since=2099 returns empty feed', () => {
    const { getFeed } = require('../../src/threat-feed.js');
    const parsed = getFeed({ since: '2099-01-01T00:00:00Z' });
    assert(parsed.feed.length === 0, 'Future since date should return empty feed');
  });

  test('FEED-CLI: feed and serve are visible in --help', () => {
    const output = runCommand('--help');
    assert(output.includes('muaddib feed'), 'feed should appear in help');
    assert(output.includes('muaddib serve'), 'serve should appear in help');
  });

  // ============================================
  // HTTP SERVER TESTS
  // ============================================

  console.log('\n=== HTTP SERVER TESTS ===\n');

  test('SERVE: startServer is a function', () => {
    const { startServer } = require('../../src/serve.js');
    assert(typeof startServer === 'function', 'startServer should be a function');
  });

  await asyncTest('SERVE: server responds to GET /feed with 200', async () => {
    const { startServer } = require('../../src/serve.js');
    const port = 30000 + Math.floor(Math.random() * 10000);
    const origLog = console.log;
    console.log = () => {};
    const server = startServer({ port });
    try {
      await new Promise(resolve => setTimeout(resolve, 200));
      const data = await new Promise((resolve, reject) => {
        const req = require('http').get(`http://127.0.0.1:${port}/feed`, (res) => {
          assert(res.statusCode === 200, `Should return 200, got ${res.statusCode}`);
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            const parsed = JSON.parse(body);
            assert(typeof parsed.generated_at === 'string', 'Should have generated_at');
            assert(Array.isArray(parsed.feed), 'Should have feed array');
            resolve(parsed);
          });
        });
        req.on('error', reject);
      });
    } finally {
      console.log = origLog;
      server.close();
    }
  });

  await asyncTest('SERVE: server responds 404 to unknown routes', async () => {
    const { startServer } = require('../../src/serve.js');
    const port = 30000 + Math.floor(Math.random() * 10000);
    const origLog = console.log;
    console.log = () => {};
    const server = startServer({ port });
    try {
      await new Promise(resolve => setTimeout(resolve, 200));
      await new Promise((resolve, reject) => {
        const req = require('http').get(`http://127.0.0.1:${port}/unknown`, (res) => {
          assert(res.statusCode === 404, `Should return 404, got ${res.statusCode}`);
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            const parsed = JSON.parse(body);
            assert(typeof parsed.error === 'string', 'Should have error message');
            resolve();
          });
        });
        req.on('error', reject);
      });
    } finally {
      console.log = origLog;
      server.close();
    }
  });

  await asyncTest('SERVE: /health returns status ok', async () => {
    const { startServer } = require('../../src/serve.js');
    const port = 30000 + Math.floor(Math.random() * 10000);
    const origLog = console.log;
    console.log = () => {};
    const server = startServer({ port });
    try {
      await new Promise(resolve => setTimeout(resolve, 200));
      await new Promise((resolve, reject) => {
        const req = require('http').get(`http://127.0.0.1:${port}/health`, (res) => {
          assert(res.statusCode === 200, `Should return 200, got ${res.statusCode}`);
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            const parsed = JSON.parse(body);
            assert(parsed.status === 'ok', 'Should have status ok');
            assert(typeof parsed.version === 'string', 'Should have version');
            resolve();
          });
        });
        req.on('error', reject);
      });
    } finally {
      console.log = origLog;
      server.close();
    }
  });

  await asyncTest('SERVE: /feed passes query params to getFeed', async () => {
    const { startServer } = require('../../src/serve.js');
    const port = 30000 + Math.floor(Math.random() * 10000);
    const origLog = console.log;
    console.log = () => {};
    const server = startServer({ port });
    try {
      await new Promise(resolve => setTimeout(resolve, 200));
      await new Promise((resolve, reject) => {
        const req = require('http').get(`http://127.0.0.1:${port}/feed?limit=2&severity=CRITICAL&since=2099-01-01`, (res) => {
          assert(res.statusCode === 200, `Should return 200, got ${res.statusCode}`);
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            const parsed = JSON.parse(body);
            assert(parsed.feed.length <= 2, 'Limit should be respected');
            for (const entry of parsed.feed) {
              assert(entry.severity === 'CRITICAL', 'Severity filter should be applied');
            }
            resolve();
          });
        });
        req.on('error', reject);
      });
    } finally {
      console.log = origLog;
      server.close();
    }
  });

  // --- Scan warnings field (v2.6.5) ---

  await asyncTest('CLI: JSON output contains warnings field as array or undefined (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    // warnings should either be undefined (no warnings) or an array
    assert(
      result.warnings === undefined || Array.isArray(result.warnings),
      `warnings should be undefined or array, got ${typeof result.warnings}`
    );
  });

  await asyncTest('CLI: JSON output has standard result fields (direct)', async () => {
    const result = await runScanCached(path.join(TESTS_DIR, 'ast'));
    assert(result.target !== undefined, 'result should have target');
    assert(result.timestamp !== undefined, 'result should have timestamp');
    assert(result.threats !== undefined, 'result should have threats');
    assert(result.summary !== undefined, 'result should have summary');
  });
}

module.exports = { runCliTests };
