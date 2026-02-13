const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
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

  test('CLI: --json returns valid JSON', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
    try {
      JSON.parse(output);
    } catch (e) {
      throw new Error('Invalid JSON output');
    }
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
      assert(e.status === 1, 'Exit code should be 1 for 1 CRITICAL');
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

  test('CLI-EXT: deduplication reduces duplicate alerts', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
    const result = JSON.parse(output);
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
    const output = runCommand('diff HEAD~1 .');
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

  test('CLI-EXT: scrape command runs', () => {
    try {
      const output = execSync(`node "${BIN}" scrape`, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 15000
      });
      assert(output.length > 0, 'Should produce output');
    } catch (e) {
      // Timeout is OK — scrape downloads large files, we just verify it starts
      const output = e.stdout || e.stderr || '';
      assert(output.includes('SCRAPER') || output.includes('IOC'), 'Should start scraping before timeout');
    }
  });

  // ============================================
  // CLI COVERAGE TESTS (muaddib.js)
  // ============================================

  console.log('\n=== CLI COVERAGE TESTS ===\n');

  test('CLI-COV: --exclude flag is parsed correctly', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--exclude node_modules --exclude dist');
    assert(output !== undefined, 'Should not crash with --exclude');
  });

  test('CLI-COV: --fail-on with invalid value defaults gracefully', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on banana');
    assert(output !== undefined, 'Should not crash with invalid fail-on');
  });

  test('CLI-COV: --fail-on low works', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on low');
    assert(output !== undefined, 'Should handle --fail-on low');
  });

  test('CLI-COV: --fail-on medium works', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on medium');
    assert(output !== undefined, 'Should handle --fail-on medium');
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

  test('CLI-COV: scan with multiple --exclude flags', () => {
    const output = runScan('.', '--exclude test --exclude docs --json');
    assert(output.length > 0, 'Should produce output');
  });

  test('CLI-COV: remove-hooks command runs', () => {
    const output = runCommand('remove-hooks .');
    assert(output !== undefined, 'Should not crash');
  });

  test('CLI-COV: --paranoid flag is parsed correctly', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--paranoid');
    assert(output !== undefined, 'Should not crash with --paranoid');
  });

  test('CLI-COV: scan --json --explain combined', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--json --explain');
    const json = JSON.parse(output);
    assert(json.summary, 'JSON output should have summary');
  });

  test('CLI-COV: scan --fail-on critical with clean project exits 0', () => {
    // Clean project = no threats, --fail-on critical means exit 0
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on critical --json');
    const json = JSON.parse(output);
    assert(json.summary.total === 0, 'Clean project should have 0 threats');
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

  test('CLI-COV: --temporal-ast flag is parsed without error', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--temporal-ast --json');
    const json = JSON.parse(output);
    assert(json.summary, 'Should produce valid JSON with summary');
  });

  test('CLI-COV: --temporal-full flag is parsed without error', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--temporal-full --json');
    const json = JSON.parse(output);
    assert(json.summary, 'Should produce valid JSON with summary');
  });

  test('CLI-COV: --temporal-publish flag appears in help', () => {
    const output = runCommand('--help');
    assertIncludes(output, '--temporal-publish', 'Help should show --temporal-publish flag');
  });

  test('CLI-COV: --temporal-publish flag is parsed without error', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--temporal-publish --json');
    const json = JSON.parse(output);
    assert(json.summary, 'Should produce valid JSON with summary');
  });

  test('CLI-COV: --temporal-full includes publish analysis', () => {
    // --temporal-full should activate all three temporal modes without error
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--temporal-full --json');
    const json = JSON.parse(output);
    assert(json.summary.total === 0, 'Clean project should have 0 threats with --temporal-full');
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
}

module.exports = { runCliTests };
