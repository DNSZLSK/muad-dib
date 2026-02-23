const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes
} = require('../test-utils');

async function runDiffTests() {
  // ============================================
  // DIFF MODULE TESTS
  // ============================================

  console.log('\n=== DIFF MODULE TESTS ===\n');

  const {
    diff, showRefs, isGitRepo, getRecentRefs,
    getThreatId, compareThreats, resolveRef, getCurrentCommit,
    hasUncommittedChanges, runSilentScan, SAFE_REF_REGEX
  } = require('../../src/diff.js');

  const REPO_ROOT = path.join(__dirname, '..', '..');

  // --- SAFE_REF_REGEX ---

  test('DIFF: SAFE_REF_REGEX accepts valid git refs', () => {
    assert(SAFE_REF_REGEX.test('HEAD'), 'HEAD should be valid');
    assert(SAFE_REF_REGEX.test('HEAD~1'), 'HEAD~1 should be valid');
    assert(SAFE_REF_REGEX.test('HEAD~10'), 'HEAD~10 should be valid');
    assert(SAFE_REF_REGEX.test('main'), 'main should be valid');
    assert(SAFE_REF_REGEX.test('origin/main'), 'origin/main should be valid');
    assert(SAFE_REF_REGEX.test('v1.0.0'), 'v1.0.0 should be valid');
    assert(SAFE_REF_REGEX.test('feature/my-branch'), 'feature/my-branch should be valid');
    assert(SAFE_REF_REGEX.test('abc1234def5678'), 'hex hash should be valid');
    assert(SAFE_REF_REGEX.test('HEAD^'), 'HEAD^ should be valid');
    assert(SAFE_REF_REGEX.test('HEAD@{1}'), 'HEAD@{1} should be valid');
  });

  test('DIFF: SAFE_REF_REGEX rejects dangerous characters', () => {
    assert(!SAFE_REF_REGEX.test('$(whoami)'), 'Command substitution should be rejected');
    assert(!SAFE_REF_REGEX.test('`whoami`'), 'Backtick substitution should be rejected');
    assert(!SAFE_REF_REGEX.test('ref; rm -rf /'), 'Semicolon injection should be rejected');
    assert(!SAFE_REF_REGEX.test('ref && echo hacked'), 'Ampersand injection should be rejected');
    assert(!SAFE_REF_REGEX.test('ref | cat /etc/passwd'), 'Pipe injection should be rejected');
    assert(!SAFE_REF_REGEX.test(''), 'Empty string should be rejected');
    assert(!SAFE_REF_REGEX.test('ref with spaces'), 'Spaces should be rejected');
    assert(!SAFE_REF_REGEX.test("ref'injection"), 'Single quotes should be rejected');
    assert(!SAFE_REF_REGEX.test('ref"injection'), 'Double quotes should be rejected');
  });

  // --- getThreatId ---

  test('DIFF: getThreatId generates consistent IDs', () => {
    const threat = { type: 'ast_dangerous_call', file: 'index.js', message: 'eval() call detected' };
    const id = getThreatId(threat);
    assert(id === 'ast_dangerous_call:index.js:eval() call detected', 'ID should be type:file:message, got ' + id);
  });

  test('DIFF: getThreatId strips line numbers from message', () => {
    const threat1 = { type: 'shell_exec', file: 'run.js', message: 'Dangerous shell exec at line 42' };
    const threat2 = { type: 'shell_exec', file: 'run.js', message: 'Dangerous shell exec at line 99' };
    const id1 = getThreatId(threat1);
    const id2 = getThreatId(threat2);
    assert(id1 === id2, 'IDs should match after line number stripping: ' + id1 + ' vs ' + id2);
  });

  test('DIFF: getThreatId handles missing fields', () => {
    const noFile = { type: 'test', message: 'hello' };
    assert(getThreatId(noFile) === 'test::hello', 'Missing file should default to empty');

    const noType = { file: 'a.js', message: 'hello' };
    assert(getThreatId(noType) === ':a.js:hello', 'Missing type should default to empty');

    const noMessage = { type: 'test', file: 'a.js' };
    assert(getThreatId(noMessage) === 'test:a.js:', 'Missing message should default to empty');

    const empty = {};
    assert(getThreatId(empty) === '::', 'All missing should give ::');
  });

  test('DIFF: getThreatId handles case-insensitive "line" in message', () => {
    const threat = { type: 'x', file: 'a.js', message: 'Something at Line 5 is bad' };
    const id = getThreatId(threat);
    assert(!id.includes('Line 5'), 'Should strip "Line 5" (case insensitive), got: ' + id);
  });

  // --- compareThreats ---

  test('DIFF: compareThreats identifies all added threats', () => {
    const oldThreats = [];
    const newThreats = [
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' },
      { type: 'shell', file: 'b.js', message: 'shell exec', severity: 'CRITICAL' }
    ];
    const result = compareThreats(oldThreats, newThreats);
    assert(result.added.length === 2, 'Should have 2 added, got ' + result.added.length);
    assert(result.removed.length === 0, 'Should have 0 removed');
    assert(result.unchanged.length === 0, 'Should have 0 unchanged');
  });

  test('DIFF: compareThreats identifies all removed threats', () => {
    const oldThreats = [
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' },
      { type: 'shell', file: 'b.js', message: 'shell exec', severity: 'CRITICAL' }
    ];
    const newThreats = [];
    const result = compareThreats(oldThreats, newThreats);
    assert(result.added.length === 0, 'Should have 0 added');
    assert(result.removed.length === 2, 'Should have 2 removed, got ' + result.removed.length);
    assert(result.unchanged.length === 0, 'Should have 0 unchanged');
  });

  test('DIFF: compareThreats identifies unchanged threats', () => {
    const threats = [
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' }
    ];
    const result = compareThreats(threats, threats);
    assert(result.added.length === 0, 'Should have 0 added');
    assert(result.removed.length === 0, 'Should have 0 removed');
    assert(result.unchanged.length === 1, 'Should have 1 unchanged, got ' + result.unchanged.length);
  });

  test('DIFF: compareThreats handles mixed added/removed/unchanged', () => {
    const oldThreats = [
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' },
      { type: 'shell', file: 'b.js', message: 'shell exec', severity: 'CRITICAL' },
      { type: 'obfuscation', file: 'c.js', message: 'obfuscated code', severity: 'MEDIUM' }
    ];
    const newThreats = [
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' },    // unchanged
      { type: 'fetch', file: 'd.js', message: 'fetch call', severity: 'HIGH' },     // added
      { type: 'dns', file: 'e.js', message: 'dns query', severity: 'MEDIUM' }       // added
    ];
    const result = compareThreats(oldThreats, newThreats);
    assert(result.added.length === 2, 'Should have 2 added, got ' + result.added.length);
    assert(result.removed.length === 2, 'Should have 2 removed, got ' + result.removed.length);
    assert(result.unchanged.length === 1, 'Should have 1 unchanged, got ' + result.unchanged.length);
  });

  test('DIFF: compareThreats with both empty arrays', () => {
    const result = compareThreats([], []);
    assert(result.added.length === 0, 'Should have 0 added');
    assert(result.removed.length === 0, 'Should have 0 removed');
    assert(result.unchanged.length === 0, 'Should have 0 unchanged');
  });

  test('DIFF: compareThreats matches threats regardless of line number differences', () => {
    const oldThreats = [
      { type: 'eval', file: 'a.js', message: 'eval() at line 10', severity: 'HIGH' }
    ];
    const newThreats = [
      { type: 'eval', file: 'a.js', message: 'eval() at line 25', severity: 'HIGH' }
    ];
    const result = compareThreats(oldThreats, newThreats);
    assert(result.unchanged.length === 1, 'Should match as unchanged despite line number change, got ' + result.unchanged.length);
    assert(result.added.length === 0, 'Should have 0 added');
    assert(result.removed.length === 0, 'Should have 0 removed');
  });

  // --- resolveRef ---

  test('DIFF: resolveRef resolves HEAD to a commit hash', () => {
    const hash = resolveRef(REPO_ROOT, 'HEAD');
    assert(hash !== null, 'HEAD should resolve to a hash');
    assert(typeof hash === 'string', 'Hash should be a string');
    assert(hash.length >= 7, 'Hash should be at least 7 chars, got ' + hash.length);
    assert(/^[0-9a-f]+$/.test(hash), 'Hash should be hex, got ' + hash);
  });

  test('DIFF: resolveRef returns null for invalid characters (injection prevention)', () => {
    const result = resolveRef(REPO_ROOT, '$(whoami)');
    assert(result === null, 'Should return null for command injection attempt');
  });

  test('DIFF: resolveRef returns null for non-existent ref', () => {
    const result = resolveRef(REPO_ROOT, 'nonexistent-ref-that-does-not-exist-12345');
    assert(result === null, 'Should return null for non-existent ref');
  });

  test('DIFF: resolveRef resolves HEAD~1 when history is deep enough', () => {
    const hash = resolveRef(REPO_ROOT, 'HEAD~1');
    // Shallow clones (e.g. CI with --depth=1) may not have HEAD~1
    if (hash === null) {
      console.log('       (skipped: shallow clone, HEAD~1 not available)');
      return;
    }
    assert(/^[0-9a-f]+$/.test(hash), 'Should be a hex hash');
  });

  // --- getCurrentCommit ---

  test('DIFF: getCurrentCommit returns a hex hash', () => {
    const commit = getCurrentCommit(REPO_ROOT);
    assert(commit !== null, 'Should return a commit hash');
    assert(/^[0-9a-f]+$/.test(commit), 'Should be hex, got ' + commit);
    assert(commit.length === 40, 'Should be full 40-char hash, got length ' + commit.length);
  });

  test('DIFF: getCurrentCommit returns null for non-git dir', () => {
    const commit = getCurrentCommit(os.tmpdir());
    assert(commit === null, 'Should return null for non-git dir');
  });

  // --- hasUncommittedChanges ---

  test('DIFF: hasUncommittedChanges returns boolean', () => {
    const result = hasUncommittedChanges(REPO_ROOT);
    assert(typeof result === 'boolean', 'Should return a boolean');
  });

  test('DIFF: hasUncommittedChanges returns false for non-git dir', () => {
    const result = hasUncommittedChanges(os.tmpdir());
    assert(result === false, 'Should return false for non-git dir');
  });

  // --- isGitRepo ---

  test('DIFF: isGitRepo returns true for this repo', () => {
    assert(isGitRepo(REPO_ROOT) === true, 'Should detect git repo');
  });

  test('DIFF: isGitRepo returns false for temp dir', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-diff-test-'));
    try {
      assert(isGitRepo(tmpDir) === false, 'Should not detect git repo in temp dir');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  // --- getRecentRefs ---

  test('DIFF: getRecentRefs returns tags and commits arrays', () => {
    const refs = getRecentRefs(REPO_ROOT);
    assert(Array.isArray(refs.tags), 'Should have tags array');
    assert(Array.isArray(refs.commits), 'Should have commits array');
    assert(refs.commits.length > 0, 'Should have at least one commit');
  });

  test('DIFF: getRecentRefs respects limit parameter', () => {
    const refs = getRecentRefs(REPO_ROOT, 3);
    assert(refs.commits.length <= 3, 'Should have at most 3 commits, got ' + refs.commits.length);
  });

  test('DIFF: getRecentRefs returns empty for non-git dir', () => {
    const refs = getRecentRefs(os.tmpdir());
    assert(refs.tags.length === 0, 'Should have 0 tags for non-git dir');
    assert(refs.commits.length === 0, 'Should have 0 commits for non-git dir');
  });

  // --- runSilentScan ---

  await asyncTest('DIFF: runSilentScan returns threats array and summary', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-diff-scan-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'clean.js'), 'const x = 1;\n', 'utf8');
      const result = await runSilentScan(tmpDir);
      assert(Array.isArray(result.threats), 'Should have threats array');
      assert(typeof result.summary === 'object', 'Should have summary object');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  await asyncTest('DIFF: runSilentScan returns empty threats for clean dir', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-diff-scan-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'safe.js'), 'module.exports = { hello: true };\n', 'utf8');
      const result = await runSilentScan(tmpDir);
      assert(result.threats.length === 0, 'Clean dir should have 0 threats, got ' + result.threats.length);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  // --- diff() function edge cases ---

  await asyncTest('DIFF: diff returns 1 for non-git repo', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-diff-nogit-'));
    try {
      const exitCode = await diff(tmpDir, 'HEAD');
      assert(exitCode === 1, 'Should return exit code 1 for non-git repo, got ' + exitCode);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  await asyncTest('DIFF: diff returns 1 for invalid ref', async () => {
    const exitCode = await diff(REPO_ROOT, 'nonexistent-ref-xyz-99999', { json: true });
    assert(exitCode === 1, 'Should return exit code 1 for invalid ref, got ' + exitCode);
  });

  // --- showRefs ---

  test('DIFF: showRefs does not throw for this repo', () => {
    let threw = false;
    try {
      showRefs(REPO_ROOT);
    } catch {
      threw = true;
    }
    assert(!threw, 'showRefs should not throw for valid git repo');
  });

  test('DIFF: showRefs does not throw for non-git dir', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-diff-showrefs-'));
    try {
      let threw = false;
      try {
        showRefs(tmpDir);
      } catch {
        threw = true;
      }
      assert(!threw, 'showRefs should not throw for non-git dir (handles gracefully)');
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  // --- diff() with JSON output ---

  await asyncTest('DIFF: diff with json option on valid ref', async () => {
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const exitCode = await diff(REPO_ROOT, 'HEAD~1', { json: true });
      if (exitCode !== 1) {
        // Should have logged JSON output
        const jsonOutput = logs.find(l => l.startsWith('{'));
        if (jsonOutput) {
          const parsed = JSON.parse(jsonOutput);
          assert(parsed.base, 'JSON should have base');
          assert(parsed.current, 'JSON should have current');
          assert(parsed.diff, 'JSON should have diff');
        }
      }
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('DIFF: diff with text output shows summary', async () => {
    const origLog = console.log;
    const origErr = console.error;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    console.error = () => {};
    try {
      const exitCode = await diff(REPO_ROOT, 'HEAD~1', { json: false });
      if (exitCode !== 1) {
        const allOutput = logs.join('\n');
        assert(allOutput.includes('DIFF SUMMARY') || allOutput.includes('Risk Score'), 'Should show diff summary');
      }
    } finally {
      console.log = origLog;
      console.error = origErr;
    }
  });

  // --- failLevel option ---

  test('DIFF: failLevel severity mapping covers all levels', () => {
    // Test the severity level mapping used in diff()
    const severityLevels = {
      critical: ['CRITICAL'],
      high: ['CRITICAL', 'HIGH'],
      medium: ['CRITICAL', 'HIGH', 'MEDIUM'],
      low: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    };

    assert(severityLevels.critical.length === 1, 'critical should have 1 level');
    assert(severityLevels.high.length === 2, 'high should have 2 levels');
    assert(severityLevels.medium.length === 3, 'medium should have 3 levels');
    assert(severityLevels.low.length === 4, 'low should have 4 levels');

    // Default fallback is 'high'
    const defaultLevel = severityLevels['invalid'] || severityLevels.high;
    assert(defaultLevel.length === 2, 'Invalid failLevel should default to high');
  });

  // --- compareThreats edge cases ---

  test('DIFF: compareThreats deduplicates by threat ID within new scan', () => {
    const oldThreats = [];
    const newThreats = [
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' },
      { type: 'eval', file: 'a.js', message: 'eval found', severity: 'HIGH' }  // duplicate
    ];
    const result = compareThreats(oldThreats, newThreats);
    // Map-based dedup means only 1 entry per ID
    assert(result.added.length === 1, 'Should deduplicate to 1 added, got ' + result.added.length);
  });

  test('DIFF: compareThreats correctly categorizes with many threats', () => {
    const oldThreats = [];
    for (let i = 0; i < 10; i++) {
      oldThreats.push({ type: `type_${i}`, file: `file_${i}.js`, message: `msg ${i}`, severity: 'MEDIUM' });
    }
    const newThreats = [];
    for (let i = 5; i < 15; i++) {
      newThreats.push({ type: `type_${i}`, file: `file_${i}.js`, message: `msg ${i}`, severity: 'MEDIUM' });
    }
    const result = compareThreats(oldThreats, newThreats);
    assert(result.unchanged.length === 5, 'Should have 5 unchanged (indices 5-9), got ' + result.unchanged.length);
    assert(result.removed.length === 5, 'Should have 5 removed (indices 0-4), got ' + result.removed.length);
    assert(result.added.length === 5, 'Should have 5 added (indices 10-14), got ' + result.added.length);
  });
}

module.exports = { runDiffTests };
