const fs = require('fs');
const path = require('path');
const {
  test, assert, assertIncludes
} = require('../test-utils');

async function runGvisorTests() {
  console.log('\n=== GVISOR SANDBOX TESTS ===\n');

  const {
    parseGvisorStrace,
    parseGvisorLog,
    parseGvisorLogs,
    findGvisorLogs,
    cleanupGvisorLogs,
    parseStraceLine,
    extractOpenatPath,
    extractConnectInfo,
    extractExecveCommand
  } = require('../../src/sandbox/gvisor-parser.js');

  const { isGvisorAvailable } = require('../../src/sandbox/index.js');

  // ── parseStraceLine ──

  test('GVISOR: parseStraceLine parses Go-log-prefixed format', () => {
    const line = 'D0331 12:34:56.789012       1 strace.go:587] [   1] node E openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3 (0.1ms)';
    const result = parseStraceLine(line);
    assert(result !== null, 'Should parse line');
    assert(result.pid === 1, 'PID should be 1, got ' + result.pid);
    assert(result.process === 'node', 'Process should be node, got ' + result.process);
    assert(result.syscall === 'openat', 'Syscall should be openat, got ' + result.syscall);
    assert(result.args.includes('/etc/passwd'), 'Args should contain path');
    assert(result.returnValue === '3', 'Return should be 3, got ' + result.returnValue);
  });

  test('GVISOR: parseStraceLine parses bare format (no Go prefix)', () => {
    const line = '[   1] python3 E connect(5, {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 16) = 0 (2.3ms)';
    const result = parseStraceLine(line);
    assert(result !== null, 'Should parse bare line');
    assert(result.pid === 1, 'PID should be 1');
    assert(result.process === 'python3', 'Process should be python3');
    assert(result.syscall === 'connect', 'Syscall should be connect');
    assert(result.returnValue === '0', 'Return should be 0');
  });

  test('GVISOR: parseStraceLine returns null for non-strace lines', () => {
    assert(parseStraceLine('Some random log line') === null, 'Random line should return null');
    assert(parseStraceLine('I0331 12:34:56.000000  1 sniffer.go:432] [SYN] 10.0.2.15:54321 > 1.2.3.4:80') === null, 'Packet log should return null');
    assert(parseStraceLine('') === null, 'Empty line should return null');
  });

  test('GVISOR: parseStraceLine handles error return values', () => {
    const line = '[   2] python3 E openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 (EACCES) (0.01ms)';
    const result = parseStraceLine(line);
    assert(result !== null, 'Should parse even failed syscalls');
    assert(result.returnValue.startsWith('-'), 'Return should be negative');
  });

  test('GVISOR: parseStraceLine handles microsecond durations', () => {
    const line = '[   1] node E read(3, 0x7f0000, 832) = 832 (21.084µs)';
    const result = parseStraceLine(line);
    assert(result !== null, 'Should parse µs duration');
    assert(result.returnValue === '832', 'Return should be 832');
  });

  // ── extractOpenatPath ──

  test('GVISOR: extractOpenatPath extracts path and flags (comma-separated)', () => {
    const result = extractOpenatPath('AT_FDCWD, "/home/user/.npmrc", O_RDONLY|O_CLOEXEC');
    assert(result !== null, 'Should extract');
    assert(result.path === '/home/user/.npmrc', 'Path should match');
    assert(result.flags.includes('O_RDONLY'), 'Flags should include O_RDONLY');
  });

  test('GVISOR: extractOpenatPath extracts write flags', () => {
    const result = extractOpenatPath('AT_FDCWD, "/root/.aws/credentials", O_WRONLY|O_CREAT, 0o644');
    assert(result !== null, 'Should extract');
    assert(result.path === '/root/.aws/credentials', 'Path should match');
    assert(result.flags.includes('O_WRONLY'), 'Flags should include O_WRONLY');
    assert(result.flags.includes('O_CREAT'), 'Flags should include O_CREAT');
  });

  test('GVISOR: extractOpenatPath returns null for unparseable args', () => {
    assert(extractOpenatPath('invalid args') === null, 'Should return null');
  });

  // ── extractConnectInfo ──

  test('GVISOR: extractConnectInfo extracts IP and port', () => {
    const result = extractConnectInfo('5, {Family: AF_INET, Addr: 45.11.59.250, Port: 443}, 16');
    assert(result !== null, 'Should extract');
    assert(result.ip === '45.11.59.250', 'IP should match');
    assert(result.port === 443, 'Port should be 443');
  });

  test('GVISOR: extractConnectInfo returns null for AF_INET6', () => {
    const result = extractConnectInfo('5, {Family: AF_INET6, Addr: ::1, Port: 8080}, 28');
    assert(result === null, 'Should return null for IPv6');
  });

  test('GVISOR: extractConnectInfo returns null for unparseable args', () => {
    assert(extractConnectInfo('invalid args') === null, 'Should return null');
  });

  // ── extractExecveCommand ──

  test('GVISOR: extractExecveCommand extracts command path', () => {
    const result = extractExecveCommand('"/usr/bin/curl", ["curl", "-X", "POST"], []');
    assert(result === '/usr/bin/curl', 'Should extract /usr/bin/curl');
  });

  test('GVISOR: extractExecveCommand returns null for empty args', () => {
    assert(extractExecveCommand('') === null, 'Should return null');
  });

  // ── parseGvisorStrace (full log parsing) ──

  test('GVISOR: parseGvisorStrace parses fixture log — sensitive reads', () => {
    const fixturePath = path.join(__dirname, '..', 'samples', 'gvisor', 'strace-sample.log');
    const content = fs.readFileSync(fixturePath, 'utf8');
    const result = parseGvisorStrace(content);

    const reads = result.sensitive_files.read;
    assert(reads.includes('/home/sandboxuser/.npmrc'), 'Should detect .npmrc read');
    assert(reads.includes('/home/sandboxuser/.ssh/id_rsa'), 'Should detect .ssh read');
    assert(reads.includes('/etc/passwd'), 'Should detect /etc/passwd read');
    assert(reads.includes('/home/sandboxuser/.env'), 'Should detect .env read');
    // /etc/shadow should NOT be included (return = -1 EACCES)
    assert(!reads.includes('/etc/shadow'), 'Should skip failed /etc/shadow read');
  });

  test('GVISOR: parseGvisorStrace parses fixture log — sensitive writes', () => {
    const fixturePath = path.join(__dirname, '..', 'samples', 'gvisor', 'strace-sample.log');
    const content = fs.readFileSync(fixturePath, 'utf8');
    const result = parseGvisorStrace(content);

    const writes = result.sensitive_files.written;
    assert(writes.includes('/home/sandboxuser/.aws/credentials'), 'Should detect .aws write');
    assert(writes.length === 1, 'Should have exactly 1 write, got ' + writes.length);
  });

  test('GVISOR: parseGvisorStrace parses fixture log — connections', () => {
    const fixturePath = path.join(__dirname, '..', 'samples', 'gvisor', 'strace-sample.log');
    const content = fs.readFileSync(fixturePath, 'utf8');
    const result = parseGvisorStrace(content);

    const conns = result.network.http_connections;
    const ips = conns.map(c => c.host);
    assert(ips.includes('45.11.59.250'), 'Should detect C2 IP');
    assert(ips.includes('93.184.216.34'), 'Should detect HTTP IP');
    assert(!ips.includes('127.0.0.1'), 'Should skip loopback');
    assert(!ips.includes('10.0.0.1'), 'Should skip probe port 65535');

    // Deduplication: 45.11.59.250:443 appears twice, should be deduped
    const c2Conns = conns.filter(c => c.host === '45.11.59.250');
    assert(c2Conns.length === 1, 'Should dedup duplicate connections, got ' + c2Conns.length);
  });

  test('GVISOR: parseGvisorStrace parses fixture log — processes', () => {
    const fixturePath = path.join(__dirname, '..', 'samples', 'gvisor', 'strace-sample.log');
    const content = fs.readFileSync(fixturePath, 'utf8');
    const result = parseGvisorStrace(content);

    const cmds = result.processes.spawned.map(p => p.command);
    assert(cmds.includes('/usr/bin/curl'), 'Should detect curl');
    assert(cmds.includes('/usr/bin/wget'), 'Should detect wget');
    // Safe processes should be excluded
    assert(!cmds.includes('/usr/local/bin/node'), 'Should skip node (safe)');
    assert(!cmds.includes('/usr/bin/npm'), 'Should skip npm (safe)');
  });

  // ── Output format parity with strace parser ──

  test('GVISOR: output format matches sandbox report structure — connections', () => {
    const content = '[   1] node E connect(5, {Family: AF_INET, Addr: 1.2.3.4, Port: 8080}, 16) = 0 (1ms)';
    const result = parseGvisorStrace(content);

    assert(Array.isArray(result.network.http_connections), 'http_connections should be array');
    assert(result.network.http_connections.length === 1, 'Should have 1 connection');
    const conn = result.network.http_connections[0];
    assert(conn.host === '1.2.3.4', 'host field should be IP string');
    assert(conn.port === 8080, 'port field should be number');
    assert(conn.protocol === 'TCP', 'protocol field should be TCP');
  });

  test('GVISOR: output format matches sandbox report structure — processes', () => {
    const content = '[   42] sh E execve("/usr/bin/curl", ["curl", "http://evil.com"], []) = 0 (1ms)';
    const result = parseGvisorStrace(content);

    assert(Array.isArray(result.processes.spawned), 'spawned should be array');
    assert(result.processes.spawned.length === 1, 'Should have 1 process');
    const proc = result.processes.spawned[0];
    assert(typeof proc.command === 'string', 'command should be string');
    assert(typeof proc.pid === 'number', 'pid should be number');
    assert(proc.command === '/usr/bin/curl', 'command should be /usr/bin/curl');
    assert(proc.pid === 42, 'pid should be 42');
  });

  test('GVISOR: output format matches sandbox report structure — sensitive files', () => {
    const content = '[   1] node E openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3 (0.1ms)';
    const result = parseGvisorStrace(content);

    assert(Array.isArray(result.sensitive_files.read), 'read should be array');
    assert(Array.isArray(result.sensitive_files.written), 'written should be array');
    assert(result.sensitive_files.read.length === 1, 'Should have 1 read');
    assert(result.sensitive_files.read[0] === '/root/.npmrc', 'Should be /root/.npmrc');
    assert(result.sensitive_files.written.length === 0, 'Should have 0 writes');
  });

  // ── Empty/edge cases ──

  test('GVISOR: parseGvisorStrace handles empty input', () => {
    const result = parseGvisorStrace('');
    assert(result.sensitive_files.read.length === 0, 'No reads');
    assert(result.sensitive_files.written.length === 0, 'No writes');
    assert(result.network.http_connections.length === 0, 'No connections');
    assert(result.processes.spawned.length === 0, 'No processes');
  });

  test('GVISOR: parseGvisorStrace handles all-noise input', () => {
    const content = 'I0331 12:00:00.000  1 boot.go:1] Starting gVisor\nSome random line\n\n';
    const result = parseGvisorStrace(content);
    assert(result.sensitive_files.read.length === 0, 'No reads');
    assert(result.network.http_connections.length === 0, 'No connections');
  });

  test('GVISOR: parseGvisorStrace skips non-sensitive file access', () => {
    const content = '[   1] node E openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3 (0.1ms)';
    const result = parseGvisorStrace(content);
    assert(result.sensitive_files.read.length === 0, 'ld.so.cache is not sensitive');
  });

  // ── parseGvisorLog (file-based) ──

  test('GVISOR: parseGvisorLog reads fixture file', () => {
    const fixturePath = path.join(__dirname, '..', 'samples', 'gvisor', 'strace-sample.log');
    const result = parseGvisorLog(fixturePath);
    assert(result.sensitive_files.read.length > 0, 'Should find sensitive reads');
    assert(result.network.http_connections.length > 0, 'Should find connections');
    assert(result.processes.spawned.length > 0, 'Should find processes');
  });

  test('GVISOR: parseGvisorLog returns empty for nonexistent file', () => {
    const result = parseGvisorLog('/nonexistent/path/gvisor.log');
    assert(result.sensitive_files.read.length === 0, 'No reads');
    assert(result.network.http_connections.length === 0, 'No connections');
    assert(result.processes.spawned.length === 0, 'No processes');
  });

  // ── findGvisorLogs ──

  test('GVISOR: findGvisorLogs returns empty for nonexistent directory', () => {
    const result = findGvisorLogs('abc123', '/nonexistent/path');
    assert(Array.isArray(result), 'Should return array');
    assert(result.length === 0, 'Should be empty for nonexistent dir');
  });

  test('GVISOR: findGvisorLogs finds logs in container ID directory', () => {
    // Create temporary fixture directory
    const tmpDir = path.join(__dirname, '..', 'samples', 'gvisor', 'tmp-runsc');
    const containerDir = path.join(tmpDir, 'abc123def456');
    fs.mkdirSync(containerDir, { recursive: true });
    fs.writeFileSync(path.join(containerDir, 'boot.log'), 'test');
    fs.writeFileSync(path.join(containerDir, 'gofer.log'), 'test');

    try {
      const result = findGvisorLogs('abc123def456', tmpDir);
      assert(result.length === 2, 'Should find 2 log files, got ' + result.length);
      assert(result.some(f => f.includes('boot.log')), 'Should find boot.log');
      assert(result.some(f => f.includes('gofer.log')), 'Should find gofer.log');
    } finally {
      // Cleanup
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('GVISOR: findGvisorLogs finds logs by truncated ID', () => {
    const tmpDir = path.join(__dirname, '..', 'samples', 'gvisor', 'tmp-runsc2');
    const shortDir = path.join(tmpDir, 'abc123def456');
    fs.mkdirSync(shortDir, { recursive: true });
    fs.writeFileSync(path.join(shortDir, 'boot.log'), 'test');

    try {
      // Pass full 64-char ID, should find via truncated 12-char
      const fullId = 'abc123def456' + '0'.repeat(52);
      const result = findGvisorLogs(fullId, tmpDir);
      assert(result.length === 1, 'Should find 1 log file via truncated ID, got ' + result.length);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ── cleanupGvisorLogs ──

  test('GVISOR: cleanupGvisorLogs removes container directory', () => {
    const tmpDir = path.join(__dirname, '..', 'samples', 'gvisor', 'tmp-cleanup');
    const containerDir = path.join(tmpDir, 'cleanup-test-id');
    fs.mkdirSync(containerDir, { recursive: true });
    fs.writeFileSync(path.join(containerDir, 'boot.log'), 'test');

    cleanupGvisorLogs('cleanup-test-id', tmpDir);
    assert(!fs.existsSync(containerDir), 'Container directory should be removed');

    // Cleanup parent if still exists
    if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('GVISOR: cleanupGvisorLogs handles nonexistent directory gracefully', () => {
    // Should not throw
    cleanupGvisorLogs('nonexistent-id', '/nonexistent/path');
  });

  // ── parseGvisorLogs (aggregated, multi-file) ──

  test('GVISOR: parseGvisorLogs aggregates across multiple log files', () => {
    const tmpDir = path.join(__dirname, '..', 'samples', 'gvisor', 'tmp-multi');
    const containerDir = path.join(tmpDir, 'multi-test');
    fs.mkdirSync(containerDir, { recursive: true });

    // Write two log files with different findings
    fs.writeFileSync(path.join(containerDir, 'boot.log'),
      '[   1] node E openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3 (0.1ms)\n' +
      '[   1] node E connect(5, {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 16) = 0 (1ms)\n'
    );
    fs.writeFileSync(path.join(containerDir, 'gofer.log'),
      '[   1] node E openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 4 (0.1ms)\n' +
      '[   1] node E connect(6, {Family: AF_INET, Addr: 5.6.7.8, Port: 80}, 16) = 0 (1ms)\n'
    );

    try {
      const result = parseGvisorLogs('multi-test', tmpDir);
      assert(result.sensitive_files.read.length === 2, 'Should aggregate 2 reads from 2 files, got ' + result.sensitive_files.read.length);
      assert(result.network.http_connections.length === 2, 'Should aggregate 2 connections, got ' + result.network.http_connections.length);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('GVISOR: parseGvisorLogs returns empty for unknown container', () => {
    const result = parseGvisorLogs('unknown-container-id', '/nonexistent');
    assert(result.sensitive_files.read.length === 0, 'No reads');
    assert(result.network.http_connections.length === 0, 'No connections');
    assert(result.processes.spawned.length === 0, 'No processes');
  });

  // ── Docker args verification (env var detection) ──

  test('GVISOR: MUADDIB_SANDBOX_RUNTIME env var detection', () => {
    const saved = process.env.MUADDIB_SANDBOX_RUNTIME;
    try {
      process.env.MUADDIB_SANDBOX_RUNTIME = 'gvisor';
      assert(process.env.MUADDIB_SANDBOX_RUNTIME === 'gvisor', 'Should read gvisor');

      delete process.env.MUADDIB_SANDBOX_RUNTIME;
      assert(process.env.MUADDIB_SANDBOX_RUNTIME === undefined, 'Should be undefined when not set');
    } finally {
      if (saved) process.env.MUADDIB_SANDBOX_RUNTIME = saved;
      else delete process.env.MUADDIB_SANDBOX_RUNTIME;
    }
  });

  test('GVISOR: isGvisorAvailable returns boolean', () => {
    const result = isGvisorAvailable();
    assert(typeof result === 'boolean', 'Should return boolean');
    // Can't assert true/false since it depends on the test environment
    // In CI without Docker/gVisor, this returns false — which is correct
  });

  // ── Strace NOT launched in gVisor mode (sandbox-runner.sh logic) ──

  test('GVISOR: sandbox-runner.sh has MUADDIB_GVISOR guard for strace', () => {
    const runnerPath = path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh');
    const content = fs.readFileSync(runnerPath, 'utf8');
    // Verify the gVisor guards exist
    assertIncludes(content, 'MUADDIB_GVISOR', 'sandbox-runner.sh should reference MUADDIB_GVISOR');
    assertIncludes(content, 'gVisor mode', 'Should have gVisor mode comments');
    // Verify strace is skipped in gVisor mode
    assertIncludes(content, 'if [ -n "$MUADDIB_GVISOR" ]', 'Should have gVisor check before strace');
  });

  test('GVISOR: sandbox-runner.sh skips tcpdump in gVisor mode', () => {
    const runnerPath = path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh');
    const content = fs.readFileSync(runnerPath, 'utf8');
    // Verify tcpdump is guarded by gVisor check
    assertIncludes(content, 'if [ -z "$MUADDIB_GVISOR" ]', 'Should have gVisor skip for tcpdump');
    assertIncludes(content, 'log-packets', 'Should mention --log-packets as alternative');
  });

  // ── index.js gVisor integration ──

  test('GVISOR: index.js exports isGvisorAvailable', () => {
    const sandbox = require('../../src/sandbox/index.js');
    assert(typeof sandbox.isGvisorAvailable === 'function', 'Should export isGvisorAvailable');
  });

  test('GVISOR: gvisor-parser.js exports all required functions', () => {
    const parser = require('../../src/sandbox/gvisor-parser.js');
    assert(typeof parser.parseGvisorLog === 'function', 'Should export parseGvisorLog');
    assert(typeof parser.parseGvisorLogs === 'function', 'Should export parseGvisorLogs');
    assert(typeof parser.parseGvisorStrace === 'function', 'Should export parseGvisorStrace');
    assert(typeof parser.findGvisorLogs === 'function', 'Should export findGvisorLogs');
    assert(typeof parser.cleanupGvisorLogs === 'function', 'Should export cleanupGvisorLogs');
  });

  // ── install-gvisor.sh exists and has correct content ──

  test('GVISOR: install-gvisor.sh exists and is complete', () => {
    const scriptPath = path.join(__dirname, '..', '..', 'scripts', 'install-gvisor.sh');
    assert(fs.existsSync(scriptPath), 'install-gvisor.sh should exist');
    const content = fs.readFileSync(scriptPath, 'utf8');
    assertIncludes(content, '#!/bin/bash', 'Should have bash shebang');
    assertIncludes(content, 'runsc', 'Should reference runsc');
    assertIncludes(content, 'sha512sum', 'Should verify checksum');
    assertIncludes(content, '--strace', 'Should configure --strace');
    assertIncludes(content, '--log-packets', 'Should configure --log-packets');
    assertIncludes(content, '--runtime=runsc', 'Should verify with docker run');
    assertIncludes(content, 'MUADDIB_SANDBOX_RUNTIME', 'Should mention env var');
  });
}

module.exports = { runGvisorTests };
