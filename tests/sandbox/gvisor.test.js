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

  // ── Real runsc format (release-20260323.0, tests/samples/gvisor/runsc-20260323-*.log) ──

  const FIXTURE_DIR = path.join(__dirname, '..', 'samples', 'gvisor');
  const BEHAV = fs.readFileSync(path.join(FIXTURE_DIR, 'runsc-20260323-behav.log'), 'utf8');
  const behavLine = (re) => BEHAV.split('\n').find(l => re.test(l));

  test('GVISOR: parseStraceLine reads a real runsc exit line (non-blocking connect = errno 115, ret 0)', () => {
    const ev = parseStraceLine(behavLine(/X connect\(.*192\.0\.2\.10/));
    assert(ev && ev.tgid === 4 && ev.tid === 4 && ev.comm === 'MainThread' && ev.phase === 'X' && ev.syscall === 'connect',
      'prefix, comm and syscall must be read, got ' + JSON.stringify(ev));
    assert(ev.ret === 0 && ev.errno === 115, 'runsc prints a failed syscall as "= 0 (0x0) errno=N": errno must be kept, got ' + JSON.stringify(ev));
  });

  test('GVISOR: parseStraceLine keeps a failed open as an error (= 0 (0x0) errno=2), not a success', () => {
    const ev = parseStraceLine(behavLine(/X openat\(.*\.ssh\/id_rsa/));
    assert(ev && ev.errno === 2 && ev.ret === 0, 'got ' + JSON.stringify(ev));
  });

  test('GVISOR: parseStraceLine reads a task name with spaces (npm sets "npm install exp")', () => {
    const line = 'I1121 23:46:30.140447       1 strace.go:605] [  11:  11] npm install exp X connect(0x15 socket:[24], 0x7efdb8364e60 {Family: AF_INET, Addr: 104.16.10.34, Port: 443}, 0x10) = 0 (0x0) errno=115 (operation now in progress) (77.12µs)';
    const ev = parseStraceLine(line);
    assert(ev && ev.comm === 'npm install exp' && ev.syscall === 'connect' && ev.tgid === 11, 'got ' + JSON.stringify(ev));
  });

  test('GVISOR: a task name that imitates a syscall marker does not hide the real syscall', () => {
    // Same real line, task name replaced by a 15-byte name that spells " X execve(".
    const real = behavLine(/X connect\(.*192\.0\.2\.10/);
    const forged = real.replace('] MainThread X connect(', '] ab X execve(zz X connect(');
    const ev = parseStraceLine(forged);
    assert(ev && ev.syscall === 'connect' && ev.comm === 'ab X execve(zz', 'the marker after the (<= 15 byte) name must win, got ' + JSON.stringify(ev));
  });

  test('GVISOR: the old made-up format is not accepted as a syscall line', () => {
    assert(parseStraceLine('[   1] node E openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3 (0.1ms)') === null, 'fictional format must not parse');
    assert(parseStraceLine('I1121 23:46:26.500657       1 boot.go:306] Setting product_name: "x"') === null, 'non-strace line');
  });

  test('GVISOR: extractOpenatPath reads the unquoted path and flags; a relative path gets its directory fd', () => {
    const ev = parseStraceLine(behavLine(/X openat\(.*\/etc\/passwd/));
    const info = extractOpenatPath(ev.args, 'openat');
    assert(info && info.path === '/etc/passwd' && /^O_RDONLY/.test(info.flags), 'got ' + JSON.stringify(info));
    const rel = extractOpenatPath('0x5 /home/sandboxuser/.ssh, 0x7f00 id_rsa, O_RDONLY|O_CLOEXEC, 0o0', 'openat');
    assert(rel && rel.path === '/home/sandboxuser/.ssh/id_rsa', 'openat(<fd of ~/.ssh>, "id_rsa") must resolve, got ' + JSON.stringify(rel));
    const flags0 = extractOpenatPath('AT_FDCWD /tmp, 0x7eb7c4761669 /etc/os-release, O_RDONLY|0x0, 0o0', 'openat');
    assert(flags0 && flags0.path === '/etc/os-release', 'flags written "O_RDONLY|0x0" (real cat line) must parse, got ' + JSON.stringify(flags0));
  });

  test('GVISOR: extractExecveCommand reads path and argv; a path that embeds ", 0x1 [" is not cut short', () => {
    const ev = parseStraceLine(behavLine(/X execve\(.*\/usr\/bin\/cat/));
    const cmd = extractExecveCommand(ev.args, 'execve');
    assert(cmd && cmd.path === '/usr/bin/cat' && cmd.argv[0] === 'cat', 'got ' + JSON.stringify(cmd));
    const trap = extractExecveCommand('0x1000 /tmp/node, 0x1 [x, 0x2000 ["evil"], 0x3000 ["PATH=/bin"]', 'execve');
    assert(trap && trap.path === '/tmp/node, 0x1 [x', 'a binary named "/tmp/node, 0x1 [x" must not read as node, got ' + JSON.stringify(trap));
    const flood = extractExecveCommand('0x1000 ' + '/a, 0x1 ['.repeat(400) + '/tmp/node, 0x2000 ["x"], 0x3000 ["PATH=/bin"]', 'execve');
    assert(flood && path.basename(flood.path) !== 'node', 'past the bounded number of split attempts the path must fail closed (not read as node), got ' + JSON.stringify(flood && flood.path.slice(-40)));
  });

  test('GVISOR: extractConnectInfo reads IPv4 address and port', () => {
    const ev = parseStraceLine(behavLine(/X connect\(.*192\.0\.2\.10/));
    const c = extractConnectInfo(ev.args);
    assert(c && c.ip === '192.0.2.10' && c.port === 443, 'got ' + JSON.stringify(c));
    assert(extractConnectInfo('0x3 socket:[1], 0x7e {Family: AF_UNIX, Addr: "/dev/log"}, 0x6e') === null, 'AF_UNIX is not a network connection');
  });

  // ── Whole real trace: only the package's processes (the subtree under su) count ──

  test('GVISOR: real trace - what the program under su did is reported', () => {
    const r = parseGvisorStrace(BEHAV);
    assert(r.scoped === true && r.straceLines > 100, 'the su subtree must be found, got ' + JSON.stringify({ scoped: r.scoped, lines: r.straceLines }));
    const reads = r.sensitive_files.read;
    assert(reads.some(f => /\/\.npmrc$/.test(f)), 'the program read of <home>/.npmrc must be reported, got ' + JSON.stringify(reads));
    assert(reads.includes('/etc/passwd'), 'the program read of /etc/passwd must be reported');
    assert(r.sensitive_files.written.some(f => /\/\.npmrc$/.test(f)), 'the program write of .npmrc must be reported');
    assert(!reads.some(f => /id_rsa/.test(f)), 'a failed open (errno=2) must not count as a read');
    const conns = r.network.http_connections.map(c => `${c.host}:${c.port}`);
    assert(conns.length === 1 && conns[0] === '192.0.2.10:443', 'the in-progress connect must count, loopback must not, got ' + JSON.stringify(conns));
    assert(r.processes.spawned.some(p => p.command === '/usr/bin/cat'), 'the grandchild cat must be reported');
  });

  test('GVISOR: real trace - su itself (reads /etc/shadow, connects to nscd) is out of scope', () => {
    assert(/\] su X openat\(.*\/etc\/shadow/.test(BEHAV) || /\] su X openat\(.*\/etc\/passwd/.test(BEHAV), 'fixture precondition: su opens account files');
    const r = parseGvisorStrace(BEHAV);
    assert(!r.sensitive_files.read.includes('/etc/shadow'), 'su reading /etc/shadow is the runner, not the package');
    assert(!r.processes.spawned.some(p => /\/su$/.test(p.command)), 'su is the runner');
  });

  test('GVISOR: real trace without clone/fork lines - no scope, nothing reported, trace unusable', () => {
    const noClone = BEHAV.split('\n').filter(l => !/ X (clone|clone3|fork|vfork)\(/.test(l)).join('\n');
    const r = parseGvisorStrace(noClone);
    assert(r.scoped === false, 'without clone exits the su child cannot be tied to su');
    assert(r.sensitive_files.read.length === 0 && r.network.http_connections.length === 0, 'nothing may be attributed without a scope');
  });

  test('GVISOR: busybox su (execs the shell in place, no fork) - the shell is still a root', () => {
    // Real lines, re-attributed: tgid 2 execs su, then execs /bin/sh itself (busybox su),
    // then the program (tgid 4) runs as its child exactly as in the fixture.
    const lines = BEHAV.split('\n');
    const suExec = lines.find(l => /\[   2:   2\] sh X execve\(.*\/usr\/bin\/su/.test(l));
    const suReadsPasswd = lines.find(l => /\[   2:   2\] su X openat\(.*\/etc\/passwd/.test(l)); // su runs before it execs the shell
    const shExec = lines.find(l => /\[   3:   3\] su X execve\(.*\/bin\/sh/.test(l)).replace('[   3:   3] su X', '[   2:   2] su X');
    const rest = lines.filter(l => /\[   [4-9]:|\[  1[0-9]:/.test(l));
    const vfork = lines.find(l => /\[   3:   3\] sh X vfork\(\) = 4/.test(l)).replace('[   3:   3]', '[   2:   2]');
    const r = parseGvisorStrace([suExec, suReadsPasswd, shExec, vfork, ...rest].join('\n'));
    assert(r.scoped === true, 'a shell exec\'d by the su image itself must be a root');
    assert(r.network.http_connections.some(c => c.host === '192.0.2.10'), 'the program under it must be in scope');
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

  // ── Real installs with the runner's lineage (root writes the honeytoken, su shell runs npm) ──
  {
    const zlib = require('zlib');
    const { scoreFindings } = require('../../src/sandbox/index.js');
    const load = (name) => zlib.gunzipSync(fs.readFileSync(path.join(FIXTURE_DIR, name))).toString('utf8');
    // The registry IP the sandbox resolver would have answered: the run.sh argument in the trace.
    const regIp = (trace) => (trace.match(/FX_REG_IP=(\d+\.\d+\.\d+\.\d+)/) || trace.match(/\/usr\/bin\/npm (\d+\.\d+\.\d+\.\d+)/))[1];
    const score = (trace, withSafe) => {
      const r = parseGvisorStrace(trace);
      const network = { http_connections: r.network.http_connections };
      if (withSafe) network.safe_dns_resolutions = [{ domain: 'registry.npmjs.org', ip: regIp(trace) }];
      return { parsed: r, scored: scoreFindings({ sensitive_files: r.sensitive_files, network, processes: r.processes }) };
    };
    const INSTALLS = {
      express: load('runsc-20260323-install-express.log.gz'),
      esbuild: load('runsc-20260323-install-esbuild.log.gz'),
      sharp: load('runsc-20260323-install-sharp.log.gz')
    };

    test('GVISOR: real express install - registry connects and npm\'s own ~/.npmrc read score 0', () => {
      const t = INSTALLS.express;
      assert((t.match(/ X connect\(.*AF_INET, Addr: /g) || []).length >= 10, 'fixture precondition: npm connects to the registry many times');
      assert(/\] libuv-worker X openat\(.*\/tmp\/fxw\/\.npmrc, O_RDONLY.*= \d+ \(0x[0-9a-f]+\) \(/.test(t), 'fixture precondition: npm reads the honeytoken .npmrc successfully');
      const { parsed, scored } = score(t, true);
      assert(parsed.scoped && parsed.sensitive_files.read.length === 0, 'the root npm config read is not the package, got ' + JSON.stringify(parsed.sensitive_files));
      assert(parsed.sensitive_files.written.length === 0, 'the honeytoken written by root (runner) is out of scope');
      assert(scored.score === 0, 'a plain registry install must score 0, got ' + JSON.stringify(scored));
      assert(score(t, false).scored.score === 25, 'the same connects with no safe resolution must still be flagged');
    });

    test('GVISOR: real installs with an install script stay under the alert threshold (esbuild, sharp: 15)', () => {
      const es = score(INSTALLS.esbuild, true).scored;
      assert(es.score === 15 && es.findings.length === 1 && /node_modules\/esbuild\/bin\/esbuild$/.test(es.findings[0].evidence), 'esbuild postinstall runs its own binary, got ' + JSON.stringify(es));
      const sh = score(INSTALLS.sharp, true).scored;
      assert(sh.score === 15 && sh.findings.length === 1 && sh.findings[0].evidence === '/usr/bin/which', 'sharp install/check runs which, got ' + JSON.stringify(sh));
    });

    // A process finding says what ran it: the image that ran just before the exec (the
    // process itself before an in-place exec, else its parent), with the script for node,
    // and the first arguments, bounded (both chosen by the package).
    const spawnedOf = (trace, re) => parseGvisorStrace(trace).processes.spawned.find(p => re.test(p.command));

    test('GVISOR: real trace - a process records its launcher and arguments (sharp: sh runs which brew)', () => {
      const p = spawnedOf(INSTALLS.sharp, /\/usr\/bin\/which$/);
      assert(p && p.launcher === 'sh', 'launcher should be sh, got ' + JSON.stringify(p));
      assert(JSON.stringify(p.argv) === JSON.stringify(['which', 'brew']), 'argv should be which brew, got ' + JSON.stringify(p && p.argv));
    });

    test('GVISOR: real trace - a node launcher is named with its script (esbuild: node install.js)', () => {
      const p = spawnedOf(INSTALLS.esbuild, /esbuild\/bin\/esbuild$/);
      assert(p && p.launcher === 'node install.js', 'launcher should be node install.js, got ' + JSON.stringify(p));
      assert(p.argv[1] === '--version', 'got ' + JSON.stringify(p.argv));
    });

    test('GVISOR: real trace - recorded arguments are bounded (4 arguments, 60 characters each)', () => {
      const long = '"' + 'a'.repeat(300) + '"';
      // Both the syscall entry (E) and exit (X) lines carry the argv: replace every occurrence.
      const t = INSTALLS.sharp.replace(/(\/usr\/bin\/which, 0x[0-9a-f]+ )\["which", "brew"\]/g, `$1["which", ${Array(9).fill(long).join(', ')}]`);
      const p = spawnedOf(t, /\/usr\/bin\/which$/);
      assert(p && p.argv.length === 4 && p.argv.every(a => a.length <= 60), 'got ' + JSON.stringify(p && p.argv.map(a => a.length)));
    });

    test('GVISOR: process findings carry the launcher and arguments as context; the score is unchanged', () => {
      const sh = score(INSTALLS.sharp, true).scored;
      assert(sh.score === 15 && sh.findings[0].context === 'launched by sh; argv: which brew', 'got ' + JSON.stringify(sh.findings));
      const bare = scoreFindings({ processes: { spawned: [{ command: '/usr/bin/python3', pid: 1 }] } });
      assert(bare.score === 40 && bare.findings[0].context === undefined, 'no launcher recorded (runc mode): no context, got ' + JSON.stringify(bare.findings));
    });

    test('GVISOR: real trace - failed execs of a PATH search (printed "= 0", no errno) are not processes', () => {
      const t = INSTALLS.express;
      assert(/X execve\(0x[0-9a-f]+ \/usr\/local\/sbin\/env, .*\) = 0 \(0x0\) \(/.test(t), 'fixture precondition: the failed attempt is printed as a success');
      const cmds = parseGvisorStrace(t).processes.spawned.map(p => p.command);
      assert(!cmds.includes('/usr/local/sbin/env') && !cmds.includes('/usr/local/bin/env') && !cmds.includes('/usr/sbin/env'), 'PATH attempts must not be processes, got ' + JSON.stringify(cmds));
      assert(cmds.includes('/usr/bin/env') && cmds.includes('/usr/bin/timeout'), 'the exec that took effect must remain, got ' + JSON.stringify(cmds));
    });

    test('GVISOR: the root npm reading ~/.gitconfig (its own config load, production trace) is not counted; a nested npm is', () => {
      // Real lines, re-attributed: the npm process's real ~/.npmrc read, repeated for the
      // ~/.gitconfig honeytoken (npm 11 reads it on every install in production traces).
      const withGitconfig = (trace) => trace.split('\n').flatMap(l =>
        /libuv-worker X openat\(.*\/\.npmrc, O_RDONLY.*= \d+ \(0x[0-9a-f]+\) \(/.test(l) ? [l, l.replace('/.npmrc,', '/.gitconfig,')] : [l]).join('\n');
      const root = parseGvisorStrace(withGitconfig(INSTALLS.express));
      assert(!root.sensitive_files.read.some(f => /\.gitconfig$/.test(f)), 'the root npm config read must not count, got ' + JSON.stringify(root.sensitive_files.read));
      const nested = parseGvisorStrace(withGitconfig(load('runsc-20260323-nested-npm-express.log.gz')));
      assert(nested.sensitive_files.read.some(f => /\.gitconfig$/.test(f)), 'an npm below the root must have its .gitconfig read counted, got ' + JSON.stringify(nested.sensitive_files.read));
    });

    test('GVISOR: real trace - npm NOT started by the su shell (as by an install script) has its ~/.npmrc read counted', () => {
      const t = load('runsc-20260323-nested-npm-express.log.gz');
      const { parsed, scored } = score(t, true);
      assert(parsed.sensitive_files.read.some(f => /\/\.npmrc$/.test(f)), 'npm started below the root (npm config get in a script reads the token) must be reported, got ' + JSON.stringify(parsed.sensitive_files));
      assert(scored.findings.some(f => f.type === 'sensitive_file_read' && f.severity === 'CRITICAL'), 'got ' + JSON.stringify(scored.findings));
    });
  }

  // ── parseGvisorLogs (aggregated, multi-file) ──

  const withLogDir = (name, files, fn) => {
    const tmpDir = path.join(__dirname, '..', 'samples', 'gvisor', 'tmp-' + name);
    const containerDir = path.join(tmpDir, name);
    fs.mkdirSync(containerDir, { recursive: true });
    for (const [file, content] of Object.entries(files)) fs.writeFileSync(path.join(containerDir, file), content);
    try { return fn(tmpDir, name); } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
  };

  test('GVISOR: parseGvisorLogs reads a real trace next to an empty gofer log', () => {
    withLogDir('agg', { 'runsc.log.boot.txt': BEHAV, 'gofer.log': '' }, (dir, id) => {
      const r = parseGvisorLogs(id, dir);
      assert(r.logFiles === 2, 'logFiles should count the 2 trace logs, got ' + r.logFiles);
      assert(r.straceLines > 100 && r.scoped === true && r.unusable === null, 'got ' + JSON.stringify({ l: r.straceLines, s: r.scoped, u: r.unusable }));
      assert(r.network.http_connections.length === 1, 'got ' + JSON.stringify(r.network.http_connections));
    });
  });

  test('GVISOR: parseGvisorLogs returns empty for unknown container', () => {
    const result = parseGvisorLogs('unknown-container-id', '/nonexistent');
    assert(result.sensitive_files.read.length === 0, 'No reads');
    assert(result.network.http_connections.length === 0, 'No connections');
    assert(result.processes.spawned.length === 0, 'No processes');
    assert(result.logFiles === 0, 'logFiles must be 0 when no trace log exists (absence of telemetry, not an empty observation), got ' + result.logFiles);
  });

  test('GVISOR: a non-empty log with no recognized syscall line is unusable (unknown format), not clean', () => {
    const fictional = '[   1] node E openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3 (0.1ms)\n[   1] node E connect(5, {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 16) = 0 (1ms)\n';
    withLogDir('fmt', { 'boot.log': fictional }, (dir, id) => {
      const r = parseGvisorLogs(id, dir);
      assert(r.logFiles === 1 && r.straceLines === 0, 'got ' + JSON.stringify({ f: r.logFiles, l: r.straceLines }));
      assert(/unknown runsc strace format/.test(r.unusable || ''), 'unknown format must be reported, got ' + r.unusable);
    });
  });

  test('GVISOR: a real trace without clone/fork (old --strace-syscalls) is unusable: no package process tree', () => {
    const noClone = BEHAV.split('\n').filter(l => !/ X (clone|clone3|fork|vfork)\(/.test(l)).join('\n');
    withLogDir('noclone', { 'boot.log': noClone }, (dir, id) => {
      const r = parseGvisorLogs(id, dir);
      assert(r.straceLines > 0 && /no package process tree/.test(r.unusable || ''), 'got ' + r.unusable);
    });
  });

  // ── scoreFindings: registry traffic seen by runsc is not a suspicious connection ──
  {
    const { scoreFindings } = require('../../src/sandbox/index.js');
    const conns = parseGvisorStrace(BEHAV).network.http_connections; // [192.0.2.10:443] from the real trace

    test('SANDBOX: a connection to an IP the sandbox resolver returned for a safe domain scores 0', () => {
      const r = scoreFindings({ network: { http_connections: conns, safe_dns_resolutions: [{ domain: 'registry.npmjs.org', ip: '192.0.2.10' }] } });
      assert(r.score === 0 && r.findings.length === 0, 'registry download must not score, got ' + JSON.stringify(r));
    });

    test('SANDBOX: a connection to an IP never resolved for a safe domain is still flagged', () => {
      const none = scoreFindings({ network: { http_connections: conns, safe_dns_resolutions: [] } });
      assert(none.score === 25 && none.findings[0].type === 'suspicious_connection', 'got ' + JSON.stringify(none));
      const other = scoreFindings({ network: { http_connections: conns, safe_dns_resolutions: [{ domain: 'registry.npmjs.org', ip: '192.0.2.11' }] } });
      assert(other.score === 25, 'another IP of the registry does not cover this one, got ' + other.score);
    });

    test('SANDBOX: the safe-IP exemption needs a domain the host classifies safe, and port 80/443', () => {
      const unsafe = scoreFindings({ network: { http_connections: conns, safe_dns_resolutions: [{ domain: 'collector.example', ip: '192.0.2.10' }] } });
      assert(unsafe.score === 25, 'a resolver entry for a non-safe domain must not exempt (the host re-checks), got ' + unsafe.score);
      const port = scoreFindings({ network: { http_connections: [{ host: '192.0.2.10', port: 22, protocol: 'TCP' }], safe_dns_resolutions: [{ domain: 'github.com', ip: '192.0.2.10' }] } });
      assert(port.score === 25, 'only 80/443 are exempt, got ' + port.score);
      const mock = scoreFindings({ network: { http_connections: [{ host: '127.0.0.2', port: 443, protocol: 'TCP' }], dns_resolutions: [{ domain: 'evil.example', ip: '127.0.0.2' }] } });
      assert(mock.score === 25, 'a mock answer for a non-safe domain must not exempt, got ' + mock.score);
    });
  }

  // ── incompleteRunReasons: an unusable trace makes a score-0 run INCONCLUSIVE ──
  {
    const { incompleteRunReasons } = require('../../src/sandbox/index.js');
    test('SANDBOX: an unusable gVisor trace (unknown format) is an incomplete run, with its reason as evidence', () => {
      const r = incompleteRunReasons({ exit_code: 0, install_output: 'added 1 package', entrypoint_output: '' }, { telemetryUnusable: 'runsc trace log present but no syscall line recognized (unknown runsc strace format)' });
      assert(r && /gVisor trace unusable/.test(r.reasons[0]) && /unknown runsc strace format/.test(r.evidence), 'got ' + JSON.stringify(r));
    });

    test('SANDBOX: each incomplete-run reason has a stable code (one journal line per run is built from them)', () => {
      const all = incompleteRunReasons({ exit_code: 1, install_output: 'npm error code E404', entrypoint_output: '[ENTRY_ERROR] MODULE_NOT_FOUND' }, { telemetryMissing: true });
      assert(all && all.kinds.join(',') === 'install_failed,entry_failed,trace_missing', 'got ' + JSON.stringify(all && all.kinds));
      const unusable = incompleteRunReasons({ exit_code: 0, entrypoint_output: '' }, { telemetryUnusable: 'x' });
      assert(unusable && unusable.kinds.join(',') === 'trace_unusable', 'got ' + JSON.stringify(unusable && unusable.kinds));
    });
  }

  // ── incompleteRunReasons: a score-0 run that observed nothing is not a CLEAN verdict ──
  {
    const { incompleteRunReasons } = require('../../src/sandbox/index.js');
    const okReport = { exit_code: 0, install_output: 'added 1 package in 3s', entrypoint_output: '' };

    test('SANDBOX: a run with no gVisor trace log is incomplete even when install and entry point succeeded', () => {
      const r = incompleteRunReasons(okReport, { telemetryMissing: true });
      assert(r && r.reasons.length === 1 && /no gVisor trace log/.test(r.reasons[0]),
        'telemetryMissing must make the run incomplete, got ' + JSON.stringify(r));
    });

    test('SANDBOX: a usable run (install ok, entry point ok, telemetry present) is not incomplete', () => {
      assert(incompleteRunReasons(okReport, { telemetryMissing: false }) === null, 'a usable run must return null');
      assert(incompleteRunReasons(okReport) === null, 'no context = telemetry not known missing = null');
    });

    test('SANDBOX: npm >= 10 "npm error code E404" is recognized as an install failure', () => {
      const r = incompleteRunReasons({ exit_code: 1, install_output: 'npm error code E404\nnpm error 404 Not Found - GET https://registry.npmjs.org/nope', entrypoint_output: '' });
      assert(r && /npm install failed \(exit 1\)/.test(r.reasons[0]), 'npm 10/11 output format must be recognized, got ' + JSON.stringify(r));
    });

    test('SANDBOX: any failed npm install (non-zero exit, e.g. EACCES or a failing install script) is incomplete', () => {
      const eacces = incompleteRunReasons({ exit_code: 243, install_output: 'npm error code EACCES\nnpm error syscall mkdir', entrypoint_output: '' });
      assert(eacces && /npm install failed \(exit 243\)/.test(eacces.reasons[0]), 'EACCES install must be incomplete, got ' + JSON.stringify(eacces));
      const script = incompleteRunReasons({ exit_code: 1, install_output: 'npm error command sh -c node setup.mjs\nnpm error ENOSPC: no space left on device, write', entrypoint_output: '' });
      assert(script && /npm install failed \(exit 1\)/.test(script.reasons[0]) && /ENOSPC/.test(script.evidence), 'a failing install script must be incomplete with its evidence, got ' + JSON.stringify(script));
    });

    test('SANDBOX: legacy "npm ERR! code ETARGET" is still recognized', () => {
      const r = incompleteRunReasons({ exit_code: 1, install_output: 'npm ERR! code ETARGET\nnpm ERR! notarget No matching version', entrypoint_output: '' });
      assert(r && /npm install failed/.test(r.reasons[0]), 'npm <= 9 format must still be recognized, got ' + JSON.stringify(r));
    });

    test('SANDBOX: entry point failure is reported with its evidence', () => {
      const r = incompleteRunReasons({ exit_code: 0, install_output: 'added 1 package', entrypoint_output: "[ENTRY_ERROR] MODULE_NOT_FOUND: Cannot find module 'x'" });
      assert(r && r.reasons[0] === 'Entry point require() failed' && /MODULE_NOT_FOUND/.test(r.evidence), 'entry error must be reported, got ' + JSON.stringify(r));
    });
  }

  // ── Docker args verification (env var detection) ──

  // (Removed 'MUADDIB_SANDBOX_RUNTIME env var detection' — it set and read process.env, testing
  // Node's own env object, not any MUAD'DIB code. The real runtime decision is covered by the
  // GVISOR M3 resolveSandboxRuntime tests below, which pass the env in as a pure input.)

  test('GVISOR: isGvisorAvailable returns boolean (smoke — real docker info probe, memoized, no seam)', () => {
    // isGvisorAvailable parses `docker info` for /runsc/ and memoizes the result. The exec is
    // internal and non-injectable, and the cache means it cannot be re-driven per test — so we
    // assert only the type contract. The env-driven decision logic is fully tested via
    // resolveSandboxRuntime (pure, below). In CI without Docker/gVisor this returns false.
    const result = isGvisorAvailable();
    assert(typeof result === 'boolean', 'Should return boolean');
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

  // (Removed two export-only tests — 'index.js exports isGvisorAvailable' and 'gvisor-parser.js
  // exports all required functions'. Every one of those symbols is destructured at the top of
  // this file (lines 10-22) and behaviorally exercised by the tests above; a missing export
  // would already throw at import time, so the assertions could never independently fail.)

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

  // ── M3 (2026-07): runtime-selection decision — visible fallback WARNING + fail-closed flag ──

  test('GVISOR M3: resolveSandboxRuntime is exported', () => {
    const sandbox = require('../../src/sandbox/index.js');
    assert(typeof sandbox.resolveSandboxRuntime === 'function', 'Should export resolveSandboxRuntime');
  });

  test('GVISOR M3: default (no env vars) → runc, no warn, no refuse (unchanged default)', () => {
    const { resolveSandboxRuntime } = require('../../src/sandbox/index.js');
    const r = resolveSandboxRuntime({}, false);
    assert(r.useGvisor === false && r.refuse === false && r.warn === false,
      'default must stay runc with no warning and no refusal');
  });

  test('GVISOR M3: requested + runsc available → gvisor', () => {
    const { resolveSandboxRuntime } = require('../../src/sandbox/index.js');
    const r = resolveSandboxRuntime({ MUADDIB_SANDBOX_RUNTIME: 'gvisor' }, true);
    assert(r.useGvisor === true && r.refuse === false && r.warn === false, 'requested + available → gvisor');
  });

  test('GVISOR M3: requested + runsc UNavailable (not required) → runc fallback WITH warn=true (before: silent info log)', () => {
    const { resolveSandboxRuntime } = require('../../src/sandbox/index.js');
    const r = resolveSandboxRuntime({ MUADDIB_SANDBOX_RUNTIME: 'gvisor' }, false);
    assert(r.useGvisor === false && r.refuse === false && r.warn === true,
      'fallback to runc must now surface warn=true (a visible downgrade WARNING), not a silent console.log');
  });

  test('GVISOR M3: REQUIRED + runsc UNavailable → refuse (fail closed, no runc downgrade)', () => {
    const { resolveSandboxRuntime } = require('../../src/sandbox/index.js');
    const r = resolveSandboxRuntime({ MUADDIB_SANDBOX_RUNTIME: 'gvisor', MUADDIB_REQUIRE_GVISOR: '1' }, false);
    assert(r.refuse === true && r.useGvisor === false,
      'MUADDIB_REQUIRE_GVISOR=1 + unavailable must refuse (fail closed), never downgrade to runc');
  });

  test('GVISOR M3: MUADDIB_REQUIRE_GVISOR alone (implies want) + available → gvisor', () => {
    const { resolveSandboxRuntime } = require('../../src/sandbox/index.js');
    const r = resolveSandboxRuntime({ MUADDIB_REQUIRE_GVISOR: '1' }, true);
    assert(r.useGvisor === true && r.refuse === false, 'require alone + available → gvisor');
  });

  test('GVISOR M3: NOT requested but runsc IS available → runc WITH warn=true (VPS installed-but-unused gap)', () => {
    const { resolveSandboxRuntime } = require('../../src/sandbox/index.js');
    const r = resolveSandboxRuntime({}, true);
    assert(r.useGvisor === false && r.refuse === false && r.warn === true,
      'runsc available but env var unset must still WARN (detectable in prod that gVisor is installed yet unused) while running runc');
  });
}

module.exports = { runGvisorTests };
