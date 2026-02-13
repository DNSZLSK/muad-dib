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
    SAFE_DOMAINS
  } = require('../../src/sandbox.js');

  test('SANDBOX-NET: scoreFindings handles empty report', () => {
    const { score, findings } = scoreFindings({});
    assert(score === 0, 'Empty report should score 0');
    assert(findings.length === 0, 'Empty report should have no findings');
  });

  test('SANDBOX-NET: scoreFindings detects suspicious DNS', () => {
    const report = { network: { dns_queries: ['evil.com', 'registry.npmjs.org'] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0 for evil.com DNS');
    const dnsFindings = findings.filter(f => f.type === 'suspicious_dns');
    assert(dnsFindings.length === 1, 'Should have 1 suspicious DNS (evil.com), got ' + dnsFindings.length);
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
    assert(httpFindings.length === 1, 'Should detect 1 suspicious HTTP request');
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
  const { getSeverity, displayResults, imageExists } = require('../../src/sandbox.js');

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

  test('SANDBOX-CANARY: generateCanaryTokens produces injectable tokens', () => {
    const { tokens, suffix } = genTokens();
    assert(typeof suffix === 'string' && suffix.length > 0, 'Should have a suffix');
    assert(Object.keys(tokens).length === 8, 'Should have 8 tokens');
    for (const value of Object.values(tokens)) {
      assertIncludes(value, 'MUADDIB_CANARY', 'Each token should contain MUADDIB_CANARY');
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
}

module.exports = { runSandboxTests };
