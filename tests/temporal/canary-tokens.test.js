const { test, assert, assertIncludes } = require('../test-utils');

const {
  CANARY_PREFIXES,
  generateCanaryTokens,
  createCanaryEnvFile,
  createCanaryNpmrc,
  detectCanaryExfiltration,
  detectCanaryInOutput
} = require('../../src/canary-tokens.js');

const EXPECTED_KEYS = [
  'GITHUB_TOKEN', 'NPM_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
  'GITLAB_TOKEN', 'DOCKER_PASSWORD', 'NPM_AUTH_TOKEN', 'GH_TOKEN'
];

async function runCanaryTokensTests() {
  console.log('\n=== CANARY TOKENS TESTS ===\n');

  // ============================================
  // generateCanaryTokens()
  // ============================================

  test('CANARY: generateCanaryTokens returns tokens and suffix', () => {
    const result = generateCanaryTokens();
    assert(result.tokens && typeof result.tokens === 'object', 'Should return tokens object');
    assert(typeof result.suffix === 'string' && result.suffix.length > 0, 'Should return non-empty suffix');
  });

  test('CANARY: generateCanaryTokens includes all 8 token keys', () => {
    const { tokens } = generateCanaryTokens();
    for (const key of EXPECTED_KEYS) {
      assert(tokens[key] !== undefined, `Missing token key: ${key}`);
    }
    assert(Object.keys(tokens).length === 8, 'Should have exactly 8 tokens, got ' + Object.keys(tokens).length);
  });

  test('CANARY: every token contains MUADDIB_CANARY', () => {
    const { tokens } = generateCanaryTokens();
    for (const [key, value] of Object.entries(tokens)) {
      assertIncludes(value, 'MUADDIB_CANARY', `Token ${key} should contain MUADDIB_CANARY`);
    }
  });

  test('CANARY: two calls produce different suffixes', () => {
    const r1 = generateCanaryTokens();
    const r2 = generateCanaryTokens();
    assert(r1.suffix !== r2.suffix, 'Suffixes should differ between calls');
  });

  test('CANARY: tokens use correct prefixes from CANARY_PREFIXES', () => {
    const { tokens } = generateCanaryTokens();
    for (const [key, prefix] of Object.entries(CANARY_PREFIXES)) {
      assert(tokens[key].startsWith(prefix), `Token ${key} should start with "${prefix}", got "${tokens[key]}"`);
    }
  });

  // ============================================
  // createCanaryEnvFile()
  // ============================================

  test('CANARY: createCanaryEnvFile returns string with all keys', () => {
    const { tokens } = generateCanaryTokens();
    const env = createCanaryEnvFile(tokens);
    assert(typeof env === 'string', 'Should return a string');
    for (const key of EXPECTED_KEYS) {
      assertIncludes(env, key + '=', `Env file should contain ${key}=`);
    }
  });

  test('CANARY: createCanaryEnvFile has correct KEY=value format', () => {
    const { tokens } = generateCanaryTokens();
    const env = createCanaryEnvFile(tokens);
    const lines = env.trim().split('\n');
    assert(lines.length === 8, 'Should have 8 lines, got ' + lines.length);
    for (const line of lines) {
      assert(line.includes('='), `Line should contain "=": ${line}`);
      const [key, value] = line.split('=');
      assert(tokens[key] === value, `Value mismatch for ${key}`);
    }
  });

  // ============================================
  // createCanaryNpmrc()
  // ============================================

  test('CANARY: createCanaryNpmrc returns string with _authToken', () => {
    const { tokens } = generateCanaryTokens();
    const npmrc = createCanaryNpmrc(tokens);
    assert(typeof npmrc === 'string', 'Should return a string');
    assertIncludes(npmrc, '_authToken=', 'Should contain _authToken=');
  });

  test('CANARY: createCanaryNpmrc contains the NPM_AUTH_TOKEN value', () => {
    const { tokens } = generateCanaryTokens();
    const npmrc = createCanaryNpmrc(tokens);
    assertIncludes(npmrc, tokens.NPM_AUTH_TOKEN, 'Should contain the actual NPM_AUTH_TOKEN value');
    assertIncludes(npmrc, '//registry.npmjs.org/', 'Should contain registry URL');
  });

  // ============================================
  // detectCanaryExfiltration()
  // ============================================

  test('CANARY: detectCanaryExfiltration finds token in http_bodies', () => {
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      http_bodies: ['POST data: secret=' + tokens.GITHUB_TOKEN]
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect exfiltration');
    assert(result.exfiltrations.length >= 1, 'Should have at least 1 exfiltration');
    assert(result.exfiltrations[0].token === 'GITHUB_TOKEN', 'Should identify GITHUB_TOKEN');
    assert(result.exfiltrations[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
    assertIncludes(result.exfiltrations[0].foundIn, 'HTTP body', 'foundIn should mention HTTP body');
  });

  test('CANARY: detectCanaryExfiltration finds token in dns_queries', () => {
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      dns_queries: ['safe.com', tokens.NPM_TOKEN + '.evil.com']
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect DNS exfiltration');
    const found = result.exfiltrations.find(e => e.token === 'NPM_TOKEN');
    assert(found, 'Should find NPM_TOKEN exfiltration');
    assertIncludes(found.foundIn, 'DNS query', 'foundIn should mention DNS query');
  });

  test('CANARY: detectCanaryExfiltration finds token in http_requests', () => {
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      http_requests: [{ method: 'GET', host: 'evil.com', path: '/steal?t=' + tokens.AWS_ACCESS_KEY_ID }]
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect URL exfiltration');
    const found = result.exfiltrations.find(e => e.token === 'AWS_ACCESS_KEY_ID');
    assert(found, 'Should find AWS_ACCESS_KEY_ID');
    assertIncludes(found.foundIn, 'HTTP request', 'foundIn should mention HTTP request');
  });

  test('CANARY: detectCanaryExfiltration returns false when no token found', () => {
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      dns_queries: ['google.com', 'npmjs.org'],
      http_bodies: ['normal data without secrets'],
      http_requests: [{ method: 'GET', host: 'example.com', path: '/' }],
      tls_connections: [{ domain: 'github.com', ip: '1.2.3.4', port: 443 }]
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === false, 'Should not detect exfiltration');
    assert(result.exfiltrations.length === 0, 'Should have 0 exfiltrations');
  });

  test('CANARY: detectCanaryExfiltration handles null networkLogs', () => {
    const { tokens } = generateCanaryTokens();
    const result = detectCanaryExfiltration(null, tokens);
    assert(result.detected === false, 'Should return false for null logs');
    assert(result.exfiltrations.length === 0, 'Should have 0 exfiltrations');
  });

  test('CANARY: detectCanaryExfiltration handles null tokens', () => {
    const result = detectCanaryExfiltration({ http_bodies: ['data'] }, null);
    assert(result.detected === false, 'Should return false for null tokens');
  });

  test('CANARY: detectCanaryExfiltration finds token in tls_connections', () => {
    const { tokens } = generateCanaryTokens();
    const networkLogs = {
      tls_connections: [{ domain: tokens.GITLAB_TOKEN + '.evil.com', ip: '1.2.3.4', port: 443 }]
    };
    const result = detectCanaryExfiltration(networkLogs, tokens);
    assert(result.detected === true, 'Should detect TLS exfiltration');
    const found = result.exfiltrations.find(e => e.token === 'GITLAB_TOKEN');
    assert(found, 'Should find GITLAB_TOKEN');
  });

  // ============================================
  // detectCanaryInOutput()
  // ============================================

  test('CANARY: detectCanaryInOutput finds token in stdout', () => {
    const { tokens } = generateCanaryTokens();
    const result = detectCanaryInOutput('Sending: ' + tokens.DOCKER_PASSWORD, '', tokens);
    assert(result.detected === true, 'Should detect in stdout');
    assert(result.exfiltrations.length >= 1, 'Should have at least 1 exfiltration');
    assert(result.exfiltrations[0].token === 'DOCKER_PASSWORD', 'Should identify DOCKER_PASSWORD');
    assertIncludes(result.exfiltrations[0].foundIn, 'stdout', 'foundIn should mention stdout');
  });

  test('CANARY: detectCanaryInOutput finds token in stderr', () => {
    const { tokens } = generateCanaryTokens();
    const result = detectCanaryInOutput('', 'Error: leaked ' + tokens.GH_TOKEN, tokens);
    assert(result.detected === true, 'Should detect in stderr');
    const found = result.exfiltrations.find(e => e.token === 'GH_TOKEN');
    assert(found, 'Should find GH_TOKEN');
    assertIncludes(found.foundIn, 'stderr', 'foundIn should mention stderr');
  });

  test('CANARY: detectCanaryInOutput returns false when no token found', () => {
    const { tokens } = generateCanaryTokens();
    const result = detectCanaryInOutput('normal output', 'normal error', tokens);
    assert(result.detected === false, 'Should not detect');
    assert(result.exfiltrations.length === 0, 'Should have 0 exfiltrations');
  });

  test('CANARY: detectCanaryInOutput handles null inputs', () => {
    const { tokens } = generateCanaryTokens();
    const result = detectCanaryInOutput(null, null, tokens);
    assert(result.detected === false, 'Should return false for null inputs');
    assert(result.exfiltrations.length === 0, 'Should have 0 exfiltrations');
  });

  test('CANARY: detectCanaryInOutput handles null tokens', () => {
    const result = detectCanaryInOutput('some output', 'some error', null);
    assert(result.detected === false, 'Should return false for null tokens');
  });
}

module.exports = { runCanaryTokensTests };
