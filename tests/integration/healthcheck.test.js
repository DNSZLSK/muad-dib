const http = require('http');
const { test, asyncTest, assert } = require('../test-utils');

async function runHealthcheckTests() {
  console.log('\n=== HEALTHCHECK TESTS ===\n');

  const {
    validateHealthcheckUrl, ping, startHealthcheck, pingFail,
    HEALTHCHECK_INTERVAL_MS, PRIVATE_IP_PATTERNS
  } = require('../../src/monitor/healthcheck.js');

  // --- validateHealthcheckUrl ---

  test('HEALTHCHECK: valid HTTPS URL passes validation', () => {
    const result = validateHealthcheckUrl('https://hc-ping.com/abc-123');
    assert(result.valid === true, 'Should be valid');
  });

  test('HEALTHCHECK: HTTP URL is rejected', () => {
    const result = validateHealthcheckUrl('http://hc-ping.com/abc-123');
    assert(result.valid === false, 'Should be invalid');
    assert(result.error.includes('HTTPS'), 'Error should mention HTTPS');
  });

  test('HEALTHCHECK: private IP 127.0.0.1 is rejected', () => {
    const result = validateHealthcheckUrl('https://127.0.0.1/ping');
    assert(result.valid === false, 'Should be invalid');
    assert(result.error.includes('Private IP'), 'Error should mention private IP');
  });

  test('HEALTHCHECK: private IP 10.x is rejected', () => {
    const result = validateHealthcheckUrl('https://10.0.0.1/ping');
    assert(result.valid === false, 'Should be invalid');
  });

  test('HEALTHCHECK: private IP 192.168.x is rejected', () => {
    const result = validateHealthcheckUrl('https://192.168.1.1/ping');
    assert(result.valid === false, 'Should be invalid');
  });

  test('HEALTHCHECK: private IP 172.16.x is rejected', () => {
    const result = validateHealthcheckUrl('https://172.16.0.1/ping');
    assert(result.valid === false, 'Should be invalid');
  });

  test('HEALTHCHECK: link-local 169.254.x is rejected', () => {
    const result = validateHealthcheckUrl('https://169.254.1.1/ping');
    assert(result.valid === false, 'Should be invalid');
  });

  test('HEALTHCHECK: invalid URL is rejected', () => {
    const result = validateHealthcheckUrl('not-a-url');
    assert(result.valid === false, 'Should be invalid');
    assert(result.error.includes('Invalid URL'), 'Error should mention invalid');
  });

  test('HEALTHCHECK: interval is 10 minutes', () => {
    assert(HEALTHCHECK_INTERVAL_MS === 10 * 60 * 1000, 'Should be 600000ms');
  });

  // --- ping: empty URL does not crash ---

  test('HEALTHCHECK: ping with an empty URL sends no request', () => {
    // Spy https.get to prove the early `if (!url) return` short-circuits BEFORE any
    // network call — not just that it doesn't throw.
    const https = require('https');
    const orig = https.get;
    let calls = 0;
    https.get = (...args) => { calls++; return orig(...args); };
    try {
      ping(null);
      ping(undefined);
      ping('');
      assert(calls === 0, `empty URLs must not issue any request, got ${calls}`);
    } finally {
      https.get = orig;
    }
  });

  test('HEALTHCHECK: ping with HTTP URL is blocked (no request sent)', () => {
    // Capture console.error to verify the block message
    const errors = [];
    const origError = console.error;
    console.error = (...args) => errors.push(args.join(' '));
    try {
      ping('http://evil.com/ping');
      assert(errors.some(e => e.includes('Blocked')), 'Should log blocked message');
    } finally {
      console.error = origError;
    }
  });

  // --- ping: timeout respected (mock server that never responds) ---

  test('HEALTHCHECK: ping arms a 5s timeout and destroys the request when it fires', () => {
    // The old test built a mock server it never used and only checked no-throw.
    // ping resolves DNS first, then calls https.get INSIDE the dns.resolve4
    // callback (healthcheck.js:91/101). Mock both — dns to return a public IP
    // synchronously, https.get to capture — proving the real timeout wiring
    // ({ timeout: 5000 } + destroy on 'timeout') with no network and no 5s wait.
    const https = require('https');
    const dns = require('dns');
    const origGet = https.get;
    const origResolve4 = dns.resolve4;
    let capturedOpts = null;
    let destroyed = false;
    const handlers = {};
    dns.resolve4 = (host, cb) => cb(null, ['1.2.3.4']); // public IP, resolved synchronously
    https.get = (url, opts) => {
      capturedOpts = opts;
      const req = {
        on: (ev, cb) => { handlers[ev] = cb; return req; },
        destroy: () => { destroyed = true; }
      };
      return req;
    };
    try {
      ping('https://hc-ping.com/abc-123'); // valid HTTPS → passes validation
      assert(capturedOpts && capturedOpts.timeout === 5000, `ping must arm a 5s timeout, got ${JSON.stringify(capturedOpts)}`);
      assert(typeof handlers.timeout === 'function', 'ping must register a timeout handler');
      handlers.timeout(); // simulate the socket timing out
      assert(destroyed, 'on timeout, ping must destroy the request (no leaked socket)');
    } finally {
      https.get = origGet;
      dns.resolve4 = origResolve4;
    }
  });

  test('HEALTHCHECK: ping blocks a host that resolves to a private IP (DNS-rebinding defense)', () => {
    // Negative counterpart on the same DNS path: a public-looking hostname that
    // resolves to a private IP must be blocked before https.get is reached.
    const https = require('https');
    const dns = require('dns');
    const origGet = https.get;
    const origResolve4 = dns.resolve4;
    let getCalls = 0;
    dns.resolve4 = (host, cb) => cb(null, ['10.0.0.9']); // private IP
    https.get = (...args) => { getCalls++; return origGet(...args); };
    try {
      ping('https://hc-ping.com/abc-123');
      assert(getCalls === 0, 'a host resolving to a private IP must be blocked before any request');
    } finally {
      https.get = origGet;
      dns.resolve4 = origResolve4;
    }
  });

  await asyncTest('HEALTHCHECK: ping with an unreachable host never throws', async () => {
    // .invalid is a reserved TLD that always fails DNS locally (no real network).
    try {
      ping('https://healthcheck-test-nonexistent-domain-12345.invalid/ping');
    } catch (e) {
      assert(false, 'ping() must never throw: ' + e.message);
    }
  });

  // --- startHealthcheck: no URL = no crash, returns noop stop ---

  test('HEALTHCHECK: startHealthcheck with no env var returns noop', () => {
    const saved = process.env.MUADDIB_HEALTHCHECK_URL;
    delete process.env.MUADDIB_HEALTHCHECK_URL;
    try {
      const hc = startHealthcheck();
      assert(typeof hc.stop === 'function', 'Should return object with stop()');
      hc.stop(); // should not crash
    } finally {
      if (saved) process.env.MUADDIB_HEALTHCHECK_URL = saved;
    }
  });

  test('HEALTHCHECK: startHealthcheck with invalid URL is disabled gracefully', () => {
    const saved = process.env.MUADDIB_HEALTHCHECK_URL;
    process.env.MUADDIB_HEALTHCHECK_URL = 'http://not-https.com/ping';
    const errors = [];
    const origError = console.error;
    console.error = (...args) => errors.push(args.join(' '));
    try {
      const hc = startHealthcheck();
      assert(typeof hc.stop === 'function', 'Should return object with stop()');
      assert(errors.some(e => e.includes('Disabled')), 'Should log disabled message');
      hc.stop();
    } finally {
      process.env.MUADDIB_HEALTHCHECK_URL = saved || '';
      if (!saved) delete process.env.MUADDIB_HEALTHCHECK_URL;
      console.error = origError;
    }
  });

  // --- pingFail: no URL = no crash ---

  test('HEALTHCHECK: pingFail with no env var does not crash', () => {
    const saved = process.env.MUADDIB_HEALTHCHECK_URL;
    delete process.env.MUADDIB_HEALTHCHECK_URL;
    try {
      pingFail(); // should not crash
    } finally {
      if (saved) process.env.MUADDIB_HEALTHCHECK_URL = saved;
    }
  });

  // --- SSRF: PRIVATE_IP_PATTERNS coverage ---

  test('HEALTHCHECK: PRIVATE_IP_PATTERNS covers all RFC 1918 + link-local + loopback + IPv6', () => {
    const testCases = [
      ['127.0.0.1', true],
      ['10.0.0.1', true],
      ['172.16.0.1', true],
      ['172.31.255.255', true],
      ['192.168.1.1', true],
      ['169.254.1.1', true],
      ['0.0.0.0', true],
      ['::1', true],
      ['::ffff:127.0.0.1', true],
      ['fc00::1', true],
      ['fe80::1', true],
      ['8.8.8.8', false],
      ['1.1.1.1', false],
      ['172.32.0.1', false],  // outside 172.16-31 range
    ];
    for (const [ip, shouldMatch] of testCases) {
      const matched = PRIVATE_IP_PATTERNS.some(p => p.test(ip));
      assert(matched === shouldMatch, `IP ${ip} should ${shouldMatch ? '' : 'NOT '}match private patterns`);
    }
  });
}

module.exports = { runHealthcheckTests };
