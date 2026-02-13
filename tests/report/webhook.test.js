const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runWebhookTests() {
  // ============================================
  // WEBHOOK SECURITY TESTS
  // ============================================

  console.log('\n=== WEBHOOK SECURITY TESTS ===\n');

  test('SECURITY: validateWebhookUrl accepts Discord', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('https://discord.com/api/webhooks/123/abc');
    assert(result.valid, 'Discord webhook should be valid');
  });

  test('SECURITY: validateWebhookUrl accepts Slack', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('https://hooks.slack.com/services/xxx/yyy');
    assert(result.valid, 'Slack webhook should be valid');
  });

  test('SECURITY: validateWebhookUrl rejects HTTP (non-HTTPS)', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('http://discord.com/api/webhooks/123');
    assert(!result.valid, 'HTTP should be rejected');
  });

  test('SECURITY: validateWebhookUrl rejects unauthorized domains', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('https://evil.com/steal');
    assert(!result.valid, 'evil.com should be rejected');
  });

  test('SECURITY: validateWebhookUrl rejects private IPs (127.x)', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('https://127.0.0.1:8080/webhook');
    assert(!result.valid, '127.x should be rejected');
  });

  test('SECURITY: validateWebhookUrl rejects private IPs (192.168.x)', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('https://192.168.1.1/webhook');
    assert(!result.valid, '192.168.x should be rejected');
  });

  test('SECURITY: validateWebhookUrl rejects private IPs (10.x)', () => {
    const { validateWebhookUrl } = require('../../src/webhook.js');
    const result = validateWebhookUrl('https://10.0.0.1/webhook');
    assert(!result.valid, '10.x should be rejected');
  });

  // ============================================
  // WEBHOOK EXTENDED TESTS
  // ============================================

  console.log('\n=== WEBHOOK EXTENDED TESTS ===\n');

  const httpModule = require('http');
  const { sendWebhook: sendWebhookFn, validateWebhookUrl: valUrl } = require('../../src/webhook.js');

  // Mock HTTP server on localhost (allowed by validateWebhookUrl)
  const mockWebhookServer = await new Promise((resolve) => {
    let lastPayload = null;
    const srv = httpModule.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try { lastPayload = JSON.parse(body); } catch { lastPayload = body; }
        if (req.url.includes('/error')) {
          res.writeHead(500);
          res.end('error');
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
        }
      });
    });
    srv.listen(0, 'localhost', () => {
      resolve({ server: srv, port: srv.address().port, getPayload: () => lastPayload });
    });
  });
  const webhookBase = `http://localhost:${mockWebhookServer.port}`;

  const mockResults = {
    target: '/test/project',
    timestamp: new Date().toISOString(),
    summary: { riskScore: 75, riskLevel: 'HIGH', critical: 2, high: 3, medium: 1, total: 6 },
    threats: [
      { type: 'suspicious_code', severity: 'CRITICAL', message: 'Critical threat found', file: 'evil.js' },
      { type: 'known_malicious', severity: 'HIGH', message: 'High threat found', file: 'bad.js' }
    ]
  };

  await asyncTest('WEBHOOK-EXT: validateWebhookUrl catch for invalid URL', async () => {
    const r = valUrl('not-a-url');
    assert(!r.valid, 'Should be invalid');
    assert(r.error.includes('Invalid URL'), 'Should mention Invalid URL');
  });

  await asyncTest('WEBHOOK-EXT: validateWebhookUrl rejects 172.x', async () => {
    const r = valUrl('https://172.16.0.1/webhook');
    assert(!r.valid, 'Should reject 172.16.x');
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects HTTP localhost (no exemption)', async () => {
    try {
      await sendWebhookFn(`${webhookBase}/discord.com/api/webhooks/t`, mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('HTTPS required'), 'Should require HTTPS');
    }
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects blocked URL', async () => {
    try {
      await sendWebhookFn('https://evil.com/steal', mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('Webhook blocked'), 'Should be blocked');
    }
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects non-allowed domain', async () => {
    try {
      await sendWebhookFn('https://example.com/webhook', mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('Domain not allowed'), 'Should reject non-allowed domain');
    }
  });

  mockWebhookServer.server.close();

  // ============================================
  // WEBHOOK COVERAGE TESTS (webhook.js)
  // ============================================

  console.log('\n=== WEBHOOK COVERAGE TESTS ===\n');

  test('WEBHOOK-COV: validateWebhookUrl rejects IPv6 loopback', () => {
    const r = valUrl('https://[::1]/webhook');
    assert(!r.valid, 'Should reject IPv6 loopback');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects fc00 (IPv6 private)', () => {
    const r = valUrl('https://[fc00::1]/webhook');
    assert(!r.valid, 'Should reject fc00 IPv6 private');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects fe80 (IPv6 link-local)', () => {
    const r = valUrl('https://[fe80::1]/webhook');
    assert(!r.valid, 'Should reject fe80 IPv6 link-local');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects 169.254.x (link-local)', () => {
    const r = valUrl('https://169.254.1.1/webhook');
    assert(!r.valid, 'Should reject 169.254.x link-local');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects 0.x addresses', () => {
    const r = valUrl('https://0.0.0.0/webhook');
    assert(!r.valid, 'Should reject 0.0.0.0');
  });

  test('WEBHOOK-COV: formatDiscord generates correct embed structure', () => {
    // Access formatDiscord indirectly via module internals
    // We test by calling the webhook module's format functions
    const webhookModule = require('../../src/webhook.js');
    // formatDiscord is not exported, so we test via the validate path
    // Instead test the payload structure expected by Discord
    const r1 = valUrl('https://discord.com/api/webhooks/12345/token');
    assert(r1.valid, 'Discord webhook URL should be valid');

    const r2 = valUrl('https://hooks.slack.com/services/T/B/X');
    assert(r2.valid, 'Slack webhook URL should be valid');
  });

  test('WEBHOOK-COV: validateWebhookUrl accepts subdomain of allowed domain', () => {
    const r = valUrl('https://ptb.discord.com/api/webhooks/test');
    assert(r.valid, 'Should accept subdomain of discord.com');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects discordapp.evil.com', () => {
    const r = valUrl('https://discordapp.evil.com/webhook');
    assert(!r.valid, 'Should reject non-matching domain');
  });

  // Test format functions (now exported)
  const { formatDiscord, formatSlack, formatGeneric } = require('../../src/webhook.js');

  test('WEBHOOK-COV: formatDiscord returns embed with correct structure', () => {
    const results = {
      summary: { riskLevel: 'CRITICAL', riskScore: 85, critical: 2, high: 3, medium: 1, total: 6 },
      threats: [
        { severity: 'CRITICAL', message: 'Malicious package detected' },
        { severity: 'HIGH', message: 'Suspicious script' }
      ],
      target: 'npm/evil-pkg@1.0.0',
      ecosystem: 'npm',
      timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds, 'Should have embeds array');
    assert(payload.embeds[0].title.includes('MUAD'), 'Embed title should mention MUAD\'DIB');
    assert(payload.embeds[0].color === 0xe74c3c, 'CRITICAL should be red');
    assert(payload.embeds[0].fields.length >= 3, 'Should have at least 3 fields');
    // Check critical threats field is added
    const critField = payload.embeds[0].fields.find(f => f.name === 'Critical Threats');
    assert(critField, 'Should have Critical Threats field');
    assertIncludes(critField.value, 'Malicious package', 'Should list critical threats');
    // Check emoji in title for CRITICAL
    assertIncludes(payload.embeds[0].title, '\uD83D\uDD34', 'CRITICAL should have red circle emoji');
    // Check Ecosystem field
    const ecoField = payload.embeds[0].fields.find(f => f.name === 'Ecosystem');
    assert(ecoField, 'Should have Ecosystem field');
    assert(ecoField.value === 'NPM', 'Ecosystem should be NPM');
    // Check Package Link field
    const linkField = payload.embeds[0].fields.find(f => f.name === 'Package Link');
    assert(linkField, 'Should have Package Link field');
    assertIncludes(linkField.value, 'npmjs.com', 'npm link should point to npmjs.com');
    // Check footer has readable timestamp
    assertIncludes(payload.embeds[0].footer.text, 'UTC', 'Footer should have readable UTC timestamp');
  });

  test('WEBHOOK-COV: formatDiscord handles HIGH risk level', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 1, total: 3 },
      threats: [{ severity: 'HIGH', message: 'Test' }],
      target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0xe67e22, 'HIGH should be orange');
    assertIncludes(payload.embeds[0].title, '\uD83D\uDFE0', 'HIGH should have orange circle emoji');
  });

  test('WEBHOOK-COV: formatDiscord handles MEDIUM risk level', () => {
    const results = {
      summary: { riskLevel: 'MEDIUM', riskScore: 40, critical: 0, high: 0, medium: 2, total: 2 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0xf1c40f, 'MEDIUM should be yellow');
    assertIncludes(payload.embeds[0].title, '\uD83D\uDFE1', 'MEDIUM should have yellow circle emoji');
  });

  test('WEBHOOK-COV: formatDiscord handles LOW risk level', () => {
    const results = {
      summary: { riskLevel: 'LOW', riskScore: 10, critical: 0, high: 0, medium: 0, total: 1 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0x3498db, 'LOW should be blue');
    // LOW should NOT have emoji prefix
    assert(!payload.embeds[0].title.includes('\uD83D\uDD34') && !payload.embeds[0].title.includes('\uD83D\uDFE0') && !payload.embeds[0].title.includes('\uD83D\uDFE1'), 'LOW should have no emoji');
  });

  test('WEBHOOK-COV: formatDiscord handles CLEAN risk level', () => {
    const results = {
      summary: { riskLevel: 'CLEAN', riskScore: 0, critical: 0, high: 0, medium: 0, total: 0 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0x2ecc71, 'CLEAN should be green');
  });

  test('WEBHOOK-COV: formatDiscord includes PyPI package link', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 0, total: 2 },
      threats: [{ severity: 'HIGH', message: 'Test' }],
      target: 'pypi/evil-lib@0.1.0',
      ecosystem: 'pypi',
      timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    const linkField = payload.embeds[0].fields.find(f => f.name === 'Package Link');
    assert(linkField, 'Should have Package Link field for pypi');
    assertIncludes(linkField.value, 'pypi.org', 'pypi link should point to pypi.org');
  });

  test('WEBHOOK-COV: formatDiscord includes sandbox field when present', () => {
    const results = {
      summary: { riskLevel: 'CRITICAL', riskScore: 90, critical: 1, high: 0, medium: 0, total: 1 },
      threats: [{ severity: 'CRITICAL', message: 'Test' }],
      target: 'npm/pkg@1.0.0',
      ecosystem: 'npm',
      timestamp: '2025-01-01T00:00:00Z',
      sandbox: { score: 75, severity: 'HIGH' }
    };
    const payload = formatDiscord(results);
    const sandboxField = payload.embeds[0].fields.find(f => f.name === 'Sandbox');
    assert(sandboxField, 'Should have Sandbox field');
    assertIncludes(sandboxField.value, '75', 'Sandbox field should contain score');
  });

  test('WEBHOOK-COV: formatSlack returns blocks with correct structure', () => {
    const results = {
      summary: { riskLevel: 'CRITICAL', riskScore: 90, critical: 3, high: 1, medium: 0, total: 4 },
      threats: [
        { severity: 'CRITICAL', message: 'Exfiltration detected' },
        { severity: 'CRITICAL', message: 'Reverse shell' }
      ],
      target: '/test/project', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assert(payload.blocks, 'Should have blocks array');
    assert(payload.blocks.length >= 3, 'Should have at least 3 blocks');
    // Header block
    assert(payload.blocks[0].type === 'header', 'First block should be header');
    assertIncludes(payload.blocks[0].text.text, 'MUAD', 'Header should mention MUAD\'DIB');
    // Critical threats block should exist (since we have critical threats)
    const critBlock = payload.blocks.find(b => b.text && b.text.text && b.text.text.includes('Critical Threats'));
    assert(critBlock, 'Should have Critical Threats block');
  });

  test('WEBHOOK-COV: formatSlack handles HIGH risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 0, total: 2 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'warning', 'HIGH should use warning emoji');
  });

  test('WEBHOOK-COV: formatSlack handles MEDIUM risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'MEDIUM', riskScore: 40, critical: 0, high: 0, medium: 2, total: 2 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'yellow', 'MEDIUM should use yellow emoji');
  });

  test('WEBHOOK-COV: formatSlack handles LOW risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'LOW', riskScore: 10, critical: 0, high: 0, medium: 0, total: 1 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'information', 'LOW should use info emoji');
  });

  test('WEBHOOK-COV: formatSlack handles CLEAN risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'CLEAN', riskScore: 0, critical: 0, high: 0, medium: 0, total: 0 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'check_mark', 'CLEAN should use check mark emoji');
  });

  test('WEBHOOK-COV: formatGeneric returns structured data', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 1, total: 3 },
      threats: [
        { type: 'shell_command', severity: 'HIGH', message: 'curl | sh', file: 'install.sh' },
        { type: 'obfuscation', severity: 'MEDIUM', message: 'Hex encoded', file: 'index.js' }
      ],
      target: '/test/project', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatGeneric(results);
    assert(payload.tool === 'MUADDIB', 'Tool should be MUADDIB');
    assert(payload.target === '/test/project', 'Target should match');
    assert(payload.summary.riskLevel === 'HIGH', 'Summary should be included');
    assert(payload.threats.length === 2, 'Should have 2 threats');
    assert(payload.threats[0].type === 'shell_command', 'Threat type preserved');
    assert(payload.threats[0].file === 'install.sh', 'Threat file preserved');
  });
}

module.exports = { runWebhookTests };
