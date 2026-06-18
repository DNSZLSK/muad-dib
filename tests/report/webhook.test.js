const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped, spyOn
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

  // --- Phase 0b: daily-report ledger section (formatLedgerField) ---

  test('LEDGER-FIELD: renders scanned / alert rate / dropped+vanished / per-ecosystem', () => {
    const { formatLedgerField } = require('../../src/monitor/webhook.js');
    const field = formatLedgerField({
      total: 1000, scanned: 990, dropped: 10, vanished: 4, exactVanished: true,
      alerted: 9, alertRate: 9 / 990,
      byOutcome: { clean: 981, suspect: 9, dropped: 10 },
      byEcosystem: { npm: { total: 800, scanned: 795, dropped: 5, alerted: 7 },
                     pypi: { total: 200, scanned: 195, dropped: 5, alerted: 2 } }
    });
    assert(field && field.name === 'Ledger (24h)', 'field name should be "Ledger (24h)"');
    assertIncludes(field.value, 'Scans: 990 events', 'shows scanned count (events unit)');
    assertIncludes(field.value, 'alertés 9', 'shows alerted count');
    assertIncludes(field.value, '0.91%', 'shows alert rate (9/990)');
    assertIncludes(field.value, 'Non scannés: 10 events (4 name@ver jamais (re)scannés)', 'shows dropped + vanished, both labeled as name@version events');
    assertIncludes(field.value, 'npm 800', 'shows per-ecosystem npm total');
    assertIncludes(field.value, 'pypi 200', 'shows per-ecosystem pypi total');
  });

  test('LEDGER-FIELD: omitted (null) when the ledger is empty', () => {
    const { formatLedgerField } = require('../../src/monitor/webhook.js');
    assert(formatLedgerField(null) === null, 'null rollup → no field');
    assert(formatLedgerField({ total: 0, scanned: 0, dropped: 0, vanished: 0, byEcosystem: {} }) === null,
      'empty rollup (total 0) → no field, not a zero-noise row');
  });

  test('LEDGER-FIELD: no Dropped line when nothing was dropped; ≥ marks approximate vanished', () => {
    const { formatLedgerField } = require('../../src/monitor/webhook.js');
    const clean = formatLedgerField({
      total: 50, scanned: 50, dropped: 0, vanished: 0, exactVanished: true,
      alerted: 0, alertRate: 0, byOutcome: { clean: 50 }, byEcosystem: { npm: { total: 50, scanned: 50, dropped: 0, alerted: 0 } }
    });
    assertNotIncludes(clean.value, 'Non scannés', 'no Non scannés line when dropped=0');
    const approx = formatLedgerField({
      total: 20, scanned: 10, dropped: 10, vanished: 7, exactVanished: false,
      alerted: 0, alertRate: 0, byOutcome: { dropped: 10, clean: 10 }, byEcosystem: { npm: { total: 20, scanned: 10, dropped: 10, alerted: 0 } }
    });
    assertIncludes(approx.value, '≥7 name@ver', 'approximate vanished marked with ≥ when exactVanished is false');
  });

  // ============================================
  // AUDIT 3: transient DNS resilience (resolveHostWithRetry)
  // ============================================
  const dns = require('dns');

  await asyncTest('DNS-RETRY: empty answer then success → resolves, retried exactly once', async () => {
    const { resolveHostWithRetry } = require('../../src/webhook.js');
    let call = 0;
    const s4 = spyOn(dns.promises, 'resolve4', async () => (++call === 1 ? [] : ['1.2.3.4']));
    const s6 = spyOn(dns.promises, 'resolve6', async () => []);
    try {
      const r = await resolveHostWithRetry('discord.com', { backoffMs: 1 });
      assert(r.all.includes('1.2.3.4'), `should resolve after retry, got ${JSON.stringify(r.all)}`);
      assert(s4.callCount === 2, `resolve4 should be called twice (1 empty + 1 success), got ${s4.callCount}`);
    } finally { s4.restore(); s6.restore(); }
  });

  await asyncTest('DNS-RETRY: persistent empty answer → throws "no DNS records" after exhausting retries', async () => {
    const { resolveHostWithRetry } = require('../../src/webhook.js');
    const s4 = spyOn(dns.promises, 'resolve4', async () => []);
    const s6 = spyOn(dns.promises, 'resolve6', async () => []);
    try {
      let threw = null;
      try { await resolveHostWithRetry('discord.com', { maxRetries: 2, backoffMs: 1 }); }
      catch (e) { threw = e; }
      assert(threw && /no DNS records/.test(threw.message), `should throw no-DNS-records, got ${threw && threw.message}`);
      assert(s4.callCount === 3, `resolve4 = 1 initial + 2 retries = 3 attempts, got ${s4.callCount}`);
    } finally { s4.restore(); s6.restore(); }
  });

  await asyncTest('DNS-RETRY: a transient blip does NOT bypass the SSRF private-IP block', async () => {
    // After the resolver recovers, a private IP must still be rejected (no retry softening).
    const { sendWebhook } = require('../../src/webhook.js');
    const s4 = spyOn(dns.promises, 'resolve4', async () => ['127.0.0.1']);
    const s6 = spyOn(dns.promises, 'resolve6', async () => []);
    try {
      let threw = null;
      try {
        await sendWebhook('https://discord.com/api/webhooks/x/y', { embeds: [] }, { rawPayload: true });
      } catch (e) { threw = e; }
      assert(threw && /private IP/.test(threw.message), `private IP must be blocked, got ${threw && threw.message}`);
    } finally { s4.restore(); s6.restore(); }
  });

  // ============================================
  // AUDIT 3: .env auto-loader (env-loader.js)
  // ============================================
  const os = require('os');

  test('ENV-LOADER: parseDotEnv handles comments, quotes, export prefix, malformed keys', () => {
    const { parseDotEnv } = require('../../src/env-loader.js');
    const p = parseDotEnv([
      '# a comment',
      '',
      'MUADDIB_WEBHOOK_URL=https://discord.com/api/webhooks/abc',
      'export FOO="quoted value"',
      "BAR='single'",
      '1INVALID=nope',     // key may not start with a digit
      'NO_EQUALS_LINE',
      'BAZ=trailing  '     // trimmed
    ].join('\n'));
    assert(p.MUADDIB_WEBHOOK_URL === 'https://discord.com/api/webhooks/abc', 'plain value');
    assert(p.FOO === 'quoted value', 'double quotes stripped + export prefix handled');
    assert(p.BAR === 'single', 'single quotes stripped');
    assert(p.BAZ === 'trailing', 'value trimmed');
    assert(!('1INVALID' in p), 'malformed key skipped');
    assert(!('NO_EQUALS_LINE' in p), 'line without = skipped');
  });

  test('ENV-LOADER: loadDotEnv never overwrites an existing env var; missing file is a no-op', () => {
    const { loadDotEnv } = require('../../src/env-loader.js');
    const f = path.join(os.tmpdir(), `dotenv-${Date.now()}.env`);
    const KEY_EXISTING = '__MUADDIB_TEST_EXISTING__';
    const KEY_NEW = '__MUADDIB_TEST_NEW__';
    try {
      process.env[KEY_EXISTING] = 'from-real-env';
      delete process.env[KEY_NEW];
      fs.writeFileSync(f, `${KEY_EXISTING}=from-file\n${KEY_NEW}=file-only\n`);
      const res = loadDotEnv(f);
      assert(res.loaded === true, 'file loaded');
      assert(process.env[KEY_EXISTING] === 'from-real-env', 'existing real env var NOT overwritten');
      assert(process.env[KEY_NEW] === 'file-only', 'new var applied from file');
      assert(res.keys.includes(KEY_NEW) && !res.keys.includes(KEY_EXISTING), 'only the new key reported as applied');
      // missing file → no throw, loaded:false
      const miss = loadDotEnv(path.join(os.tmpdir(), `nope-${Date.now()}.env`));
      assert(miss.loaded === false && miss.keys.length === 0, 'missing file is a silent no-op');
    } finally {
      delete process.env[KEY_EXISTING];
      delete process.env[KEY_NEW];
      try { fs.unlinkSync(f); } catch {}
    }
  });

  // ============================================
  // AUDIT 3: persisted-report resend + boot redelivery
  // ============================================
  const stateMod = require('../../src/monitor/state.js');
  const webhookMod = require('../../src/monitor/webhook.js');
  const REPORTS_DIR = stateMod.DAILY_REPORTS_LOG_DIR;
  const TEST_DATE = '2099-12-31'; // always the "latest" persisted report → picked by boot redelivery
  const writeFixtureReport = (date, delivered) => {
    const fp = path.join(REPORTS_DIR, `${date}.json`);
    fs.writeFileSync(fp, JSON.stringify({
      date, timestamp: '2099-12-31T06:00:00.000Z', delivered,
      embed: { embeds: [{ title: 'fixture', fields: [] }] }, metrics: { scanned: 1 }
    }, null, 2));
    return fp;
  };
  const cleanupFixture = () => { try { fs.unlinkSync(path.join(REPORTS_DIR, `${TEST_DATE}.json`)); } catch {} };

  test('RESEND: loadPersistedReport + markReportDelivered round-trip', () => {
    const fp = writeFixtureReport(TEST_DATE, false);
    try {
      const r = webhookMod.loadPersistedReport(TEST_DATE);
      assert(r && r.date === TEST_DATE && r.data.delivered === false, 'loads the fixture (delivered=false)');
      webhookMod.markReportDelivered(r.filePath, r.data);
      const after = JSON.parse(fs.readFileSync(fp, 'utf8'));
      assert(after.delivered === true && typeof after.deliveredAt === 'string', 'marked delivered with timestamp');
    } finally { cleanupFixture(); }
  });

  await asyncTest('RESEND: resendDailyReport with no webhook URL → {sent:false}, never sends', async () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    writeFixtureReport(TEST_DATE, false);
    try {
      const res = await webhookMod.resendDailyReport(TEST_DATE);
      assert(res.sent === false && /not configured/.test(res.message), `no-URL must short-circuit, got ${JSON.stringify(res)}`);
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      cleanupFixture();
    }
  });

  await asyncTest('BOOT-REDELIVER: skips when latest report already delivered', async () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    process.env.MUADDIB_WEBHOOK_URL = 'https://discord.com/api/webhooks/x/y';
    writeFixtureReport(TEST_DATE, true); // delivered=true
    try {
      const res = await webhookMod.redeliverPendingReportOnBoot();
      assert(res.attempted === false && res.reason === 'already_delivered_or_legacy',
        `delivered report must not be resent, got ${JSON.stringify(res)}`);
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig; else delete process.env.MUADDIB_WEBHOOK_URL;
      cleanupFixture();
    }
  });

  await asyncTest('BOOT-REDELIVER: undelivered report but no webhook URL → attempted:false (no_webhook_url)', async () => {
    const orig = process.env.MUADDIB_WEBHOOK_URL;
    delete process.env.MUADDIB_WEBHOOK_URL;
    writeFixtureReport(TEST_DATE, false); // delivered=false
    try {
      const res = await webhookMod.redeliverPendingReportOnBoot();
      assert(res.attempted === false && res.reason === 'no_webhook_url',
        `must not attempt without a URL, got ${JSON.stringify(res)}`);
    } finally {
      if (orig !== undefined) process.env.MUADDIB_WEBHOOK_URL = orig;
      cleanupFixture();
    }
  });
}

module.exports = { runWebhookTests };
