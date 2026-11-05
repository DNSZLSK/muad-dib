const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert } = require('../test-utils');
const { scanIocStrings, MAX_TOTAL_FINDINGS } = require('../../src/scanner/ioc-strings.js');

async function runIocStringsTests() {
  console.log('\n=== IOC STRINGS TESTS ===\n');

  // Helpers
  function mkPkg(name, files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-iocs-'));
    fs.writeFileSync(path.join(dir, 'package.json'),
      JSON.stringify({ name, version: '1.0.0', main: 'index.js' }, null, 2));
    for (const [rel, body] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, body);
    }
    return dir;
  }
  function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } }

  await asyncTest('IOC-STR: detects Axios OrDeR_7077 in source file', async () => {
    const dir = mkPkg('axios-mock', { 'index.js': 'const k = "OrDeR_7077";\nmodule.exports = k;' });
    try {
      const threats = await scanIocStrings(dir);
      const m = threats.filter(t => t.type === 'ioc_string_match' && t.evidence === 'OrDeR_7077');
      assert(m.length === 1, 'Should fire 1 finding for OrDeR_7077, got ' + m.length);
      assert(m[0].severity === 'CRITICAL', 'Should be CRITICAL');
      assert(m[0].campaign === 'axios-2026-03', 'Should tag campaign axios-2026-03');
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: detects multiple distinct IOCs in same file', async () => {
    const dir = mkPkg('multi', {
      'lib/setup.js': 'const KEY = "OrDeR_7077";\nconst CMDS = ["rsp_peinject", "rsp_runscript", "rsp_kill"];'
    });
    try {
      const threats = await scanIocStrings(dir);
      const ev = new Set(threats.filter(t => t.type === 'ioc_string_match').map(t => t.evidence));
      assert(ev.has('OrDeR_7077'), 'Should match OrDeR_7077');
      assert(ev.has('rsp_peinject'), 'Should match rsp_peinject');
      assert(ev.has('rsp_runscript'), 'Should match rsp_runscript');
      assert(ev.has('rsp_kill'), 'Should match rsp_kill');
      assert(ev.size === 4, 'Should match exactly 4 distinct, got ' + ev.size);
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: scans .py files (cross-ecosystem campaigns)', async () => {
    const dir = mkPkg('python-bait', { 'main.py': '# checkmarx.zone is the C2\nprint("hello")' });
    try {
      const threats = await scanIocStrings(dir);
      const m = threats.filter(t => t.evidence === 'checkmarx.zone');
      assert(m.length === 1, '.py files must be scanned, got ' + m.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: scans node_modules dependencies', async () => {
    const dir = mkPkg('host', { 'index.js': '// nothing here' });
    const depDir = path.join(dir, 'node_modules', 'evil-dep');
    fs.mkdirSync(depDir, { recursive: true });
    fs.writeFileSync(path.join(depDir, 'package.json'), JSON.stringify({ name: 'evil-dep', version: '1.0.0' }));
    fs.writeFileSync(path.join(depDir, 'index.js'), 'const k = "Extension.SubRoutine";\nmodule.exports = k;');
    try {
      const threats = await scanIocStrings(dir);
      const m = threats.filter(t => t.evidence === 'Extension.SubRoutine');
      assert(m.length === 1, 'Should detect IOC inside node_modules dep, got ' + m.length);
      assert(m[0].file.includes('node_modules'), 'File path should reference node_modules');
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: clean package returns no findings (zero FP)', async () => {
    const dir = mkPkg('clean', {
      'index.js': 'const lodash = require("lodash");\nmodule.exports = lodash.kebabCase;',
      'lib/util.js': 'function add(a,b){return a+b;}\nmodule.exports = add;'
    });
    try {
      const threats = await scanIocStrings(dir);
      assert(threats.length === 0, 'Clean code must produce 0 findings, got ' + threats.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: skips non-source files (.json, .md)', async () => {
    const dir = mkPkg('docs', {
      'README.md': 'See OrDeR_7077 in the writeup',
      'config.json': '{"note":"OrDeR_7077 is the Axios XOR key"}'
    });
    try {
      const threats = await scanIocStrings(dir);
      assert(threats.length === 0, 'IOCs in docs/config should NOT fire (would FP on writeups), got ' + threats.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: per-scan total findings cap', async () => {
    // Synthetic stress: build a single large file containing many IOCs.
    // Cap is per-file at 10 and per-scan at 200, so a single file maxes at 10.
    let body = '';
    for (let i = 0; i < 100; i++) body += 'const x' + i + ' = "OrDeR_7077";\n';
    const dir = mkPkg('flood', { 'index.js': body });
    try {
      const threats = await scanIocStrings(dir);
      // Same string in same file = collapsed to 1 finding (Set-based dedup per file).
      const ord = threats.filter(t => t.evidence === 'OrDeR_7077');
      assert(ord.length === 1, 'Repeats of same IOC in one file dedupe to 1, got ' + ord.length);
      assert(threats.length <= MAX_TOTAL_FINDINGS, 'Total findings within cap');
    } finally { rmrf(dir); }
  });

  await asyncTest('IOC-STR: target path that does not exist returns empty', async () => {
    const threats = await scanIocStrings('/nonexistent/path/blah');
    assert(threats.length === 0, 'Missing target returns empty, got ' + threats.length);
  });

  // ── 2026-08..11 campaigns (CHAINDROP, tensorlake, SubQuery, LiteLLM, Claude Code
  // extension, GHSA 2026-10-26..28 wave, GhostAction, node-ipc) ──
  // Expected campaign/severity come from the published research cited in
  // iocs/string-iocs.yaml, not from scanner output. Each artifact is planted the
  // way the malware carries it (string literal in a JS/Python source); the
  // negative twin changes one character, which must not fire: matching is an
  // exact substring, a near-miss is not the campaign.
  const CAMPAIGN_2026_Q4 = [
    ['thebeautifulmarchoftime', 'chaindrop-2026-08', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients', 'chaindrop-2026-08', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['awqhnjewqjkl.icu', 'chaindrop-2026-08', 'CRITICAL', 'setup.mjs'],
    ['npm-cache.com', 'chaindrop-2026-08', 'HIGH', 'setup.mjs'],
    ['0xE1f2395ee43e45A1556EC6438a88c31B83493103', 'chaindrop-2026-08', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['0xe1f2395ee43e45a1556ec6438a88c31b83493103', 'chaindrop-2026-08', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['iseekaigogo.com', 'tensorlake-2026-10', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['0xb614155Fd88114d40549b259457Bcf921Df091B9', 'tensorlake-2026-10', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['0xb614155fd88114d40549b259457bcf921df091b9', 'tensorlake-2026-10', 'CRITICAL', 'lib/Math_Symbol.js'],
    ['WORMTAG', 'tensorlake-2026-10', 'CRITICAL', 'lib/setup.mjs'],
    ['ci-artifacts.dev', 'subql-2026-10', 'CRITICAL', 'lib/readers/manifest-cache.js'],
    ['tmp.ts018051808.lock', 'subql-2026-10', 'CRITICAL', 'lib/readers/manifest-cache.js'],
    ['litellm.dev/healthcheck', 'litellm-2026-10', 'CRITICAL', 'litellm/cook.py'],
    ['134.209.82.225', 'claude-code-ext-2026-10', 'CRITICAL', 'extension.js'],
    ['185.158.107.175', 'depconf-beacon-2026-10', 'CRITICAL', 'beacon.cjs'],
    ['13.140.137.222', 'depconf-beacon-2026-10', 'CRITICAL', 'beacon.cjs'],
    ['networkservicesupp.flashhub.net', 'xmrig-npm-2026-10', 'CRITICAL', 'scripts/helper.js'],
    ['amplify-gursha-dev-121835-deployment', 'xmrig-npm-2026-10', 'CRITICAL', 'scripts/helper.js'],
    ['cdn-status.mulderitsme.net', 'csvflow-2026-10', 'CRITICAL', 'install.js'],
    ['0x9c0a507300fd902787bb193d80fca5ce6e1bff9a', 'claudeopus-stego-2026-10', 'CRITICAL', 'loader.py'],
    ['193.32.204.199', 'ghostaction-2026-10', 'CRITICAL', 'collect.js'],
    ['sh.azurestaticprovider.net', 'node-ipc-2026-05', 'CRITICAL', 'node-ipc.cjs'],
    ['qZ8pL3vNxR9wKmTyHbVcFgDsJaEoUi', 'node-ipc-2026-05', 'CRITICAL', 'node-ipc.cjs'],
  ];

  for (const [ioc, campaign, severity, rel] of CAMPAIGN_2026_Q4) {
    await asyncTest(`IOC-STR 2026-Q4: "${ioc.slice(0, 32)}" fires as ${campaign}/${severity}`, async () => {
      const body = rel.endsWith('.py')
        ? `TARGET = "${ioc}"\n`
        : `const target = "${ioc}";\nmodule.exports = target;\n`;
      const dir = mkPkg('campaign-sample', { [rel]: body });
      try {
        const hits = (await scanIocStrings(dir)).filter(t => t.type === 'ioc_string_match' && t.evidence === ioc);
        assert(hits.length === 1, `expected exactly 1 finding for ${ioc}, got ${hits.length}`);
        assert(hits[0].campaign === campaign, `campaign: expected ${campaign}, got ${hits[0].campaign}`);
        assert(hits[0].severity === severity, `severity: expected ${severity}, got ${hits[0].severity}`);
        assert(hits[0].file.replace(/\\/g, '/') === rel, `file: expected ${rel}, got ${hits[0].file}`);
      } finally { rmrf(dir); }
    });

    await asyncTest(`IOC-STR 2026-Q4: one-character near-miss of "${ioc.slice(0, 32)}" does not fire`, async () => {
      const last = ioc[ioc.length - 1];
      const nearMiss = ioc.slice(0, -1) + (last === 'x' ? 'y' : 'x');
      const dir = mkPkg('near-miss', { [rel]: `const target = "${nearMiss}";\n` });
      try {
        const hits = (await scanIocStrings(dir)).filter(t => t.type === 'ioc_string_match');
        assert(hits.length === 0, `near-miss ${nearMiss} must not fire, got ${hits.map(h => h.evidence).join(',')}`);
      } finally { rmrf(dir); }
    });
  }

  await asyncTest('IOC-STR 2026-Q4: the real macOS daemon label com.apple.sysmond does not fire', async () => {
    // The trojanized Claude Code extension used com.apple.sysmond as a fake
    // LaunchAgent label, but it is also the label of a genuine macOS daemon:
    // it was deliberately left out of the IOC list (inclusion criterion #4).
    const dir = mkPkg('mac-monitor', {
      'index.js': 'const label = "com.apple.sysmond";\nmodule.exports = { label, user: "svc-telemetry" };\n'
    });
    try {
      const hits = (await scanIocStrings(dir)).filter(t => t.type === 'ioc_string_match');
      assert(hits.length === 0, `benign sysmond reference must not fire, got ${hits.map(h => h.evidence).join(',')}`);
    } finally { rmrf(dir); }
  });
}

module.exports = { runIocStringsTests };
