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
}

module.exports = { runIocStringsTests };
