const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert } = require('../test-utils');
const { scanAntiForensic, analyzeFile } = require('../../src/scanner/anti-forensic.js');

async function runAntiForensicTests() {
  console.log('\n=== ANTI-FORENSIC AST TESTS ===\n');

  function mkPkg(files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-af-'));
    for (const [rel, body] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, body);
    }
    return dir;
  }
  function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } }

  // ── Pattern detection unit tests (analyzeFile) ──

  test('AF: XOR loop with charCodeAt is detected', () => {
    const code = 'const k = "OrDeR_7077"; for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ k.charCodeAt(i % k.length);';
    const r = analyzeFile(code);
    assert(r && r.evidence.xorLoop, 'XOR loop must be detected, got ' + JSON.stringify(r));
  });

  test('AF: XOR with literal number operand inside loop is detected', () => {
    const code = 'for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ 0x42;';
    const r = analyzeFile(code);
    assert(r && r.evidence.xorLoop, 'XOR with literal number must fire');
  });

  test('AF: XOR outside any loop is NOT detected (single op in app code)', () => {
    const code = 'const flag = a.value ^ 0x10; module.exports = flag;';
    const r = analyzeFile(code);
    assert(!r || !r.evidence.xorLoop, 'Lone XOR outside loop should not fire');
  });

  test('AF: fs.unlinkSync(__filename) is detected as self-delete', () => {
    const code = 'const fs = require("fs"); fs.unlinkSync(__filename);';
    const r = analyzeFile(code);
    assert(r && r.evidence.selfDelete && r.evidence.selfDelete.kind === 'unlink', 'self-delete via __filename must fire');
  });

  test('AF: fs.rename(__filename, "x.bak") is detected as self-delete', () => {
    const code = 'require("fs").renameSync(__filename, "/tmp/installer.bak");';
    const r = analyzeFile(code);
    assert(r && r.evidence.selfDelete && r.evidence.selfDelete.kind === 'rename', 'rename to .bak must fire');
  });

  test('AF: fs.writeFileSync to package.md is detected as decoy write', () => {
    const code = 'require("fs").writeFileSync("package.md", "# decoy");';
    const r = analyzeFile(code);
    assert(r && r.evidence.decoyWrite, 'writeFile to package.md must fire');
  });

  test('AF: fs.writeFileSync to README.md does NOT count as decoy when only signal', () => {
    // Single decoy write alone is benign; the rule needs 2+ patterns to escalate
    const code = 'require("fs").writeFileSync("README.md", "# docs");';
    const r = analyzeFile(code);
    assert(r && r.evidence.decoyWrite, 'decoy write detected (will not fire alone)');
    assert(r.count === 1, 'Only 1 pattern → rule does not escalate');
  });

  // ── Scanner-level tests (scanAntiForensic) ──

  await asyncTest('AF: full pattern (3 of 3) → CRITICAL anti_forensic_xor_autodelete', async () => {
    const code =
      'const fs = require("fs");\n' +
      'const KEY = "OrDeR_7077";\n' +
      'const PAYLOAD = Buffer.from("...","base64");\n' +
      'const out = Buffer.alloc(PAYLOAD.length);\n' +
      'for (let i = 0; i < PAYLOAD.length; i++) out[i] = PAYLOAD[i] ^ KEY.charCodeAt(i % KEY.length);\n' +
      '(new Function(out.toString()))();\n' +
      'fs.writeFileSync("package.md", "# moved");\n' +
      'fs.unlinkSync(__filename);\n';
    const dir = mkPkg({ 'index.js': code, 'package.json': '{"name":"csec-mock","version":"1.0.0","main":"index.js"}' });
    try {
      const t = await scanAntiForensic(dir);
      const crit = t.filter(x => x.type === 'anti_forensic_xor_autodelete');
      assert(crit.length === 1, 'Should fire 1 CRITICAL, got ' + crit.length);
      assert(crit[0].severity === 'CRITICAL', 'Must be CRITICAL');
    } finally { rmrf(dir); }
  });

  await asyncTest('AF: 2 of 3 (XOR + self-delete, no decoy) → HIGH anti_forensic_partial', async () => {
    const code =
      'const fs = require("fs");\n' +
      'const k = "kk";\n' +
      'for (let i = 0; i < 10; i++) buf[i] = buf[i] ^ k.charCodeAt(0);\n' +
      'fs.unlinkSync(__filename);\n';
    const dir = mkPkg({ 'index.js': code, 'package.json': '{"name":"x","version":"1.0.0"}' });
    try {
      const t = await scanAntiForensic(dir);
      const partial = t.filter(x => x.type === 'anti_forensic_partial');
      const crit = t.filter(x => x.type === 'anti_forensic_xor_autodelete');
      assert(crit.length === 0, 'Must NOT fire CRITICAL with only 2 patterns');
      assert(partial.length === 1, 'Should fire 1 HIGH partial, got ' + partial.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('AF: 1 of 3 (only XOR) does NOT fire', async () => {
    const code = 'const k = "key"; for (let i = 0; i < 10; i++) buf[i] = buf[i] ^ k.charCodeAt(0);';
    const dir = mkPkg({ 'index.js': code, 'package.json': '{"name":"x","version":"1.0.0"}' });
    try {
      const t = await scanAntiForensic(dir);
      assert(t.length === 0, 'Single-signal must not fire, got ' + t.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('AF: clean lib (lodash-style) produces 0 findings', async () => {
    const code = 'function kebabCase(s) { return s.replace(/[A-Z]/g, m => "-" + m.toLowerCase()).replace(/^-/, ""); } module.exports = { kebabCase };';
    const dir = mkPkg({ 'index.js': code, 'package.json': '{"name":"x","version":"1.0.0"}' });
    try {
      const t = await scanAntiForensic(dir);
      assert(t.length === 0, 'Clean code must not fire, got ' + t.length);
    } finally { rmrf(dir); }
  });

  await asyncTest('AF: scanner walks node_modules', async () => {
    const dir = mkPkg({ 'package.json': '{"name":"host","version":"1.0.0"}' });
    const evilDir = path.join(dir, 'node_modules', 'evil');
    fs.mkdirSync(evilDir, { recursive: true });
    fs.writeFileSync(path.join(evilDir, 'package.json'), '{"name":"evil","version":"1.0.0"}');
    fs.writeFileSync(path.join(evilDir, 'setup.js'),
      'const fs = require("fs");\n' +
      'for (let i = 0; i < 10; i++) buf[i] = buf[i] ^ 0x42;\n' +
      'fs.writeFileSync("package.md", "x");\n' +
      'fs.unlinkSync(__filename);\n');
    try {
      const t = await scanAntiForensic(dir);
      assert(t.some(x => x.type === 'anti_forensic_xor_autodelete'), 'Should fire on dep inside node_modules');
    } finally { rmrf(dir); }
  });
}

module.exports = { runAntiForensicTests };
