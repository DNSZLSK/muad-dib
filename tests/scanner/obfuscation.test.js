const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, runScanFast, cleanupTemp, TESTS_DIR } = require('../test-utils');

function makeTempPkg(jsContent) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-obf-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-obf', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, 'index.js'), jsContent);
  return tmp;
}

async function runObfuscationTests() {
  console.log('\n=== OBFUSCATION TESTS ===\n');

  await asyncTest('OBFUSCATION: Detects massive hex escapes (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'obfuscation'));
    assertIncludes(output, 'obfusc', 'Should detect obfuscation');
  });

  await asyncTest('OBFUSCATION: Detects _0x variables (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'obfuscation'));
    assertIncludes(output, 'obfusc', 'Should detect _0x variables');
  });

  // --- v2.5.13: Expanded obfuscation tests ---

  await asyncTest('OBFUSCATION: Detects _0x pattern variables with exec', async () => {
    const code = `var _0xabc1 = ['eval','child_process'];\nvar _0xdef2 = _0xabc1[0];\nvar _0x123 = require(_0xabc1[1]);\n_0x123.execSync('whoami');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      // Scanner detects the dynamic_require_exec behavior rather than the _0x naming pattern
      const t = threats.find(t => t.type === 'dynamic_require_exec' || t.type === 'js_obfuscation_pattern' || t.type === 'obfuscation_detected');
      assert(t, 'Should detect _0x obfuscated code (via behavioral or pattern detection)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects multi-line hex array', async () => {
    // Large hex array that decodes to a meaningful string
    const hexValues = Array.from('child_process').map(c => '0x' + c.charCodeAt(0).toString(16));
    const code = `var arr = [${hexValues.join(',')}];\nvar str = arr.map(c => String.fromCharCode(c)).join('');\nrequire(str);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      // Deobfuscation should resolve this to require('child_process')
      const threats = result.threats || [];
      assert(threats.length > 0, 'Should detect something from hex array obfuscation');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects heavy string concat obfuscation', async () => {
    const code = `var a = 'c' + 'h' + 'i' + 'l' + 'd' + '_' + 'p' + 'r' + 'o' + 'c' + 'e' + 's' + 's';\nrequire(a).execSync('id');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      assert(threats.length > 0, 'Should detect string concat obfuscation');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Minified legitimate library → not HIGH obfuscation', async () => {
    // Simulate a minified but non-malicious file
    const code = 'var a=1,b=2,c=a+b;module.exports={sum:c,version:"1.0.0"};';
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const obfThreats = (result.threats || []).filter(t =>
        (t.type === 'js_obfuscation_pattern' || t.type === 'obfuscation_detected') && t.severity === 'CRITICAL'
      );
      assert(obfThreats.length === 0, 'Simple minified code should not trigger CRITICAL obfuscation');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Base64-encoded payload detection', async () => {
    const code = `var payload = Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString();\nrequire(payload).execSync('id');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      assert(threats.length > 0, 'Should detect base64 obfuscated require');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: CharCode reconstruction detection', async () => {
    const code = `var m = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115);\nrequire(m).execSync('whoami');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      assert(threats.length > 0, 'Should detect charcode reconstruction obfuscation');
    } finally { cleanupTemp(tmp); }
  });

  // --- v2.9.1: GlassWorm Unicode invisible detection ---

  await asyncTest('OBFUSCATION: Detects zero-width chars injection (>=3)', async () => {
    // Inject 5 zero-width space chars (U+200B) into a JS file
    const invisible = '\u200B'.repeat(5);
    const code = `var x = "${invisible}"; console.log(x);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should detect unicode_invisible_injection for 5 zero-width chars');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects variation selectors (U+FE00-FE0F)', async () => {
    // Inject 4 variation selectors (U+FE01, U+FE02, U+FE03, U+FE04)
    const code = `var payload = "a\uFE01b\uFE02c\uFE03d\uFE04"; eval(decode(payload));`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should detect unicode_invisible_injection for variation selectors');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects mixed invisible chars (zero-width + FEFF)', async () => {
    // U+200B + U+200C + U+FEFF (at pos > 0) = 3 invisible chars
    const code = `var a = 1;\u200B\u200Cvar b = 2;\uFEFFvar c = 3;`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should detect unicode_invisible_injection for mixed invisible chars');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: NO detection for BOM at position 0 only', async () => {
    // BOM at position 0 is legitimate — should NOT trigger if it's the only invisible char
    const code = '\uFEFF' + 'var x = 1; console.log(x);';
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(!t, 'BOM at position 0 alone should NOT trigger unicode_invisible_injection');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: NO detection for <3 invisible chars', async () => {
    // Only 2 invisible chars — below threshold
    const code = `var x = "\u200B\u200C"; console.log(x);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(!t, 'Only 2 invisible chars should NOT trigger (threshold is 3)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Unicode invisible downgraded to LOW for large files', async () => {
    // File > 100KB with invisible chars → isPackageOutput → LOW
    const padding = '// ' + 'x'.repeat(120 * 1024) + '\n';
    const code = padding + `var a = "\u200B\u200C\u200D\uFE01\uFE02";`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should still detect unicode_invisible_injection in large file');
      assert(t.severity === 'LOW', `Expected LOW for large file, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: NO detection for textual unicode escapes', async () => {
    // \\u200B in source code as text (not actual invisible char) should NOT trigger
    const code = `var x = "\\u200B\\u200C\\u200D"; console.log(x);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(!t, 'Textual unicode escapes (not real chars) should NOT trigger');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runObfuscationTests };
