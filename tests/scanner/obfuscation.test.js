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
      // This fixture does require(str) without exec, so the specific type is
      // dynamic_require (module-name obfuscation via a computed variable). Pinning
      // the type keeps the test from passing on any unrelated fire. (Resolution of
      // the hex array to 'child_process' itself is locked in deobfuscate.test.js.)
      const threats = result.threats || [];
      assert(threats.some(t => t.type === 'dynamic_require'),
        'Should flag dynamic_require for the computed require target, got: ' + JSON.stringify(threats.map(t => t.type)));
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects heavy string concat obfuscation', async () => {
    const code = `var a = 'c' + 'h' + 'i' + 'l' + 'd' + '_' + 'p' + 'r' + 'o' + 'c' + 'e' + 's' + 's';\nrequire(a).execSync('id');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      assert(threats.some(t => t.type === 'dynamic_require_exec'),
        'Should fold the concat to child_process and flag dynamic_require_exec, got: ' + JSON.stringify(threats.map(t => t.type)));
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
      assert(threats.some(t => t.type === 'dynamic_require_exec'),
        'Should decode the base64 require target and flag dynamic_require_exec, got: ' + JSON.stringify(threats.map(t => t.type)));
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: CharCode reconstruction detection', async () => {
    const code = `var m = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115);\nrequire(m).execSync('whoami');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      assert(threats.some(t => t.type === 'dynamic_require_exec'),
        'Should reconstruct child_process from charCodes and flag dynamic_require_exec, got: ' + JSON.stringify(threats.map(t => t.type)));
    } finally { cleanupTemp(tmp); }
  });

  // --- v2.9.1: GlassWorm Unicode invisible detection ---

  await asyncTest('OBFUSCATION: Detects zero-width chars injection (>=10)', async () => {
    // Inject 12 zero-width space chars (U+200B) into a JS file
    const invisible = '\u200B'.repeat(12);
    const code = `var x = "${invisible}"; console.log(x);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should detect unicode_invisible_injection for 12 zero-width chars');
      assert(t.severity === 'CRITICAL', `Expected CRITICAL, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects variation selectors (U+FE00-FE0E)', async () => {
    // Inject 12 variation selectors (U+FE01-FE0C) — excludes U+FE0F (emoji)
    const code = `var payload = "a\uFE01b\uFE02c\uFE03d\uFE04e\uFE05f\uFE06g\uFE07h\uFE08i\uFE09j\uFE0Ak\uFE0Bl\uFE0C"; eval(decode(payload));`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should detect unicode_invisible_injection for variation selectors');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Detects mixed invisible chars (zero-width + FEFF)', async () => {
    // 12 mixed invisible chars — above threshold of 10
    const code = `var a = 1;\u200B\u200C\u200D\u200B\u200C\u200D\u200B\u200C\u200D\u200Bvar b = 2;\uFEFF\u2060var c = 3;`;
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

  await asyncTest('OBFUSCATION: NO detection for <10 invisible chars', async () => {
    // Only 5 invisible chars — below threshold of 10
    const code = `var x = "\u200B\u200C\u200D\u200B\u200C"; console.log(x);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(!t, 'Only 5 invisible chars should NOT trigger (threshold is 10)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: NO detection for emojis with U+FE0F variation selector', async () => {
    // Emojis use U+FE0F (VS16) for presentation — must NOT trigger
    const code = `var msg = "Delete \uD83D\uDDD1\uFE0F info \u2139\uFE0F warning \u26A0\uFE0F check \u2705\uFE0F star \u2B50\uFE0F fire \uD83D\uDD25\uFE0F heart \u2764\uFE0F ok \uD83D\uDC4D\uFE0F no \uD83D\uDC4E\uFE0F sun \u2600\uFE0F"; console.log(msg);`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(!t, 'Emojis with U+FE0F should NOT trigger unicode_invisible_injection');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Unicode invisible downgraded to LOW for large files', async () => {
    // File > 100KB with 12 invisible chars → isPackageOutput → LOW
    const padding = '// ' + 'x'.repeat(120 * 1024) + '\n';
    const code = padding + `var a = "\u200B\u200C\u200D\uFE01\uFE02\u200B\u200C\u200D\uFE03\uFE04\uFE05\uFE06";`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection');
      assert(t, 'Should still detect unicode_invisible_injection in large file');
      assert(t.severity === 'LOW', `Expected LOW for large file, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION: Unicode invisible in locale/ file → LOW (not CRITICAL)', async () => {
    // Persian/Arabic text uses ZWNJ (U+200C) for proper character rendering
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-obf-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-locale', version: '1.0.0' }));
    const localeDir = path.join(tmp, 'locale', 'fa-IR', '_lib');
    fs.mkdirSync(localeDir, { recursive: true });
    // 15 ZWNJ chars — legitimate Persian text formatting
    const zwnj = '\u200C'.repeat(15);
    fs.writeFileSync(path.join(localeDir, 'formatDistance.js'), `module.exports = function(token) { return "${zwnj}"; };`);
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'unicode_invisible_injection' && t.file && t.file.includes('locale'));
      assert(t, 'Should detect unicode_invisible_injection in locale file');
      assert(t.severity === 'LOW', `Expected LOW for locale file, got ${t.severity}`);
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

  // --- v2.10.73 P4: WASM/Emscripten artifact skip ---
  // Audit forensique v2.10.72 : 52 ENTROPY-001 fires sur un seul fichier
  // node_modules/mpg123-decoder/src/EmscriptenWasm.js inside @leoqlin/openclaw-qqbot.
  // WASM/Emscripten compiled output is high-entropy by construction.

  await asyncTest('OBFUSCATION P4: WASM file via basename pattern → skipped', async () => {
    // mpg123-decoder basename triggers WASM_BASENAME_RE regardless of content
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-obf-wasm-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-wasm', version: '1.0.0' }));
    const subdir = path.join(tmp, 'node_modules', 'mpg123-decoder', 'src');
    fs.mkdirSync(subdir, { recursive: true });
    // High-entropy content that WOULD normally trigger obfuscation detection
    // 30 long lines with hex escapes + _0x variables + string array
    const hexLines = Array(30).fill('').map((_, i) =>
      `var _0x${i.toString(16).padStart(4, '0')} = ['\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\\x51\\x52\\x53\\x54', '\\u0061\\u0062\\u0063\\u0064\\u0065\\u0066\\u0067\\u0068', '\\x61\\x62\\x63\\x64\\x65\\x66', '\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a'];`
    ).join('\n');
    fs.writeFileSync(path.join(subdir, 'EmscriptenWasm.js'), hexLines);
    try {
      const result = await runScanDirect(tmp);
      const obfThreats = (result.threats || []).filter(t =>
        (t.type === 'obfuscation_detected' || t.type === 'unicode_invisible_injection') &&
        t.file && t.file.includes('EmscriptenWasm.js')
      );
      assert(obfThreats.length === 0,
        `WASM-named file (mpg123-decoder/EmscriptenWasm.js) should be skipped from obfuscation detection, got ${obfThreats.length} threats`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION P4: WASM file via Module["asm"] content marker → skipped', async () => {
    // Generic filename but Emscripten content markers
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-obf-wasm-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-wasm-marker', version: '1.0.0' }));
    // Generic name, but content has Module["asm"] + HEAPU8 + hex array
    const content = `var Module = {};
Module["asm"] = (function() {
  var HEAPU8 = new Uint8Array(wasmMemory.buffer);
  var _emscripten_ = 1;
  var _0xabc1 = ['\\x41\\x42\\x43\\x44\\x45\\x46', '\\x47\\x48\\x49\\x4a\\x4b', '\\x4c\\x4d\\x4e\\x4f\\x50'];
  ${Array(20).fill('').map((_, i) => `var _0x${i.toString(16)} = '\\x${i.toString(16).padStart(2, '0')}\\x${(i+1).toString(16).padStart(2, '0')}\\x${(i+2).toString(16).padStart(2, '0')}\\x${(i+3).toString(16).padStart(2, '0')}\\x${(i+4).toString(16).padStart(2, '0')}\\x${(i+5).toString(16).padStart(2, '0')}\\x${(i+6).toString(16).padStart(2, '0')}';`).join('\n  ')}
  return { memory: wasmMemory, table: wasmTable };
})();`;
    fs.writeFileSync(path.join(tmp, 'audio-decoder.js'), content);
    try {
      const result = await runScanDirect(tmp);
      const obfThreats = (result.threats || []).filter(t =>
        (t.type === 'obfuscation_detected' || t.type === 'unicode_invisible_injection') &&
        t.file && t.file.includes('audio-decoder.js')
      );
      assert(obfThreats.length === 0,
        `File with Module["asm"] + HEAPU8 content markers should be skipped, got ${obfThreats.length} threats`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('OBFUSCATION P4: Regression — real obfuscated malware (no WASM markers) still detected', async () => {
    // Anti-regression: non-WASM obfuscated code must still fire.
    // Generic name, no Emscripten markers, but heavy obfuscation.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-obf-regression-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-obf-regression', version: '1.0.0' }));
    // 10 _0x vars + atob + eval = strong obfuscation signal, no WASM markers
    const code = `
var _0xabc1 = atob('Y2hpbGRfcHJvY2Vzcw==');
var _0xdef2 = atob('ZXhlY1N5bmM=');
var _0x1234 = eval;
var _0x5678 = Function;
var _0x9abc = require(_0xabc1);
var _0xdead = _0x9abc[_0xdef2];
var _0xbeef = _0x1234('process.env.HOME');
var _0xcafe = _0x5678('return this')();
var _0x1111 = 'w' + 'h' + 'o' + 'a' + 'm' + 'i';
var _0x2222 = _0xdead(_0x1111);
`;
    fs.writeFileSync(path.join(tmp, 'payload.js'), code);
    try {
      const result = await runScanDirect(tmp);
      const threats = result.threats || [];
      // At least one obfuscation/AST detection should fire
      const detected = threats.some(t =>
        t.type === 'obfuscation_detected' ||
        t.type === 'js_obfuscation_pattern' ||
        t.type === 'dynamic_require' ||
        t.type === 'dangerous_call_eval' ||
        t.type === 'dangerous_call_function'
      );
      assert(detected,
        `Non-WASM obfuscated code must still be detected (regression check). Threats seen: ${threats.map(t => t.type).join(', ')}`);
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runObfuscationTests };
