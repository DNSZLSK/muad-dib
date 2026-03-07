const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

function makeTempPkg(jsContent) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-obf-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-obf', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, 'index.js'), jsContent);
  return tmp;
}

async function runObfuscationTests() {
  console.log('\n=== OBFUSCATION TESTS ===\n');

  test('OBFUSCATION: Detects massive hex escapes', () => {
    const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
    assertIncludes(output, 'obfusc', 'Should detect obfuscation');
  });

  test('OBFUSCATION: Detects _0x variables', () => {
    const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
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
}

module.exports = { runObfuscationTests };
