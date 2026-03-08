const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScanDirect, TESTS_DIR } = require('../test-utils')
const { calculateShannonEntropy, scanEntropy } = require('../../src/scanner/entropy.js');

async function runEntropyTests() {
  console.log('\n=== ENTROPY TESTS ===\n');

  test('ENTROPY: Normal English text has low entropy (<4.5)', () => {
    const text = 'This is a normal English sentence that should have relatively low Shannon entropy.';
    const entropy = calculateShannonEntropy(text);
    assert(entropy < 4.5, 'Normal text entropy should be < 4.5, got ' + entropy.toFixed(2));
  });

  test('ENTROPY: Base64 string has high entropy (>5.0)', () => {
    const b64 = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBzaG91bGQgaGF2ZSBoaWdoIGVudHJvcHkgYW5kIHRyaWdnZXIgdGhlIHNjYW5uZXI=';
    const entropy = calculateShannonEntropy(b64);
    assert(entropy > 5.0, 'Base64 entropy should be > 5.0, got ' + entropy.toFixed(2));
  });

  test('ENTROPY: Hex string has high entropy (>3.0)', () => {
    const hex = '4a6f686e20446f6520736179732068656c6c6f20746f20746865207365637572697479207363616e6e6572206279206372656174696e67206120686578';
    const entropy = calculateShannonEntropy(hex);
    assert(entropy > 3.0, 'Hex entropy should be > 3.0, got ' + entropy.toFixed(2));
  });

  test('ENTROPY: scanEntropy on normal.js returns 0 findings', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const normalThreats = threats.filter(function(t) { return t.file === 'normal.js'; });
    assert(normalThreats.length === 0, 'Normal file should have 0 entropy findings, got ' + normalThreats.length);
  });

  test('ENTROPY: scanEntropy on high-entropy.js finds string-level threats', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const highThreats = threats.filter(function(t) {
      return t.file === 'high-entropy.js' && t.type === 'high_entropy_string';
    });
    assert(highThreats.length > 0, 'High-entropy strings should trigger findings, got ' + highThreats.length);
  });

  test('ENTROPY: Short high-entropy string (<50 chars) does NOT trigger', () => {
    const shortStr = 'xK9mQ2pLwR7vN5tY';
    const entropy = calculateShannonEntropy(shortStr);
    assert(entropy > 3.5, 'Short string should still have high entropy: ' + entropy.toFixed(2));
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const normalStringThreats = threats.filter(function(t) {
      return t.file === 'normal.js' && t.type === 'high_entropy_string';
    });
    assert(normalStringThreats.length === 0, 'Short strings should not trigger, got ' + normalStringThreats.length);
  });

  test('ENTROPY: No file-level entropy scanning (removed)', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const fileThreats = threats.filter(function(t) { return t.type === 'high_entropy_file'; });
    assert(fileThreats.length === 0, 'File-level entropy scanning should be removed, got ' + fileThreats.length + ' findings');
  });

  test('ENTROPY: .min.js file does NOT trigger', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const minThreats = threats.filter(function(t) { return t.file.endsWith('.min.js'); });
    assert(minThreats.length === 0, '.min.js file should be skipped, got ' + minThreats.length + ' findings');
  });

  test('ENTROPY: __compiled__/ files do NOT trigger', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const compiledThreats = threats.filter(function(t) { return t.file.includes('__compiled__'); });
    assert(compiledThreats.length === 0, '__compiled__/ files should be skipped, got ' + compiledThreats.length + ' findings');
  });

  test('ENTROPY: Legit minified code does NOT trigger', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const legitThreats = threats.filter(function(t) { return t.file === 'legit-minified.js'; });
    assert(legitThreats.length === 0, 'Legitimate minified code should not trigger, got ' + legitThreats.length + ' findings');
  });

  test('ENTROPY: _0x hex variable pattern triggers js_obfuscation_pattern', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const obfThreats = threats.filter(function(t) {
      return t.file === 'obfuscated.js' && t.type === 'js_obfuscation_pattern';
    });
    assert(obfThreats.length > 0, 'Obfuscated _0x code should trigger js_obfuscation_pattern, got ' + obfThreats.length);
    assert(obfThreats[0].severity === 'HIGH', 'js_obfuscation_pattern should be HIGH severity');
  });

  test('ENTROPY: Long base64 payload triggers js_obfuscation_pattern', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const b64Threats = threats.filter(function(t) {
      return t.file === 'long-base64-payload.js' && t.type === 'js_obfuscation_pattern';
    });
    assert(b64Threats.length > 0, 'Long base64 payload should trigger js_obfuscation_pattern, got ' + b64Threats.length);
  });

  test('ENTROPY: Rule MUADDIB-ENTROPY-003 exists', () => {
    const { getRule } = require('../../src/rules/index.js');
    const rule = getRule('js_obfuscation_pattern');
    assert(rule.id === 'MUADDIB-ENTROPY-003', 'Rule ID should be MUADDIB-ENTROPY-003, got ' + rule.id);
    assert(rule.mitre === 'T1027.002', 'MITRE should be T1027.002, got ' + rule.mitre);
  });

  test('ENTROPY: Playbook for js_obfuscation_pattern exists', () => {
    const { getPlaybook } = require('../../src/response/playbooks.js');
    const pb = getPlaybook('js_obfuscation_pattern');
    assert(pb && pb.length > 10, 'Playbook should exist for js_obfuscation_pattern');
  });

  // --- False positive reduction tests ---

  console.log('\n=== FALSE POSITIVE REDUCTION TESTS ===\n');

  await asyncTest('FP-AST: Function("return this") is not flagged', async () => {
    const result = await runScanDirect(path.join(TESTS_DIR, 'ast-fp', 'constant-eval'));
    const fnThreats = result.threats.filter(t => t.type === 'dangerous_call_function');
    assert(fnThreats.length === 0, 'Constant Function("return this") should NOT be flagged, got: ' + JSON.stringify(fnThreats));
  });

  await asyncTest('FP-AST: eval("literal") is LOW not HIGH', async () => {
    const result = await runScanDirect(path.join(TESTS_DIR, 'ast-fp', 'constant-eval'));
    const evalThreats = result.threats.filter(t => t.type === 'dangerous_call_eval');
    assert(evalThreats.length > 0, 'Should detect eval(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(evalThreats[0].severity === 'LOW', 'Constant eval() should be LOW, got ' + evalThreats[0].severity);
  });

  await asyncTest('FP-AST: eval(variable) remains HIGH', async () => {
    const result = await runScanDirect(path.join(TESTS_DIR, 'ast-fp', 'dynamic-eval'));
    const evalThreats = result.threats.filter(t => t.type === 'dangerous_call_eval');
    assert(evalThreats.length > 0, 'Should detect eval(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(evalThreats[0].severity === 'HIGH', 'Dynamic eval() should be HIGH, got ' + evalThreats[0].severity);
  });

  await asyncTest('FP-AST: new Function(variable) is MEDIUM (new scope, not eval)', async () => {
    const result = await runScanDirect(path.join(TESTS_DIR, 'ast-fp', 'dynamic-eval'));
    const fnThreats = result.threats.filter(t => t.type === 'dangerous_call_function');
    assert(fnThreats.length > 0, 'Should detect new Function(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(fnThreats[0].severity === 'MEDIUM', 'Dynamic new Function() should be MEDIUM, got ' + fnThreats[0].severity);
  });

  // --- Long string exclusion (FPR P4) ---

  test('FP-ENTROPY: Strings > 1000 chars are excluded (data blobs, not payloads)', () => {
    const entropyDir = path.join(__dirname, '..', 'samples', 'entropy');
    // Create a string > 1000 chars with high entropy
    const longString = 'A'.repeat(500) + 'B'.repeat(300) + 'C'.repeat(201) + 'DEFGH';
    // The scanner should skip strings > 1000 chars entirely
    const { scanEntropy: scan } = require('../../src/scanner/entropy.js');
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-entropy-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
    const longB64 = Buffer.from(require('crypto').randomBytes(800)).toString('base64');
    fs.writeFileSync(path.join(tmpDir, 'index.js'), `const blob = "${longB64}";`);
    const threats = scan(tmpDir);
    const longThreats = threats.filter(t => t.type === 'high_entropy_string');
    assert(longThreats.length === 0, 'Strings > 1000 chars should be excluded, got ' + longThreats.length);
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('FP-ENTROPY: Strings 50-1000 chars still detected', () => {
    const { scanEntropy: scan } = require('../../src/scanner/entropy.js');
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-entropy-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
    // 300 random bytes → ~400 chars of base64, well above MIN_STRING_LENGTH (50) and below MAX_STRING_LENGTH (1000)
    const medB64 = Buffer.from(require('crypto').randomBytes(300)).toString('base64');
    fs.writeFileSync(path.join(tmpDir, 'index.js'), `const payload = "${medB64}";`);
    const threats = scan(tmpDir);
    const entropyThreats = threats.filter(t => t.type === 'high_entropy_string');
    assert(entropyThreats.length > 0, 'Strings 50-1000 chars with high entropy should still be detected, got ' + entropyThreats.length + ' (str len=' + medB64.length + ')');
    fs.rmSync(tmpDir, { recursive: true });
  });

  await asyncTest('FP-OBF: hex escapes alone (unicode table) → no obfuscation alert', async () => {
    const result = await runScanDirect(path.join(TESTS_DIR, 'obfuscation-fp', 'hex-table'));
    const obfThreats = result.threats.filter(t => t.type === 'obfuscation_detected');
    assert(obfThreats.length === 0, 'Hex table alone should not trigger obfuscation, got ' + obfThreats.length);
  });

  await asyncTest('FP-OBF: .min.js with long lines → no obfuscation alert', async () => {
    const result = await runScanDirect(path.join(TESTS_DIR, 'obfuscation-fp', 'minified'));
    const obfThreats = result.threats.filter(t => t.type === 'obfuscation_detected');
    assert(obfThreats.length === 0, 'Minified .min.js should not trigger obfuscation, got ' + obfThreats.length);
  });

  // =============================================
  // v2.5.14: B11 — Fragment cluster detection
  // =============================================

  await asyncTest('ENTROPY B11: 12 short high-entropy strings → fragmented_high_entropy_cluster', async () => {
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-frag-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-frag', version: '1.0.0' }));
    // 12 fragments of 40 chars each with entropy > 5.0 (high-diversity charset)
    fs.writeFileSync(path.join(tmpDir, 'index.js'), `
const a = '2Tv;]"Df+Mo4Vx=_$Fh-Oq6Xz?a&Hj/Qs8Z|Ac';
const b = 'Ch0UzBg/TyAf.Sx@e-Rw?d,Qv>c+Pu=b*Ot<a)N';
const c = 'T|Go:b-U}Hp;c.V!Iq<d/W"Jr=e0X#Ks>f1Y$Lt?';
const d = 'e3^,W%P{ItBm;f4_-X&Q|JuCn<g5z.YxR}KvDo=h';
const e = 'vGuFtEsDrCqBpAo@n?m>l=k<j;i:h9g8f7e6d5c4';
const f = '*[/z4e9j>oCtHyM!R&W+y0a5f:k?pDuIzN"SxX,]';
const g = ';oFzQ(y3g>rI}T+_6jAuL#W.b9mDxO&Z1e<pG{R)';
const h = 'L&]7nH"Y3jD{U/f@wQ+b<sMx^8oI#Z4kE|V0gAxR';
const i = ']:tQ.hE"y9sP-gD![8rO,fC}Z7qN+eB|Y6pM*dA{';
const j = 'nN.kK+hH(eE%bB"_?|y<yY9vV6sS3pP0mM-jJ*gG';
const k = '"bE(hK.nQ4tW:z]@#cF)iL/oR5uX;{^A$dG*jM0p';
const l = '3vyB(kQ7zzF,oU;!dJ0sY?%hN4w]C)lR8{aG-pV<';
console.log(a+b+c+d+e+f+g+h+i+j+k+l);
`);
    try {
      const threats = scanEntropy(tmpDir);
      const t = threats.find(t => t.type === 'fragmented_high_entropy_cluster');
      assert(t, 'Should detect fragmented high entropy cluster');
    } finally { fs.rmSync(tmpDir, { recursive: true }); }
  });

  await asyncTest('ENTROPY B11 negative: 5 short high-entropy strings → NOT enough for cluster', async () => {
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-frag-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-frag', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmpDir, 'index.js'), `
const a = '2Tv;]"Df+Mo4Vx=_$Fh-Oq6Xz?a&Hj/Qs8Z|Ac';
const b = 'Ch0UzBg/TyAf.Sx@e-Rw?d,Qv>c+Pu=b*Ot<a)N';
const c = 'T|Go:b-U}Hp;c.V!Iq<d/W"Jr=e0X#Ks>f1Y$Lt?';
const d = 'e3^,W%P{ItBm;f4_-X&Q|JuCn<g5z.YxR}KvDo=h';
const e = 'vGuFtEsDrCqBpAo@n?m>l=k<j;i:h9g8f7e6d5c4';
console.log(a+b+c+d+e);
`);
    try {
      const threats = scanEntropy(tmpDir);
      const t = threats.find(t => t.type === 'fragmented_high_entropy_cluster');
      assert(!t, 'Should NOT detect cluster with only 5 fragments (threshold is 10)');
    } finally { fs.rmSync(tmpDir, { recursive: true }); }
  });

  // =============================================
  // v2.5.14: B12 — Windowed analysis for long strings
  // =============================================

  await asyncTest('ENTROPY B12: 1500-char string with high-entropy window → detected', async () => {
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-long-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-long', version: '1.0.0' }));
    // Generate payload with high entropy (>6.0) using many distinct printable ASCII chars
    let payload = '';
    for (let i = 0; i < 600; i++) {
      const code = 33 + (i * 7 + 13) % 93;
      let ch = String.fromCharCode(code);
      if (ch === '"' || ch === '\\' || ch === "'" || ch === '`') ch = 'X';
      payload += ch;
    }
    // Pad with 500 chars of A so that window at offset 500 is entirely payload
    const padding = 'A'.repeat(500);
    const combined = padding + payload + padding;
    // Verify combined > MAX_STRING_LENGTH (1000)
    assert(combined.length > 1000, 'Combined should be > 1000 chars');
    // Verify payload entropy > 6.0
    const payloadEntropy = calculateShannonEntropy(payload.slice(0, 500));
    assert(payloadEntropy > 6.0, 'Payload entropy should be > 6.0, got ' + payloadEntropy.toFixed(2));
    fs.writeFileSync(path.join(tmpDir, 'index.js'), 'const data = ' + JSON.stringify(combined) + ';');
    try {
      const threats = scanEntropy(tmpDir);
      const t = threats.find(t => t.type === 'high_entropy_string' && t.message.includes('long string'));
      assert(t, 'Should detect high entropy window in long padded string');
    } finally { fs.rmSync(tmpDir, { recursive: true }); }
  });

  await asyncTest('ENTROPY B12: 1500-char low-entropy string → NOT detected', async () => {
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-long-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-long', version: '1.0.0' }));
    const longLowEntropy = 'AAAA'.repeat(400); // 1600 chars of very low entropy
    fs.writeFileSync(path.join(tmpDir, 'index.js'), `const data = '${longLowEntropy}';\nconsole.log(data);`);
    try {
      const threats = scanEntropy(tmpDir);
      const t = threats.find(t => t.type === 'high_entropy_string' && t.message.includes('long string'));
      assert(!t, 'Long low-entropy string should NOT trigger windowed analysis');
    } finally { fs.rmSync(tmpDir, { recursive: true }); }
  });
}

module.exports = { runEntropyTests };
