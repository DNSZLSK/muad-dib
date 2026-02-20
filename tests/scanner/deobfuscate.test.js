const { test, assert, assertIncludes } = require('../test-utils');
const { deobfuscate } = require('../../src/scanner/deobfuscate.js');

async function runDeobfuscateTests() {
  console.log('\n=== DEOBFUSCATE TESTS ===\n');

  // =====================================================
  // 1. STRING CONCAT FOLDING (5 tests)
  // =====================================================

  test('DEOBFUSCATE: String concat — simple two literals', () => {
    const { code, transforms } = deobfuscate(`const x = 'hello' + ' world';`);
    assertIncludes(code, "'hello world'", 'Should fold two string literals');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    assert(transforms[0].type === 'string_concat', `Expected type string_concat, got ${transforms[0].type}`);
    assertIncludes(transforms[0].before, "'hello' + ' world'", 'Before should show original concat');
    assert(transforms[0].after === "'hello world'", `After should be 'hello world', got ${transforms[0].after}`);
  });

  test('DEOBFUSCATE: String concat — nested (3+ parts)', () => {
    const { code, transforms } = deobfuscate(`const m = 'ch' + 'il' + 'd_' + 'process';`);
    assertIncludes(code, "'child_process'", 'Should fold nested concat to child_process');
    assert(transforms.length === 1, `Expected 1 transform (outermost), got ${transforms.length}`);
  });

  test('DEOBFUSCATE: String concat — mixed quotes', () => {
    const { code } = deobfuscate(`const x = "he" + 'llo';`);
    assertIncludes(code, "'hello'", 'Should fold mixed quote concat');
  });

  test('DEOBFUSCATE: String concat — does NOT fold with variable', () => {
    const { code, transforms } = deobfuscate(`const y = 'hello' + someVar;`);
    assertIncludes(code, "'hello' + someVar", 'Should NOT fold when variable is present');
    assert(transforms.length === 0, `Expected 0 transforms when variable present, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: String concat — does NOT fold number + string', () => {
    const { code, transforms } = deobfuscate(`const z = 42 + 'px';`);
    assert(transforms.length === 0, `Expected 0 transforms for number+string, got ${transforms.length}`);
  });

  // =====================================================
  // 2. CHARCODE REBUILD (5 tests)
  // =====================================================

  test('DEOBFUSCATE: CharCode — simple fromCharCode', () => {
    const { code, transforms } = deobfuscate(`const x = String.fromCharCode(104, 101, 108, 108, 111);`);
    assertIncludes(code, "'hello'", 'Should decode fromCharCode to hello');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    assert(transforms[0].type === 'charcode', `Expected type charcode, got ${transforms[0].type}`);
  });

  test('DEOBFUSCATE: CharCode — multi-char (child_process)', () => {
    const { code } = deobfuscate(`const m = String.fromCharCode(99, 104, 105, 108, 100, 95, 112, 114, 111, 99, 101, 115, 115);`);
    assertIncludes(code, "'child_process'", 'Should decode to child_process');
  });

  test('DEOBFUSCATE: CharCode — spread array', () => {
    const { code, transforms } = deobfuscate(`const x = String.fromCharCode(...[104, 101, 108, 108, 111]);`);
    assertIncludes(code, "'hello'", 'Should decode spread array fromCharCode');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: CharCode — does NOT fold with variable arg', () => {
    const { code, transforms } = deobfuscate(`const x = String.fromCharCode(104, myVar, 108);`);
    assertIncludes(code, 'String.fromCharCode', 'Should NOT fold when variable arg present');
    assert(transforms.length === 0, `Expected 0 transforms, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: CharCode — does NOT fold with no args', () => {
    const { code, transforms } = deobfuscate(`const x = String.fromCharCode();`);
    assertIncludes(code, 'String.fromCharCode()', 'Should NOT fold with no args');
    assert(transforms.length === 0, `Expected 0 transforms, got ${transforms.length}`);
  });

  // =====================================================
  // 3. BASE64 DECODE (5 tests)
  // =====================================================

  test('DEOBFUSCATE: Base64 — Buffer.from().toString()', () => {
    const { code, transforms } = deobfuscate(`const x = Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString();`);
    assertIncludes(code, "'child_process'", 'Should decode base64 Buffer.from to child_process');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    assert(transforms[0].type === 'base64', `Expected type base64, got ${transforms[0].type}`);
  });

  test('DEOBFUSCATE: Base64 — atob()', () => {
    const { code, transforms } = deobfuscate(`const x = atob('aGVsbG8=');`);
    assertIncludes(code, "'hello'", 'Should decode atob to hello');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    assert(transforms[0].type === 'base64', `Expected type base64, got ${transforms[0].type}`);
  });

  test('DEOBFUSCATE: Base64 — chained with toString encoding', () => {
    const { code } = deobfuscate(`const x = Buffer.from('ZXZhbA==', 'base64').toString();`);
    assertIncludes(code, "'eval'", 'Should decode base64 eval');
  });

  test('DEOBFUSCATE: Base64 — does NOT fold Buffer.from without toString()', () => {
    const { code, transforms } = deobfuscate(`const x = Buffer.from('Y2hpbGQ=', 'base64');`);
    assertIncludes(code, "Buffer.from", 'Should NOT fold Buffer.from without .toString()');
    assert(transforms.length === 0, `Expected 0 transforms, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: Base64 — does NOT fold atob with variable', () => {
    const { code, transforms } = deobfuscate(`const x = atob(someVar);`);
    assertIncludes(code, 'atob(someVar)', 'Should NOT fold atob with variable');
    assert(transforms.length === 0, `Expected 0 transforms, got ${transforms.length}`);
  });

  // =====================================================
  // 4. HEX ARRAY MAP (5 tests)
  // =====================================================

  test('DEOBFUSCATE: Hex array — [0x...].map(c => String.fromCharCode(c)).join("")', () => {
    const { code, transforms } = deobfuscate(`const x = [0x68, 0x65, 0x6c, 0x6c, 0x6f].map(c => String.fromCharCode(c)).join('');`);
    assertIncludes(code, "'hello'", 'Should decode hex array map to hello');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    assert(transforms[0].type === 'hex_array', `Expected type hex_array, got ${transforms[0].type}`);
  });

  test('DEOBFUSCATE: Hex array — decimal numbers in array', () => {
    const { code } = deobfuscate(`const x = [104, 101, 108, 108, 111].map(c => String.fromCharCode(c)).join('');`);
    assertIncludes(code, "'hello'", 'Should decode decimal array map to hello');
  });

  test('DEOBFUSCATE: Hex array — does NOT fold with non-numeric element', () => {
    const { code, transforms } = deobfuscate(`const x = [0x68, myVar, 0x6c].map(c => String.fromCharCode(c)).join('');`);
    assert(transforms.length === 0, `Expected 0 transforms with variable in array, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: Hex array — does NOT fold without join("")', () => {
    const { code, transforms } = deobfuscate(`const x = [0x68, 0x65].map(c => String.fromCharCode(c));`);
    assert(transforms.length === 0, `Expected 0 transforms without .join(''), got ${transforms.length}`);
  });

  test('DEOBFUSCATE: Hex escaped strings — already resolved by parser', () => {
    // Acorn resolves \x hex escapes in string literals automatically
    const { code } = deobfuscate(`const x = '\\x68\\x65\\x6c\\x6c\\x6f';`);
    // Acorn parses \x68\x65\x6c\x6c\x6f as "hello" in the Literal.value
    // The source stays the same but the AST contains the resolved value
    // Our module doesn't need to transform these — Acorn handles it
    assert(typeof code === 'string', 'Should return valid string');
  });

  // =====================================================
  // 5. EDGE CASES (3 tests)
  // =====================================================

  test('DEOBFUSCATE: No obfuscation — code returned unchanged', () => {
    const original = `const fs = require('fs');\nconst x = 42;\nconsole.log(x);`;
    const { code, transforms } = deobfuscate(original);
    assert(code === original, 'Unobfuscated code should be returned unchanged');
    assert(transforms.length === 0, `Expected 0 transforms, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: Partial obfuscation — only obfuscated parts resolved', () => {
    const { code, transforms } = deobfuscate(`
      const a = 'normal';
      const b = 'child' + '_process';
      const c = 42;
    `);
    assertIncludes(code, "'child_process'", 'Should fold the concat');
    assertIncludes(code, "'normal'", 'Normal string should remain');
    assertIncludes(code, '42', 'Number should remain');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: Invalid/unparseable code — returns original', () => {
    const broken = `const x = {{{{{ not valid JS`;
    const { code, transforms } = deobfuscate(broken);
    assert(code === broken, 'Invalid code should be returned unchanged');
    assert(transforms.length === 0, `Expected 0 transforms for invalid code, got ${transforms.length}`);
  });

  // =====================================================
  // 6. COMBINED / MULTI-TRANSFORM (bonus)
  // =====================================================

  test('DEOBFUSCATE: Multiple transforms in same file', () => {
    const src = `
      const a = 'ch' + 'ild';
      const b = String.fromCharCode(101, 118, 97, 108);
      const c = atob('ZnM=');
    `;
    const { code, transforms } = deobfuscate(src);
    assertIncludes(code, "'child'", 'Should fold string concat');
    assertIncludes(code, "'eval'", 'Should decode charcode');
    assertIncludes(code, "'fs'", 'Should decode atob');
    assert(transforms.length === 3, `Expected 3 transforms, got ${transforms.length}`);
  });

  test('DEOBFUSCATE: transforms[] has correct position info', () => {
    const src = `const x = 'he' + 'llo';`;
    const { transforms } = deobfuscate(src);
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    const t = transforms[0];
    assert(typeof t.start === 'number', 'start should be a number');
    assert(typeof t.end === 'number', 'end should be a number');
    assert(t.start >= 0, 'start should be >= 0');
    assert(t.end > t.start, 'end should be > start');
    assert(t.type === 'string_concat', `type should be string_concat, got ${t.type}`);
    assertIncludes(t.before, "'he' + 'llo'", 'before should show original');
    assert(t.after === "'hello'", `after should be 'hello', got ${t.after}`);
  });
}

module.exports = { runDeobfuscateTests };
