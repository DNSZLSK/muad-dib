const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, assert, cleanupTemp } = require('./test-utils');

const {
  findFiles, findJsFiles, isDevFile, escapeHtml, getCallName,
  EXCLUDED_DIRS, DEV_PATTERNS
} = require('../src/utils.js');

async function runUtilsTests() {
  console.log('\n=== UTILS TESTS ===\n');

  // --- findFiles ---

  test('UTILS: findFiles returns .js files by default', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-utils-'));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = 1;');
    fs.writeFileSync(path.join(tmp, 'style.css'), 'body {}');
    fs.writeFileSync(path.join(tmp, 'data.json'), '{}');
    try {
      const files = findFiles(tmp);
      assert(files.length === 1, 'Should find 1 .js file, got ' + files.length);
      assert(files[0].endsWith('index.js'), 'Should be index.js');
    } finally { cleanupTemp(tmp); }
  });

  test('UTILS: findFiles respects extensions option', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-utils-'));
    fs.writeFileSync(path.join(tmp, 'app.ts'), 'const x = 1;');
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = 1;');
    try {
      const files = findFiles(tmp, { extensions: ['.ts'] });
      assert(files.length === 1, 'Should find 1 .ts file, got ' + files.length);
      assert(files[0].endsWith('app.ts'), 'Should be app.ts');
    } finally { cleanupTemp(tmp); }
  });

  test('UTILS: findFiles skips node_modules by default', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-utils-'));
    fs.writeFileSync(path.join(tmp, 'index.js'), '');
    const nm = path.join(tmp, 'node_modules', 'pkg');
    fs.mkdirSync(nm, { recursive: true });
    fs.writeFileSync(path.join(nm, 'lib.js'), '');
    try {
      const files = findFiles(tmp);
      assert(files.length === 1, 'Should find 1 file (skip node_modules), got ' + files.length);
    } finally { cleanupTemp(tmp); }
  });

  test('UTILS: findFiles recurses into subdirectories', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-utils-'));
    const sub = path.join(tmp, 'src', 'lib');
    fs.mkdirSync(sub, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'index.js'), '');
    fs.writeFileSync(path.join(sub, 'helper.js'), '');
    try {
      const files = findFiles(tmp);
      assert(files.length === 2, 'Should find 2 files across dirs, got ' + files.length);
    } finally { cleanupTemp(tmp); }
  });

  test('UTILS: findFiles respects maxDepth', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-utils-'));
    const deep = path.join(tmp, 'a', 'b', 'c');
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(tmp, 'top.js'), '');
    fs.writeFileSync(path.join(deep, 'deep.js'), '');
    try {
      const files = findFiles(tmp, { maxDepth: 1 });
      assert(files.length === 1, 'maxDepth=1 should only find top-level file, got ' + files.length);
    } finally { cleanupTemp(tmp); }
  });

  test('UTILS: findFiles returns empty for non-existent dir', () => {
    const files = findFiles('/nonexistent/path/xyz');
    assert(files.length === 0, 'Non-existent dir should return empty array');
  });

  // --- findJsFiles ---

  test('UTILS: findJsFiles finds .js, .mjs, .cjs files', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-utils-'));
    fs.writeFileSync(path.join(tmp, 'index.js'), '');
    fs.writeFileSync(path.join(tmp, 'esm.mjs'), '');
    fs.writeFileSync(path.join(tmp, 'common.cjs'), '');
    fs.writeFileSync(path.join(tmp, 'style.css'), '');
    try {
      const files = findJsFiles(tmp);
      assert(files.length === 3, 'Should find 3 JS files (.js, .mjs, .cjs), got ' + files.length);
    } finally { cleanupTemp(tmp); }
  });

  // --- isDevFile ---

  test('UTILS: isDevFile identifies test files', () => {
    assert(isDevFile('foo.test.js') === true, 'foo.test.js should be dev');
    assert(isDevFile('bar.spec.js') === true, 'bar.spec.js should be dev');
    assert(isDevFile('test.js') === true, 'test.js should be dev');
    assert(isDevFile('spec.js') === true, 'spec.js should be dev');
  });

  test('UTILS: isDevFile identifies dev directories', () => {
    assert(isDevFile('scripts/build.js') === true, 'scripts/ should be dev');
    assert(isDevFile('bin/cli.js') === true, 'bin/ should be dev');
    assert(isDevFile('__tests__/unit.js') === true, '__tests__/ should be dev');
    assert(isDevFile('__mocks__/fs.js') === true, '__mocks__/ should be dev');
    assert(isDevFile('build/output.js') === true, 'build/ should be dev');
    assert(isDevFile('fixtures/data.js') === true, 'fixtures/ should be dev');
    assert(isDevFile('examples/demo.js') === true, 'examples/ should be dev');
    assert(isDevFile('docs/api.js') === true, 'docs/ should be dev');
    assert(isDevFile('benchmark/perf.js') === true, 'benchmark/ should be dev');
  });

  test('UTILS: isDevFile returns false for source files', () => {
    assert(isDevFile('src/index.js') === false, 'src/index.js should NOT be dev');
    assert(isDevFile('lib/util.js') === false, 'lib/util.js should NOT be dev');
    assert(isDevFile('index.js') === false, 'index.js should NOT be dev');
  });

  // --- escapeHtml ---

  test('UTILS: escapeHtml escapes HTML characters', () => {
    assert(escapeHtml('<script>') === '&lt;script&gt;', 'Should escape < and >');
    assert(escapeHtml('"hello"') === '&quot;hello&quot;', 'Should escape double quotes');
    assert(escapeHtml("it's") === "it&#x27;s", 'Should escape single quotes');
    assert(escapeHtml('a & b') === 'a &amp; b', 'Should escape ampersand');
  });

  test('UTILS: escapeHtml handles null/undefined', () => {
    assert(escapeHtml(null) === '', 'null should return empty string');
    assert(escapeHtml(undefined) === '', 'undefined should return empty string');
  });

  test('UTILS: escapeHtml passes through safe strings', () => {
    assert(escapeHtml('hello world') === 'hello world', 'Safe string should pass through');
    assert(escapeHtml('') === '', 'Empty string should pass through');
  });

  // --- getCallName ---

  test('UTILS: getCallName returns name for Identifier callee', () => {
    const node = { callee: { type: 'Identifier', name: 'eval' } };
    assert(getCallName(node) === 'eval', 'Should return eval');
  });

  test('UTILS: getCallName returns property name for MemberExpression', () => {
    const node = {
      callee: {
        type: 'MemberExpression',
        property: { name: 'exec' }
      }
    };
    assert(getCallName(node) === 'exec', 'Should return exec');
  });

  test('UTILS: getCallName returns empty string for other types', () => {
    const node = { callee: { type: 'SequenceExpression' } };
    assert(getCallName(node) === '', 'Should return empty string for non-Identifier/MemberExpression');
  });

  // --- EXCLUDED_DIRS ---

  test('UTILS: EXCLUDED_DIRS contains expected entries', () => {
    assert(EXCLUDED_DIRS.includes('node_modules'), 'Should include node_modules');
    assert(EXCLUDED_DIRS.includes('.git'), 'Should include .git');
    assert(EXCLUDED_DIRS.includes('.muaddib-cache'), 'Should include .muaddib-cache');
  });
}

module.exports = { runUtilsTests };
