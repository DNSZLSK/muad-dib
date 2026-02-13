const path = require('path');
const { test, assert, assertIncludes, runScan, TESTS_DIR } = require('../test-utils');

async function runAstTests() {
  console.log('\n=== AST TESTS ===\n');

  test('AST: Detects .npmrc access', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, '.npmrc', 'Should detect .npmrc');
  });

  test('AST: Detects .ssh access', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, '.ssh', 'Should detect .ssh');
  });

  test('AST: Detects GITHUB_TOKEN', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'GITHUB_TOKEN', 'Should detect GITHUB_TOKEN');
  });

  test('AST: Detects NPM_TOKEN', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'NPM_TOKEN', 'Should detect NPM_TOKEN');
  });

  test('AST: Detects AWS_SECRET', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'AWS_SECRET', 'Should detect AWS_SECRET');
  });

  test('AST: Detects eval()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'eval', 'Should detect eval');
  });

  test('AST: Detects exec()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'exec', 'Should detect exec');
  });

  test('AST: Detects new Function()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'Function', 'Should detect Function');
  });

  test('AST: Dynamic env access flagged as MEDIUM', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
    const result = JSON.parse(output);
    const dynamicEnv = result.threats.find(t => t.type === 'env_access' && t.severity === 'MEDIUM');
    assert(dynamicEnv, 'Dynamic process.env[var] should be MEDIUM');
  });
}

module.exports = { runAstTests };
