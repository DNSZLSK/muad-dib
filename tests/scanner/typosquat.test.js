const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

async function runTyposquatTests() {
  console.log('\n=== TYPOSQUATTING TESTS ===\n');

  test('TYPOSQUAT: Detects lodahs (lodash)', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'lodahs', 'Should detect lodahs');
  });

  test('TYPOSQUAT: Detects axois (axios)', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'axois', 'Should detect axois');
  });

  test('TYPOSQUAT: Detects expres (express)', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'expres', 'Should detect expres');
  });

  test('TYPOSQUAT: Severity HIGH', () => {
    const output = runScan(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'HIGH', 'Should be HIGH');
  });

  // =============================================
  // v2.5.14: B13 — Pair-aware whitelist tests
  // =============================================

  await asyncTest('TYPOSQUAT B13: chai skips chalk but still checked against other populars', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-typo-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-typo', version: '1.0.0',
      dependencies: { 'chai': '^4.0.0' }
    }));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};');
    try {
      const result = await runScanDirect(tmp);
      const chalkMatch = (result.threats || []).find(t =>
        t.type === 'typosquat_detected' && t.message.includes('chai') && t.message.includes('chalk'));
      assert(!chalkMatch, 'chai should NOT be flagged as typosquat of chalk (whitelisted pair)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TYPOSQUAT B13: redux skips redis but still checked against other populars', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-typo-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-typo', version: '1.0.0',
      dependencies: { 'redux': '^5.0.0' }
    }));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};');
    try {
      const result = await runScanDirect(tmp);
      const redisMatch = (result.threats || []).find(t =>
        t.type === 'typosquat_detected' && t.message.includes('redux') && t.message.includes('redis'));
      assert(!redisMatch, 'redux should NOT be flagged as typosquat of redis (whitelisted pair)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TYPOSQUAT B13 negative: actual typosquat still detected', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-typo-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'test-typo', version: '1.0.0',
      dependencies: { 'lodasj': '^4.0.0' }
    }));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};');
    try {
      const result = await runScanDirect(tmp);
      const t = (result.threats || []).find(t => t.type === 'typosquat_detected');
      assert(t, 'Actual typosquat (lodasj for lodash) should still be detected');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runTyposquatTests };
