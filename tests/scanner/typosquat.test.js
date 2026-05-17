const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, runScanFast, cleanupTemp, TESTS_DIR } = require('../test-utils');

async function runTyposquatTests() {
  console.log('\n=== TYPOSQUATTING TESTS ===\n');

  await asyncTest('TYPOSQUAT: Detects lodahs (lodash) (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'lodahs', 'Should detect lodahs');
  });

  await asyncTest('TYPOSQUAT: Detects axois (axios) (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'axois', 'Should detect axois');
  });

  await asyncTest('TYPOSQUAT: Detects expres (express) (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'typosquat'));
    assertIncludes(output, 'expres', 'Should detect expres');
  });

  await asyncTest('TYPOSQUAT: Severity HIGH (fast)', async () => {
    const output = await runScanFast(path.join(TESTS_DIR, 'typosquat'));
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

  // =============================================
  // RT-C1-FPR (audit 2026-05) : ecosystem framework prefixes
  // Production FP : eslint-import-resolver-typescript fired dependency_typosquat
  // because the boundary-squat single-token branch matched 'typescript' and the
  // siblings [eslint, import, resolver] weren't all in LEGIT_BOUNDARY_TOKENS.
  // Fix: ECOSYSTEM_FRAMEWORK_PREFIXES rejects all deps whose first hyphened token
  // is a known plugin-ecosystem framework (eslint, babel, gatsby, postcss, ...).
  // =============================================

  await asyncTest('RT-C1-FPR.a: eslint-import-resolver-typescript -> no dependency_typosquat (real prod FP)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-rt-c1-fpr-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
      name: 'benign-app', version: '1.0.0',
      dependencies: { 'eslint-import-resolver-typescript': '^3.0.0' }
    }));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};');
    try {
      const result = await runScanDirect(tmp);
      const fp = (result.threats || []).find(t =>
        t.type === 'dependency_typosquat' && t.message.includes('eslint-import-resolver-typescript'));
      assert(!fp, `FIXED: eslint-import-resolver-typescript ne doit PAS firer dependency_typosquat. Threats: ${JSON.stringify((result.threats || []).map(t => t.type))}`);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('RT-C1-FPR.b: ecosystem packages (babel-loader-*, gatsby-source-*, etc.) -> no dependency_typosquat', async () => {
    const ecosystemDeps = [
      'babel-loader-svelte',
      'gatsby-source-filesystem',
      'webpack-cli-serve',
      'postcss-import-url',
      'jest-environment-jsdom',
      'stylelint-config-standard'
    ];
    for (const dep of ecosystemDeps) {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-rt-c1-fpr-'));
      fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
        name: 'benign-app', version: '1.0.0',
        dependencies: { [dep]: '^1.0.0' }
      }));
      fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};');
      try {
        const result = await runScanDirect(tmp);
        const fp = (result.threats || []).find(t =>
          t.type === 'dependency_typosquat' && t.message.includes(dep));
        assert(!fp, `FIXED: ${dep} ne doit PAS firer dependency_typosquat`);
      } finally { cleanupTemp(tmp); }
    }
  });

  await asyncTest('RT-C1-FPR.c (guard): real boundary-squat still detected (plain-crypto-js, react-token-exfil)', async () => {
    // Verifie qu'Axe 1 ne masque pas des squats sans prefixe d'ecosysteme.
    const realSquats = ['plain-crypto-js', 'react-token-exfil'];
    for (const dep of realSquats) {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-rt-c1-fpr-'));
      fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
        name: 'suspicious-app', version: '1.0.0',
        dependencies: { [dep]: '*' }
      }));
      fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = {};');
      try {
        const result = await runScanDirect(tmp);
        const t = (result.threats || []).find(tt =>
          tt.type === 'dependency_typosquat' && tt.message.includes(dep));
        assert(t, `GUARD: ${dep} doit toujours firer dependency_typosquat (no over-suppression by ecosystem prefix)`);
      } finally { cleanupTemp(tmp); }
    }
  });
}

module.exports = { runTyposquatTests };
