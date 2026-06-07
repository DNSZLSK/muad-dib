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

  // v2.11.29: findTyposquatMatch is exported as a pure utility for the
  // publish-pipeline guard (scripts/check-deps-typosquats.js). It must
  // match real typosquats and skip whitelisted / scoped / short names.
  test('TYPOSQUAT export: findTyposquatMatch catches loadash -> lodash', () => {
    const { findTyposquatMatch } = require('../../src/scanner/typosquat.js');
    const m = findTyposquatMatch('loadash');
    assert(m && m.original === 'lodash' && m.distance === 1,
      `findTyposquatMatch('loadash') should return {original:'lodash', distance:1}, got ${JSON.stringify(m)}`);
  });

  test('TYPOSQUAT export: findTyposquatMatch catches chlk/expresss/requestt', () => {
    const { findTyposquatMatch } = require('../../src/scanner/typosquat.js');
    const cases = [
      { name: 'chlk', original: 'chalk' },
      { name: 'expresss', original: 'express' },
      { name: 'requestt', original: 'request' }
    ];
    for (const c of cases) {
      const m = findTyposquatMatch(c.name);
      assert(m && m.original === c.original,
        `findTyposquatMatch('${c.name}') should match '${c.original}', got ${JSON.stringify(m)}`);
    }
  });

  test('TYPOSQUAT export: findTyposquatMatch returns null for legit deps (acorn, js-yaml, scoped)', () => {
    const { findTyposquatMatch } = require('../../src/scanner/typosquat.js');
    assert(findTyposquatMatch('acorn') === null, 'acorn is whitelisted');
    assert(findTyposquatMatch('js-yaml') === null, 'js-yaml is whitelisted');
    assert(findTyposquatMatch('@inquirer/prompts') === null, 'scoped packages skipped');
    assert(findTyposquatMatch('fs') === null, 'short names skipped (< 4 chars)');
  });

  // ── Phase 4: crates.io typosquat (POPULAR_CRATES) ──

  test('TYPOSQUAT crates: findCratesTyposquatMatch flags distance-1 squats', () => {
    const { findCratesTyposquatMatch } = require('../../src/scanner/typosquat.js');
    const a = findCratesTyposquatMatch('reqwest2');   // extra trailing char
    assert(a && a.original === 'reqwest' && a.distance === 1, `reqwest2→reqwest d1, got ${JSON.stringify(a)}`);
    const b = findCratesTyposquatMatch('serdejson');  // '-'/'_' normalized → distance 1 from serde_json
    assert(b && b.original === 'serde_json' && b.distance === 1, `serdejson→serde_json d1, got ${JSON.stringify(b)}`);
    const c = findCratesTyposquatMatch('clapp');      // extra char
    assert(c && c.original === 'clap', `clapp→clap, got ${JSON.stringify(c)}`);
  });

  test('TYPOSQUAT crates: findCratesTyposquatMatch flags distance-2 on longer crates', () => {
    const { findCratesTyposquatMatch } = require('../../src/scanner/typosquat.js');
    const m = findCratesTyposquatMatch('reqwset');    // swapped chars (distance 2), reqwest is len>=5
    assert(m && m.original === 'reqwest' && m.distance === 2, `reqwset→reqwest d2, got ${JSON.stringify(m)}`);
  });

  test('TYPOSQUAT crates: findCratesTyposquatMatch returns null for popular/whitelisted/clean/short names', () => {
    const { findCratesTyposquatMatch } = require('../../src/scanner/typosquat.js');
    assert(findCratesTyposquatMatch('tokio') === null, 'tokio is itself popular');
    assert(findCratesTyposquatMatch('serde_json') === null, 'serde_json is itself popular');
    assert(findCratesTyposquatMatch('mime') === null, 'mime is whitelisted (distance 1 from time)');
    assert(findCratesTyposquatMatch('totally-unrelated-xyzzy') === null, 'unrelated name → null');
    assert(findCratesTyposquatMatch('h2') === null, 'short name skipped (< 4 chars)');
  });
}

module.exports = { runTyposquatTests };
