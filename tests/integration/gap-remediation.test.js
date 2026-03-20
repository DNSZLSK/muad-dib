'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScanDirect, cleanupTemp } = require('../test-utils');
const { deobfuscate } = require('../../src/scanner/deobfuscate.js');
const { applyFPReductions, applyCompoundBoosts } = require('../../src/scoring.js');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gap-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-gap-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runGapRemediationTests() {
  console.log('\n=== GAP REMEDIATION TESTS (v2.9.6) ===\n');

  // ===================================================================
  // GAP 1: Computed Property Eval Resolution (4 tests)
  // ===================================================================

  await asyncTest('GAP1: const f = "eval"; globalThis[f](code) → CRITICAL', async () => {
    const code = `const f = 'eval';\nglobalThis[f]('1+1');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect resolved indirect eval as CRITICAL');
      assertIncludes(t.message, 'Resolved indirect eval', 'Message should mention resolved eval');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('GAP1: const g = "Function"; global[g]("return 1")() → CRITICAL', async () => {
    const code = `const g = 'Function';\nglobal[g]('return 1')();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'CRITICAL');
      assert(t, 'Should detect resolved indirect Function as CRITICAL');
      assertIncludes(t.message, 'Resolved indirect Function', 'Message should mention resolved Function');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('GAP1: globalThis[unknownVar](x) → HIGH (no resolution)', async () => {
    const code = `globalThis[unknownVar]('test');`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should still detect dynamic global dispatch');
      assert(t.severity === 'HIGH', `Should be HIGH (no resolution), got ${t.severity}`);
      assertIncludes(t.message, 'Dynamic global dispatch', 'Should use generic message for unresolved');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('GAP1: const f = "toString"; globalThis[f]() → HIGH (not eval/Function)', async () => {
    const code = `const f = 'toString';\nglobalThis[f]();`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should still detect dynamic global dispatch');
      assert(t.severity === 'HIGH', `Non-eval resolved should stay HIGH, got ${t.severity}`);
    } finally { cleanupTemp(tmp); }
  });

  // ===================================================================
  // GAP 2: Array.join Deobfuscation (4 tests)
  // ===================================================================

  test('GAP2: ["e","v","a","l"].join("") → resolves to "eval"', () => {
    const { code, transforms } = deobfuscate(`const x = ['e','v','a','l'].join('');`);
    assertIncludes(code, "'eval'", 'Should resolve array.join to eval');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
    assert(transforms[0].type === 'array_join', `Expected type array_join, got ${transforms[0].type}`);
  });

  test('GAP2: long array.join("") → resolves URL', () => {
    const { code, transforms } = deobfuscate(`const u = ['h','t','t','p','s',':','/','/','e','v','i','l'].join('');`);
    assertIncludes(code, "'https://evil'", 'Should resolve long array.join');
    assert(transforms.length === 1, `Expected 1 transform, got ${transforms.length}`);
  });

  test('GAP2: ["a","b","c"].join("-") → NOT transformed (non-empty separator)', () => {
    const { transforms } = deobfuscate(`const x = ['a','b','c'].join('-');`);
    assert(transforms.length === 0, `Should NOT transform with non-empty separator, got ${transforms.length}`);
  });

  test('GAP2: [1, 2, 3].join("") → NOT transformed (numbers, not strings)', () => {
    const { transforms } = deobfuscate(`const x = [1, 2, 3].join('');`);
    assert(transforms.length === 0, `Should NOT transform numeric elements, got ${transforms.length}`);
  });

  // ===================================================================
  // GAP 3: Silent Catch Block Logging (2 tests)
  // ===================================================================

  await asyncTest('GAP3: Unparseable JS file → no crash, graceful fallback', async () => {
    const tmp = makeTempPkg('const x = {{{{{ not valid JS at all');
    try {
      const result = await runScanDirect(tmp);
      // Should not crash and should return a result object
      assert(result, 'Should return a result even with unparseable JS');
      assert(result.summary && typeof result.summary.riskScore === 'number',
        'Should have a numeric riskScore in summary');
    } finally { cleanupTemp(tmp); }
  });

  test('GAP3: debugLog import exists in shell.js', () => {
    const shellSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'scanner', 'shell.js'), 'utf8'
    );
    assertIncludes(shellSrc, 'debugLog', 'shell.js should import debugLog');
    assert(!shellSrc.includes('catch {'), 'shell.js should not have bare catch blocks');
  });

  // ===================================================================
  // GAP 4a: Count-Threshold Dilution Floor (2 tests)
  // credential_regex_harvest: maxCount=2, from='HIGH' — floor applies (maxCount≤3 + from)
  // Need >2 instances AND ratio < 40% for count-threshold to fire
  // ===================================================================

  test('GAP4a: 4x credential_regex_harvest → at least one retains HIGH (dilution floor)', () => {
    const threats = [];
    for (let i = 0; i < 4; i++) {
      threats.push({
        type: 'credential_regex_harvest', severity: 'HIGH',
        file: `file${i}.js`, message: `Credential regex ${i}`
      });
    }
    // Add enough other threats to keep ratio below 40% (4/14 ≈ 28.6%)
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env${i}` });
    }

    applyFPReductions(threats, null, null);

    const credThreats = threats.filter(t => t.type === 'credential_regex_harvest');
    const highOnes = credThreats.filter(t => t.severity === 'HIGH');
    const lowOnes = credThreats.filter(t => t.severity === 'LOW');

    assert(highOnes.length === 1,
      `Exactly one should retain HIGH (dilution floor), got ${highOnes.length}`);
    assert(lowOnes.length === 3,
      `Remaining 3 should be LOW, got ${lowOnes.length}`);
    // Verify the retained one has the floor audit trail
    const restored = highOnes[0];
    const floorReduction = restored.reductions.find(r => r.rule === 'count_threshold_floor');
    assert(floorReduction, 'Restored threat should have count_threshold_floor reduction');
  });

  test('GAP4a: Count-threshold dilution floor — remaining instances ARE downgraded', () => {
    const threats = [];
    for (let i = 0; i < 4; i++) {
      threats.push({
        type: 'credential_regex_harvest', severity: 'HIGH',
        file: `file${i}.js`, message: `Credential regex ${i}`
      });
    }
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env${i}` });
    }

    applyFPReductions(threats, null, null);

    const credThreats = threats.filter(t => t.type === 'credential_regex_harvest');
    const lowOnes = credThreats.filter(t => t.severity === 'LOW');
    assert(lowOnes.length === 3, `3 should be downgraded to LOW, got ${lowOnes.length}`);
    // Verify the downgraded ones have count_threshold reduction
    for (const lt of lowOnes) {
      const ctReduction = lt.reductions.find(r => r.rule === 'count_threshold');
      assert(ctReduction, 'Downgraded threat should have count_threshold reduction');
    }
  });

  // ===================================================================
  // GAP 4b: Compound Severity Gate — originalSeverity (2 tests)
  // ===================================================================

  test('GAP4b: Compound fires when components reduced to LOW but originalSeverity was HIGH', () => {
    const threats = [
      {
        type: 'staged_binary_payload', severity: 'LOW',
        file: 'index.js', message: 'Binary ref + eval',
        originalSeverity: 'HIGH'
      },
      {
        type: 'crypto_decipher', severity: 'LOW',
        file: 'index.js', message: 'createDecipher',
        originalSeverity: 'HIGH'
      }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound, 'Compound should fire — originalSeverity was HIGH');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
  });

  test('GAP4b: Compound does NOT fire when components were genuinely LOW from start', () => {
    const threats = [
      {
        type: 'staged_binary_payload', severity: 'LOW',
        file: 'index.js', message: 'Binary ref + eval',
        originalSeverity: 'LOW'
      },
      {
        type: 'crypto_decipher', severity: 'LOW',
        file: 'index.js', message: 'createDecipher',
        originalSeverity: 'LOW'
      }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(!compound, 'Compound should NOT fire — originalSeverity was also LOW');
  });

  // ===================================================================
  // GAP 5: exec() → execFile() (1 test)
  // ===================================================================

  test('GAP5: bin/muaddib.js uses execFile instead of exec', () => {
    const muaddibSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'bin', 'muaddib.js'), 'utf8'
    );
    assertIncludes(muaddibSrc, 'execFile', 'Should use execFile');
    assert(!muaddibSrc.includes("{ exec }"), 'Should NOT import { exec }');
    assertIncludes(muaddibSrc, "execFile(npmBin", 'Should call execFile with npmBin variable');
    assert(!muaddibSrc.includes('shell: true'), 'Should NOT use shell: true');
  });
}

module.exports = { runGapRemediationTests };
