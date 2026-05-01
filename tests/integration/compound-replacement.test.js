'use strict';

const { test, assert } = require('../test-utils');
const { applyCompoundBoosts, computeGroupScore } = require('../../src/scoring.js');

function withFlag(name, val, fn) {
  const before = process.env[name];
  if (val === undefined) delete process.env[name]; else process.env[name] = val;
  try { return fn(); } finally {
    if (before === undefined) delete process.env[name]; else process.env[name] = before;
  }
}

async function runCompoundReplacementTests() {
  console.log('\n=== COMPOUND REPLACEMENT TESTS (Hybrid v3 Phase 3) ===\n');

  test('Phase 3: applyCompoundBoosts tags constituents with severity < compound', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'a.js', message: 'm' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'a.js', message: 'm' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound && compound.severity === 'CRITICAL', 'Expected crypto_staged_payload CRITICAL emitted');
    const sb = threats.find(t => t.type === 'staged_binary_payload');
    const cd = threats.find(t => t.type === 'crypto_decipher');
    assert(sb.replacedByCompound === 'crypto_staged_payload', `staged_binary_payload should be tagged: got ${sb.replacedByCompound}`);
    assert(cd.replacedByCompound === 'crypto_staged_payload', `crypto_decipher should be tagged: got ${cd.replacedByCompound}`);
  });

  test('Phase 3: constituent at SAME severity as compound is NOT tagged', () => {
    // dangerous_exec at CRITICAL would normally be a constituent of lifecycle_dangerous_exec (CRITICAL).
    // The conditional rule should NOT tag it (it carries equivalent weight on its own).
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' },
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'install.js', message: 'curl|bash' }
    ];
    applyCompoundBoosts(threats);
    const dx = threats.find(t => t.type === 'dangerous_exec');
    assert(dx.replacedByCompound === undefined, `CRITICAL constituent should NOT be tagged: got ${dx.replacedByCompound}`);
    const ls = threats.find(t => t.type === 'lifecycle_script');
    assert(ls.replacedByCompound === 'lifecycle_dangerous_exec', `MEDIUM constituent should be tagged: got ${ls.replacedByCompound}`);
  });

  test('Phase 3 OFF: replacedByCompound tag has no scoring effect', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'a.js', message: 'm', replacedByCompound: 'crypto_staged_payload' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'a.js', message: 'm' }
    ];
    withFlag('MUADDIB_COMPOUND_REPLACE', undefined, () => {
      const score = computeGroupScore(threats);
      // Both HIGHs count → 10 + 10 = 20 (subject to confidence factor — at minimum >= 10)
      assert(score >= 15, `Phase 3 OFF: tag ignored, score >= 15 expected, got ${score}`);
    });
  });

  test('Phase 3 ON: tagged constituent contributes 0 to score', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'a.js', message: 'm', replacedByCompound: 'crypto_staged_payload' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'a.js', message: 'm' }
    ];
    withFlag('MUADDIB_COMPOUND_REPLACE', '1', () => {
      const score = computeGroupScore(threats);
      // Tagged threat (HIGH=10) suppressed; only crypto_decipher counts
      assert(score < 15, `Phase 3 ON: tagged constituent suppressed, expected <15, got ${score}`);
    });
  });

  test('Phase 3: re-running applyCompoundBoosts on cached threats with compound already present still tags', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'a.js', message: 'm' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'a.js', message: 'm' },
      { type: 'crypto_staged_payload', severity: 'CRITICAL', file: 'a.js', message: 'pre-existing', compound: true }
    ];
    applyCompoundBoosts(threats);
    const compounds = threats.filter(t => t.type === 'crypto_staged_payload');
    assert(compounds.length === 1, `Should not duplicate compound, got ${compounds.length}`);
    const sb = threats.find(t => t.type === 'staged_binary_payload');
    assert(sb.replacedByCompound === 'crypto_staged_payload', 'Pre-existing compound should still tag constituents');
  });

  test('Phase 3: tagging is idempotent (re-running does not re-tag tagged threats)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'a.js', message: 'm' },
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'b.js', message: 'm' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'a.js', message: 'm' }
    ];
    applyCompoundBoosts(threats);
    applyCompoundBoosts(threats);
    const tagged = threats.filter(t => t.replacedByCompound === 'crypto_staged_payload');
    // Only the FIRST instance of each required type is tagged → 1 of 2 staged_binary_payload + 1 crypto_decipher = 2
    assert(tagged.length === 2, `Expected 2 tagged, got ${tagged.length}`);
  });
}

module.exports = { runCompoundReplacementTests };
