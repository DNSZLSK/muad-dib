'use strict';

const { test, assert } = require('../test-utils');
const { applyCompoundBoosts, applyFPReductions } = require('../../src/scoring.js');

function _seedReductions(threats) {
  applyFPReductions(threats, null, null, null);
}

function runStagedRemoteLoaderTests() {
  console.log('\n=== STAGED REMOTE LOADER TESTS (chai-* / poxios-chain campaign) ===\n');

  test('staged_remote_loader: fires on Function.constructor + process shadow in same file', () => {
    const threats = [
      { type: 'function_constructor_require', severity: 'CRITICAL', file: 'lib/caller.js' },
      { type: 'process_variable_shadow', severity: 'HIGH', file: 'lib/caller.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'staged_remote_loader');
    assert(compound !== undefined, 'staged_remote_loader compound must fire');
    assert(compound.severity === 'CRITICAL');
    assert(compound.file === 'lib/caller.js', 'compound file should match function_constructor_require file');
  });

  test('staged_remote_loader: SKIPS when signals are in different files (sameFile gate)', () => {
    const threats = [
      { type: 'function_constructor_require', severity: 'CRITICAL', file: 'lib/caller.js' },
      { type: 'process_variable_shadow', severity: 'HIGH', file: 'lib/other.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'staged_remote_loader');
    assert(compound === undefined, 'compound should NOT fire when signals are in different files');
  });

  test('staged_remote_loader: SKIPS when only one signal present', () => {
    const threats = [
      { type: 'function_constructor_require', severity: 'CRITICAL', file: 'lib/caller.js' }
    ];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'staged_remote_loader');
    assert(compound === undefined, 'compound needs both signals to fire');
  });

  test('function_constructor_require: stays CRITICAL even when file is unreachable (REACHABILITY_EXEMPT)', () => {
    // Simulate the chai-as-test scoring path: file is "unreachable" because
    // the reachability resolver fails to follow the require('./caller') chain.
    const threats = [
      { type: 'function_constructor_require', severity: 'CRITICAL', file: 'lib/caller.js' }
    ];
    const reachableFiles = new Set(['lib/index.js']); // caller.js NOT in the reachable set
    applyFPReductions(threats, reachableFiles, null, null);
    const t = threats.find(x => x.type === 'function_constructor_require');
    assert(t.severity === 'CRITICAL',
      `function_constructor_require must remain CRITICAL via REACHABILITY_EXEMPT, got ${t.severity}`);
    assert(!t.unreachable, 'must not be flagged unreachable');
  });

  test('process_variable_shadow: stays HIGH when file is unreachable (REACHABILITY_EXEMPT)', () => {
    const threats = [
      { type: 'process_variable_shadow', severity: 'HIGH', file: 'lib/caller.js' }
    ];
    const reachableFiles = new Set(['lib/index.js']);
    applyFPReductions(threats, reachableFiles, null, null);
    const t = threats.find(x => x.type === 'process_variable_shadow');
    assert(t.severity === 'HIGH',
      `process_variable_shadow must remain HIGH via REACHABILITY_EXEMPT, got ${t.severity}`);
  });

  test('clean pino-style caller.js: no signals, no compound', () => {
    // Real pino lib/caller.js exports a stack-trace utility — no Function.constructor,
    // no process shadow, no fetch. Must not produce any staged_remote_loader signal.
    const threats = [];
    _seedReductions(threats);
    applyCompoundBoosts(threats);
    const compound = threats.find(t => t.type === 'staged_remote_loader');
    assert(compound === undefined, 'no compound on clean pino caller');
  });
}

module.exports = { runStagedRemoteLoaderTests };
