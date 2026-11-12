'use strict';

// Count-threshold dilution (FP_COUNT_THRESHOLDS in src/scoring.js). The 2026-11 test audit
// found 13 of these thresholds never triggered and 3 surviving mutation: a threshold could be
// raised or lowered with no test noticing, although it is the surface an attacker uses to
// dilute a signal by repeating benign-looking copies. This file pins the table as a spec
// (changing a threshold must change this test) and checks, through applyFPReductions:
// - maxCount instances: nothing is downgraded;
// - maxCount + 1 instances: all go to LOW, except one kept at its original severity when the
//   anti-dilution floor applies (low maxCount <= 3 with a `from` severity or floorEligible);
// - the guards: a dominant type is not diluted, dynamic_require on a dangerous module and
//   env_access next to a network sink are immune.
// credential_regex_harvest is excluded from the generic loop: a later sink-coupling pass
// rewrites its severity independently of the count.

const { test, assert } = require('../test-utils');
const { applyFPReductions } = require('../../src/scoring.js');

// type: [maxCount, from (severity that is downgraded, null = any), floor]
const SPEC = {
  dynamic_require: [10, 'HIGH', false],
  dangerous_call_function: [5, null, false],
  require_cache_poison: [3, 'CRITICAL', true],
  suspicious_dataflow: [3, null, true],
  obfuscation_detected: [3, null, false],
  module_compile_dynamic: [3, 'HIGH', true],
  module_compile: [3, 'HIGH', true],
  zlib_inflate_eval: [2, 'CRITICAL', true],
  vm_code_execution: [3, 'HIGH', true],
  dynamic_import: [5, 'HIGH', false],
  js_obfuscation_pattern: [1, 'HIGH', true],
  credential_tampering: [5, null, false],
  dangerous_call_eval: [3, null, false],
  env_access: [4, 'HIGH', false],
  high_entropy_string: [5, null, false],
  prototype_hook: [10, null, false],
  crypto_decipher: [3, 'HIGH', true],
  possible_obfuscation: [5, null, false],
  unicode_variation_decoder: [3, null, false],
  proxy_data_intercept: [3, null, false],
  sensitive_string: [5, null, false],
  staged_payload: [3, null, false]
};

const FILLER_COUNT = 40; // keeps every tested type well under the 40 % ratio guard

function make(type, n, severity, message = `${type} finding`) {
  const out = [];
  for (let i = 0; i < n; i++) out.push({ type, severity, file: `src/f${i}.js`, message });
  // Neutral filler: no threshold, no install hook (a lifecycle_script would trigger the
  // lifecycle guard, tested separately below).
  for (let i = 0; i < FILLER_COUNT; i++) out.push({ type: 'unpinned_action', severity: 'LOW', file: '.github/workflows/ci.yml', message: `action ${i}` });
  return out;
}

const sevOf = (threats, type) => threats.filter(t => t.type === type).map(t => t.severity);

function runDilutionThresholdTests() {
  console.log('\n=== DILUTION THRESHOLDS (audit 2026-11) ===\n');

  for (const [type, [max, from, floor]] of Object.entries(SPEC)) {
    const sev = from || 'HIGH';
    test(`DILUTION ${type}: ${max} instances are not downgraded`, () => {
      const threats = make(type, max, sev);
      applyFPReductions(threats, null, 'demo', {});
      const s = sevOf(threats, type);
      assert(s.every(x => x === sev), `${type} x${max}: expected all ${sev}, got ${s.join(',')}`);
    });
    test(`DILUTION ${type}: ${max + 1} instances -> LOW${floor ? ', one kept at ' + sev + ' (floor)' : ''}`, () => {
      const threats = make(type, max + 1, sev);
      applyFPReductions(threats, null, 'demo', {});
      const s = sevOf(threats, type);
      const kept = s.filter(x => x === sev).length;
      const low = s.filter(x => x === 'LOW').length;
      assert(kept === (floor ? 1 : 0), `${type} x${max + 1}: expected ${floor ? 1 : 0} kept at ${sev}, got ${s.join(',')}`);
      assert(low === max + 1 - kept, `${type} x${max + 1}: expected the rest LOW, got ${s.join(',')}`);
    });
    if (from) {
      test(`DILUTION ${type}: only ${from} instances are downgraded`, () => {
        const other = from === 'HIGH' ? 'CRITICAL' : 'HIGH';
        const threats = make(type, max + 1, other);
        applyFPReductions(threats, null, 'demo', {});
        const s = sevOf(threats, type);
        assert(s.every(x => x === other), `${type} at ${other}: must not be downgraded, got ${s.join(',')}`);
      });
    }
  }

  test('DILUTION guard: a dominant type (>= 40 % of findings) is not diluted', () => {
    const threats = [];
    for (let i = 0; i < 4; i++) threats.push({ type: 'obfuscation_detected', severity: 'HIGH', file: `src/f${i}.js`, message: 'obf' });
    threats.push({ type: 'unpinned_action', severity: 'LOW', file: '.github/workflows/ci.yml', message: 'action' });
    applyFPReductions(threats, null, 'demo', {});
    assert(sevOf(threats, 'obfuscation_detected').every(x => x === 'HIGH'), 'a type that dominates the findings may be the malware itself');
  });

  test('DILUTION guard: dynamic_require of child_process keeps its severity beyond the threshold', () => {
    const threats = make('dynamic_require', 11, 'HIGH');
    threats[0].message = 'Dynamic require() resolved to child_process';
    applyFPReductions(threats, null, 'demo', {});
    assert(threats[0].severity === 'HIGH', `dangerous-module immunity broken: ${threats[0].severity}`);
    assert(threats.filter(t => t.type === 'dynamic_require' && t.severity === 'LOW').length === 10, 'the 10 others are diluted');
  });

  test('DILUTION guard: env_access in a file with a network sink keeps its severity beyond the threshold', () => {
    const threats = make('env_access', 5, 'HIGH');
    threats.push({ type: 'suspicious_module_sink', severity: 'MEDIUM', file: 'src/f0.js', message: 'ws.send' });
    applyFPReductions(threats, null, 'demo', {});
    const f0 = threats.find(t => t.type === 'env_access' && t.file === 'src/f0.js');
    assert(f0.severity === 'HIGH', `network-sink immunity broken: ${f0.severity}`);
  });

  // prototype_hook has a second hard-coded rule (> 10 HIGH -> LOW, "prototype_hook_count"),
  // so only CRITICAL instances observe the table threshold alone.
  test('DILUTION prototype_hook (CRITICAL, table rule only): 10 kept, 11 -> LOW', () => {
    const ten = make('prototype_hook', 10, 'CRITICAL');
    applyFPReductions(ten, null, 'demo', {});
    assert(sevOf(ten, 'prototype_hook').every(x => x === 'CRITICAL'), 'x10 must stay CRITICAL');
    const eleven = make('prototype_hook', 11, 'CRITICAL');
    applyFPReductions(eleven, null, 'demo', {});
    assert(sevOf(eleven, 'prototype_hook').every(x => x === 'LOW'), `x11 must go LOW, got ${sevOf(eleven, 'prototype_hook').join(',')}`);
  });

  // credential_regex_harvest: with a proven exfil sink present, the later sink-coupling pass
  // leaves it alone, so its count threshold (2) and its floor are observable.
  test('DILUTION credential_regex_harvest (proven sink present): 2 kept, 3 -> one HIGH (floor) + 2 LOW', () => {
    const sink = { type: 'reverse_shell', severity: 'HIGH', file: 'src/shell.js', message: 'net.connect + /bin/sh' };
    const two = make('credential_regex_harvest', 2, 'HIGH'); two.push({ ...sink });
    applyFPReductions(two, null, 'demo', {});
    assert(sevOf(two, 'credential_regex_harvest').every(x => x === 'HIGH'), `x2: ${sevOf(two, 'credential_regex_harvest').join(',')}`);
    const three = make('credential_regex_harvest', 3, 'HIGH'); three.push({ ...sink });
    applyFPReductions(three, null, 'demo', {});
    const s3 = sevOf(three, 'credential_regex_harvest');
    assert(s3.filter(x => x === 'HIGH').length === 1 && s3.filter(x => x === 'LOW').length === 2, `x3: ${s3.join(',')}`);
  });

  // Lifecycle guard: with an active install hook, one diluted instance of each high-intent
  // type comes back to MEDIUM, so an install-time package cannot dilute them away entirely.
  const GUARDED = ['obfuscation_detected', 'dynamic_require', 'dangerous_call_function', 'dangerous_call_eval', 'staged_payload', 'env_access'];
  for (const type of GUARDED) {
    test(`DILUTION lifecycle guard: ${type} beyond the threshold keeps one MEDIUM instance when an install hook exists`, () => {
      const [max, from] = SPEC[type];
      const threats = make(type, max + 1, from || 'HIGH');
      threats.push({ type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'postinstall: node setup.js' });
      applyFPReductions(threats, null, 'demo', {});
      const s = sevOf(threats, type);
      assert(s.filter(x => x === 'MEDIUM').length === 1 && s.filter(x => x === 'LOW').length === max, `${type}: got ${s.join(',')}`);
    });
  }
}

module.exports = { runDilutionThresholdTests };
