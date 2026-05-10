'use strict';

const { test, assert } = require('../test-utils');
const { computeGroupScore, computeGroupScoreDecay, DECAY_ALPHA, SEVERITY_WEIGHTS } = require('../../src/scoring.js');

async function runDecayAggregationTests() {
  console.log('\n=== DECAY AGGREGATION TESTS (Hybrid v3 Phase 2) ===\n');

  test('Decay: single CRITICAL = full additive (CRITICAL not decayed)', () => {
    const threats = [{ type: 'reverse_shell', severity: 'CRITICAL', file: 'a.js', message: 'm' }];
    const score = computeGroupScoreDecay(threats);
    assert(score === SEVERITY_WEIGHTS.CRITICAL, `Expected ${SEVERITY_WEIGHTS.CRITICAL}, got ${score}`);
  });

  test('Decay: 5 CRITICALs of same type = additive (no decay on CRITICAL)', () => {
    const threats = Array.from({ length: 5 }, (_, i) => ({
      type: 'reverse_shell', severity: 'CRITICAL', file: `a${i}.js`, message: 'm'
    }));
    const score = computeGroupScoreDecay(threats);
    // 5 * 25 = 125 → capped at 100
    assert(score === 100, `Expected 100 (capped), got ${score}`);
  });

  test('Decay: HIGH α=1.0 means HIGH stays additive', () => {
    assert(DECAY_ALPHA.HIGH === 1.0, 'HIGH alpha should be 1.0 (no decay)');
    const threats = Array.from({ length: 4 }, (_, i) => ({
      type: 'dangerous_exec', severity: 'HIGH', file: `a${i}.js`, message: 'm'
    }));
    // 4 * 10 * confidence-factor — same type, but HIGH alpha 1.0 means full additive
    const decayScore = computeGroupScoreDecay(threats);
    const additiveScore = computeGroupScore(threats);
    // Both should match because HIGH alpha=1.0 disables decay
    // (subject to confidence factor, but applied identically)
    assert(decayScore === additiveScore, `HIGH-only same type: decay=${decayScore} vs additive=${additiveScore}`);
  });

  test('Decay: 1 MEDIUM of type X = full weight', () => {
    const threats = [{ type: 'env_access', severity: 'MEDIUM', file: 'a.js', message: 'm' }];
    const decay = computeGroupScoreDecay(threats);
    const add = computeGroupScore(threats);
    assert(decay === add, `Single MEDIUM: decay=${decay} vs additive=${add}`);
  });

  test('Decay: 5 MEDIUMs of SAME type — capped per-type', () => {
    const threats = Array.from({ length: 5 }, (_, i) => ({
      type: 'env_access', severity: 'MEDIUM', file: `f${i}.js`, message: 'm'
    }));
    const decay = computeGroupScoreDecay(threats);
    // Since v2.11.9, computeGroupScore takes the decay path by default. To get
    // the legacy additive comparison we must explicitly opt out.
    const before = process.env.MUADDIB_DECAY;
    process.env.MUADDIB_DECAY = '0';
    const add = computeGroupScore(threats);
    if (before === undefined) delete process.env.MUADDIB_DECAY;
    else process.env.MUADDIB_DECAY = before;
    assert(decay < add, `5x same type MEDIUM: decay (${decay}) should be less than additive (${add})`);
    // Per-type cap = MEDIUM weight / (1 - 0.4) = 3 / 0.6 = 5 (rounded)
    assert(decay <= 6, `Decay should be <= per-type cap of ~6, got ${decay}`);
  });

  test('Decay: 5 MEDIUMs of DISTINCT types — no decay between types', () => {
    const threats = [
      { type: 'env_access', severity: 'MEDIUM', file: 'a.js', message: 'm' },
      { type: 'string_mutation_obfuscation', severity: 'MEDIUM', file: 'a.js', message: 'm' },
      { type: 'high_entropy_string', severity: 'MEDIUM', file: 'a.js', message: 'm' },
      { type: 'dynamic_import', severity: 'MEDIUM', file: 'a.js', message: 'm' },
      { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'm' }
    ];
    const decay = computeGroupScoreDecay(threats);
    const add = computeGroupScore(threats);
    // Distinct types each get full first-instance weight → no decay between them
    assert(decay === add, `5 distinct MEDIUM types: decay=${decay} should equal additive=${add}`);
  });

  test('Decay: pile-up of LOW within same type capped at ~1.43', () => {
    const threats = Array.from({ length: 20 }, (_, i) => ({
      type: 'possible_obfuscation', severity: 'LOW', file: `f${i}.js`, message: 'm'
    }));
    const decay = computeGroupScoreDecay(threats);
    // Per-type cap LOW = 1 / (1 - 0.3) ≈ 1.43 → rounded to 1
    assert(decay <= 2, `20x same LOW type: decay should cap at ~1-2, got ${decay}`);
  });

  test('Decay: malware mix (1 CRITICAL + 3 distinct HIGH) ≈ additive', () => {
    const threats = [
      { type: 'reverse_shell', severity: 'CRITICAL', file: 'a.js', message: 'm' },
      { type: 'dangerous_exec', severity: 'HIGH', file: 'a.js', message: 'm' },
      { type: 'remote_code_load', severity: 'HIGH', file: 'b.js', message: 'm' },
      { type: 'lifecycle_dataflow', severity: 'HIGH', file: 'package.json', message: 'm' }
    ];
    const decay = computeGroupScoreDecay(threats);
    const add = computeGroupScore(threats);
    // CRITICAL additive + 3 distinct HIGHs (no per-type pile-up) = same
    assert(decay === add, `Diverse malware mix: decay=${decay} should equal additive=${add}`);
  });

  test('Decay: prototype_hook MEDIUM cap still applies', () => {
    const threats = Array.from({ length: 50 }, (_, i) => ({
      type: 'prototype_hook', severity: 'MEDIUM', file: `f${i}.js`, message: 'm'
    }));
    const decay = computeGroupScoreDecay(threats);
    // PROTO_HOOK_MEDIUM_CAP = 15
    assert(decay <= 15, `prototype_hook MEDIUM should cap at 15, got ${decay}`);
  });

  test('Decay: suspicious_dataflow MEDIUM cap still applies', () => {
    const threats = Array.from({ length: 50 }, (_, i) => ({
      type: 'suspicious_dataflow', severity: 'MEDIUM', file: `f${i}.js`, message: 'm'
    }));
    const decay = computeGroupScoreDecay(threats);
    // DATAFLOW_MEDIUM_CAP = 3
    assert(decay <= 3, `suspicious_dataflow MEDIUM should cap at 3, got ${decay}`);
  });

  test('Decay: empty threats = 0', () => {
    assert(computeGroupScoreDecay([]) === 0);
  });

  test('Decay: env flag toggles computeGroupScore behaviour (default ON since v2.11.9)', () => {
    const threats = Array.from({ length: 8 }, (_, i) => ({
      type: 'env_access', severity: 'MEDIUM', file: `f${i}.js`, message: 'm'
    }));
    const before = process.env.MUADDIB_DECAY;
    // Opt-out path : MUADDIB_DECAY=0 takes the additive (legacy) computation.
    process.env.MUADDIB_DECAY = '0';
    const additivePath = computeGroupScore(threats);
    // Default-ON path : unset (or any value other than '0') takes the decay path.
    delete process.env.MUADDIB_DECAY;
    const decayPath = computeGroupScore(threats);
    // Restore env
    if (before === undefined) delete process.env.MUADDIB_DECAY;
    else process.env.MUADDIB_DECAY = before;
    assert(decayPath < additivePath, `Decay flag: decay (${decayPath}) should be < additive (${additivePath})`);
  });
}

module.exports = { runDecayAggregationTests };
