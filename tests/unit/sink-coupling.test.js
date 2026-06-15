'use strict';

// FPR sink-coupling gate (chantier FPR 2026-06).
// credential_regex_harvest is a true positive ONLY when an independent exfil sink to an
// anomalous destination co-occurs. Without a sink it is downgraded HIGH/CRITICAL → LOW
// (blind FPR baseline: 94.4% FP on this rule). These tests LOCK that behavior AND the TPR
// gate: the positive fixtures (with a sink) must stay flagged; the negative (no sink) must drop.

const path = require('path');
const { test, asyncTest, assert, runScanDirect, TESTS_DIR } = require('../test-utils');
const { applyFPReductions } = require('../../src/scoring.js');

function credSev(threats) {
  const t = threats.find(x => x.type === 'credential_regex_harvest');
  return t ? t.severity : null;
}

async function runSinkCouplingTests() {
  console.log('\n=== FPR SINK-COUPLING TESTS (credential_regex_harvest) ===\n');

  // ---- unit: the gate logic (applyFPReductions) ----
  test('sink-coupling: credential_regex_harvest ALONE (no sink) → LOW', () => {
    const threats = [{ type: 'credential_regex_harvest', severity: 'HIGH', file: 'lib.js', message: 'regex', reductions: [] }];
    applyFPReductions(threats, null, null);
    assert(credSev(threats) === 'LOW', `expected LOW with no sink, got ${credSev(threats)}`);
  });

  test('sink-coupling: 2× credential_regex_harvest (no sink) → both LOW', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'a.js', message: 'r1', reductions: [] },
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'b.js', message: 'r2', reductions: [] }
    ];
    applyFPReductions(threats, null, null);
    const high = threats.filter(t => t.severity === 'HIGH').length;
    assert(high === 0, `expected 0 HIGH with no sink, got ${high}`);
  });

  test('sink-coupling: credential_regex_harvest + suspicious_domain (sink) → stays HIGH', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'steal.js', message: 'regex', reductions: [] },
      { type: 'suspicious_domain', severity: 'HIGH', file: 'steal.js', message: 'exfil host', reductions: [] }
    ];
    applyFPReductions(threats, null, null);
    assert(credSev(threats) === 'HIGH', `expected HIGH with suspicious_domain sink, got ${credSev(threats)}`);
  });

  test('sink-coupling: credential_regex_harvest + ioc_string_match (sink) → stays HIGH', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 's.js', message: 'regex', reductions: [] },
      { type: 'ioc_string_match', severity: 'CRITICAL', file: 's.js', message: 'jsonkeeper', reductions: [] }
    ];
    applyFPReductions(threats, null, null);
    assert(credSev(threats) === 'HIGH', `expected HIGH with ioc sink, got ${credSev(threats)}`);
  });

  test('sink-coupling: credential_regex_harvest + intent_credential_exfil (dataflow taint = anti-FN floor) → stays HIGH', () => {
    const threats = [
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 's.js', message: 'regex', reductions: [] },
      { type: 'intent_credential_exfil', severity: 'CRITICAL', file: 's.js', message: 'cred→net', reductions: [] }
    ];
    applyFPReductions(threats, null, null);
    assert(credSev(threats) === 'HIGH', `expected HIGH with proven taint, got ${credSev(threats)}`);
  });

  // ---- integration: the MANIFEST gate-pairs end-to-end (must hold after the fix) ----
  await asyncTest('sink-coupling gate (negative): framework-bundle credential_regex_harvest → LOW', async () => {
    const r = await runScanDirect(path.join(TESTS_DIR, 'sink-coupling-fp', 'framework-bundle'));
    const t = (r.threats || []).find(x => x.type === 'credential_regex_harvest');
    assert(t, 'framework-bundle should still emit credential_regex_harvest (as LOW)');
    assert(t.severity === 'LOW', `framework-bundle credential_regex_harvest must be LOW (no sink), got ${t.severity}`);
  });

  await asyncTest('sink-coupling gate (positive): credential-harvest-exfil stays flagged (cred HIGH + sink)', async () => {
    const r = await runScanDirect(path.join(TESTS_DIR, 'staged-loader', 'credential-harvest-exfil'));
    const t = (r.threats || []).find(x => x.type === 'credential_regex_harvest');
    assert(t && t.severity === 'HIGH', `credential-harvest-exfil credential_regex_harvest must stay HIGH (sink present), got ${t && t.severity}`);
    const hasSink = (r.threats || []).some(x => ['suspicious_domain', 'ioc_string_match'].includes(x.type));
    assert(hasSink, 'credential-harvest-exfil must retain its exfil-sink signal');
  });

  // Axios extension (chantier 2026-06): axios is now a recognized network call, so
  // credential_regex_harvest fires on axios harvesters (recall) — gated FP-neutral by sink-coupling.
  await asyncTest('sink-coupling (axios negative): benign axios + credential regex, no sink → LOW', async () => {
    const r = await runScanDirect(path.join(TESTS_DIR, 'sink-coupling-fp', 'axios-benign'));
    const t = (r.threats || []).find(x => x.type === 'credential_regex_harvest');
    assert(t, 'axios-benign should emit credential_regex_harvest (axios is now a network call)');
    assert(t.severity === 'LOW', `axios-benign credential_regex_harvest must be LOW (no exfil sink), got ${t.severity}`);
  });

  await asyncTest('sink-coupling (axios positive): axios harvest + paste-host exfil → stays HIGH', async () => {
    const r = await runScanDirect(path.join(TESTS_DIR, 'staged-loader', 'axios-harvest-exfil'));
    const t = (r.threats || []).find(x => x.type === 'credential_regex_harvest');
    assert(t && t.severity === 'HIGH', `axios-harvest-exfil credential_regex_harvest must stay HIGH (axios exfil sink), got ${t && t.severity}`);
    const hasSink = (r.threats || []).some(x => ['suspicious_domain', 'ioc_string_match'].includes(x.type));
    assert(hasSink, 'axios-harvest-exfil must surface its exfil-sink signal');
  });
}

module.exports = { runSinkCouplingTests };
