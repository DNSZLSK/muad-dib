'use strict';

// FPR band-20-49 precision gates — Étape 0 blind adjudication (2026-06-15): the score 20-49 band
// of the live new-package flux is ~96% false positive, 0 TP. Two discriminant-based gates target
// the two largest FP clusters without touching true positives:
//
//   Gate #1 (MUADDIB_DF_SDK_GATE, src/scanner/dataflow.js): a suspicious_dataflow from a credential
//   ENV read (OPENAI_API_KEY, YINGDAO_ACCESS_TOKEN, …) is downgraded CRITICAL/HIGH → MEDIUM when
//   EVERY network destination is benign — a curated provider, a local/reserved host, OR a host whose
//   label is coherent with the env-var brand (own-API: YINGDAO_TOKEN → api.yingdao.com). Decoy-safe:
//   any unknown / public-IP / suspicious host keeps it CRITICAL.
//
//   Gate #2 (MUADDIB_DYNIMPORT_BOUNDED, ast-detectors/handle-import-expression.js): a computed
//   dynamic import() is CRITICAL only with positive remote/decode/env evidence (URL literal,
//   .replace() URL manipulation, atob/Buffer decode, process.env-sourced specifier). Bounded/local
//   imports (CLI dispatchers, layout/i18n loaders, dep-resolve shims) drop to HIGH.
//
// Both flags default OFF, so the OFF assertions lock the prior (legacy) behavior and the ON
// assertions prove the gate. Behavioral tests (runScanDirect) — no source greps.
// (A gate #3 host-coupling for credential_regex_harvest was measured inert on the real corpus and
//  removed 2026-06-15; the surviving sink-coupling is covered by sink-coupling.test.js.)

const path = require('path');
const { asyncTest, assert, runScanDirect, TESTS_DIR } = require('../test-utils');

const FP = (n) => path.join(TESTS_DIR, 'sink-coupling-fp', n);

async function scanWithFlag(target, flag) {
  const had = Object.prototype.hasOwnProperty.call(process.env, flag) ? process.env[flag] : undefined;
  process.env[flag] = '1';
  try {
    return await runScanDirect(target);
  } finally {
    if (had === undefined) delete process.env[flag];
    else process.env[flag] = had;
  }
}

function sevOf(r, type) {
  const t = (r.threats || []).find(x => x.type === type);
  return t ? t.severity : null;
}
function sevsOf(r, type) {
  return (r.threats || []).filter(x => x.type === type).map(x => x.severity);
}

async function runFprBandGatesTests() {
  console.log('\n=== FPR BAND-20-49 GATES (gate#1 dataflow-SDK, gate#2 dynimport-bounded) ===\n');

  // ---------- Gate #1: dataflow first-party SDK ----------
  await asyncTest('gate#1 OFF: own-brand credential dataflow stays CRITICAL (baseline)', async () => {
    const r = await runScanDirect(FP('df-sdk-ownbrand'));
    assert(sevOf(r, 'suspicious_dataflow') === 'CRITICAL',
      `baseline suspicious_dataflow must be CRITICAL, got ${sevOf(r, 'suspicious_dataflow')}`);
  });

  await asyncTest('gate#1 ON (negative): ACME_API_KEY → api.acme.com → MEDIUM, de-alerted', async () => {
    const off = await runScanDirect(FP('df-sdk-ownbrand'));
    const on = await scanWithFlag(FP('df-sdk-ownbrand'), 'MUADDIB_DF_SDK_GATE');
    assert(sevOf(on, 'suspicious_dataflow') === 'MEDIUM',
      `own-brand dataflow must drop to MEDIUM, got ${sevOf(on, 'suspicious_dataflow')}`);
    assert(on.summary.riskScore < off.summary.riskScore,
      `score must drop (off=${off.summary.riskScore} on=${on.summary.riskScore})`);
    assert(on.summary.riskScore < 20, `expected de-alert (<20), got ${on.summary.riskScore}`);
  });

  await asyncTest('gate#1 ON (positive): OPENAI_API_KEY → public IP stays CRITICAL', async () => {
    const r = await scanWithFlag(FP('df-sdk-exfil'), 'MUADDIB_DF_SDK_GATE');
    assert(sevOf(r, 'suspicious_dataflow') === 'CRITICAL',
      `exfil to a public IP must stay CRITICAL, got ${sevOf(r, 'suspicious_dataflow')}`);
  });

  await asyncTest('gate#1 ON (positive): credential → RFC2606 doc domain (example.com) stays CRITICAL', async () => {
    // Regression guard: the holdout adversarial sample env-var-reconstruction exfils to
    // telemetry-api.example.com; example.com is reserved/non-routable so it must NOT count as a
    // benign SDK destination (a real SDK never sends a live credential to example.com).
    const r = await scanWithFlag(FP('df-sdk-docdomain'), 'MUADDIB_DF_SDK_GATE');
    assert(sevOf(r, 'suspicious_dataflow') === 'CRITICAL',
      `credential → example.com must stay CRITICAL (doc domain is not a benign SDK target), got ${sevOf(r, 'suspicious_dataflow')}`);
  });

  // ---------- Gate #2: dynamic_import bounded ----------
  await asyncTest('gate#2 OFF: bounded dynamic imports are CRITICAL (baseline)', async () => {
    const r = await runScanDirect(FP('dynimport-bounded'));
    assert(sevsOf(r, 'dynamic_import').includes('CRITICAL'),
      `baseline must include a CRITICAL dynamic_import, got [${sevsOf(r, 'dynamic_import').join(',')}]`);
  });

  await asyncTest('gate#2 ON (negative): bounded/local imports drop to HIGH, none CRITICAL', async () => {
    const off = await runScanDirect(FP('dynimport-bounded'));
    const on = await scanWithFlag(FP('dynimport-bounded'), 'MUADDIB_DYNIMPORT_BOUNDED');
    const sevs = sevsOf(on, 'dynamic_import');
    assert(sevs.length > 0, 'should still emit dynamic_import (downgraded, not suppressed)');
    assert(!sevs.includes('CRITICAL'), `bounded imports must not be CRITICAL, got [${sevs.join(',')}]`);
    assert(on.summary.riskScore < off.summary.riskScore,
      `score must drop (off=${off.summary.riskScore} on=${on.summary.riskScore})`);
  });

  await asyncTest('gate#2 ON (positive): remote-URL and env-driven imports stay CRITICAL', async () => {
    const r = await scanWithFlag(FP('dynimport-remote'), 'MUADDIB_DYNIMPORT_BOUNDED');
    const sevs = sevsOf(r, 'dynamic_import');
    const crit = sevs.filter(s => s === 'CRITICAL').length;
    const high = sevs.filter(s => s === 'HIGH').length;
    // Both imports (URL-string var + process.env) resolve to CRITICAL with the same message and
    // dedupe to one finding; if EITHER were wrongly downgraded a distinct HIGH finding would appear.
    assert(crit >= 1 && high === 0,
      `remote/env imports must stay CRITICAL (none downgraded to HIGH), got [${sevs.join(',')}]`);
  });
}

module.exports = { runFprBandGatesTests };
