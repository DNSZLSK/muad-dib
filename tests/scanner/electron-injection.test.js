'use strict';

/**
 * MUADDIB-AST-097 electron_app_injection — behavioral tests.
 *
 * Positive: the two real ground-truth injectors — Discord debugger-hook credential stealer
 * (GT-036) and Atomic Wallet .asar prototype-hook address-swap (GT-044) — must score CRITICAL.
 * HIGH tier: a bare overwrite of a home-rooted app.asar with an unresolved payload.
 * Negative (the discriminators): a legit Electron app writing its OWN JSON config (every
 * corroboration signal present, but the write content is config, not code); an electron-builder
 * packing app.asar into dist/; a scaffolder writing an Electron template into a project (payload
 * present but no foreign-app discovery); and electron-native-notify (a home-probing wallet/
 * credential stealer that never writes into an app's .asar — caught by other rules, not this one).
 */

const path = require('path');
const { asyncTest, assert, runScanDirect } = require('../test-utils');

const GT = path.join(__dirname, '..', 'ground-truth', 'samples');
const FIX = path.join(__dirname, '..', 'samples', 'electron-injection');
const eaiOf = r => (r.threats || []).filter(t => t.type === 'electron_app_injection');
const sevs = list => list.map(t => t.severity);

async function runElectronInjectionTests() {
  console.log('\n=== ELECTRON APP INJECTION TESTS (MUADDIB-AST-097) ===\n');

  // ── Positives (real ground-truth malware) ──
  await asyncTest('AST-097: Discord core injection (GT-036) → electron_app_injection CRITICAL', async () => {
    const e = eaiOf(await runScanDirect(path.join(GT, 'discord-electron-inject')));
    assert(sevs(e).includes('CRITICAL'), `expected CRITICAL electron_app_injection, got ${JSON.stringify(sevs(e))}`);
  });

  await asyncTest('AST-097: Discord core injection (GT-036) scores >= 20 (alert threshold)', async () => {
    const r = await runScanDirect(path.join(GT, 'discord-electron-inject'));
    assert(r.summary.riskScore >= 20, `expected riskScore >= 20, got ${r.summary.riskScore}`);
  });

  await asyncTest('AST-097: Atomic Wallet .asar patch (GT-044) → electron_app_injection CRITICAL', async () => {
    const e = eaiOf(await runScanDirect(path.join(GT, 'atomic-wallet-patch')));
    assert(sevs(e).includes('CRITICAL'), `expected CRITICAL electron_app_injection, got ${JSON.stringify(sevs(e))}`);
  });

  await asyncTest('AST-097: Atomic Wallet .asar patch (GT-044) scores >= 20 (alert threshold)', async () => {
    const r = await runScanDirect(path.join(GT, 'atomic-wallet-patch'));
    assert(r.summary.riskScore >= 20, `expected riskScore >= 20, got ${r.summary.riskScore}`);
  });

  // ── HIGH tier: bare overwrite of a home-rooted app.asar, payload not statically resolvable ──
  await asyncTest('AST-097: bare home-rooted app.asar overwrite → HIGH (not CRITICAL)', async () => {
    const e = eaiOf(await runScanDirect(path.join(FIX, 'asar-literal-write')));
    assert(sevs(e).includes('HIGH') && !sevs(e).includes('CRITICAL'),
      `expected HIGH-only electron_app_injection, got ${JSON.stringify(sevs(e))}`);
  });

  // ── Negatives (the discriminators the AST coupling enforces) ──
  await asyncTest('AST-097 (neg): legit Electron app writing its OWN JSON config → no fire', async () => {
    const e = eaiOf(await runScanDirect(path.join(FIX, 'own-app-config')));
    assert(e.length === 0, `expected no electron_app_injection, got ${JSON.stringify(sevs(e))}`);
  });

  await asyncTest('AST-097 (neg): electron-builder packing app.asar into dist/ → no fire', async () => {
    const e = eaiOf(await runScanDirect(path.join(FIX, 'electron-builder-pack')));
    assert(e.length === 0, `expected no electron_app_injection, got ${JSON.stringify(sevs(e))}`);
  });

  await asyncTest('AST-097 (neg): scaffolder writing an Electron template to a project → no CRITICAL', async () => {
    const e = eaiOf(await runScanDirect(path.join(FIX, 'scaffolder')));
    assert(!sevs(e).includes('CRITICAL'), `expected no CRITICAL electron_app_injection, got ${JSON.stringify(sevs(e))}`);
  });

  await asyncTest('AST-097 (neg): electron-native-notify wallet stealer (home+probe, no .asar write) → no electron_app_injection', async () => {
    // This sample harvests wallet files + npm tokens and exfiltrates them; it must still be caught
    // (by credential/exfil rules) but must NOT be attributed to electron_app_injection — it never
    // overwrites an app's code. Guards against the rule over-claiming any home-probing installer.
    const r = await runScanDirect(path.join(GT, 'electron-native-notify'));
    const e = eaiOf(r);
    assert(e.length === 0, `expected no electron_app_injection, got ${JSON.stringify(sevs(e))}`);
    assert(r.summary.riskScore >= 20, `sample should still alert via other rules, got ${r.summary.riskScore}`);
  });
}

module.exports = { runElectronInjectionTests };
