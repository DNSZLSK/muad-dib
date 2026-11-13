'use strict';

// Scoring guards that the 2026-11 test audit found never triggered by the suite:
// - 4 scoring compounds (dependency_typosquat_require, lifecycle_newsletter_hijack,
//   axios_family, stub_with_string_ioc): each must fire on its full combination and
//   never on a single component.
// - the bundle-injection veto (hasBundleVetoSignal in applyFPReductions): the
//   event-stream / flatmap-stream guard that keeps a bundle's findings at full severity
//   when the same file carries a structural malware signal or a sensitive env read.

const { test, assert } = require('../test-utils');
const { applyCompoundBoosts, applyFPReductions } = require('../../src/scoring.js');

const COMPONENTS = {
  dependency_typosquat: { type: 'dependency_typosquat', severity: 'MEDIUM', file: 'package.json', message: 'dep "axios-http2" boundary-squats "axios"' },
  dependency_typosquat_used: { type: 'dependency_typosquat_used', severity: 'HIGH', file: 'index.js', message: 'require("axios-http2")' },
  lifecycle_script: { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'postinstall: node setup.js' },
  newsletter_auto_follow: { type: 'newsletter_auto_follow', severity: 'HIGH', file: 'lib/socket.js', message: 'newsletterFollow(...) on connect' },
  ioc_string_match: { type: 'ioc_string_match', severity: 'CRITICAL', file: 'setup.js', message: 'String IOC match: campaign marker' },
  anti_forensic_partial: { type: 'anti_forensic_partial', severity: 'HIGH', file: 'setup.js', message: 'deletes itself after run' },
  stub_package_external_dep: { type: 'stub_package_external_dep', severity: 'HIGH', file: 'package.json', message: 'stub package with URL dependency' }
};

const COMPOUNDS = {
  dependency_typosquat_require: ['dependency_typosquat', 'dependency_typosquat_used'],
  lifecycle_newsletter_hijack: ['lifecycle_script', 'newsletter_auto_follow'],
  axios_family: ['ioc_string_match', 'lifecycle_script', 'anti_forensic_partial'],
  stub_with_string_ioc: ['stub_package_external_dep', 'ioc_string_match']
};

const clone = names => names.map(n => ({ ...COMPONENTS[n] }));
const fired = (threats, type) => threats.some(t => t.type === type);

function runScoringGuardTests() {
  console.log('\n=== SCORING GUARDS (compounds + bundle veto, audit 2026-11) ===\n');

  for (const [compound, parts] of Object.entries(COMPOUNDS)) {
    test(`COMPOUND ${compound}: fires on ${parts.join(' + ')}`, () => {
      const threats = clone(parts);
      applyCompoundBoosts(threats, '/fake/path');
      const c = threats.find(t => t.type === compound);
      assert(c, `${compound} not emitted; got ${threats.map(t => t.type).join(', ')}`);
      assert(c.severity === 'CRITICAL', `${compound} expected CRITICAL, got ${c.severity}`);
    });
    for (let i = 0; i < parts.length; i++) {
      const missing = parts[i];
      const rest = parts.filter((_, j) => j !== i);
      test(`COMPOUND ${compound}: does not fire without ${missing}`, () => {
        const threats = clone(rest);
        applyCompoundBoosts(threats, '/fake/path');
        assert(!fired(threats, compound), `${compound} fired without ${missing}`);
      });
    }
  }

  // ---- Bundle-injection veto ----
  const BUNDLE = 'dist/app.bundle.min.js';
  const evalInBundle = () => ({ type: 'dangerous_call_eval', severity: 'CRITICAL', file: BUNDLE, message: 'eval(x) in bundle' });

  test('BUNDLE-VETO baseline: a lone eval in a bundle is downgraded (bundler artifact)', () => {
    const threats = [evalInBundle()];
    applyFPReductions(threats, null, 'demo', {});
    assert(threats[0].severity !== 'CRITICAL', `expected a downgrade, still ${threats[0].severity}`);
  });

  test('BUNDLE-VETO: reverse_shell in the same bundle keeps the eval at CRITICAL', () => {
    const threats = [evalInBundle(), { type: 'reverse_shell', severity: 'HIGH', file: BUNDLE, message: 'net.connect + /bin/sh pipe' }];
    applyFPReductions(threats, null, 'demo', {});
    const e = threats.find(t => t.type === 'dangerous_call_eval');
    assert(e.severity === 'CRITICAL', `event-stream guard broken: eval downgraded to ${e.severity}`);
  });

  test('BUNDLE-VETO: a sensitive env read (NPM_TOKEN) in the same bundle keeps the eval at CRITICAL', () => {
    const threats = [evalInBundle(), { type: 'env_access', severity: 'HIGH', file: BUNDLE, message: 'Access to sensitive variable process.env.NPM_TOKEN.' }];
    applyFPReductions(threats, null, 'demo', {});
    const e = threats.find(t => t.type === 'dangerous_call_eval');
    assert(e.severity === 'CRITICAL', `credential-read veto broken: eval downgraded to ${e.severity}`);
  });

  test('BUNDLE-VETO: a veto signal in ANOTHER file does not block the downgrade', () => {
    const threats = [evalInBundle(), { type: 'reverse_shell', severity: 'HIGH', file: 'src/other.js', message: 'net.connect + /bin/sh pipe' }];
    applyFPReductions(threats, null, 'demo', {});
    const e = threats.find(t => t.type === 'dangerous_call_eval');
    assert(e.severity !== 'CRITICAL', 'the veto must be scoped to the same file');
  });

  test('BUNDLE-VETO: a LOW veto-type signal does not block the downgrade (v2.10.75)', () => {
    const threats = [evalInBundle(), { type: 'unicode_invisible_injection', severity: 'LOW', file: BUNDLE, message: 'locale file invisibles' }];
    applyFPReductions(threats, null, 'demo', {});
    const e = threats.find(t => t.type === 'dangerous_call_eval');
    assert(e.severity !== 'CRITICAL', 'a LOW signal must not veto the downgrade');
  });
}

module.exports = { runScoringGuardTests };
