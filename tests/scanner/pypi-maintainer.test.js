'use strict';

const { test, asyncTest, assert } = require('../test-utils');

async function runPyPIMaintainerTests() {
  console.log('\n=== PYPI MAINTAINER TESTS ===\n');

  const { runPyPIMaintainerChecks, _internal } = require('../../src/scanner/pypi-maintainer.js');
  const { _resetCache, _resetRdapCache } = require('../../src/scanner/email-domain.js');

  // email-domain.js short-circuits when MUADDIB_EMAIL_DOMAIN_CHECK='0' or
  // MUADDIB_RDAP_CHECK='0'. Other suites toggle these temporarily — if their
  // restore is incomplete or they ran after us in some scheduler, our mock
  // resolvers would silently get bypassed. Force-enable for this suite, restore
  // on exit.
  const _prevEmail = globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK;
  const _prevRdap = globalThis.process.env.MUADDIB_RDAP_CHECK;
  globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK = '1';
  globalThis.process.env.MUADDIB_RDAP_CHECK = '1';

  function resetAll() {
    if (_resetCache) _resetCache();
    if (_resetRdapCache) _resetRdapCache();
  }

  // ---- adaptThreatToPyPI ----

  test('PYPI-MAINTAINER: adaptThreatToPyPI swaps file and rewrites "npm" → "PyPI"', () => {
    const npmThreat = {
      type: 'unclaimed_maintainer_email',
      severity: 'HIGH',
      message: 'Maintainer email domain "x.com" has no MX record — unclaimed mailbox, attacker can register the domain to receive a password-reset and take over the account.',
      file: 'package.json',
      domain: 'x.com'
    };
    const adapted = _internal.adaptThreatToPyPI(npmThreat, 'pyproject.toml');
    assert(adapted.file === 'pyproject.toml');
    assert(adapted.message.includes('take over the PyPI account'),
      `should mention PyPI account, got: ${adapted.message}`);
    assert(adapted.type === 'unclaimed_maintainer_email', 'type preserved');
    assert(adapted.severity === 'HIGH', 'severity preserved');
    // Original threat not mutated
    assert(npmThreat.file === 'package.json', 'original not mutated');
  });

  // ---- Empty / missing meta ----

  await asyncTest('PYPI-MAINTAINER: returns [] when meta is null', async () => {
    resetAll();
    const threats = await runPyPIMaintainerChecks('x', null);
    assert(threats.length === 0);
  });

  await asyncTest('PYPI-MAINTAINER: returns [] when meta has no emails', async () => {
    resetAll();
    const threats = await runPyPIMaintainerChecks('x', { maintainer_emails: [] });
    assert(threats.length === 0);
  });

  // ---- MX check (via injected resolveMx mock) ----

  await asyncTest('PYPI-MAINTAINER: MAINTAINER-005 fires on unclaimed domain (no MX)', async () => {
    resetAll();
    // Resolve to ENOTFOUND → no MX → fire.
    const resolveMx = async (_domain) => {
      const err = new Error('not found');
      err.code = 'ENOTFOUND';
      throw err;
    };
    const threats = await runPyPIMaintainerChecks('fake-pkg', {
      maintainer_emails: ['x@nonexistent-domain-xyz.invalid'],
      created_at: '2024-01-01T00:00:00Z'
    }, { resolveMx });
    const mx = threats.find(t => t.type === 'unclaimed_maintainer_email');
    assert(mx, `MAINTAINER-005 should fire, got: ${threats.map(t => t.type).join(',')}`);
    assert(mx.file === 'pyproject.toml', `file should be pyproject.toml, got ${mx.file}`);
    assert(mx.message.includes('PyPI'), 'message should mention PyPI');
  });

  await asyncTest('PYPI-MAINTAINER: no fire when domain has MX', async () => {
    resetAll();
    const resolveMx = async (_domain) => [{ priority: 10, exchange: 'mx.example.com' }];
    const threats = await runPyPIMaintainerChecks('fake-pkg', {
      maintainer_emails: ['x@gmail.com'],
      created_at: '2024-01-01T00:00:00Z'
    }, { resolveMx, fetchRdap: async () => null });
    const mx = threats.find(t => t.type === 'unclaimed_maintainer_email');
    assert(!mx, 'should NOT fire when domain has MX');
  });

  // ---- RDAP check (via injected fetchRdap mock) ----

  await asyncTest('PYPI-MAINTAINER: MAINTAINER-006 fires when domain registered AFTER package publish', async () => {
    resetAll();
    const resolveMx = async () => [{ priority: 10, exchange: 'mx.example.com' }];
    const fetchRdap = async (_domain) => ({ creationDate: '2024-06-01T00:00:00Z' });
    const threats = await runPyPIMaintainerChecks('fake-pkg', {
      maintainer_emails: ['x@suspicious-domain-pypi-test.com'],
      created_at: '2020-01-01T00:00:00Z'
    }, { resolveMx, fetchRdap });
    const rdap = threats.find(t => t.type === 'compromised_email_domain');
    assert(rdap, `MAINTAINER-006 should fire, got: ${threats.map(t => t.type).join(',')}`);
    assert(rdap.file === 'pyproject.toml', `expected file=pyproject.toml, got ${rdap.file}`);
    // Note: the MAINTAINER-006 message in email-domain.js doesn't contain "npm"
    // (it's about domain takeover, language-agnostic), so adaptThreatToPyPI is a
    // no-op on the message — we only check that file is rewritten.
  });

  await asyncTest('PYPI-MAINTAINER: MAINTAINER-006 no-fire when domain older than package', async () => {
    resetAll();
    const resolveMx = async () => [{ priority: 10, exchange: 'mx.example.com' }];
    const fetchRdap = async () => ({ creationDate: '2018-01-01T00:00:00Z' });
    const threats = await runPyPIMaintainerChecks('fake-pkg', {
      maintainer_emails: ['x@legit-domain.com'],
      created_at: '2020-01-01T00:00:00Z'
    }, { resolveMx, fetchRdap });
    const rdap = threats.find(t => t.type === 'compromised_email_domain');
    assert(!rdap, 'should NOT fire when domain predates package');
  });

  await asyncTest('PYPI-MAINTAINER: declarationFile option overrides default', async () => {
    resetAll();
    const resolveMx = async () => { const e = new Error('x'); e.code = 'ENOTFOUND'; throw e; };
    const threats = await runPyPIMaintainerChecks('fake-pkg', {
      maintainer_emails: ['x@nonexistent.invalid'],
      created_at: '2024-01-01T00:00:00Z'
    }, { resolveMx, declarationFile: 'setup.py' });
    const mx = threats.find(t => t.type === 'unclaimed_maintainer_email');
    assert(mx && mx.file === 'setup.py', `expected setup.py, got ${mx && mx.file}`);
  });

  // Restore env vars so we don't leak state to subsequent suites.
  if (_prevEmail === undefined) delete globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK;
  else globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK = _prevEmail;
  if (_prevRdap === undefined) delete globalThis.process.env.MUADDIB_RDAP_CHECK;
  else globalThis.process.env.MUADDIB_RDAP_CHECK = _prevRdap;
}

module.exports = { runPyPIMaintainerTests };
