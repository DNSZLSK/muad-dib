const { test, asyncTest, assert } = require('../test-utils');
const {
  checkCompromisedDomain,
  isCompromisedDomain,
  _resetRdapCache,
  COMPROMISE_MARGIN_MS
} = require('../../src/scanner/email-domain.js');

// Helper: synthetic registry meta with maintainer_emails + package created_at
function makeMeta(emails, createdAt) {
  return {
    age_days: 365,
    weekly_downloads: 1000,
    maintainer_emails: emails,
    created_at: createdAt
  };
}

// Helper ISO date N days before/after a reference
function isoOffsetDays(refIso, days) {
  return new Date(new Date(refIso).getTime() + days * 24 * 60 * 60 * 1000).toISOString();
}

async function runRdapCompromisedDomainTests() {
  console.log('\n=== F1: RDAP_COMPROMISED_EMAIL_DOMAIN TESTS ===\n');

  // ── isCompromisedDomain pure logic ──
  const PACKAGE_PUBLISH = '2022-01-01T00:00:00.000Z';

  test('F1: isCompromisedDomain — domain registered well AFTER publish → compromised', () => {
    const creationDate = isoOffsetDays(PACKAGE_PUBLISH, 365); // 1y after
    assert(isCompromisedDomain(creationDate, PACKAGE_PUBLISH) === true);
  });

  test('F1: isCompromisedDomain — domain registered well BEFORE publish → safe', () => {
    const creationDate = isoOffsetDays(PACKAGE_PUBLISH, -365); // 1y before
    assert(isCompromisedDomain(creationDate, PACKAGE_PUBLISH) === false);
  });

  test('F1: 30-day margin: domain registered 25d before publish → FLAGGED (hasty pre-publish acquisition)', () => {
    const creationDate = isoOffsetDays(PACKAGE_PUBLISH, -25);
    // creation > publish - 30j → TRUE → considered compromised (within margin).
    // Intentional per plan: the margin absorbs timing edges. 25d before publish
    // is still suspicious because legit projects usually have a registered
    // domain long before shipping. Catches typosquat / fresh-malware setups.
    assert(isCompromisedDomain(creationDate, PACKAGE_PUBLISH) === true);
  });

  test('F1: isCompromisedDomain — domain registered 35d before publish → safe (beyond margin)', () => {
    const creationDate = isoOffsetDays(PACKAGE_PUBLISH, -35);
    assert(isCompromisedDomain(creationDate, PACKAGE_PUBLISH) === false);
  });

  test('F1: isCompromisedDomain — null/missing inputs → false', () => {
    assert(isCompromisedDomain(null, PACKAGE_PUBLISH) === false);
    assert(isCompromisedDomain(PACKAGE_PUBLISH, null) === false);
    assert(isCompromisedDomain(null, null) === false);
  });

  test('F1: isCompromisedDomain — malformed dates → false (no crash)', () => {
    assert(isCompromisedDomain('not-a-date', PACKAGE_PUBLISH) === false);
    assert(isCompromisedDomain(PACKAGE_PUBLISH, 'also-bad') === false);
  });

  // ── checkCompromisedDomain integration with mocked RDAP ──

  await asyncTest('F1: domain registered 1y after package publish → compromised_email_domain HIGH', async () => {
    _resetRdapCache();
    const meta = makeMeta(['alice@takeover.test'], PACKAGE_PUBLISH);
    const recentCreation = isoOffsetDays(PACKAGE_PUBLISH, 365);
    const fetchRdap = async () => ({ creationDate: recentCreation });
    const r = await checkCompromisedDomain(meta, { fetchRdap });
    assert(r.length === 1, 'expected 1 threat, got ' + r.length);
    assert(r[0].type === 'compromised_email_domain');
    assert(r[0].severity === 'HIGH');
    assert(r[0].domain === 'takeover.test');
    assert(r[0].creation_date === recentCreation);
    assert(r[0].package_created_at === PACKAGE_PUBLISH);
  });

  await asyncTest('F1: domain registered years before publish → no threat', async () => {
    _resetRdapCache();
    const meta = makeMeta(['safe@legit.test'], PACKAGE_PUBLISH);
    const oldCreation = isoOffsetDays(PACKAGE_PUBLISH, -3000);
    const fetchRdap = async () => ({ creationDate: oldCreation });
    const r = await checkCompromisedDomain(meta, { fetchRdap });
    assert(r.length === 0);
  });

  await asyncTest('F1: RDAP returns null (404/no data) → no threat, no crash', async () => {
    _resetRdapCache();
    const meta = makeMeta(['x@ccTLD.ru'], PACKAGE_PUBLISH);
    const fetchRdap = async () => null;
    const r = await checkCompromisedDomain(meta, { fetchRdap });
    assert(r.length === 0, 'missing RDAP data must NOT generate a threat');
  });

  await asyncTest('F1: RDAP fetcher throws → no threat, no crash (silent skip)', async () => {
    _resetRdapCache();
    const meta = makeMeta(['x@flaky.test'], PACKAGE_PUBLISH);
    const fetchRdap = async () => { throw new Error('boom'); };
    const r = await checkCompromisedDomain(meta, { fetchRdap });
    assert(r.length === 0);
  });

  await asyncTest('F1: meta with no maintainer_emails → empty threats', async () => {
    _resetRdapCache();
    const meta = makeMeta([], PACKAGE_PUBLISH);
    const r = await checkCompromisedDomain(meta, { fetchRdap: () => { throw new Error('should-not-be-called'); } });
    assert(r.length === 0);
  });

  await asyncTest('F1: meta without created_at → empty threats (cannot compare)', async () => {
    _resetRdapCache();
    const meta = { maintainer_emails: ['x@unknown-publish.test'], created_at: null };
    const r = await checkCompromisedDomain(meta, { fetchRdap: () => { throw new Error('should-not-be-called'); } });
    assert(r.length === 0, 'no package publish date → cannot infer compromise');
  });

  await asyncTest('F1: env opt-out MUADDIB_RDAP_CHECK=0 → empty threats, no fetch', async () => {
    _resetRdapCache();
    const prev = globalThis.process.env.MUADDIB_RDAP_CHECK;
    globalThis.process.env.MUADDIB_RDAP_CHECK = '0';
    try {
      const meta = makeMeta(['x@takeover.test'], PACKAGE_PUBLISH);
      const r = await checkCompromisedDomain(meta, {
        fetchRdap: () => { throw new Error('should-not-be-called'); }
      });
      assert(r.length === 0, 'opt-out must skip the lookup entirely');
    } finally {
      if (prev === undefined) delete globalThis.process.env.MUADDIB_RDAP_CHECK;
      else globalThis.process.env.MUADDIB_RDAP_CHECK = prev;
    }
  });

  // ── Multiple maintainers, mixed RDAP results ──
  await asyncTest('F1: multiple maintainers, only compromised domains flagged', async () => {
    _resetRdapCache();
    const meta = makeMeta(
      ['safe@oldlegit.test', 'attacker@new-acquired.test', 'safe2@oldlegit.test'],
      PACKAGE_PUBLISH
    );
    const oldCreation = isoOffsetDays(PACKAGE_PUBLISH, -3000);
    const newCreation = isoOffsetDays(PACKAGE_PUBLISH, 500);
    const fetchRdap = async (domain) => {
      if (domain === 'oldlegit.test') return { creationDate: oldCreation };
      if (domain === 'new-acquired.test') return { creationDate: newCreation };
      return null;
    };
    const r = await checkCompromisedDomain(meta, { fetchRdap });
    assert(r.length === 1, 'only the compromised domain should fire, got ' + r.length);
    assert(r[0].domain === 'new-acquired.test');
  });

  // ── Isolated-signal safety (feedback_weak_signals_composite_scoring) ──
  await asyncTest('F1: rule severity stays HIGH×high → composite-only signal', async () => {
    const { getRule } = require('../../src/rules/index.js');
    const rule = getRule('compromised_email_domain');
    assert(rule.severity === 'HIGH', 'severity must be HIGH (10 weight)');
    assert(rule.confidence === 'high', 'confidence high (1.0 factor)');
    // Computed: HIGH=10 × high=1.0 = 10 → sub-T1 (T1 starts at 20). Safe.
  });

  // ── COMPROMISE_MARGIN_MS sanity ──
  test('F1: COMPROMISE_MARGIN_MS is 30 days', () => {
    assert(COMPROMISE_MARGIN_MS === 30 * 24 * 60 * 60 * 1000);
  });

  // ============================================================
  // F1-V2 — candidate semantics (SHADOW-ONLY until adjudicated).
  // V1 above keeps emitting every threat; V2 is computed alongside and only
  // divergences are logged. These tests pin BOTH sides of that contract.
  // ============================================================

  const { isCompromisedDomainV2, PUBLIC_EMAIL_PROVIDERS } = require('../../src/scanner/email-domain.js');
  const fs = require('fs');
  const os = require('os');
  const path = require('path');

  // POSITIVE — the node-ipc shape (May 2026): domain re-registered YEARS after
  // the package's first publish. V2 must flag it (no FN regression vs V1).
  test('F1-V2: node-ipc shape — creation years after first publish → true', () => {
    assert(isCompromisedDomainV2('2026-05-07T00:00:00.000Z', '2019-03-01T00:00:00.000Z', 'atlantis-software.net') === true);
  });

  // NEGATIVE — the V1 FP source: domain bought shortly BEFORE the first publish
  // (normal dev behavior). V1 flags it (30d margin); V2 must not.
  test('F1-V2: domain registered 14d BEFORE first publish → false (V1 margin FP killed)', () => {
    const creation = isoOffsetDays(PACKAGE_PUBLISH, -14);
    assert(isCompromisedDomain(creation, PACKAGE_PUBLISH) === true, 'precondition: V1 flags this (the FP)');
    assert(isCompromisedDomainV2(creation, PACKAGE_PUBLISH, 'newdev.example') === false, 'V2 must not flag pre-publish acquisition');
  });

  // NEGATIVE — public email providers are a domain CLASS exclusion.
  test('F1-V2: public provider → false even with creation after publish', () => {
    const creation = isoOffsetDays(PACKAGE_PUBLISH, 365);
    assert(PUBLIC_EMAIL_PROVIDERS.has('gmail.com'), 'gmail.com in the provider set');
    assert(isCompromisedDomainV2(creation, PACKAGE_PUBLISH, 'gmail.com') === false, 'provider excluded');
    assert(isCompromisedDomainV2(creation, PACKAGE_PUBLISH, 'GMAIL.COM') === false, 'case-insensitive');
    assert(isCompromisedDomainV2(creation, PACKAGE_PUBLISH, 'evil-takeover.test') === true, 'non-provider still flagged');
  });

  // EDGE — strict comparison: creation exactly at first publish → false.
  test('F1-V2: creation == first publish → false (strict >)', () => {
    assert(isCompromisedDomainV2(PACKAGE_PUBLISH, PACKAGE_PUBLISH, 'edge.test') === false);
  });

  test('F1-V2: null/malformed inputs → false (no crash)', () => {
    assert(isCompromisedDomainV2(null, PACKAGE_PUBLISH, 'x.test') === false);
    assert(isCompromisedDomainV2(PACKAGE_PUBLISH, null, 'x.test') === false);
    assert(isCompromisedDomainV2('not-a-date', PACKAGE_PUBLISH, 'x.test') === false);
  });

  // ── Shadow hook: divergence logged, V1 threats UNCHANGED ──
  function withShadow(file, fn) {
    const save = { on: process.env.MUADDIB_SHADOW, f: process.env.MUADDIB_SHADOW_FILE };
    process.env.MUADDIB_SHADOW = '1';
    process.env.MUADDIB_SHADOW_FILE = file;
    return Promise.resolve()
      .then(fn)
      .finally(() => {
        if (save.on !== undefined) process.env.MUADDIB_SHADOW = save.on; else delete process.env.MUADDIB_SHADOW;
        if (save.f !== undefined) process.env.MUADDIB_SHADOW_FILE = save.f; else delete process.env.MUADDIB_SHADOW_FILE;
      });
  }

  await asyncTest('F1-V2: V1-only case → V1 threat STILL emitted + divergence logged with package ctx', async () => {
    const f = path.join(os.tmpdir(), `rdap-shadow-${Date.now()}-a.jsonl`);
    try {
      await withShadow(f, async () => {
        _resetRdapCache();
        // Domain created 14d before first publish: V1 true (margin), V2 false.
        const creation = isoOffsetDays(PACKAGE_PUBLISH, -14);
        const meta = makeMeta(['dev@fresh-domain.test'], PACKAGE_PUBLISH);
        const r = await checkCompromisedDomain(meta, {
          fetchRdap: async () => ({ creationDate: creation }),
          shadowCtx: { name: 'fresh-pkg', version: '1.0.0', ecosystem: 'npm' }
        });
        // ZERO-REGRESSION CONTRACT: the live V1 verdict still emits the threat.
        assert(r.length === 1 && r[0].type === 'compromised_email_domain', 'V1 threat unchanged under shadow');
        const { readShadowDivergences } = require('../../src/shared/shadow.js');
        const div = readShadowDivergences({ detector: 'compromised_email_domain' });
        assert(div.length === 1, `one divergence logged, got ${div.length}`);
        assert(div[0].package === 'fresh-pkg' && div[0].ecosystem === 'npm', 'package ctx threaded');
        assert(div[0].oldVerdict === true && div[0].newVerdict === false, 'V1-only divergence shape');
        assert(div[0].evidence.domain === 'fresh-domain.test' && div[0].evidence.oldMarginDays === 30, 'evidence complete');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  await asyncTest('F1-V2: agreement (both true) → NO divergence logged', async () => {
    const f = path.join(os.tmpdir(), `rdap-shadow-${Date.now()}-b.jsonl`);
    try {
      await withShadow(f, async () => {
        _resetRdapCache();
        const creation = isoOffsetDays(PACKAGE_PUBLISH, 365); // both V1 and V2 flag
        const meta = makeMeta(['x@agreed-takeover.test'], PACKAGE_PUBLISH);
        const r = await checkCompromisedDomain(meta, {
          fetchRdap: async () => ({ creationDate: creation }),
          shadowCtx: { name: 'agreed-pkg', ecosystem: 'npm' }
        });
        assert(r.length === 1, 'V1 threat emitted');
        assert(!fs.existsSync(f), 'agreements are not logged (divergence-only contract)');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  await asyncTest('F1-V2: shadow OFF → no divergence file, identical V1 behavior', async () => {
    const f = path.join(os.tmpdir(), `rdap-shadow-${Date.now()}-c.jsonl`);
    const save = { on: process.env.MUADDIB_SHADOW, f: process.env.MUADDIB_SHADOW_FILE };
    delete process.env.MUADDIB_SHADOW;
    process.env.MUADDIB_SHADOW_FILE = f;
    try {
      _resetRdapCache();
      const creation = isoOffsetDays(PACKAGE_PUBLISH, -14); // the divergent case
      const meta = makeMeta(['dev@off-domain.test'], PACKAGE_PUBLISH);
      const r = await checkCompromisedDomain(meta, { fetchRdap: async () => ({ creationDate: creation }) });
      assert(r.length === 1, 'V1 threat emitted exactly as before');
      assert(!fs.existsSync(f), 'shadow off → nothing written');
    } finally {
      if (save.on !== undefined) process.env.MUADDIB_SHADOW = save.on;
      if (save.f !== undefined) process.env.MUADDIB_SHADOW_FILE = save.f; else delete process.env.MUADDIB_SHADOW_FILE;
      try { fs.unlinkSync(f); } catch {}
    }
  });
}

module.exports = { runRdapCompromisedDomainTests };
