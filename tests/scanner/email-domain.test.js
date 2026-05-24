const { test, asyncTest, assert } = require('../test-utils');
const {
  checkUnclaimedMaintainerEmail,
  extractDomain,
  uniqueDomains,
  _resetCache
} = require('../../src/scanner/email-domain.js');

// Helper: build a synthetic registry meta object with given emails
function makeMeta(emails) {
  return {
    age_days: 365,
    weekly_downloads: 1000,
    maintainer_emails: emails
  };
}

// Helper: a mock resolveMx that returns prescribed results per domain
function makeMockResolver(map) {
  return async function resolveMx(domain) {
    if (!(domain in map)) {
      const err = new Error('NXDOMAIN');
      err.code = 'ENOTFOUND';
      throw err;
    }
    const result = map[domain];
    if (result instanceof Error) throw result;
    return result;
  };
}

async function runEmailDomainTests() {
  console.log('\n=== F3: EMAIL_DOMAIN (DNS MX) TESTS ===\n');

  // ── extractDomain unit tests ──
  test('F3: extractDomain returns lowercased domain', () => {
    assert(extractDomain('alice@Example.COM') === 'example.com');
  });
  test('F3: extractDomain trims whitespace', () => {
    assert(extractDomain('  bob@foo.org  ') === 'foo.org');
  });
  test('F3: extractDomain rejects malformed email', () => {
    assert(extractDomain('no-at-sign') === null);
    assert(extractDomain('@no-local') === null);
    assert(extractDomain('no-domain@') === null);
    assert(extractDomain(null) === null);
    assert(extractDomain('') === null);
    assert(extractDomain('a@nodot') === null);
  });
  test('F3: extractDomain rejects whitespace inside domain', () => {
    assert(extractDomain('a@bad domain.com') === null);
  });

  test('F3: uniqueDomains deduplicates case-insensitively', () => {
    const r = uniqueDomains(['a@Foo.com', 'b@FOO.COM', 'c@bar.org']);
    assert(r.length === 2);
    assert(r.includes('foo.com'));
    assert(r.includes('bar.org'));
  });

  // ── No emails / disabled → empty threats ──
  await asyncTest('F3: no maintainer_emails → empty threats', async () => {
    _resetCache();
    const r = await checkUnclaimedMaintainerEmail({ maintainer_emails: [] });
    assert(Array.isArray(r) && r.length === 0);
  });

  await asyncTest('F3: null/undefined meta → empty threats', async () => {
    _resetCache();
    const r1 = await checkUnclaimedMaintainerEmail(null);
    const r2 = await checkUnclaimedMaintainerEmail(undefined);
    assert(r1.length === 0 && r2.length === 0);
  });

  await asyncTest('F3: env opt-out MUADDIB_EMAIL_DOMAIN_CHECK=0 → empty threats', async () => {
    _resetCache();
    const prev = globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK;
    globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK = '0';
    try {
      const meta = makeMeta(['alice@unclaimed.test']);
      const r = await checkUnclaimedMaintainerEmail(meta, {
        resolveMx: () => { throw new Error('should-not-be-called'); }
      });
      assert(r.length === 0, 'opt-out must skip the lookup entirely');
    } finally {
      if (prev === undefined) delete globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK;
      else globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK = prev;
    }
  });

  // ── Positive: domain with no MX → HIGH threat ──
  await asyncTest('F3: ENOTFOUND → unclaimed_maintainer_email HIGH', async () => {
    _resetCache();
    const meta = makeMeta(['attacker@unclaimed.example']);
    const resolveMx = async () => {
      const err = new Error('nxdomain');
      err.code = 'ENOTFOUND';
      throw err;
    };
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 1, 'expected 1 threat, got ' + r.length);
    assert(r[0].type === 'unclaimed_maintainer_email');
    assert(r[0].severity === 'HIGH');
    assert(r[0].domain === 'unclaimed.example');
    assert(r[0].file === 'package.json');
  });

  await asyncTest('F3: ENODATA → unclaimed_maintainer_email HIGH', async () => {
    _resetCache();
    const meta = makeMeta(['x@no-mx.test']);
    const resolveMx = async () => {
      const err = new Error('no data');
      err.code = 'ENODATA';
      throw err;
    };
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 1);
    assert(r[0].domain === 'no-mx.test');
  });

  await asyncTest('F3: empty MX array → unclaimed_maintainer_email HIGH', async () => {
    _resetCache();
    const meta = makeMeta(['x@empty-mx.test']);
    const resolveMx = async () => []; // empty array = no MX records
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 1);
    assert(r[0].domain === 'empty-mx.test');
  });

  // ── Negative: domain HAS MX → no threat ──
  await asyncTest('F3: valid MX records → no threat (gmail-like)', async () => {
    _resetCache();
    const meta = makeMeta(['alice@example.com']);
    const resolveMx = async () => [
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 }
    ];
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 0, 'domain with MX must NOT trigger');
  });

  // ── Robustness: transient errors must be silent (no threat, no crash) ──
  await asyncTest('F3: timeout → no threat (silent skip)', async () => {
    _resetCache();
    const meta = makeMeta(['x@slow.test']);
    // resolveMx never resolves → race-against-timeout will reject after MX_TIMEOUT_MS
    // To keep this test fast we mock with an immediate-reject DNS_TIMEOUT.
    const resolveMx = async () => {
      const err = new Error('timeout');
      err.code = 'DNS_TIMEOUT';
      throw err;
    };
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 0, 'transient timeout must NOT generate a threat');
  });

  await asyncTest('F3: ESERVFAIL → no threat (silent skip)', async () => {
    _resetCache();
    const meta = makeMeta(['x@servfail.test']);
    const resolveMx = async () => {
      const err = new Error('servfail');
      err.code = 'ESERVFAIL';
      throw err;
    };
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 0, 'ESERVFAIL must NOT generate a threat');
  });

  await asyncTest('F3: unknown error → no threat, no crash', async () => {
    _resetCache();
    const meta = makeMeta(['x@bogus.test']);
    const resolveMx = async () => { throw new Error('random'); };
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 0);
  });

  // ── Multiple maintainers, mixed results ──
  await asyncTest('F3: multiple emails, only unclaimed ones flagged', async () => {
    _resetCache();
    const meta = makeMeta(['good@safe.test', 'bad@unclaimed.test', 'other@safe.test']);
    const resolveMx = makeMockResolver({
      'safe.test': [{ exchange: 'mx.safe.test', priority: 10 }],
      'unclaimed.test': (() => { const e = new Error(); e.code = 'ENOTFOUND'; return e; })()
    });
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 1, 'only the unclaimed domain must fire, got ' + r.length);
    assert(r[0].domain === 'unclaimed.test');
  });

  // ── Cache behavior: second call hits cache ──
  await asyncTest('F3: cache hit avoids second DNS query', async () => {
    _resetCache();
    let calls = 0;
    const resolveMx = async () => { calls++; const e = new Error(); e.code = 'ENOTFOUND'; throw e; };
    const meta = makeMeta(['x@cache.test']);
    await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(calls === 1, 'second call must hit cache (got ' + calls + ' DNS queries)');
  });

  // ── Isolated-signal safety (feedback_weak_signals_composite_scoring) ──
  // HIGH (10) × confidence_medium (0.85) = 8.5 points isolated → sub-T1 (20)
  // The rule must stay HIGH/medium to keep this property.
  await asyncTest('F3: rule severity stays HIGH×medium → composite-only signal', async () => {
    const { getRule } = require('../../src/rules/index.js');
    const rule = getRule('unclaimed_maintainer_email');
    assert(rule.severity === 'HIGH', 'severity must be HIGH');
    assert(rule.confidence === 'medium', 'confidence must be medium for sub-T1 isolated score');
    // Computed: HIGH=10 × medium=0.85 = 8.5 → well below T1 (20)
  });

  // ── Malformed emails are skipped ──
  await asyncTest('F3: malformed emails are silently skipped', async () => {
    _resetCache();
    const meta = makeMeta(['bad-no-at', '@nolocal.test', 'noat@', 'good@unclaimed.test']);
    const resolveMx = async () => { const e = new Error(); e.code = 'ENOTFOUND'; throw e; };
    const r = await checkUnclaimedMaintainerEmail(meta, { resolveMx });
    assert(r.length === 1, 'only the valid email domain must be checked');
    assert(r[0].domain === 'unclaimed.test');
  });
}

module.exports = { runEmailDomainTests };
