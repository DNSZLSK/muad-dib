'use strict';

const { test, assert } = require('../test-utils');

async function runTriageTests() {
  console.log('\n=== MONITOR TRIAGE TESTS ===\n');

  const { triageRisk, hasDangerousLifecycle } = require('../../src/monitor/webhook.js');

  // ── hasDangerousLifecycle ────────────────────────────────────────────────

  test('TRIAGE: hasDangerousLifecycle false for null item', () => {
    assert(hasDangerousLifecycle(null) === false, 'null → false');
    assert(hasDangerousLifecycle(undefined) === false, 'undefined → false');
    assert(hasDangerousLifecycle({}) === false, 'empty item → false');
  });

  test('TRIAGE: hasDangerousLifecycle true for preinstall in registryScripts', () => {
    assert(hasDangerousLifecycle({ registryScripts: { preinstall: 'node x.js' } }) === true,
      'preinstall → true');
    assert(hasDangerousLifecycle({ registryScripts: { postinstall: 'node x.js' } }) === true,
      'postinstall → true');
    assert(hasDangerousLifecycle({ registryScripts: { install: 'node x.js' } }) === true,
      'install → true');
  });

  test('TRIAGE: hasDangerousLifecycle false for safe scripts only', () => {
    assert(hasDangerousLifecycle({ registryScripts: { build: 'tsc', test: 'jest' } }) === false,
      'build/test → false (no install-time hooks)');
  });

  test('TRIAGE: hasDangerousLifecycle reads _npmInfo.scripts (Stage 1 stash)', () => {
    assert(hasDangerousLifecycle({ _npmInfo: { scripts: { postinstall: 'curl evil' } } }) === true,
      'postinstall in _npmInfo.scripts → true');
  });

  // ── Tier 0: non-negotiable suspect signals ───────────────────────────────

  test('TRIAGE: IOC match → full (Tier 0)', () => {
    const r = triageRisk({ isIOCMatch: true, ecosystem: 'npm' }, mockTrustedNpmMeta());
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('ioc_match'), 'reasons must include ioc_match');
  });

  test('TRIAGE: ATO signal → full (Tier 0)', () => {
    const r = triageRisk({ atoSignal: true, ecosystem: 'npm' }, mockTrustedNpmMeta());
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('ato_signal'), 'reasons must include ato_signal');
  });

  test('TRIAGE: lifecycle scripts → full (Tier 0)', () => {
    const item = { ecosystem: 'npm', registryScripts: { postinstall: 'node ./x.js' } };
    const r = triageRisk(item, mockTrustedNpmMeta());
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('lifecycle_scripts'), 'reasons must include lifecycle_scripts');
  });

  // ── Tier 1: metadata absent ──────────────────────────────────────────────

  test('TRIAGE: no metadata → full (Tier 1, defensive default)', () => {
    const r = triageRisk({ ecosystem: 'npm' }, null);
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('no_metadata'), 'reasons must include no_metadata');
  });

  // ── Tier 2: npm reputation factor ────────────────────────────────────────

  test('TRIAGE: trusted npm package → quick', () => {
    // 5y old, 200+ versions, 1M+ weekly downloads → factor ~0.10 (clamped low)
    const r = triageRisk({ ecosystem: 'npm' }, mockTrustedNpmMeta());
    assert(r.mode === 'quick', `expected quick, got ${r.mode}, reasons=${r.reasons}`);
    assert(r.reasons.length === 0, `expected no reasons, got [${r.reasons.join(',')}]`);
  });

  test('TRIAGE: fresh npm package → full (high reputation factor)', () => {
    // 3 days old, 1 version, < 10 downloads → factor ~1.5 (clamped high)
    const r = triageRisk({ ecosystem: 'npm' }, {
      age_days: 3, version_count: 1, weekly_downloads: 0
    });
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.some(x => x.startsWith('reputation_factor=')),
      `expected reputation_factor reason, got [${r.reasons.join(',')}]`);
  });

  // ── Tier 3: PyPI direct signals ──────────────────────────────────────────

  test('TRIAGE: trusted PyPI package → quick', () => {
    const r = triageRisk({ ecosystem: 'pypi' }, {
      age_days: 365 * 3, version_count: 25
    });
    assert(r.mode === 'quick', `expected quick, got ${r.mode}, reasons=${r.reasons}`);
  });

  test('TRIAGE: fresh PyPI (age < 30d) → full', () => {
    const r = triageRisk({ ecosystem: 'pypi' }, {
      age_days: 5, version_count: 10
    });
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('pypi_age<30d'), `reasons must include pypi_age<30d, got [${r.reasons.join(',')}]`);
  });

  test('TRIAGE: PyPI with few versions → full', () => {
    const r = triageRisk({ ecosystem: 'pypi' }, {
      age_days: 365, version_count: 2
    });
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('pypi_version_count<5'), `reasons must include pypi_version_count<5`);
  });

  test('TRIAGE: PyPI with setup.py flag → full', () => {
    const r = triageRisk({ ecosystem: 'pypi' }, {
      age_days: 365, version_count: 10, has_setup_py: true
    });
    assert(r.mode === 'full', `expected full, got ${r.mode}`);
    assert(r.reasons.includes('pypi_setup_py'), `reasons must include pypi_setup_py`);
  });

  test('TRIAGE: PyPI does NOT trigger npm reputation_factor (separate paths)', () => {
    // PyPI without npm-specific signals should not see a reputation_factor reason
    const r = triageRisk({ ecosystem: 'pypi' }, { age_days: 365 * 3, version_count: 50 });
    assert(r.mode === 'quick', `expected quick, got ${r.mode}`);
    for (const reason of r.reasons) {
      assert(!reason.startsWith('reputation_factor'),
        `PyPI must not emit reputation_factor (got ${reason})`);
    }
  });

  // ── Compound / regression ────────────────────────────────────────────────

  test('TRIAGE: trusted npm package with lifecycle scripts still flips to full', () => {
    // Even @everymatrix-class trusted packages must run full when they ship
    // install-time hooks — that's where supply-chain payloads land.
    const item = { ecosystem: 'npm', registryScripts: { postinstall: 'echo hi' } };
    const r = triageRisk(item, mockTrustedNpmMeta());
    assert(r.mode === 'full', `expected full (lifecycle dominates trust), got ${r.mode}`);
    assert(r.reasons.includes('lifecycle_scripts'), 'lifecycle_scripts must be in reasons');
  });

  test('TRIAGE: returns reasons even when mode=quick (empty array, for shadow-mode logs)', () => {
    const r = triageRisk({ ecosystem: 'npm' }, mockTrustedNpmMeta());
    assert(Array.isArray(r.reasons), 'reasons must be an array');
    assert(r.reasons.length === 0, 'no reasons for trusted quick package');
  });
}

function mockTrustedNpmMeta() {
  // Mature, well-trafficked package — should drop reputation factor to ~0.10
  return { age_days: 365 * 5, version_count: 200, weekly_downloads: 5_000_000 };
}

module.exports = { runTriageTests };
