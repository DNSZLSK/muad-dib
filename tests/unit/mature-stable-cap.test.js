'use strict';

const { test, asyncTest, assert, cleanupTemp } = require('../test-utils');
const fs = require('fs');
const path = require('path');
const os = require('os');

async function runMatureStableCapTests() {
  console.log('\n=== MATURE STABLE CAP TESTS (Chantier 5) ===\n');

  const { applyMatureStableCap, MATURE_CAP_SCORE } = require('../../src/scoring.js');

  // Helper builders. The cap requires scan_version === latest_version so the
  // default fixture matches them; tests that exercise the version mismatch
  // override these explicitly.
  function maturePkgMeta(overrides = {}) {
    return {
      age_days: 6 * 365,
      version_count: 250,
      weekly_downloads: 1500000,
      stable_ownership_2y: true,
      latest_version: '7.2.1',
      scan_version: '7.2.1',
      ...overrides
    };
  }

  function makeResult(threats = [], score = 50) {
    return {
      summary: { riskScore: score, riskLevel: 'HIGH' },
      threats
    };
  }

  test('applyMatureStableCap: caps a clean mature package at MEDIUM', () => {
    const result = makeResult([
      { type: 'obfuscation_detected', severity: 'LOW' },
      { type: 'env_access', severity: 'LOW' }
    ], 50);
    const out = applyMatureStableCap(result, maturePkgMeta());
    assert(out !== null && out.applied === true, 'cap should fire');
    assert(result.summary.riskScore === MATURE_CAP_SCORE,
      `score should be ${MATURE_CAP_SCORE}, got ${result.summary.riskScore}`);
    assert(result.summary.riskLevel === 'MEDIUM', 'riskLevel should be MEDIUM');
    assert(result.summary.matureStableCap === true, 'flag should be set');
  });

  test('applyMatureStableCap: does NOT fire on a young package', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta({ age_days: 200 }));
    assert(out === null, 'young package not capped');
    assert(result.summary.riskScore === 50, 'score unchanged');
  });

  test('applyMatureStableCap: does NOT fire when version_count is low', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta({ version_count: 10 }));
    assert(out === null, 'few versions not capped');
  });

  test('applyMatureStableCap: does NOT fire when downloads are low', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta({ weekly_downloads: 200 }));
    assert(out === null, 'low downloads not capped');
  });

  test('applyMatureStableCap: does NOT fire when ownership is not stable', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta({ stable_ownership_2y: false }));
    assert(out === null, 'unstable ownership not capped');
  });

  test('applyMatureStableCap: does NOT fire on IOC match', () => {
    const result = makeResult([
      { type: 'env_access', severity: 'LOW' },
      { type: 'known_malicious_package', severity: 'CRITICAL' }
    ], 80);
    const out = applyMatureStableCap(result, maturePkgMeta());
    assert(out === null, 'IOC match must skip cap');
    assert(result.summary.riskScore === 80, 'score unchanged on IOC');
  });

  test('applyMatureStableCap: does NOT fire on shai_hulud_marker', () => {
    const result = makeResult([
      { type: 'shai_hulud_marker', severity: 'CRITICAL' }
    ], 90);
    const out = applyMatureStableCap(result, maturePkgMeta());
    assert(out === null, 'shai_hulud_marker forbids cap');
  });

  test('applyMatureStableCap: does NOT fire on HIGH_CONFIDENCE_MALICE_TYPES', () => {
    const result = makeResult([
      { type: 'lifecycle_shell_pipe', severity: 'CRITICAL' }
    ], 80);
    const out = applyMatureStableCap(result, maturePkgMeta());
    assert(out === null, 'HC malice type forbids cap');
  });

  test('applyMatureStableCap: does NOT fire when delta added > 0', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta({ delta_added_threats: 3 }));
    assert(out === null, 'delta added threats forbids cap');
  });

  test('applyMatureStableCap: fires when delta added is 0 or undefined', () => {
    const result1 = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const result2 = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out1 = applyMatureStableCap(result1, maturePkgMeta({ delta_added_threats: 0 }));
    const out2 = applyMatureStableCap(result2, maturePkgMeta()); // undefined delta
    assert(out1 && out1.applied === true, 'delta=0 should not block cap');
    assert(out2 && out2.applied === true, 'delta=undefined should not block cap');
  });

  test('applyMatureStableCap: returns null when score is already <= cap', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 20);
    const out = applyMatureStableCap(result, maturePkgMeta());
    assert(out === null, 'no-op when score already at/below cap');
    assert(result.summary.riskScore === 20, 'score preserved');
  });

  test('applyMatureStableCap: does NOT fire on historical version (mismatch)', () => {
    // Reproduces the fixture pattern : scanning chalk 5.6.1 while live latest
    // is 7.2.1. The cap must NOT mask the historical compromised version.
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta({
      latest_version: '7.2.1',
      scan_version: '5.6.1'
    }));
    assert(out === null, 'version mismatch must skip cap');
    assert(result.summary.riskScore === 50, 'score unchanged');
  });

  test('applyMatureStableCap: does NOT fire when version fields are missing', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out1 = applyMatureStableCap(result, maturePkgMeta({ scan_version: null }));
    const out2 = applyMatureStableCap(result, maturePkgMeta({ latest_version: null }));
    assert(out1 === null, 'missing scan_version blocks cap');
    assert(out2 === null, 'missing latest_version blocks cap');
  });

  test('applyMatureStableCap: handles missing metadata gracefully', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out1 = applyMatureStableCap(result, null);
    const out2 = applyMatureStableCap(result, undefined);
    const out3 = applyMatureStableCap(result, {});
    assert(out1 === null && out2 === null && out3 === null, 'missing meta = no-op');
  });

  test('applyMatureStableCap: records reasons for telemetry', () => {
    const result = makeResult([{ type: 'env_access', severity: 'LOW' }], 50);
    const out = applyMatureStableCap(result, maturePkgMeta());
    assert(out && out.reasons, 'reasons object present');
    assert(typeof out.reasons.age_days === 'number', 'age_days recorded');
    assert(typeof out.reasons.version_count === 'number', 'version_count recorded');
    assert(typeof out.reasons.weekly_downloads === 'number', 'weekly_downloads recorded');
    assert(out.reasons.stable_ownership_2y === true, 'stable_ownership_2y recorded');
  });

  // --- Metadata injection (scanContext.npmRegistryMeta → worker, 429-storm fix) ---
  // Proves the processor CONSUMES main-thread-prefetched metadata via options.npm-
  // RegistryMeta instead of fetching — the exact monitor worker `_capture` path.
  // Offline: the injection branch short-circuits before any getPackageMetadata call.
  await asyncTest('metadata injection: options.npmRegistryMeta drives reputation without a fetch', async () => {
    const { run } = require('../../src/index.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-meta-inj-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'zzz-meta-injection-fixture', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmpDir, 'index.js'), 'module.exports = 1;\n');
    try {
      // Mature, high-reputation metadata → reputation factor < 1 (strong suppression).
      const injected = {
        age_days: 9999, version_count: 500, weekly_downloads: 5000000,
        has_repository: true, stable_ownership_2y: true,
        latest_version: '1.0.0', scan_version: '1.0.0'
      };
      const res = await run(tmpDir, {
        _capture: true, name: 'zzz-meta-injection-fixture', version: '1.0.0',
        npmRegistryMeta: injected
      });
      assert(typeof res.summary.reputationFactor === 'number',
        'reputationFactor must be set from the injected metadata');
      assert(res.summary.reputationFactor < 1,
        `mature high-rep meta must suppress (<1), got ${res.summary.reputationFactor}`);

      // Negative: no injected key + registry fetch disabled → nothing consumed and
      // no network. reputationFactor must stay unset (proves injection is the cause).
      const prev = globalThis.process.env.MUADDIB_NO_REGISTRY_FETCH;
      globalThis.process.env.MUADDIB_NO_REGISTRY_FETCH = '1';
      try {
        const res2 = await run(tmpDir, {
          _capture: true, name: 'zzz-meta-injection-fixture', version: '1.0.0'
        });
        assert(res2.summary.reputationFactor === undefined,
          'without the injected key (and no fetch), reputationFactor must stay unset');
      } finally {
        if (prev === undefined) delete globalThis.process.env.MUADDIB_NO_REGISTRY_FETCH;
        else globalThis.process.env.MUADDIB_NO_REGISTRY_FETCH = prev;
      }
    } finally {
      cleanupTemp(tmpDir);
    }
  });
}

module.exports = { runMatureStableCapTests };
