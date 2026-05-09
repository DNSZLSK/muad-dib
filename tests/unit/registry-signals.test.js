'use strict';

const { test, assert } = require('../test-utils');

function runRegistrySignalsTests() {
  console.log('\n=== REGISTRY SIGNALS TESTS (Chantier 4) ===\n');

  const {
    computeAdvancedRegistrySignals,
    detectRecentMaintainerChange,
    detectPublishCadenceAnomaly,
    detectStableOwnership
  } = require('../../src/integrations/registry-signals.js');

  // Helper to build a registry packument fixture
  function pkt(versionsSpec) {
    // versionsSpec is array of { version, daysAgo, maintainers: [name,...] }
    const versions = {};
    const time = {};
    for (const spec of versionsSpec) {
      versions[spec.version] = {
        maintainers: spec.maintainers.map(name => ({ name }))
      };
      const t = new Date(Date.now() - spec.daysAgo * 24 * 60 * 60 * 1000);
      time[spec.version] = t.toISOString();
    }
    return { versions, time };
  }

  // --- detectRecentMaintainerChange ---

  test('detectRecentMaintainerChange: stable maintainers => not changed', () => {
    const meta = pkt([
      { version: '1.2.0', daysAgo: 5, maintainers: ['alice'] },
      { version: '1.1.0', daysAgo: 20, maintainers: ['alice'] },
      { version: '1.0.0', daysAgo: 200, maintainers: ['alice'] }
    ]);
    const r = detectRecentMaintainerChange(meta);
    assert(r.changed === false, 'no change detected');
    assert(r.daysSinceChange === null, 'daysSinceChange should be null');
  });

  test('detectRecentMaintainerChange: new maintainer added recently', () => {
    const meta = pkt([
      { version: '2.0.0', daysAgo: 5, maintainers: ['alice', 'attacker'] },
      { version: '1.5.0', daysAgo: 20, maintainers: ['alice'] }
    ]);
    const r = detectRecentMaintainerChange(meta);
    assert(r.changed === true, 'change detected');
    assert(typeof r.daysSinceChange === 'number', 'daysSinceChange numeric');
  });

  test('detectRecentMaintainerChange: maintainer change beyond window => not flagged', () => {
    const meta = pkt([
      { version: '2.0.0', daysAgo: 1, maintainers: ['attacker'] },
      { version: '1.5.0', daysAgo: 90, maintainers: ['alice'] }
    ]);
    const r = detectRecentMaintainerChange(meta);
    assert(r.changed === false, 'change is outside the 30-day window');
  });

  test('detectRecentMaintainerChange: insufficient history => not changed', () => {
    const meta = pkt([{ version: '1.0.0', daysAgo: 10, maintainers: ['alice'] }]);
    const r = detectRecentMaintainerChange(meta);
    assert(r.changed === false, 'single version cannot show change');
  });

  // --- detectPublishCadenceAnomaly ---

  test('detectPublishCadenceAnomaly: stable cadence => no anomaly', () => {
    const meta = pkt([
      { version: '1.6.0', daysAgo: 5, maintainers: ['a'] },
      { version: '1.5.0', daysAgo: 35, maintainers: ['a'] },
      { version: '1.4.0', daysAgo: 65, maintainers: ['a'] },
      { version: '1.3.0', daysAgo: 95, maintainers: ['a'] },
      { version: '1.2.0', daysAgo: 125, maintainers: ['a'] },
      { version: '1.1.0', daysAgo: 155, maintainers: ['a'] },
      { version: '1.0.0', daysAgo: 185, maintainers: ['a'] }
    ]);
    const r = detectPublishCadenceAnomaly(meta);
    assert(r.anomaly === false, 'stable 30-day cadence should not be anomalous');
  });

  test('detectPublishCadenceAnomaly: insufficient history => no anomaly', () => {
    const meta = pkt([
      { version: '1.0.0', daysAgo: 5, maintainers: ['a'] },
      { version: '0.9.0', daysAgo: 35, maintainers: ['a'] }
    ]);
    const r = detectPublishCadenceAnomaly(meta);
    assert(r.anomaly === false, 'fewer than CADENCE_MIN_VERSIONS versions');
  });

  // --- detectStableOwnership ---

  test('detectStableOwnership: insufficient versions => not stable', () => {
    const meta = pkt([
      { version: '1.0.0', daysAgo: 800, maintainers: ['alice'] }
    ]);
    const r = detectStableOwnership(meta);
    assert(r.stable === false, 'single version cannot be stable');
  });

  test('detectStableOwnership: long-stable mature package', () => {
    const versions = [];
    for (let i = 0; i < 150; i++) {
      versions.push({ version: `1.${i}.0`, daysAgo: 5 + i * 10, maintainers: ['alice'] });
    }
    const meta = pkt(versions);
    const r = detectStableOwnership(meta);
    assert(r.stable === true, 'mature package with same maintainer should be stable');
    assert(r.sinceDays >= 2 * 365, 'sinceDays should reflect 2+ years');
  });

  test('detectStableOwnership: maintainer change breaks stability', () => {
    const versions = [];
    versions.push({ version: '2.0.0', daysAgo: 1, maintainers: ['attacker'] });
    for (let i = 0; i < 150; i++) {
      versions.push({ version: `1.${i}.0`, daysAgo: 5 + i * 10, maintainers: ['alice'] });
    }
    const meta = pkt(versions);
    const r = detectStableOwnership(meta);
    assert(r.stable === false, 'recent maintainer change must invalidate stable ownership');
  });

  // --- computeAdvancedRegistrySignals (integration) ---

  test('computeAdvancedRegistrySignals: returns all four signal keys', () => {
    const meta = pkt([
      { version: '1.0.0', daysAgo: 5, maintainers: ['a'] },
      { version: '0.9.0', daysAgo: 30, maintainers: ['a'] }
    ]);
    const out = computeAdvancedRegistrySignals(meta);
    assert(typeof out.maintainer_change_recent === 'boolean', 'maintainer_change_recent boolean');
    assert(typeof out.publish_cadence_anomaly === 'boolean', 'publish_cadence_anomaly boolean');
    assert(typeof out.stable_ownership_2y === 'boolean', 'stable_ownership_2y boolean');
  });

  test('computeAdvancedRegistrySignals: handles missing meta gracefully', () => {
    const out = computeAdvancedRegistrySignals({});
    assert(out.maintainer_change_recent === false, 'no data -> not changed');
    assert(out.stable_ownership_2y === false, 'no data -> not stable');
  });

  // --- Integration with _factorFromMetadata via applyReputationFactor ---

  test('_factorFromMetadata: maintainer_change_recent boosts the factor', () => {
    const { applyReputationFactor } = require('../../src/scoring.js');
    const baseResult = () => ({ summary: { riskScore: 50, riskLevel: 'HIGH' } });
    const noSignals = { age_days: 1000 };
    const withChange = { age_days: 1000, maintainer_change_recent: true };

    const a = baseResult();
    const b = baseResult();
    applyReputationFactor(a, noSignals);
    applyReputationFactor(b, withChange);
    assert(b.summary.reputationFactor > a.summary.reputationFactor,
      `expected boost, baseline=${a.summary.reputationFactor} with-change=${b.summary.reputationFactor}`);
  });

  test('_factorFromMetadata: stable_ownership_2y reduces the factor', () => {
    const { applyReputationFactor } = require('../../src/scoring.js');
    const baseResult = () => ({ summary: { riskScore: 50, riskLevel: 'HIGH' } });
    const noSignals = { age_days: 1000 };
    const stableOwn = { age_days: 1000, stable_ownership_2y: true };

    const a = baseResult();
    const b = baseResult();
    applyReputationFactor(a, noSignals);
    applyReputationFactor(b, stableOwn);
    assert(b.summary.reputationFactor < a.summary.reputationFactor,
      `expected suppression, baseline=${a.summary.reputationFactor} stable-own=${b.summary.reputationFactor}`);
  });
}

module.exports = { runRegistrySignalsTests };
