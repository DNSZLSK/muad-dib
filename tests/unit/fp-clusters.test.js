'use strict';

const { test, assert } = require('../test-utils');

function runFpClustersTests() {
  console.log('\n=== FP CLUSTERS TESTS (Chantier 1) ===\n');

  const { clusterFalsePositives } = require('../../src/commands/evaluate.js');

  test('clusterFalsePositives: empty input returns zero clusters', () => {
    const out = clusterFalsePositives({});
    assert(out.totalFps === 0, 'totalFps should be 0');
    assert(out.totalUniqueClusters === 0, 'totalUniqueClusters should be 0');
    assert(Array.isArray(out.topClusters) && out.topClusters.length === 0, 'topClusters should be []');
  });

  test('clusterFalsePositives: ignores non-flagged details', () => {
    const out = clusterFalsePositives({
      curated: [
        { name: 'safe-pkg', flagged: false, threats: [{ type: 'env_access', severity: 'MEDIUM', file: 'lib/index.js' }] }
      ]
    });
    assert(out.totalFps === 0, 'non-flagged entries must be skipped');
  });

  test('clusterFalsePositives: groups identical type+pattern across packages', () => {
    const out = clusterFalsePositives({
      curated: [
        { name: 'lodash', flagged: true, threats: [{ type: 'obfuscation_detected', severity: 'LOW', file: 'package/dist/lodash.min.js' }] },
        { name: 'moment', flagged: true, threats: [{ type: 'obfuscation_detected', severity: 'LOW', file: 'package/dist/moment.min.js' }] },
        { name: 'jquery', flagged: true, threats: [{ type: 'obfuscation_detected', severity: 'LOW', file: 'package/dist/jquery.min.js' }] }
      ]
    });
    assert(out.totalFps === 3, `expected 3 FPs, got ${out.totalFps}`);
    assert(out.totalUniqueClusters === 1, `expected 1 cluster (normalized to <NAME>.min.js), got ${out.totalUniqueClusters}`);
    const c = out.topClusters[0];
    assert(c.count === 3, 'cluster should have count=3');
    assert(c.distinct_packages === 3, 'cluster should have 3 distinct packages');
    assert(c.is_bundle === true, 'dist/*.min.js must be classified as bundle');
    assert(c.severity_distribution.LOW === 3, 'all 3 threats LOW');
    assert(c.examples.length === 3, '3 examples saved (max 5)');
  });

  test('clusterFalsePositives: separates bundle vs src clusters', () => {
    const out = clusterFalsePositives({
      curated: [
        { name: 'pkg1', flagged: true, threats: [{ type: 'env_access', severity: 'HIGH', file: 'package/dist/pkg1.min.js' }] },
        { name: 'pkg2', flagged: true, threats: [{ type: 'env_access', severity: 'HIGH', file: 'package/lib/pkg2.js' }] }
      ]
    });
    // dist bundle + src lib should produce 2 clusters even with same threat type
    assert(out.totalUniqueClusters === 2, `expected 2 clusters (bundle vs src), got ${out.totalUniqueClusters}`);
    const bundleCluster = out.topClusters.find(c => c.is_bundle === true);
    const srcCluster = out.topClusters.find(c => c.is_bundle === false);
    assert(bundleCluster, 'bundle cluster missing');
    assert(srcCluster, 'src cluster missing');
  });

  test('clusterFalsePositives: normalizes hex hashes and version numbers', () => {
    const out = clusterFalsePositives({
      curated: [
        { name: 'pkg-a', flagged: true, threats: [{ type: 'high_entropy_string', severity: 'LOW', file: 'package/dist/main-abc1234.js' }] },
        { name: 'pkg-b', flagged: true, threats: [{ type: 'high_entropy_string', severity: 'LOW', file: 'package/dist/main-fedcba9876.js' }] }
      ]
    });
    assert(out.totalUniqueClusters === 1, 'hashes must be normalized to <HASH>');
  });

  test('clusterFalsePositives: tracks corpus distribution', () => {
    const out = clusterFalsePositives({
      curated: [{ name: 'a', flagged: true, threats: [{ type: 'eval_use', severity: 'MEDIUM', file: 'index.js' }] }],
      random: [{ name: 'b', flagged: true, threats: [{ type: 'eval_use', severity: 'MEDIUM', file: 'index.js' }] }],
      pypi: [{ name: 'c', flagged: true, threats: [{ type: 'eval_use', severity: 'MEDIUM', file: 'index.js' }] }]
    });
    assert(out.totalUniqueClusters === 1, 'same type+pattern across corpora -> single cluster');
    const c = out.topClusters[0];
    assert(c.corpus_distribution.curated === 1, 'curated should count 1');
    assert(c.corpus_distribution.random === 1, 'random should count 1');
    assert(c.corpus_distribution.pypi === 1, 'pypi should count 1');
  });

  test('clusterFalsePositives: caps examples at 5', () => {
    const threats = Array.from({ length: 10 }, (_, i) => ({
      name: `pkg-${i}`,
      flagged: true,
      threats: [{ type: 'sensitive_string', severity: 'LOW', file: `package/lib/x.js` }]
    }));
    const out = clusterFalsePositives({ curated: threats });
    assert(out.topClusters[0].count === 10, 'count should reflect all 10');
    assert(out.topClusters[0].examples.length === 5, 'examples capped at 5');
    assert(out.topClusters[0].distinct_packages === 10, 'distinct_packages should still be 10');
  });

  test('clusterFalsePositives: sorts clusters by count desc', () => {
    const out = clusterFalsePositives({
      curated: [
        { name: 'a', flagged: true, threats: [{ type: 't1', severity: 'LOW', file: 'a.js' }] },
        { name: 'b', flagged: true, threats: [{ type: 't2', severity: 'LOW', file: 'b.js' }] },
        { name: 'c', flagged: true, threats: [{ type: 't2', severity: 'LOW', file: 'b.js' }] },
        { name: 'd', flagged: true, threats: [{ type: 't2', severity: 'LOW', file: 'b.js' }] }
      ]
    });
    assert(out.topClusters[0].rule_type === 't2', 'most frequent cluster first');
    assert(out.topClusters[0].count === 3, 'top cluster count=3');
    assert(out.topClusters[1].rule_type === 't1', 'second cluster is t1');
  });

  test('clusterFalsePositives: handles missing file field gracefully', () => {
    const out = clusterFalsePositives({
      curated: [{ name: 'a', flagged: true, threats: [{ type: 'package_level', severity: 'HIGH' }] }]
    });
    assert(out.totalFps === 1, 'should still count threat without file');
    assert(out.topClusters[0].file_pattern === '<no-file>', 'file_pattern should be <no-file>');
  });

  test('clusterFalsePositives: schema_version present', () => {
    const out = clusterFalsePositives({});
    assert(out.schema_version === 1, 'schema_version should be 1');
  });
}

module.exports = { runFpClustersTests };
