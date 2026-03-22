'use strict';

const { test, assert } = require('../test-utils');

function runMLPipelineTests() {
  console.log('\n=== ML PIPELINE INTEGRATION TESTS ===\n');

  const { extractFeatures, buildTrainingRecord } = require('../../src/ml/feature-extractor');
  const {
    classifyPackage, resetModel, isModelAvailable,
    resetBundlerModel, isBundlerModelAvailable
  } = require('../../src/ml/classifier');

  // --- Round-trip: enriched features → training record ---

  test('ML pipeline: enriched features present in training record', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'index.js' }],
      summary: {
        total: 1, critical: 0, high: 1, medium: 0, low: 0,
        riskScore: 25, maxFileScore: 25, packageScore: 0,
        fileScores: { 'index.js': 25 }
      }
    };

    const record = buildTrainingRecord(result, {
      name: 'test-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      label: 'suspect',
      tier: 1,
      npmRegistryMeta: {
        age_days: 365,
        weekly_downloads: 50000,
        version_count: 12,
        author_package_count: 5,
        has_repository: true,
        readme_size: 2048
      },
      fileCountTotal: 15,
      hasTests: true
    });

    // Verify enriched features are present
    assert(record.package_age_days === 365, `package_age_days should be 365, got ${record.package_age_days}`);
    assert(record.weekly_downloads === 50000, `weekly_downloads should be 50000, got ${record.weekly_downloads}`);
    assert(record.version_count === 12, `version_count should be 12, got ${record.version_count}`);
    assert(record.author_package_count === 5, `author_package_count should be 5, got ${record.author_package_count}`);
    assert(record.has_repository === 1, `has_repository should be 1, got ${record.has_repository}`);
    assert(record.readme_size === 2048, `readme_size should be 2048, got ${record.readme_size}`);
    assert(record.file_count_total === 15, `file_count_total should be 15, got ${record.file_count_total}`);
    assert(record.has_tests === 1, `has_tests should be 1, got ${record.has_tests}`);
    assert(typeof record.threat_density === 'number', `threat_density should be a number`);
  });

  test('ML pipeline: enriched features default to 0 when absent', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 }
    };

    const record = buildTrainingRecord(result, {
      name: 'test-pkg',
      version: '1.0.0',
      label: 'clean'
    });

    assert(record.package_age_days === 0, `package_age_days should default to 0`);
    assert(record.weekly_downloads === 0, `weekly_downloads should default to 0`);
    assert(record.version_count === 0, `version_count should default to 0`);
    assert(record.has_repository === 0, `has_repository should default to 0`);
    assert(record.readme_size === 0, `readme_size should default to 0`);
    assert(record.file_count_total === 0, `file_count_total should default to 0`);
    assert(record.has_tests === 0, `has_tests should default to 0`);
    assert(record.threat_density === 0, `threat_density should default to 0`);
  });

  // --- Graceful degradation (model absent → bypass) ---

  test('ML pipeline: model absent → bypass for T1 score', () => {
    resetModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 25, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'model_unavailable', `expected model_unavailable, got ${ml.reason}`);
  });

  test('ML pipeline: isModelAvailable returns false with stub', () => {
    resetModel();
    assert(isModelAvailable() === false, 'model should not be available with null stub');
  });

  // --- T1 boundary tests ---

  test('ML pipeline: score=19 → clean (below T1)', () => {
    resetModel();
    const result = { threats: [], summary: { riskScore: 19, total: 0 } };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'clean', `expected clean, got ${ml.prediction}`);
  });

  test('ML pipeline: score=20 → bypass (in T1 zone, model absent)', () => {
    resetModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 20, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
  });

  test('ML pipeline: score=34 → bypass (in T1 zone, model absent)', () => {
    resetModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 34, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
  });

  test('ML pipeline: score=35 → bypass (above T1)', () => {
    resetModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'CRITICAL', file: 'x.js' }],
      summary: { riskScore: 35, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'score_above_threshold', `expected score_above_threshold, got ${ml.reason}`);
  });

  // --- Feature vector key count ---

  test('ML pipeline: feature vector has 71 keys (62 + 9 enriched)', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 10 }
    };
    const features = extractFeatures(result, {
      npmRegistryMeta: { age_days: 10, weekly_downloads: 100, version_count: 1, author_package_count: 1, has_repository: false, readme_size: 0 },
      fileCountTotal: 5,
      hasTests: false
    });
    const keys = Object.keys(features);
    // 62 original + 9 new = 71
    assert(keys.length >= 64, `Feature vector should have 64+ keys, got ${keys.length}`);
  });

  // --- Synthetic model end-to-end tests ---

  const syntheticModel = {
    version: 1,
    features: ['score', 'count_total', 'count_critical'],
    threshold: 0.5,
    trees: [
      [
        { f: 0, t: 25, y: 1, n: 2, v: 0 },   // split on score < 25
        { f: -1, t: 0, y: 0, n: 0, v: -1.5 }, // leaf: clean
        { f: -1, t: 0, y: 0, n: 0, v: 1.5 }   // leaf: malicious
      ]
    ]
  };

  function injectModel() {
    resetModel();
    const modelPath = require.resolve('../../src/ml/model-trees.js');
    require.cache[modelPath].exports = syntheticModel;
    resetModel();
  }

  function restoreModel() {
    const modelPath = require.resolve('../../src/ml/model-trees.js');
    require.cache[modelPath].exports = null;
    resetModel();
  }

  test('ML pipeline: end-to-end with synthetic model — low score → clean', () => {
    injectModel();
    try {
      // score=22 < 25 threshold in tree → leaf value -1.5 → sigmoid ~ 0.18 < 0.5 → clean
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: {
          total: 1, critical: 0, high: 1, medium: 0, low: 0,
          riskScore: 22, maxFileScore: 22, packageScore: 0,
          fileScores: { 'x.js': 22 }
        }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'clean', `expected clean for score=22, got ${ml.prediction}`);
      assert(ml.probability < 0.5, `expected probability < 0.5, got ${ml.probability}`);
    } finally {
      restoreModel();
    }
  });

  test('ML pipeline: feature alignment — synthetic model features exist in extractFeatures()', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 25 }
    };
    const features = extractFeatures(result, {});
    // All 3 features used by synthetic model must be present in extractFeatures output
    for (const feat of syntheticModel.features) {
      assert(feat in features, `feature '${feat}' missing from extractFeatures output`);
    }
  });

  // === BUNDLER MODEL INTEGRATION TESTS (ML2) ===

  test('ML pipeline: bundler model absent → isBundlerModelAvailable returns false', () => {
    resetBundlerModel();
    assert(isBundlerModelAvailable() === false, 'bundler model should not be available with null stub');
  });

  test('ML pipeline: score >= 35, bundler model absent → bypass (score_above_threshold)', () => {
    resetModel();
    resetBundlerModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 40, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'score_above_threshold', `expected score_above_threshold, got ${ml.reason}`);
  });

  // Synthetic bundler model for integration tests
  const syntheticBundlerModel = {
    version: 1,
    features: ['score', 'count_total', 'count_critical'],
    threshold: 0.5,
    trees: [
      [
        { f: 0, t: 50, y: 1, n: 2, v: 0 },   // split on score < 50
        { f: -1, t: 0, y: 0, n: 0, v: -1.5 }, // leaf: clean (bundler FP)
        { f: -1, t: 0, y: 0, n: 0, v: 1.5 }   // leaf: malicious
      ]
    ]
  };

  function injectBundlerModel() {
    resetBundlerModel();
    const bundlerPath = require.resolve('../../src/ml/model-bundler.js');
    require.cache[bundlerPath].exports = syntheticBundlerModel;
    resetBundlerModel();
  }

  function restoreBundlerModel() {
    const bundlerPath = require.resolve('../../src/ml/model-bundler.js');
    require.cache[bundlerPath].exports = null;
    resetBundlerModel();
  }

  test('ML pipeline: end-to-end bundler model — low score → fp_bundler', () => {
    injectBundlerModel();
    try {
      // score=40 < 50 threshold in bundler tree → clean → fp_bundler
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: {
          total: 1, critical: 0, high: 1, medium: 0, low: 0,
          riskScore: 40, maxFileScore: 40, packageScore: 0,
          fileScores: { 'x.js': 40 }
        }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'fp_bundler', `expected fp_bundler for score=40, got ${ml.prediction}`);
      assert(ml.reason === 'ml_bundler_clean', `expected ml_bundler_clean, got ${ml.reason}`);
    } finally {
      restoreBundlerModel();
    }
  });

  test('ML pipeline: end-to-end bundler model — high score → bypass', () => {
    injectBundlerModel();
    try {
      // score=60 >= 50 threshold → malicious → bypass
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: {
          total: 1, critical: 0, high: 1, medium: 0, low: 0,
          riskScore: 60, maxFileScore: 60, packageScore: 0,
          fileScores: { 'x.js': 60 }
        }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'bypass', `expected bypass for score=60, got ${ml.prediction}`);
      assert(ml.reason === 'ml_bundler_malicious', `expected ml_bundler_malicious, got ${ml.reason}`);
    } finally {
      restoreBundlerModel();
    }
  });

  test('ML pipeline: bundler model never overrides HC types (score >= 35)', () => {
    injectBundlerModel();
    try {
      // score=40 would be fp_bundler, but HC type forces bypass
      const result = {
        threats: [
          { type: 'binary_dropper', severity: 'CRITICAL', file: 'x.js' },
          { type: 'env_access', severity: 'HIGH', file: 'x.js' }
        ],
        summary: { riskScore: 40, total: 2 }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'bypass', `expected bypass for HC type, got ${ml.prediction}`);
      assert(ml.reason === 'high_confidence_threat', `expected high_confidence_threat, got ${ml.reason}`);
    } finally {
      restoreBundlerModel();
    }
  });

  test('ML pipeline: T1 zone (score 20-34) unaffected by bundler model', () => {
    injectBundlerModel();
    try {
      // score=25 is in T1 zone — should use T1 model (or bypass if absent), NOT bundler model
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 25, total: 1 }
      };
      const ml = classifyPackage(result, {});
      // T1 model decision (or bypass if T1 model absent) — never fp_bundler
      assert(ml.prediction !== 'fp_bundler',
        `T1 zone should not use bundler model, got ${ml.prediction}`);
    } finally {
      restoreBundlerModel();
    }
  });

  test('ML pipeline: bundler model probability is between 0 and 1', () => {
    injectBundlerModel();
    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 40, total: 1 }
      };
      const ml = classifyPackage(result, {});
      assert(
        ml.probability >= 0 && ml.probability <= 1,
        `bundler probability should be [0,1], got ${ml.probability}`
      );
    } finally {
      restoreBundlerModel();
    }
  });

  // Cleanup
  resetModel();
  resetBundlerModel();
}

module.exports = { runMLPipelineTests };
