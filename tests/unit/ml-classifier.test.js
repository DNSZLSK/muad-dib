'use strict';

const { test, assert } = require('../test-utils');

function runMLClassifierTests() {
  console.log('\n=== ML CLASSIFIER TESTS ===\n');

  const {
    classifyPackage,
    isModelAvailable,
    resetModel,
    sigmoid,
    traverseTree,
    buildFeatureVector,
    hasHighConfidenceThreat,
    isBundlerModelAvailable,
    resetBundlerModel,
    buildBundlerFeatureVector,
    predictBundler
  } = require('../../src/ml/classifier');

  // Reset model before each test section to ensure isolation
  resetModel();

  // Pre-load models into require cache, then null them for test isolation
  // (model files may contain trained data from ML pipeline)
  try { require('../../src/ml/model-trees.js'); } catch {}
  try { require('../../src/ml/model-bundler.js'); } catch {}
  restoreNullModel();
  restoreNullBundlerModel();

  // --- Guard rail tests ---

  test('classifyPackage: score < 20 returns clean (below_t1)', () => {
    resetModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'MEDIUM', file: 'x.js' }],
      summary: { riskScore: 15, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'clean', `expected clean, got ${ml.prediction}`);
    assert(ml.reason === 'below_t1', `expected below_t1, got ${ml.reason}`);
  });

  test('classifyPackage: score >= 35 returns bypass (score_above_threshold)', () => {
    resetModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 40, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'score_above_threshold', `expected score_above_threshold, got ${ml.reason}`);
  });

  test('classifyPackage: model absent returns bypass (model_unavailable)', () => {
    resetModel();
    // Default model-trees.js is null (stub), so model is unavailable
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 25, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'model_unavailable', `expected model_unavailable, got ${ml.reason}`);
  });

  test('classifyPackage: null result returns clean (below_t1)', () => {
    resetModel();
    const ml = classifyPackage(null, {});
    assert(ml.prediction === 'clean', `expected clean for null result, got ${ml.prediction}`);
    assert(ml.reason === 'below_t1', `expected below_t1, got ${ml.reason}`);
  });

  test('classifyPackage: high-confidence threat returns bypass', () => {
    resetModel();
    const result = {
      threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL', file: 'package.json' }
      ],
      summary: { riskScore: 25, total: 1 }
    };
    const ml = classifyPackage(result, {});
    // HC type forces bypass regardless of model availability
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'high_confidence_threat', `expected high_confidence_threat, got ${ml.reason}`);
  });

  test('classifyPackage: score=19 returns clean (boundary below T1)', () => {
    resetModel();
    const result = { threats: [], summary: { riskScore: 19, total: 0 } };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'clean', `expected clean for score 19, got ${ml.prediction}`);
  });

  test('classifyPackage: score=35 returns bypass (boundary above T1)', () => {
    resetModel();
    const result = { threats: [], summary: { riskScore: 35, total: 0 } };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass for score 35, got ${ml.prediction}`);
  });

  // --- sigmoid tests ---

  test('sigmoid: returns 0.5 for input 0', () => {
    const result = sigmoid(0);
    assert(Math.abs(result - 0.5) < 0.001, `expected ~0.5, got ${result}`);
  });

  test('sigmoid: returns ~1 for large positive input', () => {
    const result = sigmoid(10);
    assert(result > 0.999, `expected >0.999, got ${result}`);
  });

  test('sigmoid: returns ~0 for large negative input', () => {
    const result = sigmoid(-10);
    assert(result < 0.001, `expected <0.001, got ${result}`);
  });

  // --- traverseTree tests ---

  test('traverseTree: leaf-only tree returns leaf value', () => {
    const tree = [{ f: -1, t: 0, y: 0, n: 0, v: 0.42 }];
    const result = traverseTree(tree, []);
    assert(Math.abs(result - 0.42) < 0.001, `expected 0.42, got ${result}`);
  });

  test('traverseTree: simple split — goes left when feature < threshold', () => {
    const tree = [
      { f: 0, t: 25.0, y: 1, n: 2, v: 0 },  // root: if feature[0] < 25 → go left
      { f: -1, t: 0, y: 0, n: 0, v: 0.8 },   // left leaf
      { f: -1, t: 0, y: 0, n: 0, v: -0.3 }    // right leaf
    ];
    const result = traverseTree(tree, [20]); // 20 < 25 → left
    assert(Math.abs(result - 0.8) < 0.001, `expected 0.8, got ${result}`);
  });

  test('traverseTree: simple split — goes right when feature >= threshold', () => {
    const tree = [
      { f: 0, t: 25.0, y: 1, n: 2, v: 0 },
      { f: -1, t: 0, y: 0, n: 0, v: 0.8 },
      { f: -1, t: 0, y: 0, n: 0, v: -0.3 }
    ];
    const result = traverseTree(tree, [30]); // 30 >= 25 → right
    assert(Math.abs(result - (-0.3)) < 0.001, `expected -0.3, got ${result}`);
  });

  test('traverseTree: multi-level split', () => {
    const tree = [
      { f: 0, t: 25.0, y: 1, n: 2, v: 0 },   // root
      { f: 1, t: 3.0, y: 3, n: 4, v: 0 },     // left child: split on feature[1]
      { f: -1, t: 0, y: 0, n: 0, v: -0.5 },    // right leaf of root
      { f: -1, t: 0, y: 0, n: 0, v: 0.9 },     // left leaf of feature[1] split
      { f: -1, t: 0, y: 0, n: 0, v: 0.1 }      // right leaf of feature[1] split
    ];
    // feature[0]=20 < 25 → left → feature[1]=5 >= 3 → right
    const result = traverseTree(tree, [20, 5]);
    assert(Math.abs(result - 0.1) < 0.001, `expected 0.1, got ${result}`);
  });

  // --- hasHighConfidenceThreat tests ---

  test('hasHighConfidenceThreat: returns true for known_malicious_package', () => {
    const result = {
      threats: [{ type: 'known_malicious_package', severity: 'CRITICAL' }]
    };
    assert(hasHighConfidenceThreat(result) === true, 'expected true for IOC match');
  });

  test('hasHighConfidenceThreat: returns false for LOW severity HC type', () => {
    const result = {
      threats: [{ type: 'known_malicious_package', severity: 'LOW' }]
    };
    assert(hasHighConfidenceThreat(result) === false, 'expected false for LOW severity HC');
  });

  test('hasHighConfidenceThreat: returns false for non-HC types', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH' }]
    };
    assert(hasHighConfidenceThreat(result) === false, 'expected false for non-HC type');
  });

  test('hasHighConfidenceThreat: returns false for null result', () => {
    assert(hasHighConfidenceThreat(null) === false, 'expected false for null');
  });

  // --- isModelAvailable tests ---

  test('isModelAvailable: returns false with null stub', () => {
    resetModel();
    assert(isModelAvailable() === false, 'expected false with null model stub');
  });

  // --- resetModel isolation ---

  test('resetModel: allows re-evaluation of model availability', () => {
    resetModel();
    const first = isModelAvailable();
    resetModel();
    const second = isModelAvailable();
    assert(first === second, 'resetModel should produce consistent results');
  });

  // --- Synthetic model tests ---

  const syntheticModel = {
    version: 1,
    features: ['score', 'count_total', 'count_critical'],
    threshold: 0.5,
    trees: [
      [
        { f: 0, t: 25, y: 1, n: 2, v: 0 },   // split on score < 25
        { f: -1, t: 0, y: 0, n: 0, v: -1.5 }, // leaf: clean (sigmoid(-1.5) ~ 0.18)
        { f: -1, t: 0, y: 0, n: 0, v: 1.5 }   // leaf: malicious (sigmoid(1.5) ~ 0.82)
      ]
    ]
  };

  function injectSyntheticModel() {
    resetModel();
    const modelPath = require.resolve('../../src/ml/model-trees.js');
    require.cache[modelPath].exports = syntheticModel;
    resetModel(); // force re-load
  }

  function restoreNullModel() {
    const modelPath = require.resolve('../../src/ml/model-trees.js');
    require.cache[modelPath].exports = null;
    resetModel();
  }

  test('classifyPackage: synthetic model returns clean or malicious (not bypass)', () => {
    injectSyntheticModel();
    try {
      // score=22 (in T1 zone), no HC threats → model should decide
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 22, total: 1 }
      };
      const ml = classifyPackage(result, {});
      assert(
        ml.prediction === 'clean' || ml.prediction === 'malicious',
        `expected clean or malicious, got ${ml.prediction} (reason: ${ml.reason})`
      );
      assert(
        ml.reason === 'ml_clean' || ml.reason === 'ml_malicious',
        `expected ml_clean or ml_malicious, got ${ml.reason}`
      );
    } finally {
      restoreNullModel();
    }
  });

  test('classifyPackage: synthetic model probability is between 0 and 1', () => {
    injectSyntheticModel();
    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 25, total: 1 }
      };
      const ml = classifyPackage(result, {});
      assert(
        ml.probability >= 0 && ml.probability <= 1,
        `probability should be [0,1], got ${ml.probability}`
      );
    } finally {
      restoreNullModel();
    }
  });

  test('buildFeatureVector: returns correct length matching model features', () => {
    injectSyntheticModel();
    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 25, total: 1, critical: 0, high: 1, medium: 0, low: 0 }
      };
      const vec = buildFeatureVector(result, {});
      assert(vec.length === 3, `expected vector length 3, got ${vec.length}`);
      // First element should be score=25
      assert(vec[0] === 25, `expected vec[0]=25 (score), got ${vec[0]}`);
      // Second element should be count_total=1
      assert(vec[1] === 1, `expected vec[1]=1 (count_total), got ${vec[1]}`);
      // Third element should be count_critical=0
      assert(vec[2] === 0, `expected vec[2]=0 (count_critical), got ${vec[2]}`);
    } finally {
      restoreNullModel();
    }
  });

  // === BUNDLER MODEL TESTS (ML2) ===

  // --- isBundlerModelAvailable tests ---

  test('isBundlerModelAvailable: returns false with null stub', () => {
    resetBundlerModel();
    assert(isBundlerModelAvailable() === false, 'expected false with null bundler model stub');
  });

  test('resetBundlerModel: allows re-evaluation of availability', () => {
    resetBundlerModel();
    const first = isBundlerModelAvailable();
    resetBundlerModel();
    const second = isBundlerModelAvailable();
    assert(first === second, 'resetBundlerModel should produce consistent results');
  });

  // --- Bundler model guard rail tests ---

  // Synthetic bundler model: splits on score — score < 50 → clean, >= 50 → malicious
  const syntheticBundlerModel = {
    version: 1,
    features: ['score', 'count_total', 'count_critical'],
    threshold: 0.5,
    trees: [
      [
        { f: 0, t: 50, y: 1, n: 2, v: 0 },   // split on score < 50
        { f: -1, t: 0, y: 0, n: 0, v: -1.5 }, // leaf: clean (sigmoid(-1.5) ~ 0.18)
        { f: -1, t: 0, y: 0, n: 0, v: 1.5 }   // leaf: malicious (sigmoid(1.5) ~ 0.82)
      ]
    ]
  };

  function injectBundlerModel() {
    resetBundlerModel();
    const bundlerPath = require.resolve('../../src/ml/model-bundler.js');
    require.cache[bundlerPath].exports = syntheticBundlerModel;
    resetBundlerModel(); // force re-load
  }

  function restoreNullBundlerModel() {
    const bundlerPath = require.resolve('../../src/ml/model-bundler.js');
    require.cache[bundlerPath].exports = null;
    resetBundlerModel();
  }

  test('classifyPackage: score >= 35, bundler model absent → bypass (score_above_threshold)', () => {
    resetModel();
    restoreNullBundlerModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 40, total: 1 }
    };
    const ml = classifyPackage(result, {});
    assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
    assert(ml.reason === 'score_above_threshold', `expected score_above_threshold, got ${ml.reason}`);
  });

  test('classifyPackage: score >= 35, HC type + bundler model → bypass (high_confidence_threat)', () => {
    resetModel();
    injectBundlerModel();
    try {
      const result = {
        threats: [
          { type: 'reverse_shell', severity: 'CRITICAL', file: 'x.js' }
        ],
        summary: { riskScore: 40, total: 1 }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
      assert(ml.reason === 'high_confidence_threat', `expected high_confidence_threat, got ${ml.reason}`);
    } finally {
      restoreNullBundlerModel();
    }
  });

  test('classifyPackage: score >= 35, no HC, bundler model → fp_bundler (clean prediction)', () => {
    resetModel();
    injectBundlerModel();
    try {
      // score=40 < 50 threshold in bundler tree → leaf value -1.5 → sigmoid ~ 0.18 < 0.5 → clean → fp_bundler
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 40, total: 1 }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'fp_bundler', `expected fp_bundler, got ${ml.prediction}`);
      assert(ml.reason === 'ml_bundler_clean', `expected ml_bundler_clean, got ${ml.reason}`);
      assert(ml.probability < 0.5, `expected probability < 0.5, got ${ml.probability}`);
    } finally {
      restoreNullBundlerModel();
    }
  });

  test('classifyPackage: score >= 35, no HC, bundler model → bypass (malicious prediction)', () => {
    resetModel();
    injectBundlerModel();
    try {
      // score=60 >= 50 threshold in bundler tree → leaf value 1.5 → sigmoid ~ 0.82 >= 0.5 → malicious → bypass
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 60, total: 1 }
      };
      const ml = classifyPackage(result, {});
      assert(ml.prediction === 'bypass', `expected bypass, got ${ml.prediction}`);
      assert(ml.reason === 'ml_bundler_malicious', `expected ml_bundler_malicious, got ${ml.reason}`);
      assert(ml.probability >= 0.5, `expected probability >= 0.5, got ${ml.probability}`);
    } finally {
      restoreNullBundlerModel();
    }
  });

  test('predictBundler: returns bypass when bundler model absent', () => {
    restoreNullBundlerModel();
    const result = predictBundler([40, 1, 0]);
    assert(result.prediction === 'bypass', `expected bypass, got ${result.prediction}`);
    assert(result.probability === 0.5, `expected 0.5, got ${result.probability}`);
  });

  test('predictBundler: returns prediction with injected bundler model', () => {
    injectBundlerModel();
    try {
      const result = predictBundler([40, 1, 0]); // score=40 < 50 → clean
      assert(result.prediction === 'clean', `expected clean, got ${result.prediction}`);
      assert(result.probability < 0.5, `expected probability < 0.5, got ${result.probability}`);
    } finally {
      restoreNullBundlerModel();
    }
  });

  test('buildBundlerFeatureVector: returns empty array when model absent', () => {
    restoreNullBundlerModel();
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { riskScore: 40, total: 1 }
    };
    const vec = buildBundlerFeatureVector(result, {});
    assert(vec.length === 0, `expected empty vector, got length ${vec.length}`);
  });

  test('buildBundlerFeatureVector: returns correct length with injected model', () => {
    injectBundlerModel();
    try {
      const result = {
        threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
        summary: { riskScore: 40, total: 1, critical: 0, high: 1, medium: 0, low: 0 }
      };
      const vec = buildBundlerFeatureVector(result, {});
      assert(vec.length === 3, `expected vector length 3, got ${vec.length}`);
      assert(vec[0] === 40, `expected vec[0]=40 (score), got ${vec[0]}`);
    } finally {
      restoreNullBundlerModel();
    }
  });

  // Cleanup
  resetModel();
  resetBundlerModel();
}

module.exports = { runMLClassifierTests };
