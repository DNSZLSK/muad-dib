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
    hasHighConfidenceThreat
  } = require('../../src/ml/classifier');

  // Reset model before each test section to ensure isolation
  resetModel();

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

  // Cleanup
  resetModel();
}

module.exports = { runMLClassifierTests };
