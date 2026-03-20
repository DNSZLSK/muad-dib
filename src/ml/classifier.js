'use strict';

/**
 * ML Classifier — XGBoost tree ensemble in pure JavaScript.
 *
 * Provides guard-railed ML predictions for T1 zone (score 20-34) packages.
 * Graceful degradation: returns bypass when model is unavailable.
 *
 * Guard rails:
 * - score < 20 → clean (below T1 threshold)
 * - score >= 35 → bypass (above T1 zone, always suspicious)
 * - model absent → bypass
 * - high-confidence threat types → bypass (never suppress HC types)
 */

const { extractFeatures } = require('./feature-extractor.js');

// Lazy-loaded model (allows resetModel for testing)
let _model = undefined; // undefined = not yet loaded, null = absent

// High-confidence malice types that must NEVER be suppressed by ML
const HC_TYPES = new Set([
  'known_malicious_package',
  'known_malicious_hash',
  'pypi_malicious_package',
  'typosquat_detected',
  'pypi_typosquat_detected',
  'reverse_shell',
  'binary_dropper',
  'staged_binary_payload'
]);

/**
 * Load the model from model-trees.js. Returns the model object or null.
 */
function loadModel() {
  if (_model !== undefined) return _model;
  try {
    const trees = require('./model-trees.js');
    _model = trees || null;
  } catch {
    _model = null;
  }
  return _model;
}

/**
 * Check if a trained model is available.
 * @returns {boolean}
 */
function isModelAvailable() {
  return loadModel() !== null;
}

/**
 * Reset model cache (for testing isolation).
 */
function resetModel() {
  _model = undefined;
}

/**
 * Sigmoid function: maps raw margin to probability [0, 1].
 * @param {number} x - raw margin (sum of tree outputs)
 * @returns {number} probability
 */
function sigmoid(x) {
  return 1.0 / (1.0 + Math.exp(-x));
}

/**
 * Traverse a single decision tree with a feature vector.
 * @param {Array} tree - array of nodes [{f, t, y, n, v}, ...]
 * @param {Array<number>} featureValues - ordered feature values
 * @returns {number} leaf value
 */
function traverseTree(tree, featureValues) {
  let nodeIdx = 0;
  while (nodeIdx < tree.length) {
    const node = tree[nodeIdx];
    // Leaf node: f === -1
    if (node.f === -1) {
      return node.v;
    }
    // Decision node: go left (yes) if feature < threshold, else right (no)
    const featureVal = featureValues[node.f] || 0;
    if (featureVal < node.t) {
      nodeIdx = node.y;
    } else {
      nodeIdx = node.n;
    }
  }
  // Fallback: shouldn't reach here with valid trees
  return 0;
}

/**
 * Run XGBoost prediction on ordered feature values.
 * @param {Array<number>} featureValues - ordered feature values matching model.features
 * @returns {{ probability: number, prediction: string }}
 */
function predict(featureValues) {
  const model = loadModel();
  if (!model) return { probability: 0.5, prediction: 'bypass' };

  // Sum margins from all trees
  let margin = 0;
  for (const tree of model.trees) {
    margin += traverseTree(tree, featureValues);
  }

  const probability = sigmoid(margin);
  const prediction = probability >= model.threshold ? 'malicious' : 'clean';
  return { probability, prediction };
}

/**
 * Build ordered feature vector from scan result and metadata.
 * Maps feature names from the model to extracted features.
 *
 * @param {Object} result - scan result from run()
 * @param {Object} meta - { npmRegistryMeta, fileCountTotal, hasTests, unpackedSize, registryMeta }
 * @returns {Array<number>} ordered feature values
 */
function buildFeatureVector(result, meta) {
  const model = loadModel();
  if (!model) return [];

  const features = extractFeatures(result, meta || {});
  const values = new Array(model.features.length);
  for (let i = 0; i < model.features.length; i++) {
    values[i] = features[model.features[i]] || 0;
  }
  return values;
}

/**
 * Check if result contains any high-confidence threat types.
 * @param {Object} result - scan result
 * @returns {boolean}
 */
function hasHighConfidenceThreat(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => HC_TYPES.has(t.type) && t.severity !== 'LOW');
}

/**
 * Classify a package scan result with guard rails.
 *
 * @param {Object} result - scan result from run() with { threats, summary }
 * @param {Object} meta - enriched metadata for feature extraction
 * @returns {{ prediction: string, probability: number, reason: string }}
 *   prediction: 'clean' | 'malicious' | 'bypass'
 *   reason: explains why this prediction was made
 */
function classifyPackage(result, meta) {
  const score = (result && result.summary && result.summary.riskScore) || 0;

  // Guard rail 1: below T1 threshold — always clean
  if (score < 20) {
    return { prediction: 'clean', probability: 0, reason: 'below_t1' };
  }

  // Guard rail 2: above T1 zone — always bypass (let rules decide)
  if (score >= 35) {
    return { prediction: 'bypass', probability: 1, reason: 'score_above_threshold' };
  }

  // Guard rail 3: high-confidence threat types — never suppress (checked before model load)
  if (hasHighConfidenceThreat(result)) {
    return { prediction: 'bypass', probability: 1, reason: 'high_confidence_threat' };
  }

  // Guard rail 4: model not available — bypass
  if (!isModelAvailable()) {
    return { prediction: 'bypass', probability: 0.5, reason: 'model_unavailable' };
  }

  // Build feature vector and predict
  const featureValues = buildFeatureVector(result, meta);
  const { probability, prediction } = predict(featureValues);

  return {
    prediction,
    probability: Math.round(probability * 1000) / 1000,
    reason: prediction === 'clean' ? 'ml_clean' : 'ml_malicious'
  };
}

module.exports = {
  classifyPackage,
  isModelAvailable,
  resetModel,
  loadModel,
  predict,
  traverseTree,
  sigmoid,
  buildFeatureVector,
  hasHighConfidenceThreat
};
