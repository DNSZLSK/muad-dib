'use strict';

/**
 * ML Classifier — XGBoost tree ensemble in pure JavaScript.
 *
 * Provides guard-railed ML predictions for T1 zone (score 20-34) packages.
 * Graceful degradation: returns bypass when model is unavailable.
 *
 * Guard rails:
 * - score < 20 → clean (below T1 threshold)
 * - score >= 35:
 *   1. HC_TYPES present → bypass (never suppress)
 *   2. Bundler model available → bundler model decides (fp_bundler or bypass)
 *   3. Bundler model absent → bypass (unchanged)
 * - model absent → bypass (T1 zone)
 * - high-confidence threat types → bypass (never suppress HC types, T1 zone)
 */

const { extractFeatures } = require('./feature-extractor.js');

// Lazy-loaded models (allows resetModel for testing)
let _model = undefined; // undefined = not yet loaded, null = absent
let _bundlerModel = undefined; // undefined = not yet loaded, null = absent
let _shadowModel = undefined; // undefined = not yet loaded, null = absent

// Shadow mode stats (reset on model reload)
const _shadowStats = { total: 0, agree: 0, disagree: 0 };

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

// --- Bundler detector model (ML2) ---

/**
 * Load the bundler detector model from model-bundler.js. Returns the model object or null.
 */
function loadBundlerModel() {
  if (_bundlerModel !== undefined) return _bundlerModel;
  try {
    const trees = require('./model-bundler.js');
    _bundlerModel = trees || null;
  } catch {
    _bundlerModel = null;
  }
  return _bundlerModel;
}

/**
 * Check if a trained bundler model is available.
 * @returns {boolean}
 */
function isBundlerModelAvailable() {
  return loadBundlerModel() !== null;
}

/**
 * Reset bundler model cache (for testing isolation).
 */
function resetBundlerModel() {
  _bundlerModel = undefined;
}

// --- Shadow model (ML1 v2, logs only, no filtering) ---

/**
 * Load shadow model from model-trees-shadow.js. Returns model object or null.
 * Shadow model runs in parallel with the main model for comparison.
 */
function loadShadowModel() {
  if (_shadowModel !== undefined) return _shadowModel;
  try {
    _shadowModel = require('./model-trees-shadow.js') || null;
  } catch {
    _shadowModel = null;
  }
  return _shadowModel;
}

function isShadowModelAvailable() {
  return loadShadowModel() !== null;
}

function resetShadowModel() {
  _shadowModel = undefined;
  _shadowStats.total = 0;
  _shadowStats.agree = 0;
  _shadowStats.disagree = 0;
}

/**
 * Run shadow model prediction and log comparison with main model.
 * Never affects the actual classification decision.
 *
 * @param {Object} result - scan result
 * @param {Object} meta - enriched metadata
 * @param {string} mainPrediction - the main model's prediction
 * @param {number} mainProbability - the main model's probability
 * @param {string} packageName - for logging
 */
function runShadowComparison(result, meta, mainPrediction, mainProbability, packageName) {
  const shadow = loadShadowModel();
  if (!shadow) return;

  const features = extractFeatures(result, meta || {});
  const values = new Array(shadow.features.length);
  for (let i = 0; i < shadow.features.length; i++) {
    values[i] = features[shadow.features[i]] || 0;
  }

  let margin = 0;
  for (const tree of shadow.trees) {
    margin += traverseTree(tree, values);
  }

  const shadowProb = sigmoid(margin);
  const shadowPred = shadowProb >= shadow.threshold ? 'malicious' : 'clean';

  _shadowStats.total++;
  if (shadowPred === mainPrediction) {
    _shadowStats.agree++;
  } else {
    _shadowStats.disagree++;
    console.log(`[ML-SHADOW] Disagreement on ${packageName}: main=${mainPrediction}(${mainProbability}) shadow=${shadowPred}(${Math.round(shadowProb * 1000) / 1000}) [${_shadowStats.disagree}/${_shadowStats.total} disagree]`);
  }

  // Periodic summary every 100 classifications
  if (_shadowStats.total % 100 === 0) {
    const agreeRate = ((_shadowStats.agree / _shadowStats.total) * 100).toFixed(1);
    console.log(`[ML-SHADOW] Stats: ${_shadowStats.total} total, ${agreeRate}% agree, ${_shadowStats.disagree} disagree`);
  }
}

function getShadowStats() {
  return { ..._shadowStats };
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
 * Build ordered feature vector for the bundler model from scan result and metadata.
 * @param {Object} result - scan result from run()
 * @param {Object} meta - enriched metadata
 * @returns {Array<number>} ordered feature values
 */
function buildBundlerFeatureVector(result, meta) {
  const model = loadBundlerModel();
  if (!model) return [];

  const features = extractFeatures(result, meta || {});
  const values = new Array(model.features.length);
  for (let i = 0; i < model.features.length; i++) {
    values[i] = features[model.features[i]] || 0;
  }
  return values;
}

/**
 * Run bundler model prediction on ordered feature values.
 * @param {Array<number>} featureValues - ordered feature values matching bundler model features
 * @returns {{ probability: number, prediction: string }}
 */
function predictBundler(featureValues) {
  const model = loadBundlerModel();
  if (!model) return { probability: 0.5, prediction: 'bypass' };

  let margin = 0;
  for (const tree of model.trees) {
    margin += traverseTree(tree, featureValues);
  }

  const probability = sigmoid(margin);
  const prediction = probability >= model.threshold ? 'malicious' : 'clean';
  return { probability, prediction };
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
 *   prediction: 'clean' | 'malicious' | 'bypass' | 'fp_bundler'
 *   reason: explains why this prediction was made
 */
function classifyPackage(result, meta) {
  const score = (result && result.summary && result.summary.riskScore) || 0;

  // Guard rail 1: below T1 threshold — always clean
  if (score < 20) {
    return { prediction: 'clean', probability: 0, reason: 'below_t1' };
  }

  // Guard rail 2: above T1 zone — bundler model or bypass
  if (score >= 35) {
    // Guard rail 2a: HC types present → always bypass (never suppress)
    if (hasHighConfidenceThreat(result)) {
      return { prediction: 'bypass', probability: 1, reason: 'high_confidence_threat' };
    }

    // Guard rail 2b: bundler model available → let it decide
    if (isBundlerModelAvailable()) {
      const bundlerVec = buildBundlerFeatureVector(result, meta);
      const bundlerResult = predictBundler(bundlerVec);
      if (bundlerResult.prediction === 'clean') {
        return {
          prediction: 'fp_bundler',
          probability: Math.round(bundlerResult.probability * 1000) / 1000,
          reason: 'ml_bundler_clean'
        };
      }
      return {
        prediction: 'bypass',
        probability: Math.round(bundlerResult.probability * 1000) / 1000,
        reason: 'ml_bundler_malicious'
      };
    }

    // Guard rail 2c: bundler model absent → bypass
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

  const roundedProb = Math.round(probability * 1000) / 1000;

  // Shadow model comparison (log-only, never affects decision)
  if (isShadowModelAvailable()) {
    const pkgName = (result && result.summary && result.summary.packageName) ||
                    (meta && meta.name) || 'unknown';
    runShadowComparison(result, meta, prediction, roundedProb, pkgName);
  }

  return {
    prediction,
    probability: roundedProb,
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
  hasHighConfidenceThreat,
  // Bundler detector (ML2)
  isBundlerModelAvailable,
  resetBundlerModel,
  loadBundlerModel,
  predictBundler,
  buildBundlerFeatureVector,
  // Shadow model (ML1 v2, log-only comparison)
  isShadowModelAvailable,
  resetShadowModel,
  loadShadowModel,
  getShadowStats
};
