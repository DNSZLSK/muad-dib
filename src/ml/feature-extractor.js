'use strict';

/**
 * ML Feature Extractor — extracts numeric/boolean features from scan results
 * for ML classifier training (Phase 1 of FPR reduction pipeline).
 *
 * Features are designed to capture the discriminative signals between true
 * positives and false positives: threat composition, severity distribution,
 * scoring breakdown, and package metadata.
 *
 * Output: flat object with numeric/boolean values suitable for XGBoost/RF.
 */

// Top threat types by frequency in production (covers ~95% of all findings).
// Types not in this list are aggregated into `threat_type_other`.
const TOP_THREAT_TYPES = [
  'suspicious_dataflow',
  'env_access',
  'sensitive_string',
  'dangerous_call_eval',
  'dangerous_call_exec',
  'dangerous_call_function',
  'obfuscation_detected',
  'high_entropy_string',
  'dynamic_require',
  'dynamic_import',
  'lifecycle_script',
  'typosquat_detected',
  'staged_payload',
  'staged_binary_payload',
  'network_require',
  'sandbox_evasion',
  'credential_regex_harvest',
  'remote_code_load',
  'suspicious_domain',
  'prototype_hook',
  'intent_credential_exfil',
  'intent_command_exfil',
  'cross_file_dataflow',
  'module_compile',
  'crypto_decipher',
  'env_charcode_reconstruction',
  'lifecycle_shell_pipe',
  'curl_exec',
  'reverse_shell',
  'binary_dropper',
  'mcp_config_injection'
];

const TOP_THREAT_TYPES_SET = new Set(TOP_THREAT_TYPES);

/**
 * Extract ML features from a scan result object.
 *
 * @param {Object} result - scan result from run() with { threats, summary }
 * @param {Object} meta - package metadata { name, version, ecosystem, unpackedSize, registryMeta }
 * @returns {Object} flat feature vector with numeric/boolean values
 */
function extractFeatures(result, meta) {
  const features = Object.create(null);
  const threats = (result && result.threats) || [];
  const summary = (result && result.summary) || {};

  // --- Scoring features ---
  features.score = summary.riskScore || 0;
  features.max_file_score = summary.maxFileScore || 0;
  features.package_score = summary.packageScore || 0;
  features.global_risk_score = summary.globalRiskScore || 0;

  // --- Severity counts ---
  features.count_total = summary.total || 0;
  features.count_critical = summary.critical || 0;
  features.count_high = summary.high || 0;
  features.count_medium = summary.medium || 0;
  features.count_low = summary.low || 0;

  // --- Distinct threat types ---
  const distinctTypes = new Set(threats.map(t => t.type));
  features.distinct_threat_types = distinctTypes.size;

  // --- Per-type counts (top 31 types) ---
  const typeCounts = Object.create(null);
  for (const t of threats) {
    typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
  }
  for (const type of TOP_THREAT_TYPES) {
    features[`type_${type}`] = typeCounts[type] || 0;
  }
  // Aggregate count for types not in top list
  let otherCount = 0;
  for (const [type, count] of Object.entries(typeCounts)) {
    if (!TOP_THREAT_TYPES_SET.has(type)) {
      otherCount += count;
    }
  }
  features.type_other = otherCount;

  // --- Boolean behavioral signals ---
  features.has_lifecycle_script = threats.some(t => t.type === 'lifecycle_script' || t.type === 'lifecycle_shell_pipe') ? 1 : 0;
  features.has_network_access = threats.some(t =>
    t.type === 'network_require' || t.type === 'remote_code_load' ||
    t.type === 'curl_exec' || t.type === 'suspicious_dataflow'
  ) ? 1 : 0;
  features.has_obfuscation = threats.some(t =>
    t.type === 'obfuscation_detected' || t.type === 'high_entropy_string' ||
    t.type === 'js_obfuscation_pattern'
  ) ? 1 : 0;
  features.has_env_access = threats.some(t => t.type === 'env_access' || t.type === 'env_charcode_reconstruction') ? 1 : 0;
  features.has_eval = threats.some(t => t.type === 'dangerous_call_eval' || t.type === 'dangerous_call_function') ? 1 : 0;
  features.has_staged_payload = threats.some(t => t.type === 'staged_payload' || t.type === 'staged_binary_payload') ? 1 : 0;
  features.has_typosquat = threats.some(t => t.type === 'typosquat_detected' || t.type === 'pypi_typosquat_detected') ? 1 : 0;
  features.has_ioc_match = threats.some(t => t.type === 'known_malicious_package' || t.type === 'known_malicious_hash' || t.type === 'pypi_malicious_package') ? 1 : 0;
  features.has_intent_pair = threats.some(t => t.type === 'intent_credential_exfil' || t.type === 'intent_command_exfil') ? 1 : 0;
  features.has_sandbox_finding = threats.some(t => t.type && t.type.startsWith('sandbox_')) ? 1 : 0;

  // --- File distribution features ---
  const fileScores = summary.fileScores || {};
  const fileScoreValues = Object.values(fileScores);
  features.file_count_with_threats = fileScoreValues.length;
  features.file_score_mean = fileScoreValues.length > 0
    ? Math.round(fileScoreValues.reduce((a, b) => a + b, 0) / fileScoreValues.length)
    : 0;
  features.file_score_max = fileScoreValues.length > 0
    ? Math.max(...fileScoreValues)
    : 0;

  // --- Severity concentration: ratio of CRITICAL+HIGH vs total ---
  features.severity_ratio_high = features.count_total > 0
    ? Math.round(((features.count_critical + features.count_high) / features.count_total) * 100) / 100
    : 0;

  // --- Points concentration: max single-threat points vs score ---
  const breakdown = summary.breakdown || [];
  features.max_single_points = breakdown.length > 0 ? breakdown[0].points : 0;
  features.points_concentration = features.score > 0 && breakdown.length > 0
    ? Math.round((breakdown[0].points / features.score) * 100) / 100
    : 0;

  // --- Package metadata (from registry) ---
  const registry = (meta && meta.registryMeta) || {};
  features.unpacked_size_bytes = (meta && meta.unpackedSize) || registry.unpackedSize || 0;
  features.dep_count = countDeps(registry.dependencies);
  features.dev_dep_count = countDeps(registry.devDependencies);

  // --- Reputation factor (if computed by monitor) ---
  features.reputation_factor = summary.reputationFactor || 1.0;

  // --- Enriched registry/package metadata (Phase 2a) ---
  const npmMeta = (meta && meta.npmRegistryMeta) || {};
  features.package_age_days = npmMeta.age_days || 0;
  features.weekly_downloads = npmMeta.weekly_downloads || 0;
  features.version_count = npmMeta.version_count || 0;
  features.author_package_count = npmMeta.author_package_count || 0;
  features.has_repository = npmMeta.has_repository ? 1 : 0;
  features.readme_size = npmMeta.readme_size || 0;
  features.file_count_total = (meta && meta.fileCountTotal) || 0;
  features.has_tests = (meta && meta.hasTests) ? 1 : 0;
  features.threat_density = features.file_count_with_threats > 0
    ? Math.round((features.count_total / features.file_count_with_threats) * 100) / 100
    : 0;

  return features;
}

/**
 * Count dependencies from a registry metadata dependencies object.
 * Handles both object format ({name: version}) and number.
 */
function countDeps(deps) {
  if (!deps) return 0;
  if (typeof deps === 'number') return deps;
  if (typeof deps === 'object') return Object.keys(deps).length;
  return 0;
}

/**
 * Build a complete JSONL record for a scanned package.
 *
 * @param {Object} result - scan result from run()
 * @param {Object} params - { name, version, ecosystem, unpackedSize, registryMeta, label, tier, sandboxResult }
 * @returns {Object} complete record with metadata + features + label
 */
function buildTrainingRecord(result, params) {
  const {
    name, version, ecosystem,
    unpackedSize, registryMeta,
    npmRegistryMeta, fileCountTotal, hasTests,
    label, tier, sandboxResult
  } = params;

  const features = extractFeatures(result, {
    name, version, ecosystem,
    unpackedSize, registryMeta,
    npmRegistryMeta, fileCountTotal, hasTests
  });

  const record = Object.create(null);

  // --- Identity (not features, for traceability) ---
  record.name = name || '';
  record.version = version || '';
  record.ecosystem = ecosystem || 'npm';
  record.timestamp = new Date().toISOString();

  // --- Label ---
  // 'clean' = no findings or T3 only
  // 'suspect' = T1/T2 (pending manual review)
  // 'unconfirmed' = sandbox clean, not manually reviewed (default for automated relabeling)
  // 'confirmed' = manually confirmed malicious
  // 'fp' = manually confirmed false positive (requires manualReview=true)
  record.label = label || 'suspect';
  record.tier = tier || null;

  // --- Features ---
  Object.assign(record, features);

  // --- Sandbox score (if available) ---
  record.sandbox_score = (sandboxResult && sandboxResult.score) || 0;
  record.sandbox_finding_count = (sandboxResult && sandboxResult.findings)
    ? sandboxResult.findings.length
    : 0;

  return record;
}

module.exports = {
  extractFeatures,
  buildTrainingRecord,
  TOP_THREAT_TYPES,
  TOP_THREAT_TYPES_SET
};
