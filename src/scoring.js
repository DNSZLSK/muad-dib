// ============================================
// SCORING CONSTANTS
// ============================================
// Severity weights for risk score calculation (0-100)
// These values determine the impact of each threat type on the final score.
// Example: 4 CRITICAL threats = 100 (max score), 10 HIGH threats = 100
const SEVERITY_WEIGHTS = {
  // CRITICAL: Threats with immediate impact (active malware, data exfiltration)
  // High weight because a single critical threat justifies immediate action
  CRITICAL: 25,

  // HIGH: Serious threats (dangerous code, known malicious dependencies)
  // 10 HIGH threats reach the maximum score
  HIGH: 10,

  // MEDIUM: Potential threats (suspicious patterns, light obfuscation)
  // Moderate impact, requires investigation but not necessarily malicious
  MEDIUM: 3,

  // LOW: Informational findings, minimal impact on risk score
  LOW: 1
};

// Thresholds for determining the overall risk level
const RISK_THRESHOLDS = {
  CRITICAL: 75,  // >= 75: Immediate action required
  HIGH: 50,      // >= 50: Priority investigation
  MEDIUM: 25     // >= 25: Monitor
  // < 25 && > 0: LOW
  // === 0: SAFE
};

// Maximum score (capped)
const MAX_RISK_SCORE = 100;

// Cap MEDIUM prototype_hook contribution (frameworks like Restify have 50+ extensions)
const PROTO_HOOK_MEDIUM_CAP = 15;

// ============================================
// PER-FILE MAX SCORING (v2.2.11)
// ============================================
// Threat types classified as package-level (not tied to a specific source file).
// These are added to the package score, not grouped by file.
const PACKAGE_LEVEL_TYPES = new Set([
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified',
  'known_malicious_package', 'typosquat_detected',
  'shai_hulud_marker', 'suspicious_file',
  'pypi_malicious_package', 'pypi_typosquat_detected',
  'dangerous_api_added_critical', 'dangerous_api_added_high', 'dangerous_api_added_medium',
  'publish_burst', 'publish_dormant_spike', 'publish_rapid_succession',
  'maintainer_new_suspicious', 'maintainer_sole_change',
  'sandbox_network_activity', 'sandbox_file_changes', 'sandbox_process_spawns',
  'sandbox_canary_exfiltration'
]);

/**
 * Classify a threat as package-level or file-level.
 * Package-level: metadata findings (package.json, node_modules, sandbox)
 * File-level: code-level findings in specific source files
 */
function isPackageLevelThreat(threat) {
  if (PACKAGE_LEVEL_TYPES.has(threat.type)) return true;
  if (threat.file === 'package.json') return true;
  if (threat.file && (threat.file.startsWith('node_modules/') || threat.file.startsWith('node_modules\\'))) return true;
  if (threat.file && threat.file.startsWith('[SANDBOX]')) return true;
  return false;
}

/**
 * Compute a risk score for a group of threats using standard weights.
 * Handles prototype_hook MEDIUM cap per group.
 * @param {Array} threats - array of threat objects (after FP reductions)
 * @returns {number} score 0-100
 */
function computeGroupScore(threats) {
  const criticalCount = threats.filter(t => t.severity === 'CRITICAL').length;
  const highCount = threats.filter(t => t.severity === 'HIGH').length;
  const mediumCount = threats.filter(t => t.severity === 'MEDIUM').length;
  const lowCount = threats.filter(t => t.severity === 'LOW').length;

  const mediumProtoHookCount = threats.filter(
    t => t.type === 'prototype_hook' && t.severity === 'MEDIUM'
  ).length;
  const protoHookPoints = Math.min(mediumProtoHookCount * SEVERITY_WEIGHTS.MEDIUM, PROTO_HOOK_MEDIUM_CAP);
  const otherMediumCount = mediumCount - mediumProtoHookCount;

  let score = 0;
  score += criticalCount * SEVERITY_WEIGHTS.CRITICAL;
  score += highCount * SEVERITY_WEIGHTS.HIGH;
  score += otherMediumCount * SEVERITY_WEIGHTS.MEDIUM;
  score += protoHookPoints;
  score += lowCount * SEVERITY_WEIGHTS.LOW;
  return Math.min(MAX_RISK_SCORE, score);
}

// ============================================
// FP REDUCTION POST-PROCESSING
// ============================================
// Legitimate frameworks produce high volumes of certain threat types that
// malware never does. This function downgrades severity when the count
// exceeds thresholds only seen in legitimate codebases.
const FP_COUNT_THRESHOLDS = {
  dynamic_require: { maxCount: 10, from: 'HIGH', to: 'LOW' },
  dangerous_call_function: { maxCount: 5, from: 'MEDIUM', to: 'LOW' },
  require_cache_poison: { maxCount: 3, from: 'CRITICAL', to: 'LOW' },
  suspicious_dataflow: { maxCount: 5, to: 'LOW' },
  obfuscation_detected: { maxCount: 3, to: 'LOW' },
  module_compile_dynamic: { maxCount: 3, from: 'CRITICAL', to: 'LOW' },
  module_compile: { maxCount: 3, from: 'CRITICAL', to: 'LOW' },
  zlib_inflate_eval: { maxCount: 2, from: 'CRITICAL', to: 'LOW' }
};

// Types exempt from dist/ downgrade — IOC matches and lifecycle scripts are always real
const DIST_EXEMPT_TYPES = new Set([
  'ioc_match', 'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker',
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified'
]);

// Regex matching dist/build/minified/bundled file paths
const DIST_FILE_RE = /(?:^|[/\\])(?:dist|build)[/\\]|\.min\.js$|\.bundle\.js$/i;

// Types exempt from reachability downgrade — IOC matches, lifecycle, and package-level types
const REACHABILITY_EXEMPT_TYPES = new Set([
  ...DIST_EXEMPT_TYPES,
  'cross_file_dataflow',
  'typosquat_detected', 'pypi_typosquat_detected',
  'pypi_malicious_package',
  'ai_config_injection', 'ai_config_injection_compound'
]);

// Custom class prototypes that HTTP frameworks legitimately extend.
// Distinguished from dangerous core Node.js prototype hooks.
const FRAMEWORK_PROTOTYPES = ['Request', 'Response', 'App', 'Router'];
const FRAMEWORK_PROTO_RE = new RegExp(
  '^(' + FRAMEWORK_PROTOTYPES.join('|') + ')\\.prototype\\.'
);

function applyFPReductions(threats, reachableFiles) {
  // Count occurrences of each threat type (package-level, across all files)
  const typeCounts = {};
  for (const t of threats) {
    typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
  }

  for (const t of threats) {
    // Count-based downgrade: if a threat type appears too many times,
    // it's a framework/plugin system, not malware
    const rule = FP_COUNT_THRESHOLDS[t.type];
    if (rule && typeCounts[t.type] > rule.maxCount && (!rule.from || t.severity === rule.from)) {
      t.severity = rule.to;
    }

    // require_cache_poison: single hit → HIGH (plugin dedup/hot-reload, not malware)
    // Malware poisons cache repeatedly; a single access is framework behavior
    if (t.type === 'require_cache_poison' && t.severity === 'CRITICAL' &&
        typeCounts.require_cache_poison === 1) {
      t.severity = 'HIGH';
    }

    // Prototype hook: framework class prototypes → MEDIUM
    // Core Node.js prototypes (http.IncomingMessage, net.Socket) stay CRITICAL
    // Browser/native APIs (globalThis.fetch, XMLHttpRequest) stay HIGH
    if (t.type === 'prototype_hook' && t.severity === 'HIGH' &&
        FRAMEWORK_PROTO_RE.test(t.message)) {
      t.severity = 'MEDIUM';
    }

    // HTTP client prototype whitelist: packages with >20 prototype_hook hits
    // targeting HTTP objects (Request, Response, fetch, etc.) are legitimate HTTP clients
    if (t.type === 'prototype_hook' && (t.severity === 'HIGH' || t.severity === 'CRITICAL') &&
        typeCounts.prototype_hook > 20) {
      const HTTP_PROTO_RE = /\b(Request|Response|fetch|get|post|put|delete|patch|head|options|query|command)\b/i;
      if (HTTP_PROTO_RE.test(t.message)) {
        t.severity = 'MEDIUM';
      }
    }

    // Dist/build/minified files: bundler artifacts get severity downgraded one notch.
    // Real malware injects payloads in source files, not in dist/ output.
    if (t.file && !DIST_EXEMPT_TYPES.has(t.type) && DIST_FILE_RE.test(t.file)) {
      if (t.severity === 'CRITICAL') t.severity = 'HIGH';
      else if (t.severity === 'HIGH') t.severity = 'MEDIUM';
      else if (t.severity === 'MEDIUM') t.severity = 'LOW';
    }

    // Reachability: findings in files not reachable from entry points → LOW
    if (reachableFiles && reachableFiles.size > 0 && t.file &&
        !REACHABILITY_EXEMPT_TYPES.has(t.type) &&
        !isPackageLevelThreat(t)) {
      const normalizedFile = t.file.replace(/\\/g, '/');
      if (!reachableFiles.has(normalizedFile)) {
        t.severity = 'LOW';
        t.unreachable = true;
      }
    }
  }
}

/**
 * Calculate per-file max risk score from deduplicated threats.
 * Formula: riskScore = min(100, max(file_scores) + package_level_score)
 * @param {Array} deduped - deduplicated threat array
 * @returns {Object} { riskScore, riskLevel, globalRiskScore, maxFileScore, packageScore, mostSuspiciousFile, fileScores, criticalCount, highCount, mediumCount, lowCount }
 */
function calculateRiskScore(deduped) {
  // 1. Separate deduped threats into package-level and file-level
  const packageLevelThreats = [];
  const fileLevelThreats = [];
  for (const t of deduped) {
    if (isPackageLevelThreat(t)) {
      packageLevelThreats.push(t);
    } else {
      fileLevelThreats.push(t);
    }
  }

  // 2. Group file-level threats by file
  const fileGroups = new Map();
  for (const t of fileLevelThreats) {
    const key = t.file || '(unknown)';
    if (!fileGroups.has(key)) fileGroups.set(key, []);
    fileGroups.get(key).push(t);
  }

  // 3. Compute per-file scores and find the most suspicious file
  let maxFileScore = 0;
  let mostSuspiciousFile = null;
  const fileScores = {};
  for (const [file, fileThreats] of fileGroups) {
    const score = computeGroupScore(fileThreats);
    fileScores[file] = score;
    if (score > maxFileScore) {
      maxFileScore = score;
      mostSuspiciousFile = file;
    }
  }

  // 4. Compute package-level score (typosquat, lifecycle, dependency IOC, etc.)
  const packageScore = computeGroupScore(packageLevelThreats);

  // 5. Final score = max file score + package-level score, capped at 100
  const riskScore = Math.min(MAX_RISK_SCORE, maxFileScore + packageScore);

  // 6. Old global score for comparison (sum of ALL findings)
  const globalRiskScore = computeGroupScore(deduped);

  // 7. Severity counts (global, for summary display)
  const criticalCount = deduped.filter(t => t.severity === 'CRITICAL').length;
  const highCount = deduped.filter(t => t.severity === 'HIGH').length;
  const mediumCount = deduped.filter(t => t.severity === 'MEDIUM').length;
  const lowCount = deduped.filter(t => t.severity === 'LOW').length;

  const riskLevel = riskScore >= RISK_THRESHOLDS.CRITICAL ? 'CRITICAL'
                  : riskScore >= RISK_THRESHOLDS.HIGH ? 'HIGH'
                  : riskScore >= RISK_THRESHOLDS.MEDIUM ? 'MEDIUM'
                  : riskScore > 0 ? 'LOW'
                  : 'SAFE';

  return {
    riskScore, riskLevel, globalRiskScore,
    maxFileScore, packageScore, mostSuspiciousFile, fileScores,
    criticalCount, highCount, mediumCount, lowCount
  };
}

module.exports = {
  SEVERITY_WEIGHTS, RISK_THRESHOLDS, MAX_RISK_SCORE,
  isPackageLevelThreat, computeGroupScore, applyFPReductions, calculateRiskScore
};
