'use strict';

// ============================================
// INTENT GRAPH — Intra-File Coherence Analysis
// ============================================
// Boosts score when a SINGLE file contains both a high-confidence credential
// source AND a dangerous sink (eval, exec, network). This is genuinely suspicious
// because legitimate code rarely reads .npmrc and evals in the same file.
//
// DESIGN PRINCIPLES (informed by SpiderScan, Cerebro, taint-slicing research):
// 1. INTRA-FILE ONLY — cross-file pairing without proven data flow = FP explosion
//    (aws-sdk has process.env in config.js + https.request in http.js = not malicious)
// 2. Cross-file detection is handled by module-graph.js → cross_file_dataflow threats
// 3. Sources = ONLY high-confidence credential access (NOT env_access, NOT suspicious_dataflow)
// 4. Sinks = ONLY threats already identified by scanners (NO content-based scanning)
// 5. No double-counting — suspicious_dataflow is already a compound detection

// ============================================
// SOURCE CLASSIFICATION
// ============================================
const SOURCE_TYPES = {
  sensitive_string: 'credential_read',        // .npmrc, .ssh, .env file references
  env_harvesting_dynamic: 'credential_read',  // Object.keys(process.env), rest destructuring
  credential_regex_harvest: 'credential_read', // regex patterns for tokens/passwords
  llm_api_key_harvest: 'credential_read',     // OPENAI_API_KEY, ANTHROPIC_API_KEY
  credential_cli_steal: 'credential_read',    // gh auth token, gcloud auth
  // env_access EXCLUDED — standard config (process.env.PORT, AWS_REGION, NODE_ENV)
  // suspicious_dataflow EXCLUDED — already compound detection
  // cross_file_dataflow EXCLUDED — already scored CRITICAL by module-graph
};

// ============================================
// SINK CLASSIFICATION (from existing threats only)
// ============================================
const THREAT_SINK_TYPES = {
  dangerous_call_eval: 'exec_sink',
  dangerous_call_function: 'exec_sink',
  staged_eval_decode: 'exec_sink',
  vm_code_execution: 'exec_sink',
  module_compile: 'exec_sink',
  module_compile_dynamic: 'exec_sink',
  credential_tampering: 'file_tamper',
  git_hook_injection: 'file_tamper',
  workflow_write: 'file_tamper',
  mcp_config_injection: 'file_tamper',
  ide_persistence: 'file_tamper',
};

// Message-based sink detection for threats not in THREAT_SINK_TYPES
const SINK_MESSAGE_PATTERNS = [
  { pattern: /https?\.request|dns\.resolve|net\.connect/, type: 'network_external' },
  { pattern: /webhook/i, type: 'network_external' },
];

// ============================================
// COHERENCE MATRIX
// ============================================
// Only applied to intra-file pairs. Cross-file coherence is handled by module-graph.
const COHERENCE_MATRIX = {
  credential_read: {
    network_external: { modifier: 30, severity: 'CRITICAL' },
    network_internal: { modifier: 10, severity: 'HIGH' },
    exec_sink:        { modifier: 25, severity: 'CRITICAL' },
    file_local:       { modifier: 5,  severity: 'MEDIUM' },
    file_tamper:      { modifier: 20, severity: 'HIGH' },
  },
  fingerprint_read: {
    network_external: { modifier: 0,  severity: 'LOW' },
    network_internal: { modifier: 0,  severity: 'LOW' },
    exec_sink:        { modifier: 10, severity: 'MEDIUM' },
    file_local:       { modifier: 0,  severity: 'LOW' },
    file_tamper:      { modifier: 5,  severity: 'LOW' },
  },
  telemetry_read: {
    network_external: { modifier: 0,  severity: 'LOW' },
    network_internal: { modifier: 0,  severity: 'LOW' },
    exec_sink:        { modifier: 0,  severity: 'LOW' },
    file_local:       { modifier: 0,  severity: 'LOW' },
    file_tamper:      { modifier: 0,  severity: 'LOW' },
  },
  config_read: {
    network_external: { modifier: 5,  severity: 'LOW' },
    network_internal: { modifier: 0,  severity: 'LOW' },
    exec_sink:        { modifier: 5,  severity: 'LOW' },
    file_local:       { modifier: 0,  severity: 'LOW' },
    file_tamper:      { modifier: 0,  severity: 'LOW' },
  },
  command_output: {
    network_external: { modifier: 20, severity: 'HIGH' },
    network_internal: { modifier: 5,  severity: 'MEDIUM' },
    exec_sink:        { modifier: 15, severity: 'HIGH' },
    file_local:       { modifier: 5,  severity: 'MEDIUM' },
    file_tamper:      { modifier: 15, severity: 'HIGH' },
  },
};

// Kept for backward compatibility but no longer used in pairing
// Cross-file detection is handled by module-graph.js (cross_file_dataflow)
const CROSS_FILE_MULTIPLIER = 0.5;

/**
 * Classify a threat as a source type.
 * Only high-confidence credential access patterns.
 */
function classifySource(threat) {
  if (SOURCE_TYPES[threat.type]) return SOURCE_TYPES[threat.type];

  // Explicitly excluded types
  if (threat.type === 'suspicious_dataflow') return null;
  if (threat.type === 'env_access') return null;
  if (threat.type === 'cross_file_dataflow') return null;

  // Message-based: only for threats referencing sensitive file paths
  if (threat.message) {
    const msg = threat.message;
    if (/\.npmrc|\.ssh\/|\.aws\/|id_rsa|\.gitconfig/i.test(msg)) {
      return 'credential_read';
    }
  }

  return null;
}

/**
 * Classify a threat as a sink type.
 * Only from existing threat types — no content scanning.
 */
function classifySink(threat) {
  if (THREAT_SINK_TYPES[threat.type]) return THREAT_SINK_TYPES[threat.type];

  if (threat.message) {
    for (const { pattern, type } of SINK_MESSAGE_PATTERNS) {
      if (pattern.test(threat.message)) return type;
    }
  }

  return null;
}

/**
 * Build intent pairs from INTRA-FILE co-occurrence only.
 * Cross-file detection is handled by module-graph.js (cross_file_dataflow).
 *
 * @param {Array} threats - deduplicated threat array
 * @returns {Object} { pairs, intentScore, intentThreats }
 */
function buildIntentPairs(threats) {
  // Only consider MEDIUM+ threats. LOW severity means applyFPReductions already
  // determined this is noise (bundler artifact, dist/ file, count threshold exceeded).
  // Re-elevating LOW threats via intent pairing would undo FP reductions.
  const eligible = threats.filter(t => t.severity !== 'LOW');

  // Group eligible threats by file
  const byFile = new Map();
  for (const t of eligible) {
    const file = t.file || '(unknown)';
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file).push(t);
  }

  const pairSet = new Set();
  const pairs = [];
  let intentScore = 0;

  // Only pair sources and sinks within the SAME file
  for (const [file, fileThreats] of byFile) {
    const sources = [];
    const sinks = [];

    for (const t of fileThreats) {
      const srcType = classifySource(t);
      const sinkType = classifySink(t);
      if (srcType) sources.push(srcType);
      if (sinkType) sinks.push(sinkType);
    }

    if (sources.length === 0 || sinks.length === 0) continue;

    // Deduplicate source×sink combinations within this file
    for (const srcType of new Set(sources)) {
      const srcMatrix = COHERENCE_MATRIX[srcType];
      if (!srcMatrix) continue;

      for (const sinkType of new Set(sinks)) {
        const entry = srcMatrix[sinkType];
        if (!entry || entry.modifier === 0) continue;

        const pairKey = `${srcType}:${sinkType}:${file}`;
        if (pairSet.has(pairKey)) continue;
        pairSet.add(pairKey);

        pairs.push({
          sourceType: srcType,
          sinkType,
          severity: entry.severity,
          modifier: entry.modifier,
          crossFile: false,
          sourceFile: file,
          sinkFile: file
        });
        intentScore += entry.modifier;
      }
    }
  }

  // Generate intent threats only for high-confidence pairs (modifier >= 25)
  const intentThreats = [];
  for (const pair of pairs) {
    if (pair.modifier >= 25) {
      const type = pair.sourceType === 'credential_read'
        ? 'intent_credential_exfil'
        : pair.sourceType === 'command_output'
          ? 'intent_command_exfil'
          : 'intent_credential_exfil';
      intentThreats.push({
        type,
        severity: pair.severity,
        message: `Intent coherence: ${pair.sourceType} → ${pair.sinkType} (${pair.sourceFile})`,
        file: pair.sourceFile
      });
    }
  }

  return { pairs, intentScore, intentThreats };
}

module.exports = {
  classifySource,
  classifySink,
  buildIntentPairs,
  COHERENCE_MATRIX,
  CROSS_FILE_MULTIPLIER
};
