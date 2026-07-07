/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

'use strict';

const fs = require('fs');
const path = require('path');

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
// 6. Destination-aware: SDK patterns (env key matches API domain) are NOT exfiltration

// ============================================
// SOURCE CLASSIFICATION
// ============================================
const SOURCE_TYPES = {
  sensitive_string: 'credential_read',        // .npmrc, .ssh, .env file references
  env_harvesting_dynamic: 'credential_read',  // Object.keys(process.env), rest destructuring
  credential_regex_harvest: 'credential_read', // regex patterns for tokens/passwords
  llm_api_key_harvest: 'credential_read',     // OPENAI_API_KEY, ANTHROPIC_API_KEY
  credential_cli_steal: 'credential_read',    // gh auth token, gcloud auth
  // env_access: conditionally classified — see classifySource()
  // suspicious_dataflow EXCLUDED — already compound detection
  // cross_file_dataflow EXCLUDED — already scored CRITICAL by module-graph
};

// Sensitive env var patterns — env_access referencing these is credential theft, not config
const SENSITIVE_ENV_PATTERNS = /TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|API_KEY|AUTH/i;

// Destination-aware SDK detection — extracted to a shared leaf module
// (src/sdk-destination.js) so the same logic gates dataflow.js and the cross-file /
// detached taint detectors, not just intent coherence. Re-exported below for
// backward compatibility (dataflow.js imports isSDKPattern from this module).
const {
  isSDKPattern,
  networkDestinationsAllBenign,
  extractEnvVarFromMessage,
  extractBrandFromEnvVar,
  SDK_ENV_DOMAIN_MAP,
} = require('./sdk-destination.js');


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

/**
 * Classify a threat as a source type.
 * Only high-confidence credential access patterns.
 */
function classifySource(threat) {
  if (SOURCE_TYPES[threat.type]) return SOURCE_TYPES[threat.type];

  // env_access: only classify as credential_read if accessing sensitive vars
  // Standard config (NODE_ENV, PORT, DEBUG) → null (no pairing)
  if (threat.type === 'env_access') {
    if (threat.message && SENSITIVE_ENV_PATTERNS.test(threat.message)) {
      return 'credential_read';
    }
    return null;
  }

  // Explicitly excluded types
  if (threat.type === 'suspicious_dataflow') return null;
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
 * @param {string} [targetPath] - root path for reading source files (SDK pattern detection)
 * @returns {Object} { pairs, intentScore, intentThreats }
 */
function buildIntentPairs(threats, targetPath) {
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

  // Cache file contents for SDK pattern checks (lazy, per file)
  const fileContentCache = new Map();

  // Only pair sources and sinks within the SAME file
  for (const [file, fileThreats] of byFile) {
    const sources = [];
    const sinks = [];
    // Track which threats are credential sources (for env var extraction)
    const sourceThreats = [];

    for (const t of fileThreats) {
      const srcType = classifySource(t);
      const sinkType = classifySink(t);
      if (srcType) {
        sources.push(srcType);
        sourceThreats.push(t);
      }
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

        // Destination-aware check: credential_read → network_external. Two
        // complementary gates, EITHER ⇒ legitimate, skip the pair:
        //  (1) isSDKPattern — per-env-var: the env var brand matches its API domain
        //      (e.g. STRIPE_API_KEY → stripe.com).
        //  (2) networkDestinationsAllBenign — env-var-independent: EVERY network host
        //      in the file is a provider/local/reserved destination. Catches multi-
        //      provider CLIs (reads GEMINI_API_KEY *and* ANTHROPIC_API_KEY, calls both)
        //      and providers absent from the curated env→domain map. Same anti-evasion
        //      floor (any suspicious/unknown/public-IP host ⇒ keep firing).
        if (srcType === 'credential_read' && sinkType === 'network_external' && targetPath) {
          try {
            let content = fileContentCache.get(file);
            if (content === undefined) {
              const filePath = path.join(targetPath, file);
              content = fs.readFileSync(filePath, 'utf8');
              fileContentCache.set(file, content);
            }
            const envVarName = extractEnvVarFromMessage(sourceThreats);
            if ((envVarName && isSDKPattern(envVarName, content)) || networkDestinationsAllBenign(content)) {
              // First-party/SDK destination — skip this pair
              pairSet.add(pairKey); // Mark as seen to avoid re-checking
              continue;
            }
          } catch {
            // File read error — default to suspicious (CRITICAL)
          }
        }

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
  isSDKPattern,
  extractEnvVarFromMessage,
  extractBrandFromEnvVar,
  SDK_ENV_DOMAIN_MAP
};
