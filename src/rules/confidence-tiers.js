/**
 * FPR plan Chantier 6 - multi-tier confidence classification.
 *
 * Socket and Endor distinguish "AI-detected potential" from "Known Malware"
 * (post-revue) ; muad-dib has only severity (CRITICAL/HIGH/MEDIUM/LOW), which
 * collapses two very different signals - a deterministic IOC match and a
 * heuristic obfuscation guess - into the same bucket. This module adds a
 * second dimension : confidenceTier in {verified, high, medium, low}.
 *
 * Tier semantics :
 *
 *   - verified : the threat is observed against a known-malicious artifact
 *     (IOC match, known hash, known package, Shai-Hulud marker). Zero
 *     residual doubt ; never decays through any FP-reduction path.
 *
 *   - high : compound or co-occurrence evidence, intent-graph proven flows,
 *     HIGH_CONFIDENCE_MALICE_TYPES. Multi-signal correlation that no benign
 *     pattern reproduces ; manual review almost always confirms.
 *
 *   - medium : a single deterministic rule fires (eval, dangerous_exec,
 *     dynamic_require). Sometimes legitimate (build tools, plugin loaders)
 *     so the FP rate is non-trivial but the signal is exact when triggered.
 *
 *   - low : heuristic (possible_obfuscation, high_entropy_string), count-
 *     based (>N occurrences of a type), or a single sensitive-string match.
 *     Useful for triage but should not drive automated alerts.
 *
 * Output filtering : the CLI shows verified+high by default. JSON / SARIF
 * always include all tiers (no information loss). The evaluate.js corpus
 * reports two FPR numbers : "FPR all" (status quo) and "FPR perceived"
 * (verified + high only) - the latter is the metric Socket / Endor publish.
 */

'use strict';

const { HIGH_CONFIDENCE_MALICE_TYPES } = require('../monitor/classify.js');

// ---------------------------------------------------------------------------
// Type-to-tier mapping. Each set is mutually exclusive ; a threat type that
// appears in VERIFIED never appears in HIGH, etc. Order of evaluation is
// VERIFIED > HIGH > LOW > (default by severity).
// ---------------------------------------------------------------------------

// Deterministic match against a known artifact - never decays.
const VERIFIED_TYPES = new Set([
  'ioc_match',
  'ioc_string_match',
  'known_malicious_hash',
  'known_malicious_package',
  'pypi_malicious_package',
  'shai_hulud_marker',
  'dependency_ioc_match'
]);

// Multi-signal compound evidence + proven flows. These are unambiguous when
// they fire because each requires multiple correlated signals or a static
// dataflow proof. The set extends HIGH_CONFIDENCE_MALICE_TYPES with intent
// graph results and the scoring compound types.
const HIGH_TIER_EXTRA = new Set([
  // Intent graph (intra-file dataflow proven)
  'intent_credential_exfil',
  'intent_command_exfil',
  // Scoring compounds (require co-occurrence)
  'crypto_staged_payload',
  'lifecycle_typosquat',
  'lifecycle_inline_exec',
  'lifecycle_remote_require',
  'lifecycle_dataflow',
  'lifecycle_dangerous_exec',
  'obfuscated_lifecycle_env',
  'lifecycle_file_exec',
  // Cross-file proven dataflow
  'cross_file_dataflow',
  // Single-fire critical types from classify.js
  'reverse_shell',
  'fetch_decrypt_exec',
  'download_exec_binary',
  'staged_eval_decode',
  'function_constructor_require',
  'self_destruct_eval',
  'curl_env_exfil',
  'function_runtime_args',
  'external_tarball_dep',
  // Worm propagation patterns
  'node_modules_write',
  'npm_publish_worm',
  // Sandbox correlated signals
  'sandbox_network_after_sensitive_read',
  'sandbox_known_exfil_domain',
  'canary_exfiltration',
  // Known-bad lifecycle anomalies
  'lifecycle_added_critical',
  'systemd_persistence',
  'npm_token_steal',
  'root_filesystem_wipe',
  'proc_mem_scan',
  'trusted_new_unknown_dependency',
  'newsletter_auto_follow',
  // Anti-forensic signatures
  'anti_forensic_xor_autodelete',
  'detached_credential_exfil',
  // Workflow injection
  'workflow_write',
  // Geo-evasion (locale check + country code + exit = compound evidence)
  'geo_evasion_killswitch'
]);

// Heuristic / count-based / weak-signal types. Always low tier regardless
// of severity to honor the plan's metric definition. If the same threat is
// also in VERIFIED or HIGH it does not reach this set - the order of checks
// in getConfidenceTier prevents that.
const LOW_TIER_TYPES = new Set([
  'possible_obfuscation',
  'sensitive_string',
  'high_entropy_string',
  'large_string_array',
  'string_mutation_obfuscation',
  'js_obfuscation_pattern'
]);

/**
 * Resolve the confidence tier of a threat. Pure function : takes only the
 * fields we care about so it can be unit-tested without a full threat shape.
 *
 *   - threatType : the threat.type string (required).
 *   - severity   : 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'. Used as the fallback
 *                  signal when the type is not classified explicitly.
 *   - flags      : optional { isCountDowngrade, isUnreachable } extra hints.
 *                  isCountDowngrade=true forces the threat to LOW even if its
 *                  type would otherwise be MEDIUM (count thresholds typically
 *                  signal benign frameworks). isUnreachable=true forces LOW
 *                  (dead-code findings carry no execution risk).
 */
function getConfidenceTier(threatType, severity, flags) {
  if (typeof threatType !== 'string' || threatType.length === 0) return 'low';
  if (VERIFIED_TYPES.has(threatType)) return 'verified';
  if (HIGH_TIER_EXTRA.has(threatType)) return 'high';
  if (HIGH_CONFIDENCE_MALICE_TYPES.has(threatType)) return 'high';
  if (LOW_TIER_TYPES.has(threatType)) return 'low';

  if (flags) {
    if (flags.isCountDowngrade) return 'low';
    if (flags.isUnreachable) return 'low';
  }

  // Fall back to severity. CRITICAL/HIGH single-rule heuristics get medium ;
  // MEDIUM/LOW heuristics get low.
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'medium';
  return 'low';
}

/**
 * Decorate a threats array in place with t.confidenceTier. Idempotent :
 * threats already carrying a tier are not overwritten so callers can fix up
 * specific findings before this is invoked.
 */
function annotateConfidenceTiers(threats) {
  if (!Array.isArray(threats)) return 0;
  let annotated = 0;
  for (const t of threats) {
    if (!t || typeof t !== 'object') continue;
    if (typeof t.confidenceTier === 'string' && t.confidenceTier.length > 0) continue;
    const isCountDowngrade = Array.isArray(t.reductions) &&
      t.reductions.some(r => r && /count|threshold/.test(r.rule || ''));
    const isUnreachable = t.unreachable === true || !!t.unreachableFunction;
    t.confidenceTier = getConfidenceTier(t.type, t.severity, {
      isCountDowngrade,
      isUnreachable
    });
    annotated++;
  }
  return annotated;
}

const TIER_ORDER = { verified: 4, high: 3, medium: 2, low: 1 };

function tierAtLeast(tier, minTier) {
  return (TIER_ORDER[tier] || 0) >= (TIER_ORDER[minTier] || 0);
}

module.exports = {
  getConfidenceTier,
  annotateConfidenceTiers,
  tierAtLeast,
  VERIFIED_TYPES,
  HIGH_TIER_EXTRA,
  LOW_TIER_TYPES,
  TIER_ORDER
};
