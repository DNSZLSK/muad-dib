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

// ============================================
// DESTINATION-AWARE SDK DETECTION
// ============================================
// Curated allowlist: when an env var matching the pattern is sent to a matching domain,
// it is legitimate SDK usage, not credential exfiltration.
// Safe-by-default: unknown env vars or unknown domains remain CRITICAL.
const SDK_ENV_DOMAIN_MAP = [
  { envPattern: /^AWS_/i, domains: ['amazonaws.com', 'aws.amazon.com'] },
  { envPattern: /^AZURE_/i, domains: ['azure.com', 'microsoft.com'] },
  { envPattern: /^GOOGLE_|^GCP_/i, domains: ['googleapis.com', 'google.com'] },
  { envPattern: /^FIREBASE_/i, domains: ['firebase.com', 'googleapis.com'] },
  { envPattern: /^SALESFORCE_/i, domains: ['salesforce.com', 'force.com'] },
  { envPattern: /^SUPABASE_/i, domains: ['supabase.co', 'supabase.com'] },
  { envPattern: /^MAILGUN_/i, domains: ['mailgun.net', 'mailgun.com'] },
  { envPattern: /^STRIPE_/i, domains: ['stripe.com'] },
  { envPattern: /^TWILIO_/i, domains: ['twilio.com'] },
  { envPattern: /^SENDGRID_/i, domains: ['sendgrid.com', 'sendgrid.net'] },
  { envPattern: /^DATADOG_/i, domains: ['datadoghq.com'] },
  { envPattern: /^SENTRY_/i, domains: ['sentry.io'] },
  { envPattern: /^SLACK_/i, domains: ['slack.com'] },
  { envPattern: /^GITHUB_/i, domains: ['github.com', 'githubusercontent.com'] },
  { envPattern: /^GITLAB_/i, domains: ['gitlab.com'] },
  { envPattern: /^CLOUDFLARE_/i, domains: ['cloudflare.com'] },
  { envPattern: /^OPENAI_/i, domains: ['openai.com'] },
  { envPattern: /^ANTHROPIC_/i, domains: ['anthropic.com'] },
  { envPattern: /^MONGODB_|^MONGO_/i, domains: ['mongodb.com', 'mongodb.net'] },
  { envPattern: /^AUTH0_/i, domains: ['auth0.com'] },
  { envPattern: /^HUBSPOT_/i, domains: ['hubspot.com', 'hubapi.com'] },
  { envPattern: /^CONTENTFUL_/i, domains: ['contentful.com'] },
];

// Tokens stripped when extracting brand keyword from env var name
const ENV_NOISE_TOKENS = new Set([
  'API', 'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL',
  'AUTH', 'ACCESS', 'PRIVATE', 'PUBLIC', 'CLIENT', 'ID', 'URL'
]);

// Suspicious tunneling/proxy domains — never considered legitimate SDK destinations
const SUSPICIOUS_DOMAIN_PATTERNS = /ngrok|serveo|localtunnel|burpcollaborator|requestbin|pipedream|webhook\.site/i;

// URL extraction regex (matches http/https URLs in source code)
const URL_EXTRACT_RE = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g;

// Hostname extraction from Node.js request options: hostname: 'domain.com' or host: 'domain.com'
const HOSTNAME_OPTION_RE = /(?:hostname|host)\s*:\s*['"`]([a-zA-Z0-9\-._]+)['"`]/g;

/**
 * Extract env var name from an intent source threat message.
 * Messages look like: "process.env.SALESFORCE_API_KEY", "env var MAILGUN_API_KEY accessed"
 */
function extractEnvVarFromMessage(sourceThreats) {
  for (const t of sourceThreats) {
    if (!t.message) continue;
    // Match process.env.VAR_NAME pattern
    const envMatch = t.message.match(/process\.env\.([A-Z_][A-Z0-9_]*)/i);
    if (envMatch) return envMatch[1];
    // Match standalone VAR_NAME patterns (e.g., "SALESFORCE_API_KEY")
    const varMatch = t.message.match(/\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b/);
    if (varMatch) return varMatch[1];
  }
  return null;
}

/**
 * Extract brand keyword from env var name by removing noise tokens.
 * MAILGUN_API_KEY → MAILGUN, SALESFORCE_CLIENT_SECRET → SALESFORCE
 */
function extractBrandFromEnvVar(envVarName) {
  const parts = envVarName.toUpperCase().split('_');
  const brandParts = parts.filter(p => !ENV_NOISE_TOKENS.has(p) && p.length > 0);
  return brandParts.length > 0 ? brandParts[0] : null;
}

/**
 * Extract domain from a URL string.
 * Returns the hostname (without port).
 */
function extractDomain(url) {
  try {
    const match = url.match(/^https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase() : null;
  } catch {
    return null;
  }
}

/**
 * Check if a domain matches any of the expected SDK domains (suffix match).
 * api.mailgun.net matches mailgun.net, sub.api.stripe.com matches stripe.com
 */
function domainMatchesSuffix(domain, expectedDomains) {
  for (const expected of expectedDomains) {
    if (domain === expected || domain.endsWith('.' + expected)) return true;
  }
  return false;
}

/**
 * Check if an env var + file content represents a legitimate SDK pattern.
 *
 * Returns true ONLY if:
 * 1. The env var matches a known SDK mapping (allowlist) OR heuristic brand match
 * 2. ALL URLs in the file point to domains matching the expected SDK
 * 3. No suspicious tunneling/proxy domains are present
 *
 * @param {string} envVarName - e.g., "SALESFORCE_API_KEY"
 * @param {string} fileContent - source code of the file
 * @returns {boolean} true if SDK pattern (should skip intent pair)
 */
function isSDKPattern(envVarName, fileContent) {
  // Extract domains from full URLs (https://api.stripe.com/v1/charges)
  const urls = fileContent.match(URL_EXTRACT_RE) || [];
  const domains = urls.map(u => extractDomain(u)).filter(Boolean);

  // Also extract hostnames from Node.js request options (hostname: 'api.stripe.com')
  let hostnameMatch;
  const hostnameRe = new RegExp(HOSTNAME_OPTION_RE.source, 'g');
  while ((hostnameMatch = hostnameRe.exec(fileContent)) !== null) {
    const hostname = hostnameMatch[1].toLowerCase();
    if (hostname && !domains.includes(hostname)) {
      domains.push(hostname);
    }
  }

  // No URLs found — can't confirm SDK pattern, default to suspicious
  if (domains.length === 0) return false;

  // Check for suspicious tunneling domains — immediate fail
  for (const domain of domains) {
    if (SUSPICIOUS_DOMAIN_PATTERNS.test(domain)) return false;
  }

  // Check for raw IP addresses — immediate fail
  for (const domain of domains) {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) return false;
  }

  // 1. Try curated allowlist first
  for (const mapping of SDK_ENV_DOMAIN_MAP) {
    if (mapping.envPattern.test(envVarName)) {
      // All domains must match expected SDK domains
      return domains.every(d => domainMatchesSuffix(d, mapping.domains));
    }
  }

  // 2. Heuristic fallback: extract brand keyword and check domain labels
  const brand = extractBrandFromEnvVar(envVarName);
  if (!brand || brand.length < 3) return false; // Too short for reliable matching

  const brandLower = brand.toLowerCase();
  // Check if every domain has the brand as a whole label
  // e.g., brand "ACME" matches "api.acme.com" (label "acme") but not "api.acmetech.com"
  return domains.every(d => {
    const labels = d.split('.');
    return labels.some(label => label === brandLower);
  });
}


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

        // Destination-aware SDK check: credential_read → network_external
        // If the env var matches the API domain, this is legitimate SDK usage
        if (srcType === 'credential_read' && sinkType === 'network_external' && targetPath) {
          const envVarName = extractEnvVarFromMessage(sourceThreats);
          if (envVarName) {
            try {
              let content = fileContentCache.get(file);
              if (content === undefined) {
                const filePath = path.join(targetPath, file);
                content = fs.readFileSync(filePath, 'utf8');
                fileContentCache.set(file, content);
              }
              if (isSDKPattern(envVarName, content)) {
                // SDK pattern confirmed — skip this pair
                pairSet.add(pairKey); // Mark as seen to avoid re-checking
                continue;
              }
            } catch {
              // File read error — default to suspicious (CRITICAL)
            }
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
