'use strict';

// ============================================
// DESTINATION-AWARE SDK DETECTION (shared leaf module)
// ============================================
// Extracted from intent-graph.js (v2.11.x) so the same destination logic can gate
// every credential→network taint detector — intent coherence (intent-graph.js),
// dataflow (scanner/dataflow.js), cross-file flow (scanner/module-graph) and the
// detached/uncaught compounds (scanner/ast-detectors). No project dependencies
// (only the Node stdlib via callers) → safe to require from any scanner, no cycles.
//
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
    // Capture only valid hostname characters so a path-less URL immediately followed by
    // a quote/paren (e.g. fetch('https://api.openai.com')) does not absorb the trailing
    // ')" into the host. Stops at /, :, ?, #, quotes, parens, etc.
    const match = url.match(/^https?:\/\/([a-zA-Z0-9.-]+)/i);
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

  // 1. Try curated allowlist first (strict: ALL domains must match)
  // Curated allowlist is authoritative — no relaxation here to prevent
  // attacker injecting a legitimate domain alongside their C2 domain.
  for (const mapping of SDK_ENV_DOMAIN_MAP) {
    if (mapping.envPattern.test(envVarName)) {
      return domains.every(d => domainMatchesSuffix(d, mapping.domains));
    }
  }

  // R2: credential-suffixed env vars get relaxed domain matching (at least ONE match).
  // SDKs commonly call their own API + CDN/logging/analytics domains.
  // Safety: suspicious domains and raw IPs are already rejected above.
  // Only applies to the heuristic fallback — curated allowlist stays strict.
  const CREDENTIAL_SUFFIXES = ['_API_KEY', '_SECRET', '_TOKEN', '_SECRET_KEY', '_ACCESS_KEY'];
  const upperName = envVarName.toUpperCase();
  const hasCredentialSuffix = CREDENTIAL_SUFFIXES.some(s => upperName.endsWith(s));

  // 2. Heuristic fallback: extract brand keyword and check domain labels
  const brand = extractBrandFromEnvVar(envVarName);
  if (!brand || brand.length < 3) return false; // Too short for reliable matching

  const brandLower = brand.toLowerCase();
  // 2a. Strict check: every domain matches brand (existing behavior)
  // e.g., brand "ACME" matches "api.acme.com" (label "acme") but not "api.acmetech.com"
  if (domains.every(d => {
    const labels = d.split('.');
    return labels.some(label => label === brandLower);
  })) return true;

  // 2b. R2 relaxed: credential suffix + at least one domain matches brand
  if (hasCredentialSuffix && domains.some(d => {
    const labels = d.split('.');
    return labels.some(label => label === brandLower);
  })) return true;

  return false;
}

// ============================================
// DESTINATION-BENIGNNESS GATE (env-var-independent)
// ============================================
// isSDKPattern() needs a single extractable env var + matching domain. That model
// breaks on (a) multi-provider files (a CLI that reads GEMINI_API_KEY *and*
// ANTHROPIC_API_KEY and calls both), and (b) flows whose credential source has no
// extractable env var (cross_file_dataflow / detached compounds). For those, judge the
// DESTINATIONS, not the env var: a credential→network flow is benign iff EVERY network
// host in scope is provably non-exfil.
//
// Benign classes (NOT attacker-spoofable):
//   - loopback / RFC1918 private / link-local IPs, localhost, *.local        (local IPC)
//   - reserved test domains (example.com, *.test, *.invalid)                 (RFC 2606/6761)
//   - curated SaaS/cloud/AI provider API domains                            (cannot echo a
//     POST body back to a third party — UNLIKE paste sites / bot webhooks, deliberately
//     EXCLUDED, see SUSPICIOUS_DOMAIN_PATTERNS + the exclusion note below)
// Deliberately NOT benign: package "own domain" from package.json (attacker writes it),
// unknown domains, public IPs, suspicious tunnels/paste hosts. Any of those ⇒ keep firing.
// Safe-by-default: no extractable host ⇒ NOT benign (do not suppress).

// AI providers (2025-26) absent from the env→domain map. Bot/messaging/paste channels
// (telegram, discord webhooks, pastebin, gist, transfer.sh, …) are intentionally absent:
// they CAN relay an exfil POST to the attacker, so they must keep firing.
const AI_PROVIDER_DOMAIN_SUFFIXES = [
  'claude.com', 'openrouter.ai', 'deepseek.com', 'x.ai', 'mistral.ai', 'cohere.ai',
  'cohere.com', 'huggingface.co', 'perplexity.ai', 'groq.com', 'together.ai',
  'together.xyz', 'replicate.com', 'fireworks.ai', 'anyscale.com', 'ai21.com',
  'voyageai.com', 'deepinfra.com',
];

// Flat suffix list = every domain already curated in SDK_ENV_DOMAIN_MAP + the AI extras.
// Derived (not duplicated) so the two stay in sync. Matched via domainMatchesSuffix, which
// is label-anchored: 'evilx.ai' does NOT match 'x.ai'.
const PROVIDER_DOMAIN_SUFFIXES = Array.from(new Set([
  ...SDK_ENV_DOMAIN_MAP.flatMap(m => m.domains),
  ...AI_PROVIDER_DOMAIN_SUFFIXES,
]));

function stripPort(host) {
  let h = String(host).trim().toLowerCase();
  // Bracketed IPv6 with optional port: [::1]:443 / [::1] → ::1
  const br = h.match(/^\[([^\]]+)\]/);
  if (br) return br[1];
  // host:port for IPv4 / hostname — only when there's a single colon (bare IPv6 like
  // ::1 has multiple colons and must NOT be truncated).
  if ((h.match(/:/g) || []).length === 1) h = h.replace(/:\d+$/, '');
  return h;
}

// loopback / RFC1918 private / link-local / localhost / reserved-test domain.
function isLocalOrReservedHost(host) {
  const h = stripPort(host);
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true; // IPv6 loopback
  if (h === 'example.com' || h === 'example.org' || h === 'example.net') return true;
  if (h.endsWith('.example.com') || h.endsWith('.example.org') || h.endsWith('.example.net')) return true;
  if (h.endsWith('.example') || h.endsWith('.test') || h.endsWith('.invalid')) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 0) return true;            // loopback / this-host
    if (a === 10) return true;                        // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true;          // 192.168.0.0/16
    if (a === 169 && b === 254) return true;          // 169.254.0.0/16 link-local
    return false;                                     // any other IPv4 literal = public
  }
  return false;
}

// A public (non-loopback/private) IPv4 literal — a direct-IP exfil endpoint (ecto pattern).
function isPublicIpHost(host) {
  const h = stripPort(host);
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return false;
  return !isLocalOrReservedHost(h);
}

// Extract every network host referenced in a file (URLs + Node request options).
function extractHostsFromContent(fileContent) {
  if (!fileContent) return [];
  const urls = fileContent.match(URL_EXTRACT_RE) || [];
  const hosts = urls.map(u => extractDomain(u)).filter(Boolean);
  let m;
  const re = new RegExp(HOSTNAME_OPTION_RE.source, 'g');
  while ((m = re.exec(fileContent)) !== null) {
    const h = m[1].toLowerCase();
    if (h && !hosts.includes(h)) hosts.push(h);
  }
  // Bare host literals assigned as defaults, e.g. `process.env.HOST || "127.0.0.1"` then
  // used as `host: HOST` (common "configurable local collector" shape — the variable host
  // isn't matched above). Capture quoted IPv4 / localhost / 0.0.0.0 literals. Safe: any
  // co-present public IP or unknown host still fails the all-benign check downstream, so
  // this can only RELAX a file whose every literal host is loopback/private.
  const LITERAL_HOST_RE = /['"`](localhost|0\.0\.0\.0|(?:\d{1,3}\.){3}\d{1,3})['"`]/g;
  while ((m = LITERAL_HOST_RE.exec(fileContent)) !== null) {
    const h = m[1].toLowerCase();
    if (h && !hosts.includes(h)) hosts.push(h);
  }
  return hosts;
}

/**
 * Destination-benignness gate for credential→network taint flows whose env var is not
 * (or need not be) known. Returns true ONLY if EVERY extracted host is provably non-exfil
 * (local/reserved OR a curated provider). Any suspicious/paste host, public IP, or unknown
 * domain ⇒ false. No hosts found ⇒ false (cannot confirm).
 *
 * @param {string} fileContent - source of the file containing the network sink
 * @returns {boolean} true ⇒ first-party/local, safe to downgrade the taint flow
 */
function networkDestinationsAllBenign(fileContent) {
  const hosts = extractHostsFromContent(fileContent);
  if (hosts.length === 0) return false;
  for (const h of hosts) {
    if (SUSPICIOUS_DOMAIN_PATTERNS.test(h)) return false;
    if (isPublicIpHost(h)) return false;
    if (isLocalOrReservedHost(h)) continue;
    if (PROVIDER_DOMAIN_SUFFIXES.some(s => domainMatchesSuffix(h, [s]))) continue;
    return false; // unknown / unrecognised destination → keep firing
  }
  return true;
}

/**
 * Gate #1 variant of networkDestinationsAllBenign: a host ALSO passes if one of its labels
 * matches a credential env-var BRAND (e.g. YINGDAO_ACCESS_TOKEN → api.yingdao.com). This covers
 * the dominant credential→own-API FP cluster (Étape 0 2026-06-15: ~25% of band 20-49, 0 TP) that
 * networkDestinationsAllBenign rejects because a package's own domain is not a curated provider.
 * Decoy-safe by construction: EVERY host must be local/reserved OR a curated provider OR
 * brand-coherent; any unknown / public-IP / suspicious-tunnel host ⇒ false. No hosts ⇒ false.
 * Brand coherence is not attacker-spoofable for the credential-theft case: stealing a VICTIM's
 * OTHER-service key (OPENAI_API_KEY) and sending it to attacker.com yields brand "openai" vs label
 * "attacker" ⇒ mismatch ⇒ keeps firing.
 *
 * @param {string} fileContent - source of the file containing the network sink
 * @param {string[]} brands - brand tokens extracted from the credential env-var names
 * @returns {boolean}
 */
function networkDestinationsAllBenignOrBrand(fileContent, brands) {
  const hosts = extractHostsFromContent(fileContent);
  if (hosts.length === 0) return false;
  // RFC 2606 / 6761 documentation & test placeholders (example.com/.net/.org, *.test, *.invalid)
  // are NOT real SDK destinations — no benign SDK ships a live credential flow to example.com.
  // A credential→placeholder flow is either a synthetic exfil sample or an evasion stand-in, so it
  // must keep firing (it is deliberately NOT in the local-IPC benign class, unlike loopback/RFC1918).
  const DOC_DOMAIN_RE = /(^|\.)example\.(?:com|net|org)$|\.(?:test|example|invalid)$/i;
  const brandSet = (brands || [])
    .map(b => String(b || '').toLowerCase())
    .filter(b => b.length >= 3);
  for (const h of hosts) {
    if (SUSPICIOUS_DOMAIN_PATTERNS.test(h)) return false;
    if (isPublicIpHost(h)) return false;
    if (DOC_DOMAIN_RE.test(h)) return false;
    if (isLocalOrReservedHost(h)) continue;
    if (PROVIDER_DOMAIN_SUFFIXES.some(s => domainMatchesSuffix(h, [s]))) continue;
    const labels = String(h).toLowerCase().split('.');
    if (brandSet.length && labels.some(l => brandSet.includes(l))) continue;
    return false; // unknown / unrecognised destination → keep firing
  }
  return true;
}

module.exports = {
  SDK_ENV_DOMAIN_MAP,
  ENV_NOISE_TOKENS,
  SUSPICIOUS_DOMAIN_PATTERNS,
  URL_EXTRACT_RE,
  HOSTNAME_OPTION_RE,
  PROVIDER_DOMAIN_SUFFIXES,
  extractEnvVarFromMessage,
  extractBrandFromEnvVar,
  extractDomain,
  domainMatchesSuffix,
  isSDKPattern,
  networkDestinationsAllBenignOrBrand,
  stripPort,
  isLocalOrReservedHost,
  isPublicIpHost,
  extractHostsFromContent,
  networkDestinationsAllBenign,
};
