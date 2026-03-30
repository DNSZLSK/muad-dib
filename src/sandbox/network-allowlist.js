'use strict';

// ── Network Allowlist & Blacklist for Sandbox Analysis ──
//
// Classifies domains/IPs contacted during npm install into three categories:
//   - safe:        legitimate install-time traffic (registries, CDNs, GitHub)
//   - blacklisted: known exfiltration/C2 infrastructure (OAST, webhook sinks, campaign IPs)
//   - unknown:     everything else — potential outlier requiring investigation
//
// Threat model: SafeDep found only 0.027% of 3M+ packages make DNS queries to
// non-npm domains during install. Network outliers are the highest-precision
// signal available for detecting supply chain attacks at install time.

// ── Safe domains: legitimate traffic during npm install ──
// These domains are expected during normal package installation.
// Subdomains are matched (e.g., foo.github.com matches github.com).
const SAFE_INSTALL_DOMAINS = [
  // npm registry
  'registry.npmjs.org',
  'npmjs.com',
  'npmjs.org',
  // yarn registry
  'registry.yarnpkg.com',
  'yarnpkg.com',
  // GitHub (source tarballs, git deps)
  'github.com',
  'api.github.com',
  'objects.githubusercontent.com',
  'raw.githubusercontent.com',
  'codeload.github.com',
  'github.githubassets.com',
  // CDNs (native binary downloads via node-gyp, prebuild)
  'cdn.jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'cloudflare.com',
  // AWS S3 (prebuild binaries: sharp, canvas, sqlite3, etc.)
  'amazonaws.com',
  // Google (googleapis client, protobuf downloads)
  'googleapis.com',
  'storage.googleapis.com',
  // Node.js (node-gyp headers)
  'nodejs.org',
  // GitLab (git deps)
  'gitlab.com',
  // Bitbucket (git deps)
  'bitbucket.org'
];

// ── Known exfiltration / C2 domains ──
// Any contact during install is near-certain malicious (quasi-zero FP).
// Sources: OAST tooling, known campaign C2, webhook sink services.
const KNOWN_EXFIL_DOMAINS = [
  // OAST / Interactsh / BurpSuite
  'oastify.com',
  'oast.fun',
  'oast.me',
  'oast.live',
  'oast.online',
  'oast.site',
  'burpcollaborator.net',
  'interact.sh',
  // Webhook sink services
  'webhook.site',
  'pipedream.net',
  'requestbin.com',
  'hookbin.com',
  'canarytokens.com',
  // GlassWorm C2 IPs (mars 2026, 433+ packages)
  '217.69.3.218',
  '217.69.3.152',
  '199.247.10.166',
  '199.247.13.106',
  '140.82.52.31',
  '45.32.150.251',
  // TeamPCP / CanisterWorm C2 (mars 2026)
  'icp0.io',
  'raw.icp0.io',
  'ic0.app',
  'hackmoltrepeat.com',
  'recv.hackmoltrepeat.com',
  'scan.aquasecurtiy.org',    // Trivy exfil C2 (typosquat of aquasecurity)
  'api.telegram.org',          // Telegram bot exfiltration
  'checkmarx.zone',
  '45.148.10.212',
  '83.142.209.11'
];

// ── Regex patterns for wildcard exfil domains ──
// Matches subdomains of OAST/exfil infrastructure.
const KNOWN_EXFIL_PATTERNS = [
  /\.oast\.(online|site|live|fun|me)$/i,
  /\.oastify\.com$/i,
  /\.burpcollaborator\.net$/i,
  /\.interact\.sh$/i,
  /\.webhook\.site$/i,
  /\.pipedream\.net$/i,
  /\.requestbin\.com$/i
];

// ── Suspicious tunnel/proxy domains (not blacklisted, but escalate unknown → suspicious) ──
const TUNNEL_DOMAINS = [
  'ngrok.io',
  'ngrok-free.app',
  'serveo.net',
  'localhost.run',
  'loca.lt',
  'trycloudflare.com'
];

// Parse MUADDIB_SANDBOX_NETWORK_ALLOWLIST env var (comma-separated domains)
function getCustomAllowlist() {
  const envVal = process.env.MUADDIB_SANDBOX_NETWORK_ALLOWLIST;
  if (!envVal) return [];
  return envVal.split(',')
    .map(d => d.trim().toLowerCase())
    .filter(d => d.length > 0 && d.length < 256);
}

/**
 * Classify a domain/IP contacted during sandbox install.
 *
 * @param {string} domain - Domain name or IP address
 * @returns {'safe'|'blacklisted'|'tunnel'|'unknown'} classification
 */
function classifyDomain(domain) {
  if (!domain || typeof domain !== 'string') return 'unknown';
  const d = domain.toLowerCase().trim();
  if (d.length === 0) return 'unknown';

  // Check safe domains (exact or subdomain match)
  const allSafe = SAFE_INSTALL_DOMAINS.concat(getCustomAllowlist());
  for (const safe of allSafe) {
    if (d === safe || d.endsWith('.' + safe)) return 'safe';
  }

  // Check blacklisted domains (exact match)
  for (const exfil of KNOWN_EXFIL_DOMAINS) {
    if (d === exfil || d.endsWith('.' + exfil)) return 'blacklisted';
  }

  // Check blacklisted patterns (regex — catches subdomains like abc123.oast.online)
  for (const pat of KNOWN_EXFIL_PATTERNS) {
    if (pat.test(d)) return 'blacklisted';
  }

  // Check tunnel domains
  for (const tunnel of TUNNEL_DOMAINS) {
    if (d === tunnel || d.endsWith('.' + tunnel)) return 'tunnel';
  }

  return 'unknown';
}

module.exports = {
  SAFE_INSTALL_DOMAINS,
  KNOWN_EXFIL_DOMAINS,
  KNOWN_EXFIL_PATTERNS,
  TUNNEL_DOMAINS,
  classifyDomain,
  getCustomAllowlist
};
