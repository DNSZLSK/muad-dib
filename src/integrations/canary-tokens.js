const crypto = require('crypto');

/**
 * Generate a base32-encoded string of the given length.
 * Uses characters A-Z and 2-7 (RFC 4648 base32 alphabet).
 */
function generateBase32(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes).map(b => chars[b % 32]).join('');
}

// Minimum consecutive chars from an encoded variant to match in a DNS domain.
// 8 chars avoids FP on short legitimate hex subdomains (e.g. commit SHAs, CDN hashes).
const MIN_ENCODED_MATCH = 8;

/**
 * Generate hex/base64/base64url encoded variants of a token value.
 * Attackers encode tokens before DNS exfiltration to evade raw string matching.
 * @param {string} value - Raw token value
 * @returns {Array<{encoding: string, encoded: string}>}
 */
function generateEncodedVariants(value) {
  const buf = Buffer.from(value);
  return [
    { encoding: 'hex', encoded: buf.toString('hex') },
    { encoding: 'base64', encoded: buf.toString('base64') },
    { encoding: 'base64url', encoded: buf.toString('base64url') }
  ];
}

/**
 * Check if a DNS domain contains an encoded token variant.
 * Strips dots to reassemble data chunked across DNS labels (RFC 1035: max 63 chars/label).
 * @param {string} domain - Full DNS query domain
 * @param {Array<{encoding: string, encoded: string}>} variants
 * @returns {{encoding: string, match: string}|null}
 */
function findEncodedInDomain(domain, variants) {
  const stripped = domain.replace(/\./g, '');
  for (const { encoding, encoded } of variants) {
    if (encoded.length < MIN_ENCODED_MATCH) continue;
    for (let i = 0; i <= encoded.length - MIN_ENCODED_MATCH; i++) {
      const chunk = encoded.substring(i, i + MIN_ENCODED_MATCH);
      if (stripped.includes(chunk)) {
        return { encoding, match: chunk };
      }
    }
  }
  return null;
}

/**
 * Canary token generators.
 * Each generator produces a format-valid token that matches the real service format.
 * No common marker (like "MUADDIB_CANARY") — detection relies on exact value matching.
 */
const CANARY_GENERATORS = {
  // GitHub PAT: ghp_ + 36 alphanumeric chars
  GITHUB_TOKEN: () => 'ghp_' + crypto.randomBytes(27).toString('base64url').substring(0, 36),
  // npm token: npm_ + 36 hex chars
  NPM_TOKEN: () => 'npm_' + crypto.randomBytes(18).toString('hex'),
  // AWS Access Key: AKIA + 16 chars [A-Z2-7]
  AWS_ACCESS_KEY_ID: () => 'AKIA' + generateBase32(16),
  // AWS Secret: 40 chars base64
  AWS_SECRET_ACCESS_KEY: () => crypto.randomBytes(30).toString('base64').substring(0, 40),
  // GitLab PAT: glpat- + 20 alphanumeric
  GITLAB_TOKEN: () => 'glpat-' + crypto.randomBytes(15).toString('base64url').substring(0, 20),
  // Docker: dckr_pat_ + 56 alphanumeric
  DOCKER_PASSWORD: () => 'dckr_pat_' + crypto.randomBytes(42).toString('base64url').substring(0, 56),
  // npm auth token: same as NPM_TOKEN format
  NPM_AUTH_TOKEN: () => 'npm_' + crypto.randomBytes(18).toString('hex'),
  // GH_TOKEN: same as GITHUB_TOKEN format
  GH_TOKEN: () => 'ghp_' + crypto.randomBytes(27).toString('base64url').substring(0, 36)
};

/**
 * Generate a unique set of canary tokens with format-valid values.
 * Each token matches its real service format (ghp_, AKIA, npm_, etc.).
 * @returns {{ tokens: Record<string, string>, suffix: string }}
 */
function generateCanaryTokens() {
  const tokens = {};
  for (const [key, generator] of Object.entries(CANARY_GENERATORS)) {
    tokens[key] = generator();
  }
  // Suffix retained for backward compatibility (used in some callers)
  const suffix = crypto.randomBytes(8).toString('hex');
  return { tokens, suffix };
}

/**
 * Generate .env file content with canary tokens.
 * @param {Record<string, string>} tokens - The token map from generateCanaryTokens()
 * @returns {string} .env file content
 */
function createCanaryEnvFile(tokens) {
  const lines = [];
  for (const [key, value] of Object.entries(tokens)) {
    lines.push(`${key}=${value}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Generate .npmrc file content with a canary auth token.
 * @param {Record<string, string>} tokens - The token map from generateCanaryTokens()
 * @returns {string} .npmrc file content
 */
function createCanaryNpmrc(tokens) {
  return `//registry.npmjs.org/:_authToken=${tokens.NPM_AUTH_TOKEN}\n`;
}

/**
 * Generate fake AWS credentials file content.
 * Format matches ~/.aws/credentials (INI format, format-valid key IDs).
 * @param {Record<string, string>} tokens - The token map from generateCanaryTokens()
 * @returns {string} AWS credentials file content
 */
function createCanaryAwsCredentials(tokens) {
  return [
    '[default]',
    `aws_access_key_id = ${tokens.AWS_ACCESS_KEY_ID}`,
    `aws_secret_access_key = ${tokens.AWS_SECRET_ACCESS_KEY}`,
    'region = us-east-1',
    ''
  ].join('\n');
}

/**
 * Generate a fake SSH private key (Ed25519 format).
 * The key is structurally valid PEM but cryptographically meaningless.
 * Malware that reads ~/.ssh/id_rsa or id_ed25519 will exfiltrate this.
 * @returns {string} Fake SSH private key content
 */
function createCanarySshKey() {
  const fakeKeyData = crypto.randomBytes(64).toString('base64');
  return [
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    fakeKeyData.substring(0, 70),
    fakeKeyData.substring(0, 70),
    '-----END OPENSSH PRIVATE KEY-----',
    ''
  ].join('\n');
}

/**
 * Generate a fake .gitconfig with user identity.
 * Malware fingerprinting the developer will exfiltrate this.
 * @returns {string} Fake .gitconfig content
 */
function createCanaryGitconfig() {
  return [
    '[user]',
    '\tname = John Developer',
    '\temail = john.dev@company-internal.example.com',
    '[credential]',
    '\thelper = store',
    ''
  ].join('\n');
}

/**
 * Search for canary tokens in network logs from sandbox.
 * Network log structure matches sandbox.js report.network:
 *   dns_queries: string[], http_bodies: string[],
 *   http_requests: [{method, host, path}], tls_connections: [{domain, ip, port}],
 *   http_connections: [{host, port}], blocked_connections: [{ip, port}]
 *
 * @param {object} networkLogs - report.network from sandbox
 * @param {Record<string, string>} tokens - The token map from generateCanaryTokens()
 * @returns {{ detected: boolean, exfiltrations: Array<{token: string, value: string, foundIn: string, severity: string}> }}
 */
function detectCanaryExfiltration(networkLogs, tokens) {
  const exfiltrations = [];
  if (!networkLogs || !tokens) {
    return { detected: false, exfiltrations };
  }

  const tokenEntries = Object.entries(tokens);

  // Check HTTP bodies (most direct evidence of exfiltration)
  for (const body of (networkLogs.http_bodies || [])) {
    if (!body) continue;
    for (const [tokenName, tokenValue] of tokenEntries) {
      if (body.includes(tokenValue)) {
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `HTTP body: ${body.substring(0, 100)}`,
          severity: 'CRITICAL'
        });
      }
    }
  }

  // Check HTTP request URLs (token in query string or path)
  for (const req of (networkLogs.http_requests || [])) {
    const url = `${req.method || ''} ${req.host || ''}${req.path || ''}`;
    for (const [tokenName, tokenValue] of tokenEntries) {
      if (url.includes(tokenValue)) {
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `HTTP request: ${url.substring(0, 100)}`,
          severity: 'CRITICAL'
        });
      }
    }
  }

  // Check DNS queries (token encoded in subdomain — DNS exfiltration)
  for (const domain of (networkLogs.dns_queries || [])) {
    if (!domain) continue;
    for (const [tokenName, tokenValue] of tokenEntries) {
      // Raw value match
      if (domain.includes(tokenValue)) {
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `DNS query: ${domain}`,
          severity: 'CRITICAL'
        });
        continue;
      }
      // Encoded variant match (hex, base64, base64url — catches DNS label chunking)
      const variants = generateEncodedVariants(tokenValue);
      const encodedMatch = findEncodedInDomain(domain, variants);
      if (encodedMatch) {
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `DNS query (${encodedMatch.encoding}-encoded): ${domain}`,
          severity: 'CRITICAL'
        });
      }
    }
  }

  // Check TLS connection domains (less likely but possible)
  for (const tls of (networkLogs.tls_connections || [])) {
    const domain = tls.domain || '';
    for (const [tokenName, tokenValue] of tokenEntries) {
      if (domain.includes(tokenValue)) {
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `TLS connection: ${domain}`,
          severity: 'CRITICAL'
        });
      }
    }
  }

  return { detected: exfiltrations.length > 0, exfiltrations };
}

/**
 * Search for canary tokens in process stdout/stderr output.
 * @param {string} stdout - Process stdout
 * @param {string} stderr - Process stderr
 * @param {Record<string, string>} tokens - The token map from generateCanaryTokens()
 * @returns {{ detected: boolean, exfiltrations: Array<{token: string, value: string, foundIn: string, severity: string}> }}
 */
function detectCanaryInOutput(stdout, stderr, tokens) {
  const exfiltrations = [];
  if (!tokens) {
    return { detected: false, exfiltrations };
  }

  const tokenEntries = Object.entries(tokens);
  const sources = [
    { label: 'stdout', content: stdout || '' },
    { label: 'stderr', content: stderr || '' }
  ];

  for (const { label, content } of sources) {
    if (!content) continue;
    for (const [tokenName, tokenValue] of tokenEntries) {
      if (content.includes(tokenValue)) {
        // Find context around the match
        const idx = content.indexOf(tokenValue);
        const start = Math.max(0, idx - 30);
        const end = Math.min(content.length, idx + tokenValue.length + 30);
        const context = content.substring(start, end);
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `${label}: ...${context}...`,
          severity: 'CRITICAL'
        });
      }
    }
  }

  return { detected: exfiltrations.length > 0, exfiltrations };
}

module.exports = {
  CANARY_GENERATORS,
  generateCanaryTokens,
  createCanaryEnvFile,
  createCanaryNpmrc,
  createCanaryAwsCredentials,
  createCanarySshKey,
  createCanaryGitconfig,
  detectCanaryExfiltration,
  detectCanaryInOutput
};
