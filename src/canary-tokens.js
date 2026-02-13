const crypto = require('crypto');

/**
 * Canary token definitions.
 * Each key is an env var name, value is a prefix.
 * A random suffix is appended at generation time.
 */
const CANARY_PREFIXES = {
  GITHUB_TOKEN: 'ghp_MUADDIB_CANARY_',
  NPM_TOKEN: 'npm_MUADDIB_CANARY_',
  AWS_ACCESS_KEY_ID: 'AKIA_MUADDIB_CANARY_',
  AWS_SECRET_ACCESS_KEY: 'MUADDIB_CANARY_SECRET_',
  GITLAB_TOKEN: 'glpat-MUADDIB_CANARY_',
  DOCKER_PASSWORD: 'dckr_MUADDIB_CANARY_',
  NPM_AUTH_TOKEN: 'npm_MUADDIB_CANARY_AUTH_',
  GH_TOKEN: 'ghp_MUADDIB_CANARY_GH_'
};

/**
 * Generate a unique set of canary tokens with random suffixes.
 * @returns {{ tokens: Record<string, string>, suffix: string }}
 */
function generateCanaryTokens() {
  const suffix = crypto.randomBytes(8).toString('hex');
  const tokens = {};
  for (const [key, prefix] of Object.entries(CANARY_PREFIXES)) {
    tokens[key] = prefix + suffix;
  }
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
      if (domain.includes(tokenValue)) {
        exfiltrations.push({
          token: tokenName,
          value: tokenValue,
          foundIn: `DNS query: ${domain}`,
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
  CANARY_PREFIXES,
  generateCanaryTokens,
  createCanaryEnvFile,
  createCanaryNpmrc,
  detectCanaryExfiltration,
  detectCanaryInOutput
};
