'use strict';

const https = require('https');
const dns = require('dns');

/**
 * External healthcheck ping for uptime monitoring (Healthchecks.io, etc.).
 *
 * Security: HTTPS-only, no private IPs (SSRF protection via DNS resolution).
 * No domain allowlist — any public HTTPS endpoint is accepted.
 *
 * Usage:
 *   MUADDIB_HEALTHCHECK_URL=https://hc-ping.com/uuid
 *   - /start  sent on monitor startup
 *   - GET     sent every HEALTHCHECK_INTERVAL_MS
 *   - /fail   sent on fatal error (unhandledRejection, abnormal SIGTERM)
 */

const HEALTHCHECK_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

// Private IP ranges for SSRF protection
const PRIVATE_IP_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^::ffff:127\./,
  /^fc00:/,
  /^fe80:/
];

/**
 * Validate a healthcheck URL: HTTPS-only, no private IPs.
 * @param {string} url
 * @returns {{ valid: boolean, error?: string }}
 */
function validateHealthcheckUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') {
      return { valid: false, error: 'HTTPS required for healthcheck URL' };
    }
    if (PRIVATE_IP_PATTERNS.some(p => p.test(parsed.hostname))) {
      return { valid: false, error: 'Private IP addresses not allowed' };
    }
    return { valid: true };
  } catch (e) {
    return { valid: false, error: `Invalid URL: ${e.message}` };
  }
}

/**
 * Send a GET ping to the healthcheck URL. Never throws, never blocks.
 * @param {string} url — full URL (may include /start or /fail suffix)
 */
function ping(url) {
  if (!url) return;

  const validation = validateHealthcheckUrl(url);
  if (!validation.valid) {
    console.error(`[HEALTHCHECK] Blocked: ${validation.error}`);
    return;
  }

  try {
    const parsed = new URL(url);

    // DNS resolution check: verify resolved IPs are not private (SSRF via DNS rebinding)
    dns.resolve4(parsed.hostname, (dnsErr, addresses) => {
      if (dnsErr) {
        // DNS failure — skip silently (network may be temporarily down)
        return;
      }
      if (addresses.some(ip => PRIVATE_IP_PATTERNS.some(p => p.test(ip)))) {
        console.error(`[HEALTHCHECK] Blocked: DNS resolves to private IP`);
        return;
      }

      const req = https.get(url, { timeout: 5000 }, (res) => {
        res.resume(); // drain response
      });
      req.on('error', () => {}); // swallow errors silently
      req.on('timeout', () => { req.destroy(); });
    });
  } catch {
    // Never crash the monitor
  }
}

let _intervalHandle = null;

/**
 * Start healthcheck pinging. Sends /start immediately, then pings every 10 min.
 * @returns {{ stop: Function }} — call stop() to clear the interval
 */
function startHealthcheck() {
  const url = process.env.MUADDIB_HEALTHCHECK_URL;
  if (!url) return { stop() {} };

  const validation = validateHealthcheckUrl(url);
  if (!validation.valid) {
    console.error(`[HEALTHCHECK] Disabled: ${validation.error}`);
    return { stop() {} };
  }

  console.log('[HEALTHCHECK] Enabled — pinging every 10 min');

  // Ping /start
  const startUrl = url.endsWith('/') ? url + 'start' : url + '/start';
  ping(startUrl);

  // Periodic heartbeat
  _intervalHandle = setInterval(() => ping(url), HEALTHCHECK_INTERVAL_MS);
  // Don't keep the process alive just for healthcheck
  if (_intervalHandle.unref) _intervalHandle.unref();

  return {
    stop() {
      if (_intervalHandle) {
        clearInterval(_intervalHandle);
        _intervalHandle = null;
      }
    }
  };
}

/**
 * Send /fail ping (fatal error). Fire-and-forget.
 */
function pingFail() {
  const url = process.env.MUADDIB_HEALTHCHECK_URL;
  if (!url) return;
  const failUrl = url.endsWith('/') ? url + 'fail' : url + '/fail';
  ping(failUrl);
}

module.exports = {
  startHealthcheck,
  pingFail,
  ping,
  validateHealthcheckUrl,
  HEALTHCHECK_INTERVAL_MS,
  PRIVATE_IP_PATTERNS
};
