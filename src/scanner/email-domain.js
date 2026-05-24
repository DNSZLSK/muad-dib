// F3 — Unclaimed maintainer email domain detection.
//
// Threat model: if the maintainer's email domain has no valid MX record, the
// domain is "unclaimed" for mail. An attacker can register the domain, create
// the mailbox, trigger an npm password-reset, take over the account.
//
// Design constraints:
//  - HIGH × confidence_medium = 8.5 points → composite-only (sub-T1).
//    This signal MUST never trigger an alert in isolation; it only contributes
//    to scoring alongside other indicators.
//  - Network failures (timeout, ESERVFAIL, etc.) are SILENT (debug-only logs).
//    No retries. rdap.org-style community redirectors are best-effort and the
//    scan must not block or spam logs on flaky ccTLD DNS.
//  - 30-day in-process cache (positive AND negative) keyed by domain.
//
// Inspired by GuardDog's npm/unclaimed_maintainer_email_domain.py.

const dns = require('dns');
const { debugLog } = require('../utils.js');

const MX_TIMEOUT_MS = 3000;
const MX_CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days

// In-process cache: domain → { hasMx: bool|null, fetchedAt: ms }
// hasMx === null = uncertain (transient error), don't cache long-term — but
// we DO cache it short-term to avoid re-querying within the same scan batch.
const _mxCache = new Map();

function extractDomain(email) {
  if (!email || typeof email !== 'string') return null;
  const at = email.lastIndexOf('@');
  if (at <= 0 || at >= email.length - 1) return null;
  const domain = email.slice(at + 1).toLowerCase().trim();
  // Basic sanity: must contain a dot, no whitespace, reasonable length
  if (!domain.includes('.') || /\s/.test(domain) || domain.length > 253) return null;
  return domain;
}

function uniqueDomains(emails) {
  const set = new Set();
  for (const e of emails || []) {
    const d = extractDomain(e);
    if (d) set.add(d);
  }
  return Array.from(set);
}

async function resolveMxWithTimeout(resolveMx, domain, timeoutMs) {
  let timer = null;
  try {
    return await Promise.race([
      resolveMx(domain),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('DNS_TIMEOUT'), { code: 'DNS_TIMEOUT' })), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Returns true if the domain has at least one MX record, false if it
 * definitively has none (ENOTFOUND/ENODATA), null on transient/uncertain
 * errors (timeout/ESERVFAIL/etc — treat as "skip silently").
 */
async function hasMxRecord(resolveMx, domain) {
  const cached = _mxCache.get(domain);
  if (cached && (Date.now() - cached.fetchedAt) < MX_CACHE_TTL) {
    return cached.hasMx;
  }
  let hasMx;
  try {
    const records = await resolveMxWithTimeout(resolveMx, domain, MX_TIMEOUT_MS);
    hasMx = Array.isArray(records) && records.length > 0;
  } catch (err) {
    const code = err && err.code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      hasMx = false;
    } else {
      // Timeout, ESERVFAIL, EREFUSED, network-down: uncertain → skip silently.
      debugLog('[EMAIL-DOMAIN] MX lookup uncertain for ' + domain + ': ' + (code || err.message));
      // Short-cache the uncertainty so we don't re-query during the same scan
      _mxCache.set(domain, { hasMx: null, fetchedAt: Date.now() });
      return null;
    }
  }
  _mxCache.set(domain, { hasMx, fetchedAt: Date.now() });
  return hasMx;
}

/**
 * F3 entry point.
 * @param {object|null} meta - Digested metadata from getPackageMetadata.
 *   Reads meta.maintainer_emails (string[]).
 * @param {object} options - { resolveMx } for tests to inject a mock resolver.
 * @returns {Promise<Array>} threats array (empty when disabled, offline, or no email)
 */
async function checkUnclaimedMaintainerEmail(meta, options = {}) {
  // Opt-out for offline / air-gapped scans
  if (globalThis.process.env.MUADDIB_EMAIL_DOMAIN_CHECK === '0') return [];
  if (!meta || !Array.isArray(meta.maintainer_emails) || meta.maintainer_emails.length === 0) {
    return [];
  }
  const resolveMx = options.resolveMx || dns.promises.resolveMx;
  const domains = uniqueDomains(meta.maintainer_emails);
  if (domains.length === 0) return [];

  const threats = [];
  for (const domain of domains) {
    let hasMx;
    try {
      hasMx = await hasMxRecord(resolveMx, domain);
    } catch (err) {
      debugLog('[EMAIL-DOMAIN] unexpected error for ' + domain + ': ' + err.message);
      continue;
    }
    if (hasMx === false) {
      threats.push({
        type: 'unclaimed_maintainer_email',
        severity: 'HIGH',
        message: 'Maintainer email domain "' + domain + '" has no MX record — unclaimed mailbox, attacker can register the domain to receive a password-reset and take over the account.',
        file: 'package.json',
        count: 1,
        domain
      });
    }
  }
  return threats;
}

// Exposed for tests
function _resetCache() { _mxCache.clear(); }

module.exports = {
  checkUnclaimedMaintainerEmail,
  extractDomain,
  uniqueDomains,
  hasMxRecord,
  _resetCache,
  MX_TIMEOUT_MS,
  MX_CACHE_TTL
};
