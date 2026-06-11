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
const { isShadowEnabled, recordShadowDivergence } = require('../shared/shadow.js');

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

// =============================================================================
// F1 — RDAP-based compromised email domain detection.
//
// Threat model: an attacker waits for the maintainer's email domain to expire,
// re-registers it, takes the mailbox, triggers an npm password-reset, takes
// over the account. The signal: the domain's `registration` event date is
// AFTER the package was first published.
//
// Why RDAP and not WHOIS:
//  - RDAP is the IETF replacement for WHOIS (RFC 7480-7483), returns JSON
//  - HTTP/HTTPS — works with Node's built-in fetch, no external dep
//  - rdap.org is a community redirector that forwards to TLD-specific RDAP
//    servers. Best-effort: many ccTLDs (.ru, .cn, .tk, .io) have no RDAP at
//    all → we MUST skip silently on 404/timeout (no log spam in prod).
//
// Design constraints (same as F3 + plan):
//  - HIGH × confidence_high = 10 points → composite-only (sub-T1=20).
//  - Network failures SILENT (debug-only). No retries.
//  - 30-day cache for RDAP responses (they don't change often).
//  - 30-day margin on the comparison: alert iff
//      creation_date > package_first_publish - 30j
//    The -30j absorbs registration-vs-publish timing edges (e.g., maintainer
//    bought the domain a few weeks before shipping their first version).
//  - Opt-out via MUADDIB_RDAP_CHECK=0 (default ON).
//
// Inspired by GuardDog's npm/potentially_compromised_email_domain.py (which
// uses python-whois). We replace the WHOIS dependency with an RDAP HTTP call
// to satisfy the CLAUDE.md "no external runtime deps" rule.
// =============================================================================

const RDAP_TIMEOUT_MS = 5000;
const RDAP_CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days
const RDAP_BASE_URL = 'https://rdap.org/domain/';
// 30-day margin on creation-vs-publish comparison (see above).
const COMPROMISE_MARGIN_MS = 30 * 24 * 60 * 60 * 1000;

// In-process cache: domain → { creationDate: ISO|null, fetchedAt: ms }
const _rdapCache = new Map();

/**
 * Query the RDAP service for a domain's registration date.
 * Returns { creationDate: ISO string } or null on any error/missing data.
 * SILENT on failure — debug log only.
 */
async function fetchRdap(domain, options = {}) {
  const timeoutMs = options.timeoutMs || RDAP_TIMEOUT_MS;
  const cached = _rdapCache.get(domain);
  if (cached && (Date.now() - cached.fetchedAt) < RDAP_CACHE_TTL) {
    return cached.creationDate ? { creationDate: cached.creationDate } : null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(RDAP_BASE_URL + encodeURIComponent(domain), {
      signal: controller.signal,
      redirect: 'follow',
      headers: { 'Accept': 'application/rdap+json' }
    });
    if (!response.ok) {
      // 404 = no RDAP for this TLD, or unknown domain. Other errors transient.
      // Drain body to free resources.
      try { await response.text(); } catch { /* ignore */ }
      _rdapCache.set(domain, { creationDate: null, fetchedAt: Date.now() });
      return null;
    }
    let data;
    try {
      data = await response.json();
    } catch {
      return null; // malformed JSON
    }
    if (!data || !Array.isArray(data.events)) {
      _rdapCache.set(domain, { creationDate: null, fetchedAt: Date.now() });
      return null;
    }
    const reg = data.events.find(e =>
      e && typeof e.eventAction === 'string' &&
      e.eventAction.toLowerCase() === 'registration'
    );
    const creationDate = reg && typeof reg.eventDate === 'string' ? reg.eventDate : null;
    _rdapCache.set(domain, { creationDate, fetchedAt: Date.now() });
    return creationDate ? { creationDate } : null;
  } catch (err) {
    debugLog('[RDAP] fetch failed for ' + domain + ': ' + (err.code || err.message));
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Returns true if the domain registration came AFTER the package was first
 * published (with a 30-day margin to absorb timing edges).
 */
function isCompromisedDomain(creationDateISO, packageCreatedAtISO) {
  if (!creationDateISO || !packageCreatedAtISO) return false;
  const cDate = new Date(creationDateISO).getTime();
  const rDate = new Date(packageCreatedAtISO).getTime();
  if (isNaN(cDate) || isNaN(rDate)) return false;
  return cDate > (rDate - COMPROMISE_MARGIN_MS);
}

// =============================================================================
// V2 candidate semantics (SHADOW-ONLY until adjudicated — V1 above still emits
// every threat). Two changes vs V1, both validated by the node-ipc takeover
// (May 2026: domain atlantis-software.net re-registered 2026-05-07, malicious
// 9.2.3/12.0.1 published 05-14, FIRST publish years earlier):
//
//  1. STRICT comparison — creation > first_publish, the 30-day pre-publish
//     margin removed. A dev who buys their domain a few weeks before shipping
//     v1 is the NORMAL case (the margin was the main source of the 850+ FP);
//     a dev cannot have published with an email on a domain that did not
//     exist yet, so creation strictly after first publish stays a hard signal.
//     RDAP caveat that makes this work: many registries RESET the creation
//     date on re-registration (.net/Namecheap do — node-ipc's signal).
//  2. Public email providers excluded — gmail.com etc. can never be "taken
//     over" by re-registration; any weird RDAP answer for them is noise.
//     This is a domain-CLASS exclusion, not a package whitelist.
// =============================================================================

// Consumer email providers — domain takeover does not apply (the provider
// owns the domain; accounts are compromised via other vectors, out of scope
// for this RDAP signal).
const PUBLIC_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'googlemail.com',
  'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'ymail.com', 'rocketmail.com',
  'proton.me', 'protonmail.com', 'pm.me',
  'icloud.com', 'me.com', 'mac.com',
  'aol.com',
  'gmx.com', 'gmx.de', 'gmx.net',
  'mail.ru', 'inbox.ru', 'list.ru', 'bk.ru',
  'qq.com', 'foxmail.com', '163.com', '126.com', 'yeah.net', 'sina.com',
  'yandex.ru', 'yandex.com',
  'zoho.com', 'fastmail.com', 'hey.com',
  'tutanota.com', 'tuta.com', 'tuta.io',
  'web.de', 't-online.de', 'freenet.de',
  'free.fr', 'orange.fr', 'laposte.net', 'wanadoo.fr', 'sfr.fr',
  'naver.com', 'daum.net', 'hanmail.net',
  'rediffmail.com', 'seznam.cz', 'wp.pl', 'o2.pl', 'interia.pl',
  'duck.com', 'pobox.com', 'hushmail.com', 'mailbox.org', 'posteo.de'
]);

/**
 * V2: strict creation-after-first-publish, public providers excluded.
 * Pure — used by the shadow hook below and by scripts/backtest-email-domain.js.
 */
function isCompromisedDomainV2(creationDateISO, firstPublishISO, domain) {
  if (!creationDateISO || !firstPublishISO) return false;
  if (domain && PUBLIC_EMAIL_PROVIDERS.has(String(domain).toLowerCase())) return false;
  const cDate = new Date(creationDateISO).getTime();
  const rDate = new Date(firstPublishISO).getTime();
  if (isNaN(cDate) || isNaN(rDate)) return false;
  return cDate > rDate;
}

/**
 * F1 entry point.
 * @param {object|null} meta - Digested metadata. Reads maintainer_emails + created_at
 *   (= the package's FIRST publish date, both npm and PyPI sides).
 * @param {object} options - { fetchRdap } for tests to inject a mock.
 *   { shadowCtx: {name, version, ecosystem} } identifies the scanned package in
 *   shadow-divergence records (optional — without it divergences log package:null).
 * @returns {Promise<Array>} threats array
 */
async function checkCompromisedDomain(meta, options = {}) {
  if (globalThis.process.env.MUADDIB_RDAP_CHECK === '0') return [];
  if (!meta || !Array.isArray(meta.maintainer_emails) || meta.maintainer_emails.length === 0) {
    return [];
  }
  if (!meta.created_at) return []; // need a package publish date to compare against

  const fetchFn = options.fetchRdap || fetchRdap;
  const domains = uniqueDomains(meta.maintainer_emails);
  if (domains.length === 0) return [];

  const threats = [];
  for (const domain of domains) {
    let rdap;
    try {
      rdap = await fetchFn(domain);
    } catch (err) {
      debugLog('[RDAP] unexpected error for ' + domain + ': ' + err.message);
      continue;
    }
    if (!rdap || !rdap.creationDate) continue;
    // SHADOW (zero effect on the threats emitted below): compare the live V1
    // verdict with the V2 candidate and log only disagreements. Adjudication =
    // scripts/backtest-email-domain.js replay + `muaddib shadow-report`.
    try {
      if (isShadowEnabled()) {
        const v1 = isCompromisedDomain(rdap.creationDate, meta.created_at);
        const v2 = isCompromisedDomainV2(rdap.creationDate, meta.created_at, domain);
        if (v1 !== v2) {
          const ctx = options.shadowCtx || {};
          recordShadowDivergence({
            detector: 'compromised_email_domain',
            package: ctx.name, version: ctx.version, ecosystem: ctx.ecosystem,
            oldVerdict: v1, newVerdict: v2,
            evidence: { domain, creationDate: rdap.creationDate, firstPublish: meta.created_at, oldMarginDays: 30 }
          });
        }
      }
    } catch { /* shadow must never affect the scan */ }
    if (isCompromisedDomain(rdap.creationDate, meta.created_at)) {
      const cd = rdap.creationDate.slice(0, 10);
      const pd = meta.created_at.slice(0, 10);
      threats.push({
        type: 'compromised_email_domain',
        severity: 'HIGH',
        message: 'Maintainer email domain "' + domain + '" was registered on ' + cd
          + ' AFTER the package was first published on ' + pd
          + ' — likely domain takeover / account compromise indicator.',
        file: 'package.json',
        count: 1,
        domain,
        creation_date: rdap.creationDate,
        package_created_at: meta.created_at
      });
    }
  }
  return threats;
}

function _resetRdapCache() { _rdapCache.clear(); }

module.exports = {
  checkUnclaimedMaintainerEmail,
  extractDomain,
  uniqueDomains,
  hasMxRecord,
  _resetCache,
  MX_TIMEOUT_MS,
  MX_CACHE_TTL,
  // F1 exports
  checkCompromisedDomain,
  fetchRdap,
  isCompromisedDomain,
  // V2 candidate (shadow-only until adjudicated; used by the backtest script)
  isCompromisedDomainV2,
  PUBLIC_EMAIL_PROVIDERS,
  _resetRdapCache,
  RDAP_TIMEOUT_MS,
  RDAP_CACHE_TTL,
  COMPROMISE_MARGIN_MS
};
