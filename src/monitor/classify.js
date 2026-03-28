'use strict';

const { levenshteinDistance } = require('../scanner/typosquat.js');
const { loadCachedIOCs } = require('../ioc/updater.js');

// --- Popular npm names (used for quick typosquat check) ---

const POPULAR_NPM_NAMES = [
  'lodash', 'express', 'react', 'axios', 'chalk', 'commander', 'moment',
  'request', 'async', 'bluebird', 'underscore', 'uuid', 'debug',
  'webpack', 'typescript', 'eslint', 'prettier', 'jest',
  'mongoose', 'redis', 'mongodb', 'socket.io', 'dotenv',
  'jsonwebtoken', 'bcrypt', 'passport', 'aws-sdk', 'stripe',
  'firebase', 'graphql', 'electron', 'puppeteer',
  'react-native', 'next', 'nuxt', 'gatsby', 'svelte',
  'node-fetch', 'got', 'pino', 'winston'
];

// --- Popularity pre-filter ---
const POPULAR_THRESHOLD = 50_000; // Weekly downloads to classify as "popular"
const DOWNLOADS_CACHE_TTL = 24 * 60 * 60 * 1000; // 24h
const downloadsCache = new Map(); // key: packageName -> { downloads, fetchedAt }

// --- Tarball cache retention constants ---
const TARBALL_CACHE_DEFAULT_RETENTION_DAYS = 7;
const TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS = 30;

// --- IOC match types (these are the only static-analysis types that warrant a webhook) ---

const IOC_MATCH_TYPES = new Set([
  'known_malicious_package',
  'known_malicious_hash',
  'pypi_malicious_package',
  'shai_hulud_marker',
  'shai_hulud_backdoor'
]);

// High-confidence malice types: quasi-never legitimate in benign packages.
// When present, reputation attenuation is BYPASSED -- raw score used for webhook.
// This prevents supply-chain compromises of established packages from being suppressed.
const HIGH_CONFIDENCE_MALICE_TYPES = new Set([
  'lifecycle_shell_pipe',                  // curl|sh in preinstall
  'fetch_decrypt_exec',                    // steganographic payload chain
  'download_exec_binary',                  // download+chmod+exec
  'reverse_shell',                         // reverse shell (always malicious)
  'crypto_staged_payload',                 // decrypt->eval staged payload chain
  'intent_credential_exfil',               // intra-file credential->network
  'intent_command_exfil',                  // intra-file command->network
  'cross_file_dataflow',                   // proven taint cross-modules
  'canary_exfiltration',                   // canary sandbox exfiltrated
  'sandbox_network_after_sensitive_read',  // compound sandbox detection
  'detached_credential_exfil',            // detached process + credential exfil (DPRK/Lazarus)
  'node_modules_write',                    // writeFile to node_modules/ (worm propagation)
  'npm_publish_worm',                      // exec("npm publish") (worm propagation)
  'systemd_persistence',                   // writeFile to systemd/ or systemctl enable (CanisterWorm T1543.002)
  'npm_token_steal',                       // exec("npm config get _authToken") (CanisterWorm findNpmTokens)
  'root_filesystem_wipe',                  // rm -rf / (CanisterWorm kamikaze.sh wiper T1485)
  'proc_mem_scan'                          // /proc/mem scanning (TeamPCP Trivy credential stealer)
]);

// Lifecycle compound types that indicate real malicious intent beyond a simple postinstall
const LIFECYCLE_INTENT_TYPES = new Set([
  'lifecycle_dataflow',           // lifecycle + suspicious dataflow
  'lifecycle_dangerous_exec',     // lifecycle + dangerous shell
  'lifecycle_inline_exec',        // lifecycle + node -e
  'lifecycle_remote_require',     // lifecycle + remote code load
  'lifecycle_hidden_payload',     // lifecycle targeting node_modules/
  'obfuscated_lifecycle_env',     // lifecycle + obfuscation + env access
  'bun_runtime_evasion',          // Bun runtime in lifecycle (sandbox evasion)
  'lifecycle_shell_pipe',         // curl|sh in preinstall (also HC, but belt+suspenders)
]);

// --- Suspect tier constants ---

// Tier 1: high-intent threat types that always warrant sandbox analysis
const TIER1_TYPES = new Set([
  'sandbox_evasion', 'env_charcode_reconstruction',
  'staged_payload', 'staged_binary_payload',
  'mcp_config_injection', 'ai_agent_abuse', 'crypto_miner'
]);

// Tier 2: active threat types that warrant sandbox when queue pressure is low
const TIER2_ACTIVE_TYPES = new Set([
  'suspicious_dataflow', 'dangerous_call_eval', 'dangerous_call_function'
]);

// Tier 3: passive/informational types -- no sandbox, no stats.suspect increment
const TIER3_PASSIVE_TYPES = new Set([
  'sensitive_string', 'suspicious_domain', 'obfuscation_detected',
  'prototype_hook', 'env_access', 'dynamic_import',
  'dynamic_require', 'high_entropy_string'
]);

// --- Verbose mode (--verbose sends ALL alerts including temporal/publish/maintainer) ---
// @deprecated verboseMode is unused in production -- temporal/publish/maintainer
// alerts are controlled by their own feature flags (isTemporalEnabled, etc.).
// Retained for backward compatibility with existing tests and CLI flag parsing.

let verboseMode = false;

// --- Helper functions ---

function hasHighOrCritical(result) {
  return result.summary.critical > 0 || result.summary.high > 0;
}

function hasHighConfidenceThreat(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => HIGH_CONFIDENCE_MALICE_TYPES.has(t.type) && t.severity !== 'LOW');
}

function hasIOCMatch(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => IOC_MATCH_TYPES.has(t.type));
}

function hasTyposquat(result) {
  if (!result || !result.threats) return false;
  return result.threats.some(t => t.type === 'typosquat_detected' || t.type === 'pypi_typosquat_detected');
}

function hasLifecycleWithIntent(result) {
  if (!result || !result.threats) return false;
  const hasLifecycle = result.threats.some(t => t.type === 'lifecycle_script');
  if (!hasLifecycle) return false;
  // lifecycle_script + any lifecycle compound or HC type -> T1a justified
  return result.threats.some(t => LIFECYCLE_INTENT_TYPES.has(t.type));
}

/**
 * Classify a scan result into suspect tiers.
 * @param {Object} result - scan result with threats and summary
 * @returns {{ suspect: boolean, tier: '1a'|'1b'|2|3|null }}
 *   - tier '1a': mandatory sandbox (HC malice types, TIER1_TYPES non-LOW, lifecycle + intent compound)
 *   - tier '1b': conditional sandbox (HIGH/CRITICAL severity without HC type -- bundler FP zone)
 *   - tier 2: sandbox si queue < 50 (2+ distinct types with active signal)
 *   - tier 3: logged only, no sandbox, no stats.suspect (passive-only signals)
 *   - { suspect: false, tier: null } for CLEAN packages
 */
function isSuspectClassification(result) {
  if (!result || !result.threats || result.threats.length === 0) {
    return { suspect: false, tier: null };
  }

  // Tier 1a: high-confidence malice types, TIER1_TYPES (non-LOW), or lifecycle + intent compound
  // These are quasi-never legitimate in benign packages -> mandatory sandbox
  if (hasHighConfidenceThreat(result)) {
    return { suspect: true, tier: '1a' };
  }
  if (result.threats.some(t => TIER1_TYPES.has(t.type) && t.severity !== 'LOW')) {
    return { suspect: true, tier: '1a' };
  }
  if (hasLifecycleWithIntent(result)) {
    return { suspect: true, tier: '1a' };
  }

  // Tier 1b: HIGH/CRITICAL severity without HC type or TIER1_TYPES
  // Typical bundler FP zone (eval in webpack, minification as obfuscation, etc.)
  // Sandbox conditional on score >= 25 or low queue pressure
  if (result.summary.critical > 0 || result.summary.high > 0) {
    return { suspect: true, tier: '1b' };
  }

  const distinctTypes = new Set(result.threats.map(t => t.type));
  if (distinctTypes.size < 2) {
    return { suspect: false, tier: null };
  }

  // Tier 2: 2+ distinct types with at least one active type
  if (result.threats.some(t => TIER2_ACTIVE_TYPES.has(t.type))) {
    return { suspect: true, tier: 2 };
  }

  // Tier 3: 2+ distinct types but all passive
  const allPassive = result.threats.every(t => TIER3_PASSIVE_TYPES.has(t.type));
  if (allPassive) {
    return { suspect: true, tier: 3 };
  }

  // 2+ distinct types with non-passive types not in tier 2 active list -- tier 2
  return { suspect: true, tier: 2 };
}

/**
 * Classify an error into a category for the daily report breakdown.
 * @param {Error} err
 * @returns {'too_large'|'tar_failed'|'http_error'|'static_timeout'|'timeout'|'other'}
 */
function classifyError(err) {
  const msg = (err && err.message) || '';
  if (/too large|tarball too large/i.test(msg)) return 'too_large';
  if (/tar\b|extract/i.test(msg)) return 'tar_failed';
  if (/HTTP [45]\d\d|HTTP \d{3}/i.test(msg)) return 'http_error';
  if (/static scan timeout/i.test(msg)) return 'static_timeout';
  if (/timeout/i.test(msg)) return 'timeout';
  return 'other';
}

/**
 * Increment error counter with category tracking.
 * @param {Error} [err] - optional error for classification
 * @param {Object} stats - stats object with errors and errorsByType counters
 */
function recordError(err, stats) {
  stats.errors++;
  const category = err ? classifyError(err) : 'other';
  stats.errorsByType[category]++;
}

/**
 * Format error count with breakdown by type for the daily report.
 * Returns "0" if no errors, or "138 (HTTP: 60, tar: 40, timeout: 20, other: 18)" style.
 */
function formatErrorBreakdown(total, byType) {
  if (total === 0) return '0';
  const parts = [];
  if (byType.http_error > 0) parts.push(`HTTP: ${byType.http_error}`);
  if (byType.tar_failed > 0) parts.push(`tar: ${byType.tar_failed}`);
  if (byType.too_large > 0) parts.push(`too large: ${byType.too_large}`);
  if (byType.timeout > 0) parts.push(`timeout: ${byType.timeout}`);
  if (byType.static_timeout > 0) parts.push(`static: ${byType.static_timeout}`);
  if (byType.other > 0) parts.push(`other: ${byType.other}`);
  if (parts.length === 0) return `${total}`;
  return `${total} (${parts.join(', ')})`;
}

function formatFindings(result) {
  if (!result || !result.threats || result.threats.length === 0) return '';
  const seen = new Set();
  const parts = [];
  for (const t of result.threats) {
    const key = `${t.type}(${t.severity})`;
    if (!seen.has(key)) {
      seen.add(key);
      parts.push(key);
    }
  }
  return parts.join(', ');
}

function isSandboxEnabled() {
  const env = process.env.MUADDIB_MONITOR_SANDBOX;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function isCanaryEnabled() {
  const env = process.env.MUADDIB_MONITOR_CANARY;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

/** @deprecated See comment above verboseMode. */
function isVerboseMode() {
  if (verboseMode) return true;
  const env = process.env.MUADDIB_MONITOR_VERBOSE;
  return env !== undefined && env.toLowerCase() === 'true';
}

/** @deprecated See comment above verboseMode. */
function setVerboseMode(value) {
  verboseMode = !!value;
}

/**
 * Quick typosquat check using only package name (no API calls).
 * Used as cache trigger -- not for detection (full scanner handles that).
 * @param {string} name - Package name
 * @returns {boolean} True if name is suspiciously close to a popular package
 */
function quickTyposquatCheck(name) {
  const lower = name.toLowerCase();
  if (lower.startsWith('@')) return false;
  if (lower.length < 4) return false;
  if (POPULAR_NPM_NAMES.includes(lower)) return false;

  for (const popular of POPULAR_NPM_NAMES) {
    if (Math.abs(lower.length - popular.length) > 2) continue;
    const dist = levenshteinDistance(lower, popular);
    if (dist <= 2 && popular.length >= 5) return true;
    if (dist === 1) return true;
  }
  return false;
}

/**
 * Layer 3: Determine if a package should be cached and at what retention level.
 * @param {string} name - Package name
 * @param {Object|null} docMeta - Metadata from extractTarballFromDoc
 * @param {Object|null} doc - Full CouchDB doc
 * @returns {{ shouldCache: boolean, reason: string, retentionDays: number }}
 */
function evaluateCacheTrigger(name, docMeta, doc) {
  // Trigger 1: IOC match -- 30-day retention
  try {
    const iocs = loadCachedIOCs();
    if ((iocs.wildcardPackages && iocs.wildcardPackages.has(name)) ||
        (iocs.packagesMap && iocs.packagesMap.has(name))) {
      return { shouldCache: true, reason: 'ioc_match', retentionDays: TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS };
    }
  } catch { /* non-fatal */ }

  // Trigger 2: Typosquat signal -- 7-day retention
  try {
    if (quickTyposquatCheck(name)) {
      return { shouldCache: true, reason: 'typosquat_signal', retentionDays: TARBALL_CACHE_DEFAULT_RETENTION_DAYS };
    }
  } catch { /* non-fatal */ }

  // Trigger 3: First publish (single version in doc) -- 7-day retention
  if (doc && doc.versions) {
    const versionCount = Object.keys(doc.versions).length;
    if (versionCount === 1) {
      return { shouldCache: true, reason: 'first_publish', retentionDays: TARBALL_CACHE_DEFAULT_RETENTION_DAYS };
    }
  }

  return { shouldCache: false, reason: '', retentionDays: 0 };
}

module.exports = {
  // Constants
  IOC_MATCH_TYPES,
  HIGH_CONFIDENCE_MALICE_TYPES,
  LIFECYCLE_INTENT_TYPES,
  TIER1_TYPES,
  TIER2_ACTIVE_TYPES,
  TIER3_PASSIVE_TYPES,
  POPULAR_NPM_NAMES,
  POPULAR_THRESHOLD,
  DOWNLOADS_CACHE_TTL,
  TARBALL_CACHE_DEFAULT_RETENTION_DAYS,
  TARBALL_CACHE_HIGH_RISK_RETENTION_DAYS,

  // Mutable state
  downloadsCache,

  // Functions
  hasHighOrCritical,
  hasHighConfidenceThreat,
  hasIOCMatch,
  hasTyposquat,
  hasLifecycleWithIntent,
  isSuspectClassification,
  classifyError,
  recordError,
  formatErrorBreakdown,
  formatFindings,
  isSandboxEnabled,
  isCanaryEnabled,
  isVerboseMode,
  setVerboseMode,
  quickTyposquatCheck,
  evaluateCacheTrigger,
};
