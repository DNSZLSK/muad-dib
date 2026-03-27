// Shared REHABILITATED_PACKAGES — single source of truth
// Packages that were temporarily compromised but are now safe
// These packages will NOT be blocked (except specific compromised versions)
const REHABILITATED_PACKAGES = {
  // September 2025 - Massive compromise via phishing, fixed within hours
  'chalk': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, malicious versions removed from npm'
  },
  'debug': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'ansi-styles': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'strip-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'wrap-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'is-arrayish': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'simple-swizzle': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'color-convert': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'supports-color': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'has-flag': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },

  // Packages with specific compromised versions (not all)
  'ua-parser-js': {
    compromised: ['0.7.29', '0.8.0', '1.0.0'],
    safe: false,
    note: 'Specific versions compromised Oct 2021'
  },
  'coa': {
    compromised: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
    safe: false,
    note: 'Specific versions compromised Nov 2021'
  },
  'rc': {
    compromised: ['1.2.9', '1.3.9', '2.3.9'],
    safe: false,
    note: 'Specific versions compromised Nov 2021'
  },

  // MUAD'DIB self-allowlisting (only the tool itself, not deps — deps must pass IOC checks)
  'muaddib-scanner': {
    compromised: [],
    safe: true,
    note: 'Our package — self-allowlisted to avoid self-flagging during scan'
  }
};

// Regex to validate npm package names (prevents command injection)
const NPM_PACKAGE_REGEX = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

// Download/extraction limits
const MAX_TARBALL_SIZE = 50 * 1024 * 1024; // 50MB
const DOWNLOAD_TIMEOUT = 30_000; // 30 seconds

// Shared scanner constants
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB — skip files larger than this to avoid memory issues
let _maxFileSize = MAX_FILE_SIZE;

/** Get current max file size (configurable via .muaddibrc.json). */
function getMaxFileSize() { return _maxFileSize; }
/** Set max file size override. */
function setMaxFileSize(size) { _maxFileSize = size; }
/** Reset max file size to default. */
function resetMaxFileSize() { _maxFileSize = MAX_FILE_SIZE; }
const ACORN_OPTIONS = { ecmaVersion: 2024, sourceType: 'module', allowHashBang: true };

const acorn = require('acorn');
const crypto = require('crypto');

/**
 * AST parse cache — same content+options returns the same AST.
 * Scanners do not mutate AST nodes (verified: only read comparisons).
 * Cleared between scans via clearASTCache().
 * Key = sha256(code) + '|' + optionsKey (collision-free content-addressable key)
 */
const _astCache = new Map();
const _AST_CACHE_MAX = 600; // Max entries (one scan ≈ 500 files max)

/**
 * Parse JS source with module-mode fallback to script-mode.
 * `const package = ...` is valid in script mode but reserved in module mode.
 * Results are cached for reuse across scanners within the same scan.
 * Returns AST or null if both modes fail.
 */
function safeParse(code, extraOptions = {}) {
  // Build cache key: sha256 content hash + options signature
  const optKey = Object.keys(extraOptions).length === 0 ? '' : JSON.stringify(extraOptions);
  const cacheKey = crypto.createHash('sha256').update(code).digest('hex') + '|' + optKey;

  const cached = _astCache.get(cacheKey);
  if (cached !== undefined) return cached;

  const opts = { ...ACORN_OPTIONS, ...extraOptions };
  let ast = null;
  try {
    ast = acorn.parse(code, opts);
  } catch {
    try {
      ast = acorn.parse(code, { ...opts, sourceType: 'script' });
    } catch {
      ast = null;
    }
  }

  // Cache the result (including null for unparseable files)
  if (_astCache.size >= _AST_CACHE_MAX) _astCache.clear();
  _astCache.set(cacheKey, ast);
  return ast;
}

function clearASTCache() {
  _astCache.clear();
}

module.exports = { REHABILITATED_PACKAGES, NPM_PACKAGE_REGEX, MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT, MAX_FILE_SIZE, ACORN_OPTIONS, safeParse, clearASTCache, getMaxFileSize, setMaxFileSize, resetMaxFileSize };
