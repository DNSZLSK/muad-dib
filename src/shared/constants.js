/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

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
// Decompressed-size cap for tar.gz extraction (M4). PARTIAL tar-bomb mitigation only —
// bypassable by a bomb forged to a multiple of 4GB + (<1GB), because the gzip ISIZE trailer
// this is checked against is mod 2^32. A hard cap needs streaming decompression (separate tech debt).
const MAX_EXTRACTED_SIZE = 1024 * 1024 * 1024; // 1GB

// Shared scanner constants
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB — skip files larger than this to avoid memory issues
let _maxFileSize = MAX_FILE_SIZE;

/** Get current max file size (configurable via .muaddibrc.json). */
function getMaxFileSize() { return _maxFileSize; }
/** Set max file size override. */
function setMaxFileSize(size) { _maxFileSize = size; }
/** Reset max file size to default. */
function resetMaxFileSize() { _maxFileSize = MAX_FILE_SIZE; }
// 2026: import attributes, RegExp modifiers, duplicate named groups (2025), using / await using (2026).
// Pinned, not 'latest', so an acorn upgrade cannot silently change what the scanners parse.
const ACORN_OPTIONS = { ecmaVersion: 2026, sourceType: 'module', allowHashBang: true };

const acorn = require('acorn');
const crypto = require('crypto');

/**
 * AST parse cache — same content+options returns the same AST.
 * Scanners do not mutate AST nodes (verified: only read comparisons).
 * Cleared between scans via clearASTCache().
 * Key = sha256(code) + '|' + optionsKey (collision-free content-addressable key)
 */
const _astCache = new Map();
const _AST_CACHE_MAX = 200; // Max entries (reduced from 600 to limit memory during evaluate)

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
  let ast;
  try {
    ast = acorn.parse(code, opts);
  } catch {
    try {
      // CommonJS runs inside a function wrapper: a top-level return is valid for Node.
      ast = acorn.parse(code, { ...opts, sourceType: 'script', allowReturnOutsideFunction: true });
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

// PyPI install-time / import-time code execution: the PyPI equivalent of an npm install
// hook. Emitted only by the Python scanners (python-source.js, python-ast-detectors), so
// their presence is itself the PyPI signal. Shared by scoring.js (MT-1 ceiling bypass) and
// ml/feature-extractor.js (VECTOR_TYPES of the F8 obfuscation_without_vector cap), so the two
// lists cannot drift apart.
const PYPI_IMPORT_TIME_RCE_TYPES = new Set([
  'import_time_exec',
  'import_time_subprocess',
  'import_time_os_system',
  'import_time_deserialization',
  'import_time_fetch_exec',
  'fetch_to_fork_exec_inline',
  'pyast_module_level_exec',
  'pyast_module_level_subprocess_shell',
  'pyast_module_level_unsafe_deserialization',
  'pyast_setup_cmdclass_override',
  'pyast_ctypes_shellcode_load'
]);

module.exports = { PYPI_IMPORT_TIME_RCE_TYPES, REHABILITATED_PACKAGES, NPM_PACKAGE_REGEX, MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT, MAX_EXTRACTED_SIZE, MAX_FILE_SIZE, ACORN_OPTIONS, safeParse, clearASTCache, getMaxFileSize, setMaxFileSize, resetMaxFileSize };
