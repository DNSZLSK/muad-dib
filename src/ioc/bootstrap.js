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

// muaddib-ignore — os.homedir() is used for IOC cache path, not credential access
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const crypto = require('crypto');
const { debugLog } = require('../utils.js');
const { verifyManifest, countCompactPackages, MIN_COMPACT_PACKAGES } = require('./ioc-db-signature.js');

// IOC database for npm installs. The npm package deliberately ships NO IOC data (.npmignore:
// malicious package names trip Socket / npm audit), so this download is the only source of
// known-malicious detection for a user who never ran `muaddib update`. It used to point at
// `releases/latest/download/iocs.json.gz`, an asset no release has carried since v2.10.44:
// every fresh install got a 404 and scanned with no IOC at all (a known-malicious dependency
// scored 0). It now points at a FIXED rolling release, `ioc-db`, rebuilt daily by
// .github/workflows/ioc-db.yml and independent of version releases.
const IOC_DB_BASE_URL = 'https://github.com/DNSZLSK/muad-dib/releases/download/ioc-db/';
// The database asset is content-addressed (iocs-compact-<sha12>.json.gz); its name comes from
// the signed manifest. IOC_DB_URL is the release base, kept for the existing exports.
const IOC_DB_URL = IOC_DB_BASE_URL;
// Signed manifest { sha256, size, npmEntries, builtAt } and its Ed25519 signature: see
// ioc-db-signature.js. Nothing is accepted that the manifest does not describe.
const IOC_DB_MANIFEST_URL = 'https://github.com/DNSZLSK/muad-dib/releases/download/ioc-db/ioc-db.manifest.json';
const IOC_DB_SIGNATURE_URL = 'https://github.com/DNSZLSK/muad-dib/releases/download/ioc-db/ioc-db.manifest.sig';
// Kept for API compatibility (tests, external callers).
const IOCS_URL = IOC_DB_URL;

// Local storage paths
const HOME_DATA_DIR = path.join(os.homedir(), '.muaddib', 'data');
// Full database written by `muaddib update` (scraper.js); when present, no download is needed.
const IOCS_PATH = path.join(HOME_DATA_DIR, 'iocs.json');
// Compact database downloaded from the ioc-db release (read by updater.js loadCachedIOCs).
const HOME_COMPACT_PATH = path.join(HOME_DATA_DIR, 'iocs-compact.json');
// Manifest of the installed copy: its builtAt is the anti-rollback floor of the next download.
const HOME_COMPACT_MANIFEST_PATH = HOME_COMPACT_PATH + '.manifest.json';
// Compact database present in a source checkout (git-tracked); npm installs do not have it.
const LOCAL_COMPACT_IOCS = path.join(__dirname, 'data', 'iocs-compact.json');
// The ioc-db release is rebuilt daily; refresh a copy older than this (silently, keeping the
// old copy on failure).
const COMPACT_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// Local bundled IOC file (committed in repo) — when present we don't need a network download.
// Loader (src/ioc/updater.js) reads this directly, so the home-cache download becomes a
// no-op for users who already have the source tree.
const LOCAL_BUNDLED_IOCS = path.join(__dirname, 'data', 'iocs.json');

// Per-process memoization: once download has failed (or been skipped), don't retry on the
// next scan within the same process. Eval runs hundreds of scans — without this we burn a
// 60s timeout per scan when the asset is missing.
let _ensureIocsResult = null;

// Minimum file size to consider IOCs valid (1MB)
const MIN_IOCS_SIZE = 1_000_000;

// Download timeout (60 seconds — file is ~15MB)
const DOWNLOAD_TIMEOUT = 60_000;

// Max redirects to follow
const MAX_REDIRECTS = 5;

// Decompression bomb guard: cap the DECOMPRESSED byte count streamed to disk. A compromised
// release asset (exactly this project's threat model — maintainer account takeover) could
// otherwise fill the disk: this was the only unbounded decompressor in the repo (download.js
// has the M4 gzip hint, scraper.js has MAX_ENTRY/TOTAL_UNCOMPRESSED). Env-tunable like the
// scraper caps; default leaves ample headroom over the ~112-223MB iocs.json.
const MAX_DECOMPRESSED_SIZE = parseInt(process.env.MUADDIB_BOOTSTRAP_MAX_DECOMPRESSED || '', 10) || 1024 * 1024 * 1024; // 1 GB

// Allowed redirect domains (SSRF protection)
const ALLOWED_REDIRECT_DOMAINS = [
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com'
];

/**
 * Checks if a redirect URL is allowed (SSRF protection).
 * Only HTTPS to whitelisted domains is permitted.
 * @param {string} redirectUrl - The redirect target URL
 * @returns {boolean}
 */
function isAllowedRedirect(redirectUrl) {
  try {
    const urlObj = new URL(redirectUrl);
    if (urlObj.protocol !== 'https:') return false;
    return ALLOWED_REDIRECT_DOMAINS.includes(urlObj.hostname);
  } catch {
    return false;
  }
}

/**
 * Download a gzipped file, decompress, and write to destPath atomically.
 * Follows redirects with SSRF-safe domain validation.
 * @param {string} url - Source URL (HTTPS)
 * @param {string} destPath - Local file path to write decompressed data
 * @returns {Promise<{sha256: string, bytes: number}>} digest and size of the COMPRESSED bytes received
 */
function downloadAndDecompress(url, destPath) {
  return new Promise((resolve, reject) => {
    let redirectCount = 0;

    const doRequest = (requestUrl) => {
      const req = https.get(requestUrl, { timeout: DOWNLOAD_TIMEOUT }, (res) => {
        // Handle redirects (GitHub releases redirect to objects.githubusercontent.com)
        if (res.statusCode === 301 || res.statusCode === 302) {
          res.resume();
          redirectCount++;
          if (redirectCount > MAX_REDIRECTS) {
            return reject(new Error('Too many redirects'));
          }
          const location = res.headers.location;
          if (!location) {
            return reject(new Error('Redirect without Location header'));
          }
          const absoluteLocation = new URL(location, requestUrl).href;
          if (!isAllowedRedirect(absoluteLocation)) {
            return reject(new Error('Redirect to disallowed domain: ' + new URL(absoluteLocation).hostname));
          }
          return doRequest(absoluteLocation);
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error('HTTP ' + res.statusCode + ' downloading IOCs'));
        }

        // Stream: response → gunzip → temp file. The compressed bytes are hashed on the way so
        // the caller can match them against the signed manifest.
        const tmpPath = destPath + '.tmp';
        const hash = crypto.createHash('sha256');
        let compressedBytes = 0;
        res.on('data', (chunk) => { hash.update(chunk); compressedBytes += chunk.length; });
        const gunzip = zlib.createGunzip();
        const fileStream = fs.createWriteStream(tmpPath);

        // Decompression bomb guard: count decompressed bytes, abort past the cap.
        let decompressedBytes = 0;
        gunzip.on('data', (chunk) => {
          decompressedBytes += chunk.length;
          if (decompressedBytes > MAX_DECOMPRESSED_SIZE) {
            res.destroy();
            gunzip.destroy();
            fileStream.destroy();
            try { fs.unlinkSync(tmpPath); } catch (e) { debugLog('cleanup failed:', e.message); }
            reject(new Error('Decompressed size exceeds cap (' + MAX_DECOMPRESSED_SIZE + ' bytes) — aborting'));
          }
        });

        gunzip.on('error', (err) => {
          fileStream.destroy();
          try { fs.unlinkSync(tmpPath); } catch (e) { debugLog('cleanup failed:', e.message); }
          reject(new Error('Decompression failed: ' + err.message));
        });

        fileStream.on('error', (err) => {
          try { fs.unlinkSync(tmpPath); } catch (e) { debugLog('cleanup failed:', e.message); }
          reject(err);
        });

        fileStream.on('finish', () => {
          // Atomic write: rename .tmp → final path
          try {
            fs.renameSync(tmpPath, destPath);
            resolve({ sha256: hash.digest('hex'), bytes: compressedBytes });
          } catch (err) {
            try { fs.unlinkSync(tmpPath); } catch (e) { debugLog('cleanup failed:', e.message); }
            reject(err);
          }
        });

        res.on('error', (err) => {
          gunzip.destroy();
          fileStream.destroy();
          try { fs.unlinkSync(tmpPath); } catch (e) { debugLog('cleanup failed:', e.message); }
          reject(err);
        });

        res.pipe(gunzip).pipe(fileStream);
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Download timeout after ' + DOWNLOAD_TIMEOUT + 'ms'));
      });
    };

    doRequest(url);
  });
}

function _isLargeFile(p, min) {
  try { return fs.statSync(p).size >= min; } catch { return false; }
}


/**
 * GET a small HTTPS resource into memory (manifest, signature), same redirect guard as the
 * database download, capped at maxBytes.
 * @param {string} url
 * @param {number} [maxBytes]
 * @returns {Promise<Buffer>}
 */
function httpsGetBuffer(url, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let redirectCount = 0;
    const doRequest = (requestUrl) => {
      const req = https.get(requestUrl, { timeout: DOWNLOAD_TIMEOUT }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          res.resume();
          if (++redirectCount > MAX_REDIRECTS) return reject(new Error('Too many redirects'));
          const location = res.headers.location;
          if (!location) return reject(new Error('Redirect without Location header'));
          const next = new URL(location, requestUrl).href;
          if (!isAllowedRedirect(next)) return reject(new Error('Redirect to disallowed domain: ' + new URL(next).hostname));
          return doRequest(next);
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error('HTTP ' + res.statusCode + ' downloading ' + path.basename(new URL(requestUrl).pathname)));
        }
        const chunks = [];
        let total = 0;
        res.on('data', (c) => {
          total += c.length;
          if (total > maxBytes) { res.destroy(); reject(new Error('response larger than ' + maxBytes + ' bytes')); return; }
          chunks.push(c);
        });
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Download timeout after ' + DOWNLOAD_TIMEOUT + 'ms')); });
    };
    doRequest(url);
  });
}

// Download seams (tests replace them; production uses the SSRF-guarded HTTPS downloads).
let _download = downloadAndDecompress;
let _getBuffer = httpsGetBuffer;
// Test seams: file locations and verifying key. Production never changes them.
let _publicKeyOverride = null;
const P = {
  iocsPath: IOCS_PATH,
  homeCompact: HOME_COMPACT_PATH,
  homeManifest: HOME_COMPACT_MANIFEST_PATH,
  localBundled: LOCAL_BUNDLED_IOCS,
  localCompact: LOCAL_COMPACT_IOCS,
  homeDataDir: HOME_DATA_DIR
};

/**
 * Download the compact database from the ioc-db release into ~/.muaddib/data/iocs-compact.json. The file is
 * replaced only after it parses and holds at least MIN_COMPACT_PACKAGES npm entries.
 * @returns {Promise<number>} npm entries in the new file
 */
async function fetchCompactDatabase() {
  // 1. Authenticity first: the signed manifest names the exact bytes to accept.
  const manifestBytes = await _getBuffer(IOC_DB_MANIFEST_URL);
  const signature = (await _getBuffer(IOC_DB_SIGNATURE_URL)).toString('utf8');
  let previousBuiltAt = null;
  try { previousBuiltAt = JSON.parse(fs.readFileSync(P.homeManifest, 'utf8')).builtAt || null; } catch { /* first download */ }
  const manifest = verifyManifest(manifestBytes, signature, { previousBuiltAt, publicKey: _publicKeyOverride || undefined });

  // 2. The database itself must be exactly those bytes, then still pass the format checks.
  const staging = P.homeCompact + '.download';
  try {
    const got = await _download(IOC_DB_BASE_URL + manifest.asset, staging);
    if (!got || got.sha256 !== manifest.sha256 || got.bytes !== manifest.size) {
      throw new Error('downloaded IOC database does not match its signed manifest');
    }
    const n = countCompactPackages(staging);
    if (n < MIN_COMPACT_PACKAGES || n !== manifest.npmEntries) {
      throw new Error(`downloaded IOC database rejected: ${n < 0 ? 'unreadable' : n + ' npm entries'} (manifest ${manifest.npmEntries}, minimum ${MIN_COMPACT_PACKAGES})`);
    }
    fs.renameSync(staging, P.homeCompact);
    fs.writeFileSync(P.homeManifest, manifestBytes);
    return n;
  } finally {
    try { fs.unlinkSync(staging); } catch { /* renamed or never written */ }
  }
}

/**
 * Make sure an IOC database is available before a scan.
 *
 * Sources, in order: the full database written by `muaddib update` (~/.muaddib/data/iocs.json),
 * the database of a source checkout (src/ioc/data), then the compact database downloaded from
 * the ioc-db release (~/.muaddib/data/iocs-compact.json, refreshed when older than 24 h; a failed
 * refresh keeps the previous copy). Never throws.
 * @returns {Promise<boolean>} true when a database is available
 */
async function ensureIOCs() {
  // Per-process memoization — first scan decides, subsequent scans reuse the result.
  if (_ensureIocsResult !== null) return _ensureIocsResult;

  try {
    if (_isLargeFile(P.iocsPath, MIN_IOCS_SIZE)) return (_ensureIocsResult = true);
    if (_isLargeFile(P.localBundled, MIN_IOCS_SIZE) || _isLargeFile(P.localCompact, MIN_IOCS_SIZE)) {
      return (_ensureIocsResult = true);
    }

    let haveCompact = false;
    let fresh = false;
    try {
      const st = fs.statSync(P.homeCompact);
      haveCompact = st.size > 0;
      fresh = Date.now() - st.mtimeMs < COMPACT_MAX_AGE_MS;
    } catch { /* not downloaded yet */ }
    if (haveCompact && fresh) return (_ensureIocsResult = true);

    // Offline / test escape hatch (same variable as the per-scan registry fetch): never hit the
    // network; a previously downloaded copy is still used.
    if (process.env.MUADDIB_NO_REGISTRY_FETCH === '1') return (_ensureIocsResult = haveCompact);

    if (!fs.existsSync(P.homeDataDir)) fs.mkdirSync(P.homeDataDir, { recursive: true });

    if (!haveCompact) process.stderr.write('[MUADDIB] Downloading the IOC database...\n');
    try {
      const n = await fetchCompactDatabase();
      if (!haveCompact) process.stderr.write(`[MUADDIB] IOC database ready (${n} npm entries)\n`);
      return (_ensureIocsResult = true);
    } catch (err) {
      if (haveCompact) {
        debugLog('IOC database refresh failed, keeping the previous copy:', err.message);
        return (_ensureIocsResult = true);
      }
      throw err;
    }
  } catch (err) {
    process.stderr.write('[WARN] Could not download the IOC database: ' + err.message + '\n');
    process.stderr.write('[WARN] Known-malicious package detection is OFF for this scan (the scan is INCONCLUSIVE). Run "muaddib update" to build the database locally.\n');
    return (_ensureIocsResult = false);
  }
}

// Test hooks: reset the memoization, replace the download without spawning a process.
function _resetEnsureIocsForTests() {
  _ensureIocsResult = null;
}
function _setDownloadForTests(fn, getBuffer) {
  _download = fn || downloadAndDecompress;
  _getBuffer = getBuffer || httpsGetBuffer;
}
// Point every location at a temp dir and/or verify with a test key; call with no args to restore.
function _setTestEnvironment(opts) {
  const o = opts || {};
  const dir = o.homeDataDir || HOME_DATA_DIR;
  P.homeDataDir = dir;
  P.iocsPath = o.homeDataDir ? path.join(dir, 'iocs.json') : IOCS_PATH;
  P.homeCompact = o.homeDataDir ? path.join(dir, 'iocs-compact.json') : HOME_COMPACT_PATH;
  P.homeManifest = P.homeCompact + '.manifest.json';
  P.localBundled = o.localBundled !== undefined ? o.localBundled : LOCAL_BUNDLED_IOCS;
  P.localCompact = o.localCompact !== undefined ? o.localCompact : LOCAL_COMPACT_IOCS;
  _publicKeyOverride = o.publicKey || null;
}

module.exports = {
  ensureIOCs,
  downloadAndDecompress,
  isAllowedRedirect,
  IOCS_URL,
  IOC_DB_URL,
  IOCS_PATH,
  HOME_COMPACT_PATH,
  HOME_COMPACT_MANIFEST_PATH,
  IOC_DB_MANIFEST_URL,
  IOC_DB_SIGNATURE_URL,
  httpsGetBuffer,
  MIN_COMPACT_PACKAGES,
  countCompactPackages,
  _setDownloadForTests,
  _setTestEnvironment,
  HOME_DATA_DIR,
  MIN_IOCS_SIZE,
  _resetEnsureIocsForTests
};
