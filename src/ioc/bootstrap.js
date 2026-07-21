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
const { debugLog } = require('../utils.js');

// GitHub Releases URL for pre-compressed IOC database
const IOCS_URL = 'https://github.com/DNSZLSK/muad-dib/releases/latest/download/iocs.json.gz';

// Local storage paths
const HOME_DATA_DIR = path.join(os.homedir(), '.muaddib', 'data');
const IOCS_PATH = path.join(HOME_DATA_DIR, 'iocs.json');

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
 * @returns {Promise<void>}
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

        // Stream: response → gunzip → temp file
        const tmpPath = destPath + '.tmp';
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
            resolve();
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

/**
 * Ensure IOC database is available. Downloads from GitHub Releases on first run.
 * Gracefully fails — scan still works with compact IOCs if download fails.
 * @returns {Promise<boolean>} true if IOCs are available (cached or downloaded), false if download failed
 */
async function ensureIOCs() {
  // Per-process memoization — first scan decides, subsequent scans reuse the result.
  if (_ensureIocsResult !== null) return _ensureIocsResult;

  try {
    // Create data directory if needed
    if (!fs.existsSync(HOME_DATA_DIR)) {
      fs.mkdirSync(HOME_DATA_DIR, { recursive: true });
    }

    // Skip if IOCs already exist and are large enough
    if (fs.existsSync(IOCS_PATH)) {
      const stat = fs.statSync(IOCS_PATH);
      if (stat.size >= MIN_IOCS_SIZE) {
        return (_ensureIocsResult = true);
      }
    }

    // Bundled-source fast path: dev installs and the npm tarball both ship src/ioc/data/iocs.json.
    // When that file is present, the updater loader already merges it — no need to hit GitHub.
    if (fs.existsSync(LOCAL_BUNDLED_IOCS)) {
      try {
        const stat = fs.statSync(LOCAL_BUNDLED_IOCS);
        if (stat.size >= MIN_IOCS_SIZE) {
          return (_ensureIocsResult = true);
        }
      } catch { /* fall through to download */ }
    }

    // Offline / CI escape hatch: cache is empty/missing AND we don't want to
    // hit the network. Tests and air-gapped environments use this to avoid
    // 1-2s timeouts × N tests when the asset is unavailable. Same env var as
    // the per-scan registry fetch hatch so a single MUADDIB_NO_REGISTRY_FETCH=1
    // covers both bootstrap + per-scan paths. Important: this gate sits AFTER
    // the cache check so a healthy cache still returns true even in offline
    // mode (otherwise tests that pre-populate the cache would falsely fail).
    if (process.env.MUADDIB_NO_REGISTRY_FETCH === '1') {
      return (_ensureIocsResult = false);
    }

    // Download IOCs (messages go to stderr to avoid contaminating JSON/SARIF stdout)
    process.stderr.write('[MUADDIB] First run: downloading IOC database...\n');
    await downloadAndDecompress(IOCS_URL, IOCS_PATH);

    // Verify downloaded file
    const stat = fs.statSync(IOCS_PATH);
    if (stat.size < MIN_IOCS_SIZE) {
      try { fs.unlinkSync(IOCS_PATH); } catch {}
      process.stderr.write('[WARN] Downloaded IOC file is too small, using compact IOCs\n');
      return (_ensureIocsResult = false);
    }

    process.stderr.write('[MUADDIB] IOC database ready (' + Math.round(stat.size / 1024 / 1024) + ' MB)\n');
    return (_ensureIocsResult = true);
  } catch (err) {
    process.stderr.write('[WARN] Could not download IOC database: ' + err.message + '\n');
    process.stderr.write('[WARN] Continuing with bundled/YAML IOCs (run "muaddib update" for full coverage)\n');
    return (_ensureIocsResult = false);
  }
}

// Test hook — lets the test suite reset the memoization without spawning a fresh process.
function _resetEnsureIocsForTests() {
  _ensureIocsResult = null;
}

module.exports = {
  ensureIOCs,
  downloadAndDecompress,
  isAllowedRedirect,
  IOCS_URL,
  IOCS_PATH,
  HOME_DATA_DIR,
  MIN_IOCS_SIZE,
  _resetEnsureIocsForTests
};
