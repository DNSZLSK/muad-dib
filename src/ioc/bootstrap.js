// muaddib-ignore — os.homedir() is used for IOC cache path, not credential access
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');

// GitHub Releases URL for pre-compressed IOC database
const IOCS_URL = 'https://github.com/DNSZLSK/muad-dib/releases/latest/download/iocs.json.gz';

// Local storage paths
const HOME_DATA_DIR = path.join(os.homedir(), '.muaddib', 'data');
const IOCS_PATH = path.join(HOME_DATA_DIR, 'iocs.json');

// Minimum file size to consider IOCs valid (1MB)
const MIN_IOCS_SIZE = 1_000_000;

// Download timeout (60 seconds — file is ~15MB)
const DOWNLOAD_TIMEOUT = 60_000;

// Max redirects to follow
const MAX_REDIRECTS = 5;

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

        gunzip.on('error', (err) => {
          fileStream.destroy();
          try { fs.unlinkSync(tmpPath); } catch {}
          reject(new Error('Decompression failed: ' + err.message));
        });

        fileStream.on('error', (err) => {
          try { fs.unlinkSync(tmpPath); } catch {}
          reject(err);
        });

        fileStream.on('finish', () => {
          // Atomic write: rename .tmp → final path
          try {
            fs.renameSync(tmpPath, destPath);
            resolve();
          } catch (err) {
            try { fs.unlinkSync(tmpPath); } catch {}
            reject(err);
          }
        });

        res.on('error', (err) => {
          gunzip.destroy();
          fileStream.destroy();
          try { fs.unlinkSync(tmpPath); } catch {}
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
  try {
    // Create data directory if needed
    if (!fs.existsSync(HOME_DATA_DIR)) {
      fs.mkdirSync(HOME_DATA_DIR, { recursive: true });
    }

    // Skip if IOCs already exist and are large enough
    if (fs.existsSync(IOCS_PATH)) {
      const stat = fs.statSync(IOCS_PATH);
      if (stat.size >= MIN_IOCS_SIZE) {
        return true;
      }
    }

    // Download IOCs (messages go to stderr to avoid contaminating JSON/SARIF stdout)
    process.stderr.write('[MUADDIB] First run: downloading IOC database...\n');
    await downloadAndDecompress(IOCS_URL, IOCS_PATH);

    // Verify downloaded file
    const stat = fs.statSync(IOCS_PATH);
    if (stat.size < MIN_IOCS_SIZE) {
      try { fs.unlinkSync(IOCS_PATH); } catch {}
      process.stderr.write('[WARN] Downloaded IOC file is too small, using compact IOCs\n');
      return false;
    }

    process.stderr.write('[MUADDIB] IOC database ready (' + Math.round(stat.size / 1024 / 1024) + ' MB)\n');
    return true;
  } catch (err) {
    process.stderr.write('[WARN] Could not download IOC database: ' + err.message + '\n');
    process.stderr.write('[WARN] Continuing with compact IOCs (limited PyPI coverage)\n');
    return false;
  }
}

module.exports = {
  ensureIOCs,
  downloadAndDecompress,
  isAllowedRedirect,
  IOCS_URL,
  IOCS_PATH,
  HOME_DATA_DIR,
  MIN_IOCS_SIZE
};
