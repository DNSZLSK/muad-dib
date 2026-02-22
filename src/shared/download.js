const https = require('https');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT } = require('./constants.js');

// Allowed redirect domains for tarball downloads (SSRF protection)
const ALLOWED_DOWNLOAD_DOMAINS = [
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'pypi.org',
  'files.pythonhosted.org'
];

// Private IP ranges — block redirects to internal networks
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
 * Validates that a redirect URL is allowed (SSRF protection).
 * Only HTTPS to whitelisted domains is permitted.
 * @param {string} redirectUrl - The redirect target URL
 * @returns {{allowed: boolean, error?: string}}
 */
function isAllowedDownloadRedirect(redirectUrl) {
  try {
    const urlObj = new URL(redirectUrl);
    if (urlObj.protocol !== 'https:') {
      return { allowed: false, error: `Redirect blocked: non-HTTPS protocol ${urlObj.protocol}` };
    }
    const hostname = urlObj.hostname.toLowerCase();
    // Block private IP addresses
    if (PRIVATE_IP_PATTERNS.some(p => p.test(hostname))) {
      return { allowed: false, error: `Redirect blocked: private IP ${hostname}` };
    }
    const domainAllowed = ALLOWED_DOWNLOAD_DOMAINS.some(domain =>
      hostname === domain || hostname.endsWith('.' + domain)
    );
    if (!domainAllowed) {
      return { allowed: false, error: `Redirect blocked: domain ${hostname} not in allowlist` };
    }
    return { allowed: true };
  } catch {
    return { allowed: false, error: `Redirect blocked: invalid URL ${redirectUrl}` };
  }
}

/**
 * Download a file from HTTPS URL to disk, with SSRF-safe redirect handling.
 * @param {string} url - Source URL (must be HTTPS)
 * @param {string} destPath - Local file path to write to
 * @param {number} [timeoutMs] - Download timeout in ms (default: DOWNLOAD_TIMEOUT)
 * @returns {Promise<number>} Number of bytes downloaded
 */
function downloadToFile(url, destPath, timeoutMs = DOWNLOAD_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const doRequest = (requestUrl) => {
      const req = https.get(requestUrl, { timeout: timeoutMs }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          res.resume();
          const location = res.headers.location;
          if (!location) return reject(new Error(`Redirect without Location for ${requestUrl}`));
          // Resolve relative redirects against the request URL
          const absoluteLocation = new URL(location, requestUrl).href;
          const check = isAllowedDownloadRedirect(absoluteLocation);
          if (!check.allowed) {
            return reject(new Error(check.error));
          }
          return doRequest(absoluteLocation);
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${requestUrl}`));
        }
        const contentLength = parseInt(res.headers['content-length'], 10);
        if (contentLength && contentLength > MAX_TARBALL_SIZE) {
          res.resume();
          return reject(new Error(`Package too large: ${contentLength} bytes (max ${MAX_TARBALL_SIZE})`));
        }
        const fileStream = fs.createWriteStream(destPath);
        let downloadedBytes = 0;
        res.on('data', (chunk) => {
          downloadedBytes += chunk.length;
          if (downloadedBytes > MAX_TARBALL_SIZE) {
            res.destroy();
            fileStream.destroy();
            try { fs.unlinkSync(destPath); } catch {}
            reject(new Error(`Package too large: ${downloadedBytes}+ bytes (max ${MAX_TARBALL_SIZE})`));
          }
        });
        res.pipe(fileStream);
        fileStream.on('finish', () => resolve(downloadedBytes));
        fileStream.on('error', (err) => {
          try { fs.unlinkSync(destPath); } catch {}
          reject(err);
        });
        res.on('error', (err) => {
          fileStream.destroy();
          try { fs.unlinkSync(destPath); } catch {}
          reject(err);
        });
      });
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Timeout downloading ${requestUrl}`));
      });
    };
    doRequest(url);
  });
}

/**
 * Extract a .tar.gz to a directory. Returns the package root.
 * Uses execFileSync (no shell) to prevent command injection.
 * @param {string} tgzPath - Path to the .tar.gz file
 * @param {string} destDir - Destination directory
 * @returns {string} Path to extracted package root
 */
function extractTarGz(tgzPath, destDir) {
  // Use cwd + relative paths so C: never appears in tar arguments
  // (GNU tar treats C: as remote host, bsdtar doesn't support --force-local)
  const tgzDir = path.dirname(path.resolve(tgzPath));
  const tgzName = path.basename(tgzPath);
  const relDest = path.relative(tgzDir, path.resolve(destDir)) || '.';
  execFileSync('tar', ['xzf', tgzName, '-C', relDest], { cwd: tgzDir, timeout: 60_000, stdio: 'pipe' });
  // npm tarballs extract into a package/ subdirectory; detect it
  const packageSubdir = path.join(destDir, 'package');
  try {
    const stat = fs.lstatSync(packageSubdir);
    if (!stat.isSymbolicLink() && stat.isDirectory()) {
      return packageSubdir;
    }
  } catch {
    // packageSubdir doesn't exist or is a broken symlink — continue
  }
  // Otherwise return destDir itself (PyPI sdists vary)
  const entries = fs.readdirSync(destDir);
  if (entries.length === 1) {
    const single = path.join(destDir, entries[0]);
    try {
      const stat = fs.lstatSync(single);
      if (!stat.isSymbolicLink() && stat.isDirectory()) return single;
    } catch {
      // broken symlink or permission denied — skip
    }
  }
  return destDir;
}

/**
 * Sanitize a package name for use in temporary directory names.
 * Removes path traversal sequences, slashes, and @ symbols.
 * @param {string} packageName - Raw package name
 * @returns {string} Safe string for directory names
 */
function sanitizePackageName(packageName) {
  return packageName
    .replace(/\.\./g, '')
    .replace(/\//g, '_')
    .replace(/@/g, '');
}

module.exports = {
  downloadToFile,
  extractTarGz,
  sanitizePackageName,
  isAllowedDownloadRedirect,
  ALLOWED_DOWNLOAD_DOMAINS,
  PRIVATE_IP_PATTERNS
};
