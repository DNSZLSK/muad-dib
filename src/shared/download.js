const https = require('https');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const AdmZip = require('adm-zip');
const { MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT } = require('./constants.js');
const { registryAuthHeaders } = require('./registry-auth.js');

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
  /^fe80:/,
  /^ff/i,                      // IPv6 multicast (RFC 4291 ff00::/8)
  /^2001:0?db8:/i,             // IPv6 documentation (RFC 3849 2001:db8::/32)
  /^100:/,                     // IPv6 discard (RFC 6666 100::/64)
  /^64:ff9b:/i                 // IPv6 NAT64 well-known (RFC 6052 64:ff9b::/96)
];

/**
 * Normalize a hostname by unwrapping IPv6-mapped IPv4 addresses
 * and converting decimal IP notation to dotted notation.
 * @param {string} hostname - Raw hostname from URL
 * @returns {string} Normalized hostname for SSRF validation
 */
function normalizeHostname(hostname) {
  hostname = hostname.toLowerCase();
  // Unwrap IPv6-mapped IPv4: ::ffff:192.168.1.1 → 192.168.1.1
  if (hostname.startsWith('::ffff:')) {
    const ipv4Part = hostname.slice(7);
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ipv4Part)) {
      return ipv4Part;
    }
  }
  // Convert integer IP notation (decimal or hex): 2130706433 or 0x7f000001 → 127.0.0.1
  if (/^(0x[\da-f]+|\d+)$/i.test(hostname)) {
    const num = hostname.startsWith('0x') ? parseInt(hostname, 16) : parseInt(hostname, 10);
    if (num > 0 && num < 4294967296) {
      return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
    }
  }
  // Convert dotted IP with octal/hex octets: 0177.0.0.01 or 0x7f.0.0.1 → 127.0.0.1
  if (/^[\da-fox.]+$/i.test(hostname)) {
    const parts = hostname.split('.');
    if (parts.length === 4) {
      const octets = parts.map(p => {
        if (/^0x[\da-f]+$/i.test(p)) return parseInt(p, 16);
        if (/^0\d+$/.test(p)) return parseInt(p, 8);
        return parseInt(p, 10);
      });
      if (octets.every(o => !isNaN(o) && o >= 0 && o <= 255)) {
        return octets.join('.');
      }
    }
  }
  return hostname;
}

/**
 * Validates that a redirect URL is allowed (SSRF protection).
 * Only HTTPS to whitelisted domains is permitted.
 * Normalizes IPv6-mapped IPv4 and decimal IP notation before validation.
 * @param {string} redirectUrl - The redirect target URL
 * @returns {{allowed: boolean, error?: string}}
 */
function isAllowedDownloadRedirect(redirectUrl) {
  try {
    const urlObj = new URL(redirectUrl);
    if (urlObj.protocol !== 'https:') {
      return { allowed: false, error: `Redirect blocked: non-HTTPS protocol ${urlObj.protocol}` };
    }
    const rawHostname = urlObj.hostname.toLowerCase();
    const hostname = normalizeHostname(rawHostname);
    // Block private IP addresses (check both raw and normalized)
    if (PRIVATE_IP_PATTERNS.some(p => p.test(hostname) || p.test(rawHostname))) {
      return { allowed: false, error: `Redirect blocked: private IP ${rawHostname}` };
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
 * Check if an IP address is private/internal.
 */
function isPrivateIP(ip) {
  const normalized = normalizeHostname(ip);
  return PRIVATE_IP_PATTERNS.some(p => p.test(normalized));
}

/**
 * Resolve hostname to IP and validate it's not a private address.
 * Prevents DNS rebinding attacks where a domain initially resolves to
 * a public IP but later rebinds to a private IP.
 */
async function safeDnsResolve(hostname) {
  // Skip for IP addresses (already validated in isAllowedDownloadRedirect)
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    if (isPrivateIP(hostname)) throw new Error(`DNS rebinding blocked: ${hostname} is private`);
    return hostname;
  }
  const dns = require('dns');
  const [v4, v6] = await Promise.allSettled([
    dns.promises.resolve4(hostname),
    dns.promises.resolve6(hostname),
  ]);
  const addresses = [
    ...(v4.status === 'fulfilled' ? v4.value : []),
    ...(v6.status === 'fulfilled' ? v6.value : []),
  ];
  if (addresses.length === 0) {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error(`DNS rebinding blocked: ${hostname} resolved to private IP ${addr}`);
    }
  }
  return addresses[0];
}

/**
 * Download a file from HTTPS URL to disk, with SSRF-safe redirect handling.
 * @param {string} url - Source URL (must be HTTPS)
 * @param {string} destPath - Local file path to write to
 * @param {number} [timeoutMs] - Download timeout in ms (default: DOWNLOAD_TIMEOUT)
 * @returns {Promise<number>} Number of bytes downloaded
 */
const MAX_REDIRECTS = 5;

function downloadToFile(url, destPath, timeoutMs = DOWNLOAD_TIMEOUT) {
  // DNS rebinding protection: validate hostname before connecting
  const parsedUrl = new URL(url);
  return safeDnsResolve(parsedUrl.hostname).then(() => {
    return new Promise((resolve, reject) => {
      const doRequest = (requestUrl, redirectCount) => {
        if (redirectCount === undefined) redirectCount = 0;
        if (redirectCount >= MAX_REDIRECTS) {
          return reject(new Error(`Too many redirects (${MAX_REDIRECTS}) for ${url}`));
        }
        const req = https.get(requestUrl, { timeout: timeoutMs, headers: registryAuthHeaders(requestUrl) }, (res) => {
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
            return doRequest(absoluteLocation, redirectCount + 1);
          }
          if (res.statusCode === 429) {
            res.resume();
            // Signal the host's brain to back off (escalating pause). Host is
            // URL-derived: this path downloads npm tarballs AND pypi wheels.
            try { const lim = require('./http-limiter.js'); lim.signal429(lim.hostForUrl(requestUrl)); } catch {}
            return reject(new Error(`HTTP 429 rate limited for ${requestUrl}`));
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
  });
}

/**
 * Detect archive format from a path/URL extension.
 * URL-derived names are reliable enough here: PyPI's `urls[].packagetype`
 * + filename are authoritative, npm tarballs are always `.tgz`. Returns
 * 'targz', 'zip', or 'unknown'. Callers either pass an `options.format`
 * override or trust this detection.
 *
 * @param {string} archivePath - Path or URL ending in the archive filename
 * @returns {'targz'|'zip'|'unknown'}
 */
function detectArchiveFormat(archivePath) {
  if (typeof archivePath !== 'string') return 'unknown';
  const lower = archivePath.toLowerCase();
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) return 'targz';
  if (lower.endsWith('.whl') || lower.endsWith('.zip')) return 'zip';
  return 'unknown';
}

/**
 * Extract a tar.gz tarball with the system `tar` binary. Used for npm
 * tarballs and PyPI sdists. Internal implementation — call extractArchive
 * for new code; extractTarGz remains as a thin wrapper for the existing
 * scanner/temporal-ast-diff.js callsite.
 */
function _extractTarGzImpl(tgzPath, destDir) {
  // Use cwd + relative paths so C: never appears in tar arguments
  // (GNU tar treats C: as remote host, bsdtar doesn't support --force-local)
  const tgzDir = path.dirname(path.resolve(tgzPath));
  const tgzName = path.basename(tgzPath);
  const relDest = path.relative(tgzDir, path.resolve(destDir)) || '.';
  execFileSync('tar', ['xzf', tgzName, '-C', relDest, '--no-same-owner'], { cwd: tgzDir, timeout: 60_000, stdio: 'pipe' });
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
 * Extract a ZIP archive (PyPI wheels, generic zips) to a directory.
 * adm-zip is already a runtime dependency (used by src/ioc/scraper.js).
 *
 * Two hardening layers before extraction touches disk:
 *  1. zip-slip: resolve each entry path against destDir and reject anything
 *     that escapes. path.resolve normalizes ../, mixed separators, and
 *     absolute paths in a single pass.
 *  2. size cap: sum of uncompressed entry sizes must stay below
 *     MAX_TARBALL_SIZE — defends against zip bombs that pass tarball
 *     size checks but expand into multi-GB on disk.
 */
function _extractZipImpl(zipPath, destDir) {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  const resolvedDest = path.resolve(destDir);
  let totalUncompressed = 0;
  for (const entry of entries) {
    totalUncompressed += (entry.header && entry.header.size) || 0;
    if (totalUncompressed > MAX_TARBALL_SIZE) {
      throw new Error(
        `Zip extract refused: total uncompressed size ${totalUncompressed} exceeds ${MAX_TARBALL_SIZE}`
      );
    }
    const target = path.resolve(destDir, entry.entryName);
    if (target !== resolvedDest && !target.startsWith(resolvedDest + path.sep)) {
      throw new Error(`Unsafe zip entry escapes destDir: ${entry.entryName}`);
    }
  }
  zip.extractAllTo(destDir, /* overwrite */ true);
  // Wheels carry a flat layout (no leading `package/`); collapse into the
  // single top-level dir if there is exactly one (matches sdist behavior so
  // the scanner pipeline can treat the result uniformly).
  try {
    const top = fs.readdirSync(destDir);
    if (top.length === 1) {
      const single = path.join(destDir, top[0]);
      const stat = fs.lstatSync(single);
      if (!stat.isSymbolicLink() && stat.isDirectory()) return single;
    }
  } catch { /* ignore — fall back to destDir */ }
  return destDir;
}

/**
 * Extract an archive to a directory, dispatching on file extension.
 * Supports `.tar.gz` / `.tgz` (tar) and `.whl` / `.zip` (adm-zip).
 *
 * @param {string} archivePath - Path to the archive on disk
 * @param {string} destDir - Destination directory (must exist)
 * @param {Object} [options]
 * @param {'targz'|'zip'} [options.format] - override auto-detection
 * @returns {string} Path to extracted package root
 * @throws {Error} when the format is unknown or extraction fails
 */
function extractArchive(archivePath, destDir, options = {}) {
  const format = options.format || detectArchiveFormat(archivePath);
  if (format === 'targz') return _extractTarGzImpl(archivePath, destDir);
  if (format === 'zip') return _extractZipImpl(archivePath, destDir);
  throw new Error(`Unsupported archive format for ${path.basename(archivePath)}`);
}

/**
 * Backwards-compatible wrapper for the original tar.gz-only extractor.
 * Kept because src/scanner/temporal-ast-diff.js and existing tests still
 * import it by name. New code should call extractArchive instead.
 */
function extractTarGz(tgzPath, destDir) {
  return _extractTarGzImpl(tgzPath, destDir);
}

/**
 * Sanitize a package name for use in temporary directory names.
 * Removes path traversal sequences, slashes, and @ symbols.
 * @param {string} packageName - Raw package name
 * @returns {string} Safe string for directory names
 */
function sanitizePackageName(packageName) {
  return packageName
    .normalize('NFC')
    .replace(/[^\x20-\x7E]/g, '')   // Strip non-ASCII (Unicode confusables)
    .replace(/\.\./g, '')
    .replace(/[/\\]/g, '_')          // Both slash types → _
    .replace(/[@:]/g, '')            // @ and : (Windows drive letter)
    // eslint-disable-next-line no-control-regex -- intentional control-char strip (filename safety net)
    .replace(/[\x00-\x1F]/g, '');   // Control chars (safety net)
}

module.exports = {
  downloadToFile,
  extractTarGz,
  extractArchive,
  detectArchiveFormat,
  sanitizePackageName,
  isAllowedDownloadRedirect,
  normalizeHostname,
  isPrivateIP,
  safeDnsResolve,
  ALLOWED_DOWNLOAD_DOMAINS,
  PRIVATE_IP_PATTERNS,
  MAX_REDIRECTS
};
