'use strict';

/**
 * Tarball archiving for suspect packages.
 *
 * Downloads and stores tarballs + metadata JSON for packages flagged as suspect,
 * enabling retrospective audit when npm/PyPI unpublish the package.
 *
 * Fire-and-forget: never blocks the scan pipeline.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');
const { downloadToFile } = require('../shared/download.js');

// Archive root — configurable via env for testing
const ARCHIVE_DIR = process.env.MUADDIB_ARCHIVE_DIR || '/opt/muaddib/archive';
const ARCHIVE_TIMEOUT_MS = 10_000;

/**
 * Get the date string in YYYY-MM-DD format (Paris timezone, consistent with monitor).
 * Falls back to UTC if Intl is unavailable.
 */
function getArchiveDateString() {
  try {
    const now = new Date();
    const parts = new Intl.DateTimeFormat('fr-CA', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(now);
    const y = parts.find(p => p.type === 'year').value;
    const m = parts.find(p => p.type === 'month').value;
    const d = parts.find(p => p.type === 'day').value;
    return `${y}-${m}-${d}`;
  } catch {
    return new Date().toISOString().slice(0, 10);
  }
}

/**
 * Sanitize package name for use in filenames.
 * Replaces / (scoped packages) with __ and removes unsafe characters.
 */
function sanitizeForFilename(name) {
  return name.replace(/^@/, '').replace(/\//g, '__').replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * Compute SHA-256 hash of a file.
 */
function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest('hex');
}

/**
 * Archive a suspect package tarball and its scan metadata.
 *
 * @param {string} packageName - Package name (e.g. "evil-pkg" or "@scope/evil-pkg")
 * @param {string} version - Package version
 * @param {string} tarballUrl - Registry URL to download the tarball from
 * @param {object} scanResult - Scan result object from the pipeline
 * @param {number} scanResult.score - Risk score
 * @param {string} scanResult.priority - Priority tier (e.g. "P1", "P2")
 * @param {Array} [scanResult.rulesTriggered] - Array of triggered rule IDs
 * @param {string} [scanResult.llmVerdict] - LLM detective verdict if available
 * @returns {Promise<boolean>} true if archived, false if skipped/failed
 */
async function archiveSuspectTarball(packageName, version, tarballUrl, scanResult) {
  if (!tarballUrl || !packageName || !version) return false;

  const dateStr = getArchiveDateString();
  const dayDir = path.join(ARCHIVE_DIR, dateStr);
  const safeName = sanitizeForFilename(packageName);
  const basename = `${safeName}-${version}`;
  const tgzPath = path.join(dayDir, `${basename}.tgz`);
  const jsonPath = path.join(dayDir, `${basename}.json`);

  // Dedup: skip if already archived
  if (fs.existsSync(tgzPath)) {
    return false;
  }

  // Ensure day directory exists
  fs.mkdirSync(dayDir, { recursive: true });

  // Download with semaphore (shares concurrency with rest of pipeline)
  await acquireRegistrySlot();
  try {
    await downloadToFile(tarballUrl, tgzPath, ARCHIVE_TIMEOUT_MS);
  } finally {
    releaseRegistrySlot();
  }

  // Compute hash and write metadata
  const tarballSha256 = sha256File(tgzPath);
  const metadata = {
    package: packageName,
    version,
    timestamp: new Date().toISOString(),
    score: scanResult.score || 0,
    priority: scanResult.priority || null,
    rules_triggered: scanResult.rulesTriggered || [],
    llm_verdict: scanResult.llmVerdict || null,
    tarball_sha256: tarballSha256
  };

  fs.writeFileSync(jsonPath, JSON.stringify(metadata, null, 2));
  return true;
}

module.exports = {
  archiveSuspectTarball,
  ARCHIVE_DIR,
  // Exported for testing
  sanitizeForFilename,
  sha256File,
  getArchiveDateString
};
