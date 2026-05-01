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

// Retention window for archived tarballs. Anything older is purged on startup.
// Bounded to [1, 365] days; non-numeric or out-of-range values fall back to 30.
const DEFAULT_RETENTION_DAYS = 30;
function getRetentionDays() {
  const raw = process.env.MUADDIB_ARCHIVE_RETENTION_DAYS;
  if (raw === undefined || raw === '') return DEFAULT_RETENTION_DAYS;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1 || n > 365) return DEFAULT_RETENTION_DAYS;
  return n;
}

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

  // Defense-in-depth: never archive packages that are statically clean.
  // Callers in the pipeline already gate on tier 1a/1b/2 classification, but a
  // numeric score of 0 with no triggered rules is unambiguously CLEAN — those
  // dominated archive volume in production.
  const score = (scanResult && typeof scanResult.score === 'number') ? scanResult.score : 0;
  const rules = (scanResult && Array.isArray(scanResult.rulesTriggered)) ? scanResult.rulesTriggered : [];
  if (score === 0 && rules.length === 0) {
    return false;
  }

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

/**
 * Parse a YYYY-MM-DD directory name into a UTC midnight Date.
 * Returns null for malformed names (so we never delete an unrelated directory).
 */
function parseArchiveDayDir(name) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(name);
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  const date = new Date(Date.UTC(y, mo - 1, d));
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

/**
 * Recursively delete a directory, swallowing per-file errors so one bad file
 * doesn't abort the cleanup of the rest of the archive.
 */
function rmDirRecursiveSafe(dirPath) {
  try {
    fs.rmSync(dirPath, { recursive: true, force: true });
    return true;
  } catch (err) {
    console.warn(`[Archive] Failed to remove ${dirPath}: ${err.message}`);
    return false;
  }
}

/**
 * Purge archived tarballs older than the retention window. Runs at monitor
 * startup so no external cron is needed.
 *
 * Streams stats: { kept, purged, freedBytes }. Errors are logged, never thrown.
 */
function cleanupOldArchives(retentionDays = getRetentionDays()) {
  const stats = { kept: 0, purged: 0, freedBytes: 0 };
  if (!fs.existsSync(ARCHIVE_DIR)) return stats;

  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  let entries;
  try {
    entries = fs.readdirSync(ARCHIVE_DIR, { withFileTypes: true });
  } catch (err) {
    console.warn(`[Archive] Cannot read ${ARCHIVE_DIR}: ${err.message}`);
    return stats;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const date = parseArchiveDayDir(entry.name);
    if (!date) continue; // ignore unrelated subdirs
    if (date.getTime() >= cutoff) {
      stats.kept++;
      continue;
    }
    const fullPath = path.join(ARCHIVE_DIR, entry.name);
    let bytes = 0;
    try {
      for (const f of fs.readdirSync(fullPath)) {
        try { bytes += fs.statSync(path.join(fullPath, f)).size; } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    if (rmDirRecursiveSafe(fullPath)) {
      stats.purged++;
      stats.freedBytes += bytes;
    }
  }

  if (stats.purged > 0) {
    const mb = (stats.freedBytes / 1024 / 1024).toFixed(0);
    console.log(`[Archive] Purged ${stats.purged} day(s) older than ${retentionDays}d (~${mb}MB freed). Kept ${stats.kept}.`);
  }
  return stats;
}

module.exports = {
  archiveSuspectTarball,
  cleanupOldArchives,
  ARCHIVE_DIR,
  // Exported for testing
  sanitizeForFilename,
  sha256File,
  getArchiveDateString,
  getRetentionDays,
  parseArchiveDayDir
};
