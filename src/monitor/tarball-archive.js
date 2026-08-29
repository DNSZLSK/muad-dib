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

// Retention window for archived tarballs. Purged at startup and every 6h thereafter.
// Bounded to [1, 365] days; non-numeric or out-of-range values fall back to 7.
// Math: ~4.5GB/day average → 7d ≈ 31GB, fits in 96GB disk with safe margin.
const DEFAULT_RETENTION_DAYS = 7;
function getRetentionDays() {
  const raw = process.env.MUADDIB_ARCHIVE_RETENTION_DAYS;
  if (raw === undefined || raw === '') return DEFAULT_RETENTION_DAYS;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1 || n > 365) return DEFAULT_RETENTION_DAYS;
  return n;
}

// Defensive disk-space gate. Skip archiving when free space falls below threshold,
// so a burst of suspects can't run the volume to 100% between periodic cleanups.
// Bounded to [1, 100] GB, default 5GB.
const DEFAULT_MIN_FREE_GB = 5;
function getMinFreeBytes() {
  const raw = process.env.MUADDIB_ARCHIVE_MIN_FREE_GB;
  let gb = DEFAULT_MIN_FREE_GB;
  if (raw !== undefined && raw !== '') {
    const n = parseInt(raw, 10);
    if (Number.isFinite(n) && n >= 1 && n <= 100) gb = n;
  }
  return gb * 1024 * 1024 * 1024;
}

// Tarball download is gated on this score so the heavy .tgz is kept ONLY for
// alert-threshold packages; the cheap JSON metadata is still written for every
// suspect. Aligns with the webhook alert floor (20). Bounded to [0, 100], default 20.
const DEFAULT_TGZ_MIN_SCORE = 20;
function getArchiveTgzMinScore() {
  const raw = process.env.MUADDIB_ARCHIVE_TGZ_MIN_SCORE;
  if (raw === undefined || raw === '') return DEFAULT_TGZ_MIN_SCORE;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0 || n > 100) return DEFAULT_TGZ_MIN_SCORE;
  return n;
}

function hasEnoughSpace(targetDir) {
  try {
    if (typeof fs.statfsSync !== 'function') return true; // Node <18.15 — fail-open
    const dirForStat = fs.existsSync(targetDir) ? targetDir : path.dirname(targetDir);
    const s = fs.statfsSync(dirForStat);
    return s.bavail * s.bsize > getMinFreeBytes();
  } catch {
    return true; // never block archiving on a stat error
  }
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
  // numeric score of 0 with no triggered rules is unambiguously CLEAN.
  const score = (scanResult && typeof scanResult.score === 'number') ? scanResult.score : 0;
  const rules = (scanResult && Array.isArray(scanResult.rulesTriggered)) ? scanResult.rulesTriggered : [];
  if (score === 0 && rules.length === 0) {
    return false;
  }

  // Tarballs dominate archive volume (~439MB/day of .tgz vs ~3.6MB/day of JSON).
  // Keep the cheap JSON metadata for EVERY suspect (audit trail + GT-promotion index),
  // but download/retain the heavy .tgz ONLY for packages at/above the alert threshold
  // (score >= MUADDIB_ARCHIVE_TGZ_MIN_SCORE, default 20 = webhook floor). This shrinks
  // the archive from tens of GB to hundreds of MB without losing the record of what was seen.
  const keepTarball = score >= getArchiveTgzMinScore();

  const dateStr = getArchiveDateString();
  const dayDir = path.join(ARCHIVE_DIR, dateStr);
  const safeName = sanitizeForFilename(packageName);
  const basename = `${safeName}-${version}`;
  const tgzPath = path.join(dayDir, `${basename}.tgz`);
  const jsonPath = path.join(dayDir, `${basename}.json`);

  // At/above the alert threshold: archive the full .tgz (existing behavior, unchanged).
  // Below it: keep only the cheap JSON metadata (audit trail + GT-promotion index).
  if (keepTarball) {
    // Dedup: skip if already archived
    if (fs.existsSync(tgzPath)) {
      return false;
    }

    // Disk-space gate: don't let a burst of suspects run the volume to 100% between
    // the periodic cleanups. Guards the heavy .tgz download.
    if (!hasEnoughSpace(ARCHIVE_DIR)) {
      console.warn(`[Archive] Skip ${packageName}@${version}: free space below ${DEFAULT_MIN_FREE_GB}GB threshold`);
      return false;
    }

    // Ensure day directory exists
    fs.mkdirSync(dayDir, { recursive: true });

    // Download with semaphore (shares concurrency with rest of pipeline). Download
    // errors propagate to the fire-and-forget .catch() in the caller (queue.js).
    await acquireRegistrySlot();
    try {
      await downloadToFile(tarballUrl, tgzPath, ARCHIVE_TIMEOUT_MS);
    } finally {
      releaseRegistrySlot();
    }

    const tarballSha256 = sha256File(tgzPath);
    const metadata = {
      package: packageName,
      version,
      timestamp: new Date().toISOString(),
      score: scanResult.score || 0,
      priority: scanResult.priority || null,
      rules_triggered: scanResult.rulesTriggered || [],
      llm_verdict: scanResult.llmVerdict || null,
      tarball_archived: true,
      tarball_sha256: tarballSha256
    };
    fs.writeFileSync(jsonPath, JSON.stringify(metadata, null, 2));
    return true;
  }

  // Below the alert threshold — record cheap JSON metadata only, skip the tarball.
  // Dedup on the JSON record so re-scans of the same package@version don't rewrite it.
  if (fs.existsSync(jsonPath)) {
    return false;
  }
  fs.mkdirSync(dayDir, { recursive: true });
  const metadata = {
    package: packageName,
    version,
    timestamp: new Date().toISOString(),
    score: scanResult.score || 0,
    priority: scanResult.priority || null,
    rules_triggered: scanResult.rulesTriggered || [],
    llm_verdict: scanResult.llmVerdict || null,
    tarball_archived: false,
    tarball_sha256: null
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

// Hard ceiling: even UN-PULLED captures are dropped past this age, so a PC that
// stays off for weeks cannot fill the archive volume forever (bounded resources).
// Must be >= the soft retention window. Bounded to [soft, 3650] days, default 30.
const DEFAULT_MAX_RETENTION_DAYS = 30;
function getMaxRetentionDays() {
  const soft = getRetentionDays();
  const raw = process.env.MUADDIB_ARCHIVE_MAX_RETENTION_DAYS;
  const fallback = Math.max(DEFAULT_MAX_RETENTION_DAYS, soft);
  if (raw === undefined || raw === '') return fallback;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < soft || n > 3650) return fallback;
  return n;
}

// A day-dir is "pulled" once the workstation's rsync step has confirmed it holds
// an intact copy (hash-verified) and dropped a `.pulled` sentinel. Only then is
// the day's irreplaceable .tgz safe to purge on the soft timer.
function dayDirIsPulled(fullPath) {
  try { return fs.existsSync(path.join(fullPath, '.pulled')); } catch { return false; }
}

// Does the day-dir hold any irreplaceable tarball? (JSON-only days are benign
// metadata — re-derivable, safe to purge on the timer.)
function dayDirHasTarball(fullPath) {
  try { return fs.readdirSync(fullPath).some(f => f.endsWith('.tgz')); } catch { return false; }
}

function _dirBytes(fullPath) {
  let bytes = 0;
  try {
    for (const f of fs.readdirSync(fullPath)) {
      try { bytes += fs.statSync(path.join(fullPath, f)).size; } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
  return bytes;
}

/**
 * Purge archived tarballs older than the retention window — SAFELY. Runs at
 * monitor startup and every 6h so no external cron is needed.
 *
 * Safe-delete contract (the archive is the ONLY copy of malware npm has since
 * unpublished — a blind timer purge destroys irreplaceable captures):
 *   1. Aged + PULLED (workstation confirmed a hash-verified copy) → purge.
 *   2. Aged + JSON-only (no .tgz — benign metadata, re-derivable)  → purge.
 *   3. Aged + un-pulled + holds .tgz → KEEP, awaiting the PC pull, UNLESS:
 *        a. older than the HARD ceiling (getMaxRetentionDays) → purge (bounded
 *           disk wins; loud), or
 *        b. free space is below the min-free floor → purge OLDEST-first until the
 *           floor clears (losing old suspect beats a full disk that blocks
 *           capture of NEW suspect). Everything here is score>=tgz-min (benign is
 *           already JSON-only and gone in step 2), so oldest-first is the honest
 *           order.
 *
 * Stats: { kept, purged, freedBytes, retainedUnpulled, unpulledPurged }.
 * Errors are logged, never thrown.
 */
function cleanupOldArchives(retentionDays = getRetentionDays()) {
  const stats = { kept: 0, purged: 0, freedBytes: 0, retainedUnpulled: 0, unpulledPurged: 0 };
  if (!fs.existsSync(ARCHIVE_DIR)) return stats;

  const now = Date.now();
  const softCutoff = now - retentionDays * 24 * 60 * 60 * 1000;
  const hardCutoff = now - getMaxRetentionDays() * 24 * 60 * 60 * 1000;
  let entries;
  try {
    entries = fs.readdirSync(ARCHIVE_DIR, { withFileTypes: true });
  } catch (err) {
    console.warn(`[Archive] Cannot read ${ARCHIVE_DIR}: ${err.message}`);
    return stats;
  }

  const retained = []; // un-pulled aged dirs kept — candidates for disk-pressure eviction

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const date = parseArchiveDayDir(entry.name);
    if (!date) continue; // ignore unrelated subdirs
    const fullPath = path.join(ARCHIVE_DIR, entry.name);
    if (date.getTime() >= softCutoff) { stats.kept++; continue; }

    // Aged past the soft retention window.
    if (dayDirIsPulled(fullPath) || !dayDirHasTarball(fullPath)) {
      const bytes = _dirBytes(fullPath);
      if (rmDirRecursiveSafe(fullPath)) { stats.purged++; stats.freedBytes += bytes; }
      continue;
    }

    // Un-pulled AND holds irreplaceable tarballs.
    const bytes = _dirBytes(fullPath);
    if (date.getTime() < hardCutoff) {
      console.warn(`[Archive] HARD-CEILING purge of UN-PULLED ${entry.name} (~${(bytes / 1048576).toFixed(0)}MB) — older than ${getMaxRetentionDays()}d and never pulled. Irreplaceable captures LOST.`);
      if (rmDirRecursiveSafe(fullPath)) { stats.purged++; stats.unpulledPurged++; stats.freedBytes += bytes; }
      continue;
    }
    stats.retainedUnpulled++;
    retained.push({ path: fullPath, name: entry.name, date: date.getTime(), bytes });
  }

  // Disk-pressure override: reclaim oldest un-pulled first, only while below the floor.
  if (retained.length && !hasEnoughSpace(ARCHIVE_DIR)) {
    retained.sort((a, b) => a.date - b.date);
    for (const r of retained) {
      if (hasEnoughSpace(ARCHIVE_DIR)) break;
      console.warn(`[Archive] DISK-PRESSURE purge of UN-PULLED ${r.name} (~${(r.bytes / 1048576).toFixed(0)}MB) — free space below floor, reclaiming oldest suspect. LOST.`);
      if (rmDirRecursiveSafe(r.path)) { stats.purged++; stats.unpulledPurged++; stats.freedBytes += r.bytes; stats.retainedUnpulled--; }
    }
  }

  if (stats.purged > 0 || stats.retainedUnpulled > 0) {
    const mb = (stats.freedBytes / 1024 / 1024).toFixed(0);
    console.log(`[Archive] Cleanup: purged ${stats.purged} day(s) (~${mb}MB), kept ${stats.kept} recent, retained ${stats.retainedUnpulled} un-pulled aged (awaiting PC pull), un-pulled dropped ${stats.unpulledPurged}.`);
  }
  return stats;
}

/**
 * Periodically re-run cleanupOldArchives so a long-running daemon (no restarts for
 * weeks) can't accumulate archives past the retention window. Defaults to every 6h.
 * .unref()'d so the timer never keeps the event loop alive on shutdown.
 */
const DEFAULT_PERIODIC_INTERVAL_MS = 6 * 60 * 60 * 1000;
function startPeriodicCleanup(intervalMs = DEFAULT_PERIODIC_INTERVAL_MS) {
  const timer = setInterval(() => {
    try {
      cleanupOldArchives();
    } catch (err) {
      console.warn(`[Archive] Periodic cleanup failed: ${err.message}`);
    }
  }, intervalMs);
  timer.unref();
  return timer;
}

module.exports = {
  archiveSuspectTarball,
  cleanupOldArchives,
  startPeriodicCleanup,
  hasEnoughSpace,
  ARCHIVE_DIR,
  // Exported for testing
  sanitizeForFilename,
  sha256File,
  getArchiveDateString,
  getRetentionDays,
  getMaxRetentionDays,
  getMinFreeBytes,
  getArchiveTgzMinScore,
  parseArchiveDayDir,
  dayDirIsPulled,
  dayDirHasTarball
};
