'use strict';

/**
 * JSONL Writer — appends training records to data/ml-training.jsonl.
 *
 * One JSON object per line, newline-delimited (JSONL format).
 * Uses append mode for crash-safe incremental writes.
 * Auto-creates data/ directory if missing.
 *
 * File rotation: when the file exceeds MAX_JSONL_SIZE (100MB),
 * it is renamed to ml-training-{timestamp}.jsonl and a fresh file starts.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_TRAINING_FILE = path.join(__dirname, '..', '..', 'data', 'ml-training.jsonl');
let TRAINING_FILE = DEFAULT_TRAINING_FILE;
const MAX_JSONL_SIZE = 100 * 1024 * 1024; // 100MB rotation threshold

/**
 * Override the training file path (for testing).
 * @param {string} filePath - new file path
 */
function setTrainingFile(filePath) {
  TRAINING_FILE = filePath;
}

/**
 * Reset the training file path to the default.
 */
function resetTrainingFile() {
  TRAINING_FILE = DEFAULT_TRAINING_FILE;
}

/**
 * Append a single record to the JSONL training file.
 * @param {Object} record - training record from buildTrainingRecord()
 */
function appendRecord(record) {
  try {
    const dir = path.dirname(TRAINING_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Rotate if file is too large
    maybeRotate();

    const line = JSON.stringify(record) + '\n';
    fs.appendFileSync(TRAINING_FILE, line, 'utf8');
  } catch (err) {
    // Non-fatal: JSONL export failure should never crash the monitor
    if (err.code === 'EROFS' || err.code === 'EACCES' || err.code === 'EPERM') {
      // Read-only filesystem — silently skip (same pattern as atomicWriteFileSync)
      return;
    }
    console.error(`[ML] Failed to append JSONL record: ${err.message}`);
  }
}

/**
 * Rotate the JSONL file if it exceeds MAX_JSONL_SIZE.
 * Renames to ml-training-{ISO timestamp}.jsonl.
 */
function maybeRotate() {
  try {
    if (!fs.existsSync(TRAINING_FILE)) return;
    const stat = fs.statSync(TRAINING_FILE);
    if (stat.size < MAX_JSONL_SIZE) return;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const rotatedName = TRAINING_FILE.replace('.jsonl', `-${timestamp}.jsonl`);
    fs.renameSync(TRAINING_FILE, rotatedName);
    console.log(`[ML] Rotated training file → ${path.basename(rotatedName)} (${(stat.size / 1024 / 1024).toFixed(1)}MB)`);
  } catch (err) {
    console.error(`[ML] Rotation failed: ${err.message}`);
  }
}

/**
 * Read all records from the current JSONL file.
 * Useful for offline analysis and model training.
 * @returns {Object[]} array of parsed records
 */
function readRecords() {
  try {
    if (!fs.existsSync(TRAINING_FILE)) return [];
    const content = fs.readFileSync(TRAINING_FILE, 'utf8');
    return content
      .split('\n')
      .filter(line => line.trim())
      .map((line, i) => {
        try {
          return JSON.parse(line);
        } catch {
          console.warn(`[ML] Skipping malformed JSONL line ${i + 1}`);
          return null;
        }
      })
      .filter(Boolean);
  } catch (err) {
    console.error(`[ML] Failed to read JSONL: ${err.message}`);
    return [];
  }
}

/**
 * Get stats about the current JSONL file.
 * @returns {{ recordCount: number, fileSizeBytes: number, fileSizeMB: string }}
 */
function getStats() {
  try {
    if (!fs.existsSync(TRAINING_FILE)) {
      return { recordCount: 0, fileSizeBytes: 0, fileSizeMB: '0.0' };
    }
    const stat = fs.statSync(TRAINING_FILE);
    // Count lines without reading the entire file into memory
    const content = fs.readFileSync(TRAINING_FILE, 'utf8');
    const lineCount = content.split('\n').filter(l => l.trim()).length;
    return {
      recordCount: lineCount,
      fileSizeBytes: stat.size,
      fileSizeMB: (stat.size / 1024 / 1024).toFixed(1)
    };
  } catch {
    return { recordCount: 0, fileSizeBytes: 0, fileSizeMB: '0.0' };
  }
}

// Valid labels for ML training records
const VALID_LABELS = new Set(['fp', 'confirmed', 'unconfirmed']);

/**
 * Update the label of records matching a given package name.
 * Used when manual confirmation (fp/confirmed) is applied retroactively.
 *
 * @param {string} packageName - package name to relabel
 * @param {string} newLabel - 'fp', 'confirmed', or 'unconfirmed'
 * @param {number} [sandboxFindingCount] - number of sandbox findings (defense-in-depth for 'confirmed')
 * @param {boolean} [manualReview] - required for 'fp' label (prevents automated contamination)
 * @returns {number} number of records updated
 */
function relabelRecords(packageName, newLabel, sandboxFindingCount, manualReview) {
  // Validate label
  if (!VALID_LABELS.has(newLabel)) {
    console.warn(`[ML] BLOCKED relabel to '${newLabel}' for ${packageName}: invalid label (valid: ${[...VALID_LABELS].join(', ')})`);
    return 0;
  }

  // Defense-in-depth: 'fp' requires explicit manual review flag to prevent
  // automated sandbox-clean → fp contamination (8176 records in 3 months)
  if (newLabel === 'fp' && manualReview !== true) {
    console.warn(`[ML] BLOCKED relabel to 'fp' for ${packageName}: manualReview required (use 'unconfirmed' for automated relabeling)`);
    return 0;
  }

  // Defense-in-depth: never write 'confirmed' without real sandbox findings
  if (newLabel === 'confirmed' && (!sandboxFindingCount || sandboxFindingCount === 0)) {
    console.warn(`[ML] BLOCKED relabel to 'confirmed' for ${packageName}: sandbox_finding_count=${sandboxFindingCount || 0}`);
    return 0;
  }
  try {
    if (!fs.existsSync(TRAINING_FILE)) return 0;
    const content = fs.readFileSync(TRAINING_FILE, 'utf8');
    const lines = content.split('\n');
    let updated = 0;
    const newLines = lines.map(line => {
      if (!line.trim()) return line;
      try {
        const record = JSON.parse(line);
        if (record.name === packageName && record.label !== newLabel) {
          record.label = newLabel;
          updated++;
          return JSON.stringify(record);
        }
        return line;
      } catch {
        return line;
      }
    });

    if (updated > 0) {
      fs.writeFileSync(TRAINING_FILE, newLines.join('\n'), 'utf8');
      console.log(`[ML] Relabeled ${updated} records for ${packageName} → ${newLabel}`);
    }
    return updated;
  } catch (err) {
    console.error(`[ML] Failed to relabel records: ${err.message}`);
    return 0;
  }
}

module.exports = {
  appendRecord,
  readRecords,
  getStats,
  relabelRecords,
  maybeRotate,
  get TRAINING_FILE() { return TRAINING_FILE; },
  setTrainingFile,
  resetTrainingFile,
  MAX_JSONL_SIZE
};
