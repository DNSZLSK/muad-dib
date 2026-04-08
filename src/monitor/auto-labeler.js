'use strict';

/**
 * Auto-labeler — registry takedown-based ML training label correction.
 *
 * Verifies packages in the JSONL training dataset against npm/PyPI registries:
 * - npm `0.0.1-security` replacement → confirmed_malicious (npm Security takedown)
 * - HTTP 404 + high score → confirmed_malicious (removed, high conviction)
 * - HTTP 404 + low score → removed_unlabeled (removed, unknown intent)
 * - Alive > 30 days + low score → confirmed_benign (survival heuristic)
 * - Alive > 30 days + moderate score → likely_benign
 *
 * Never modifies the input JSONL — writes a new file.
 * Reuses the shared HTTP semaphore to avoid starving monitor scans.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { acquireRegistrySlot, releaseRegistrySlot } = require('../shared/http-limiter.js');
const { atomicWriteFileSync } = require('./state.js');

const DEFAULT_INPUT = path.join(__dirname, '..', '..', 'data', 'ml-training.jsonl');
const DEFAULT_OUTPUT = path.join(__dirname, '..', '..', 'data', 'ml-training-relabeled.jsonl');
const DEFAULT_DELAY_MS = 200; // 5 req/s max — gentle on registries
const SURVIVAL_DAYS = 30;

// Labels eligible for auto-relabeling
const RELABELABLE = new Set(['suspect', 'ml_clean', 'unconfirmed', 'clean']);

// --- HTTP helper (minimal, avoids circular deps with ingestion.js) ---

function httpsGetJson(url, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 404) {
        res.resume();
        return resolve({ _httpStatus: 404 });
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        try {
          const body = Buffer.concat(chunks).toString('utf8');
          resolve(JSON.parse(body));
        } catch (err) {
          reject(new Error(`JSON parse error for ${url}: ${err.message}`));
        }
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout for ${url}`));
    });
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Registry status checks ---

/**
 * Check npm registry status for a package.
 * @param {string} name - package name
 * @returns {Promise<{status: string, latestVersion?: string, detail?: string}>}
 */
async function checkNpmStatus(name) {
  await acquireRegistrySlot();
  try {
    const data = await httpsGetJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);

    if (data._httpStatus === 404) {
      return { status: 'removed' };
    }

    const latest = data['dist-tags'] && data['dist-tags'].latest;
    if (latest === '0.0.1-security') {
      return { status: 'security_takedown', latestVersion: latest };
    }

    return { status: 'alive', latestVersion: latest || 'unknown' };
  } catch (err) {
    return { status: 'error', detail: err.message };
  } finally {
    releaseRegistrySlot();
  }
}

/**
 * Check PyPI registry status for a package.
 * @param {string} name - package name
 * @returns {Promise<{status: string, detail?: string}>}
 */
async function checkPyPIStatus(name) {
  try {
    const data = await httpsGetJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);

    if (data._httpStatus === 404) {
      return { status: 'removed' };
    }

    return { status: 'alive' };
  } catch (err) {
    return { status: 'error', detail: err.message };
  }
}

// --- Label computation ---

/**
 * Compute the new label for a record based on registry status.
 *
 * Guards:
 * - security_takedown → always confirmed_malicious
 * - removed + score >= 50 → confirmed_malicious (high conviction)
 * - removed + score < 50 → removed_unlabeled (don't train on uncertain data)
 * - alive + age >= 30d + score < 20 → confirmed_benign
 * - alive + age >= 30d + score 20-34 → likely_benign
 * - alive + age >= 30d + score >= 35 → no change (sleeper risk)
 * - alive + age < 30d → no change (too early)
 *
 * @param {Object} record - JSONL training record (must have: score, timestamp, label)
 * @param {{status: string}} registryStatus - from checkNpmStatus/checkPyPIStatus
 * @returns {{label: string, source: string} | null} new label or null if no change
 */
function computeNewLabel(record, registryStatus) {
  const { status } = registryStatus;
  const score = record.score || 0;

  // Already confirmed — don't re-label
  if (record.label === 'confirmed_malicious' || record.label === 'confirmed_benign' ||
      record.label === 'fp' || record.label === 'confirmed') {
    return null;
  }

  // --- Takedown signals ---
  if (status === 'security_takedown') {
    return { label: 'confirmed_malicious', source: 'npm_security_takedown' };
  }

  if (status === 'removed') {
    if (score >= 50) {
      return { label: 'confirmed_malicious', source: 'registry_removed_high_score' };
    }
    return { label: 'removed_unlabeled', source: 'registry_removed_low_score' };
  }

  // --- Survival signals ---
  if (status === 'alive') {
    const recordAge = record.timestamp
      ? (Date.now() - new Date(record.timestamp).getTime()) / (1000 * 60 * 60 * 24)
      : 0;

    if (recordAge >= SURVIVAL_DAYS) {
      if (score < 20) {
        return { label: 'confirmed_benign', source: 'survival_30d' };
      }
      if (score >= 20 && score < 35) {
        return { label: 'likely_benign', source: 'survival_30d_moderate' };
      }
      // score >= 35: no change (sleeper risk)
    }
  }

  return null;
}

// --- Dataset relabeling ---

/**
 * Read JSONL, check each unique package against registries, write relabeled output.
 *
 * @param {Object} [options]
 * @param {string} [options.input] - input JSONL path
 * @param {string} [options.output] - output JSONL path
 * @param {boolean} [options.dryRun] - log changes without writing
 * @param {number} [options.delayMs] - ms between registry requests
 * @returns {Promise<Object>} summary stats
 */
async function relabelDataset(options = {}) {
  const inputPath = options.input || DEFAULT_INPUT;
  const outputPath = options.output || DEFAULT_OUTPUT;
  const dryRun = options.dryRun || false;
  const delayMs = options.delayMs != null ? options.delayMs : DEFAULT_DELAY_MS;

  // 1. Read records
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Input file not found: ${inputPath}`);
  }
  const content = fs.readFileSync(inputPath, 'utf8');
  const lines = content.split('\n');
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      records.push({ idx: i, data: JSON.parse(line), raw: lines[i] });
    } catch {
      records.push({ idx: i, data: null, raw: lines[i] });
    }
  }

  // 2. Extract unique packages eligible for relabeling
  const packageMap = new Map(); // key → { name, ecosystem, score, timestamp, indices[] }
  for (const rec of records) {
    if (!rec.data) continue;
    if (!RELABELABLE.has(rec.data.label)) continue;
    const key = `${rec.data.ecosystem || 'npm'}/${rec.data.name}`;
    if (!packageMap.has(key)) {
      packageMap.set(key, {
        name: rec.data.name,
        ecosystem: rec.data.ecosystem || 'npm',
        score: rec.data.score || 0,
        timestamp: rec.data.timestamp,
        indices: []
      });
    }
    packageMap.get(key).indices.push(rec.idx);
    // Use highest score seen for this package
    if ((rec.data.score || 0) > packageMap.get(key).score) {
      packageMap.get(key).score = rec.data.score;
    }
    // Use earliest timestamp
    if (rec.data.timestamp && (!packageMap.get(key).timestamp || rec.data.timestamp < packageMap.get(key).timestamp)) {
      packageMap.get(key).timestamp = rec.data.timestamp;
    }
  }

  console.log(`[RELABEL] ${records.length} records, ${packageMap.size} unique packages to check`);

  // 3. Check each package against registry
  const summary = {
    checked: 0,
    relabeled_malicious: 0,
    relabeled_benign: 0,
    relabeled_likely_benign: 0,
    removed_unlabeled: 0,
    unchanged: 0,
    errors: 0,
    records_updated: 0
  };

  const labelChanges = new Map(); // packageKey → { label, source }

  for (const [key, pkg] of packageMap) {
    let registryStatus;
    try {
      if (pkg.ecosystem === 'npm') {
        registryStatus = await checkNpmStatus(pkg.name);
      } else if (pkg.ecosystem === 'pypi') {
        registryStatus = await checkPyPIStatus(pkg.name);
      } else {
        summary.unchanged++;
        summary.checked++;
        continue;
      }
    } catch (err) {
      summary.errors++;
      summary.checked++;
      continue;
    }

    if (registryStatus.status === 'error') {
      summary.errors++;
      summary.checked++;
      if (delayMs > 0) await sleep(delayMs);
      continue;
    }

    const newLabel = computeNewLabel(pkg, registryStatus);
    summary.checked++;

    if (newLabel) {
      labelChanges.set(key, newLabel);
      if (newLabel.label === 'confirmed_malicious') summary.relabeled_malicious++;
      else if (newLabel.label === 'confirmed_benign') summary.relabeled_benign++;
      else if (newLabel.label === 'likely_benign') summary.relabeled_likely_benign++;
      else if (newLabel.label === 'removed_unlabeled') summary.removed_unlabeled++;

      if (dryRun) {
        console.log(`[RELABEL] DRY-RUN: ${key} → ${newLabel.label} (${newLabel.source}, score=${pkg.score}, status=${registryStatus.status})`);
      }
    } else {
      summary.unchanged++;
    }

    if (delayMs > 0) await sleep(delayMs);
  }

  // 4. Apply label changes to records
  const outputLines = [];
  for (const rec of records) {
    if (!rec.data) {
      outputLines.push(rec.raw);
      continue;
    }
    const key = `${rec.data.ecosystem || 'npm'}/${rec.data.name}`;
    const change = labelChanges.get(key);
    if (change && RELABELABLE.has(rec.data.label)) {
      rec.data.label = change.label;
      rec.data.relabel_source = change.source;
      rec.data.relabel_timestamp = new Date().toISOString();
      outputLines.push(JSON.stringify(rec.data));
      summary.records_updated++;
    } else {
      outputLines.push(rec.raw);
    }
  }

  // 5. Write output
  if (!dryRun) {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    atomicWriteFileSync(outputPath, outputLines.join('\n'));
    console.log(`[RELABEL] Written ${outputLines.length} records to ${path.basename(outputPath)} (${summary.records_updated} updated)`);
  } else {
    console.log(`[RELABEL] DRY-RUN complete: ${summary.records_updated} records would be updated`);
  }

  console.log(`[RELABEL] Summary: ${summary.relabeled_malicious} malicious, ${summary.relabeled_benign} benign, ${summary.relabeled_likely_benign} likely_benign, ${summary.removed_unlabeled} removed_unlabeled, ${summary.unchanged} unchanged, ${summary.errors} errors`);

  return summary;
}

module.exports = {
  checkNpmStatus,
  checkPyPIStatus,
  computeNewLabel,
  relabelDataset,
  // Constants (for testing)
  RELABELABLE,
  SURVIVAL_DAYS,
  DEFAULT_INPUT,
  DEFAULT_OUTPUT,
  DEFAULT_DELAY_MS
};
