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
 * Evaluation random sample (architecture lot 7).
 *
 * The suspect archive only keeps tarballs scored >= 20, so a malware the monitor
 * scored under 20 is never kept and the detection rate cannot be measured. This
 * module draws a fixed fraction of ALL scanned packages, independently of the
 * score, so that the drawn set is an unbiased sample of the feed: its tarballs
 * are kept (tarball-archive.js captureForEvaluation) and the draw is written to
 * the scan ledger (evalSample: true) on every outcome. The denominator is the drawn
 * versions that were scanned, once per name@version; drawn versions whose only
 * outcome is 'dropped' or 'spilled' were never scanned and are counted apart.
 *
 * The draw is a keyed hash of ecosystem:name@version (HMAC-SHA256), so:
 *   - the same package@version gets the same answer in every thread and after a
 *     restart (the key is persisted in the data directory), so the ledger flag and
 *     the capture always agree;
 *   - a publisher cannot tell in advance whether a version will be sampled (the
 *     key is random and private to the deployment), so the sample cannot be
 *     steered around.
 *
 * Rate: MUADDIB_EVAL_SAMPLE_RATE, a fraction in [0, 1], default 0.01; 0 disables.
 * Key: MUADDIB_EVAL_SAMPLE_SALT, or the file <data dir>/eval-sample.key (created on
 * first use, mode 0600). If the file cannot be read or written, a per-process key
 * is used and the failure is logged once: the sample stays random, only its
 * stability across restarts is lost.
 */

const fs = require('fs');
const crypto = require('crypto');
const { dataPath } = require('../shared/data-dir.js');

const DEFAULT_EVAL_SAMPLE_RATE = 0.01;

function getEvalSampleRate() {
  const raw = process.env.MUADDIB_EVAL_SAMPLE_RATE;
  if (raw === undefined || raw === '') return DEFAULT_EVAL_SAMPLE_RATE;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1) return DEFAULT_EVAL_SAMPLE_RATE;
  return n;
}

let cachedKey = null;
let cachedKeySource = null;

function loadKey() {
  const fromEnv = process.env.MUADDIB_EVAL_SAMPLE_SALT;
  if (typeof fromEnv === 'string' && fromEnv !== '') {
    if (cachedKeySource !== 'env:' + fromEnv) {
      cachedKey = Buffer.from(fromEnv, 'utf8');
      cachedKeySource = 'env:' + fromEnv;
    }
    return cachedKey;
  }
  const file = dataPath('eval-sample.key');
  if (cachedKey && cachedKeySource === 'file:' + file) return cachedKey;
  try {
    let hex;
    try {
      hex = fs.readFileSync(file, 'utf8').trim();
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      const fresh = crypto.randomBytes(32).toString('hex');
      try {
        fs.writeFileSync(file, fresh + '\n', { flag: 'wx', mode: 0o600 });
        hex = fresh;
      } catch (werr) {
        // Another thread or process created it first: use theirs.
        if (werr.code !== 'EEXIST') throw werr;
        hex = fs.readFileSync(file, 'utf8').trim();
      }
    }
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('malformed key file');
    cachedKey = Buffer.from(hex, 'hex');
    cachedKeySource = 'file:' + file;
  } catch (err) {
    if (cachedKeySource !== 'process') {
      console.warn(`[EvalSample] key file ${file} unusable (${err.message}); using a per-process key, the sample is not stable across restarts`);
      cachedKey = crypto.randomBytes(32);
      cachedKeySource = 'process';
    }
  }
  return cachedKey;
}

/**
 * Is this package version part of the evaluation random sample?
 * Never throws.
 *
 * @param {string|null} ecosystem
 * @param {string} name
 * @param {string} version
 * @returns {boolean}
 */
function isEvalRandomSample(ecosystem, name, version) {
  return keyedDraw('', getEvalSampleRate(), ecosystem, name, version);
}

// Keyed draw in [0, 1) compared to rate. The label separates independent draws made
// with the same key (the random sample uses the empty label, unchanged since its
// introduction, so the ledger flag stays comparable across versions).
function keyedDraw(label, rate, ecosystem, name, version) {
  try {
    if (!name || !version) return false;
    if (rate <= 0) return false;
    if (rate >= 1) return true;
    const mac = crypto.createHmac('sha256', loadKey())
      .update(`${label}${ecosystem || ''}:${name}@${version}`)
      .digest();
    return mac.readUInt32BE(0) / 0x100000000 < rate;
  } catch {
    return false;
  }
}

/**
 * Near-miss draw (score 1 to floor-1). Near misses arrive at about 9 GB of tarballs a
 * day in production, so keeping the first ones until the daily byte budget runs out
 * kept only the first hours of each day (budget reached at 05:27 Paris time on
 * 2026-11-17). A keyed draw at a fixed rate spreads the kept near misses over the
 * whole day; the byte budget stays as a safety net.
 *
 * Rate: MUADDIB_EVAL_NEAR_MISS_RATE, a fraction in [0, 1], default 0.2; same key as the
 * random sample, independent draw (different label). Never throws.
 */
const DEFAULT_EVAL_NEAR_MISS_RATE = 0.2;

function getEvalNearMissRate() {
  const raw = process.env.MUADDIB_EVAL_NEAR_MISS_RATE;
  if (raw === undefined || raw === '') return DEFAULT_EVAL_NEAR_MISS_RATE;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1) return DEFAULT_EVAL_NEAR_MISS_RATE;
  return n;
}

function isEvalNearMissSample(ecosystem, name, version) {
  return keyedDraw('near_miss|', getEvalNearMissRate(), ecosystem, name, version);
}

function _resetKeyCacheForTests() {
  cachedKey = null;
  cachedKeySource = null;
}

module.exports = {
  isEvalRandomSample,
  getEvalSampleRate,
  DEFAULT_EVAL_SAMPLE_RATE,
  isEvalNearMissSample,
  getEvalNearMissRate,
  DEFAULT_EVAL_NEAR_MISS_RATE,
  _resetKeyCacheForTests
};
