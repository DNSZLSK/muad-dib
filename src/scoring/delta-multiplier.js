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

/**
 * FPR plan Chantier 3 - delta-aware scanning.
 *
 * Diff-aware multiplier inspired by Aikido & Socket : compare the threat
 * signatures of the current version against the last 3 published versions.
 * A threat present in N-3..N-1 is a *stable pattern* of the package, not a
 * new attack ; downgrade to LOW (unless it's an HC type or an IOC, which
 * never decay through staleness). A threat new in N is left untouched and
 * marked deltaNew so consumers can boost its visibility.
 *
 * Caching :
 *   .muaddib-cache/version-deltas/<sha-key>.json
 *   { package, version, signatures, cachedAt }
 *   TTL 90 days, bounded at 50K entries (CLAUDE.md "bounded resources").
 *
 * The cache is read-only at scoring time : signatures are populated by the
 * monitor (or by a delta-mode CLI scan that opts-in to fetch + scan prior
 * versions). When fewer than 3 prior signatures are available the multiplier
 * is a no-op - we never risk a TPR regression on a partial baseline.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { HIGH_CONFIDENCE_MALICE_TYPES } = require('../monitor/classify.js');

// Env override so tests write to a mkdtemp instead of littering the
// production cache (unset in prod → unchanged behavior).
const CACHE_DIR = process.env.MUADDIB_DELTA_CACHE_DIR
  || path.join(process.cwd(), '.muaddib-cache', 'version-deltas');
const CACHE_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const CACHE_MAX_ENTRIES = 50000;
const MIN_PRIOR_VERSIONS_FOR_DECAY = 3;

// IOC / always-malicious types that never decay through delta. Mirrors the
// MATURE_CAP_IOC_TYPES set in scoring.js but local-scoped to make this module
// importable without circularity (scoring.js imports delta-multiplier).
const DELTA_IOC_EXEMPT = new Set([
  'ioc_match',
  'ioc_string_match',
  'known_malicious_hash',
  'known_malicious_package',
  'pypi_malicious_package',
  'shai_hulud_marker',
  'dependency_ioc_match',
  // Lifecycle additions and modifications are version-specific by definition
  'lifecycle_added_critical',
  'lifecycle_added_high',
  'lifecycle_modified',
  'trusted_new_unknown_dependency'
]);

function _safeKey(packageName, version) {
  return crypto.createHash('sha256')
    .update(`${packageName}@${version}`)
    .digest('hex')
    .slice(0, 24);
}

function _ensureCacheDir() {
  try {
    if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
    return true;
  } catch { return false; }
}

function _cachePath(packageName, version) {
  return path.join(CACHE_DIR, _safeKey(packageName, version) + '.json');
}

/**
 * Normalize a threat into a stable signature for cross-version comparison.
 * Two threats from different versions of the same package compare equal when
 * they share the same normalized signature.
 *
 *   type:file_pattern
 *
 * file_pattern is the threat.file with hex hashes (>=8 hex chars) collapsed
 * to "HEX" and semver triplets collapsed to "VER". This way a webpack chunk
 * `dist/main.a3f2b1c.js` does not look distinct from `dist/main.0d4e5f6.js`.
 */
function buildThreatSignature(threat) {
  if (!threat || typeof threat.type !== 'string') return null;
  let file = (typeof threat.file === 'string') ? threat.file : '';
  // Forward-slash normalize
  file = file.replace(/\\/g, '/');
  // Collapse hex hashes (chunk hashes, sha256 fragments)
  file = file.replace(/[a-f0-9]{8,}/gi, 'HEX');
  // Collapse semver-like triplets in the path
  file = file.replace(/\d+\.\d+\.\d+/g, 'VER');
  // Numeric run collapse (chunk numbers)
  file = file.replace(/\b\d{2,}\b/g, 'N');
  return `${threat.type}:${file}`;
}

/**
 * Compute the signature set for a list of threats, used both to populate the
 * cache after scanning a prior version and to compare the current scan
 * against the cached priors.
 */
function computeSignatures(threats) {
  const out = new Set();
  if (!Array.isArray(threats)) return out;
  for (const t of threats) {
    const sig = buildThreatSignature(t);
    if (sig) out.add(sig);
  }
  return out;
}

/**
 * Loads the cached signature set for a given package@version. Returns null
 * when the cache file is missing, expired, or unparseable.
 */
function loadCachedSignatures(packageName, version) {
  if (!packageName || !version) return null;
  const file = _cachePath(packageName, version);
  if (!fs.existsSync(file)) return null;
  try {
    const stat = fs.statSync(file);
    if (Date.now() - stat.mtimeMs > CACHE_TTL_MS) return null;
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data.package !== packageName || data.version !== version) return null;
    if (!Array.isArray(data.signatures)) return null;
    return new Set(data.signatures);
  } catch {
    return null;
  }
}

/**
 * Persists the signature set for a package@version. Append-only: a missed
 * write or crash is recoverable on next scan because we never overwrite
 * unrelated entries. Honour the entry cap so the cache cannot grow without
 * bound (CLAUDE.md "bounded resources").
 */
function saveCachedSignatures(packageName, version, signatures) {
  if (!packageName || !version) return false;
  if (!_ensureCacheDir()) return false;
  try {
    // Evict oldest entries when over cap
    const entries = fs.readdirSync(CACHE_DIR).filter(f => f.endsWith('.json'));
    if (entries.length >= CACHE_MAX_ENTRIES) {
      const stats = entries
        .map(f => {
          const p = path.join(CACHE_DIR, f);
          try { return { p, mtime: fs.statSync(p).mtimeMs }; } catch { return null; }
        })
        .filter(Boolean)
        .sort((a, b) => a.mtime - b.mtime);
      const toEvict = stats.slice(0, Math.max(1, Math.floor(CACHE_MAX_ENTRIES * 0.1)));
      for (const e of toEvict) { try { fs.unlinkSync(e.p); } catch { /* ignore */ } }
    }

    const file = _cachePath(packageName, version);
    const sigList = signatures instanceof Set ? [...signatures] : (Array.isArray(signatures) ? signatures : []);
    fs.writeFileSync(file, JSON.stringify({
      package: packageName,
      version,
      signatures: sigList,
      cachedAt: new Date().toISOString()
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Apply the delta multiplier to a result. Mutates threats in place :
 *
 *   - threat.deltaPresentInPrior : count of prior versions sharing the
 *     signature (0..priorVersionSignatures.size).
 *   - threat.deltaStable          : true when present in >= 3 priors AND
 *     not HC/IOC AND severity gets lowered to LOW.
 *   - threat.deltaNew             : true when absent from N-1 (= the most
 *     recent prior), so the threat is genuinely new in the current version.
 *
 * The riskScore on result.summary is recomputed by the caller (scoring.js)
 * via calculateRiskScore() so we don't reach into summary here.
 *
 * @param {Array} threats  The current scan's threat list.
 * @param {Map<string,Set<string>>} priorVersionSignatures  Map<version,sigs>,
 *   typically built by computePriorSignatures(). Versions should be ordered
 *   from most recent to oldest but the function does not rely on order.
 * @returns {{ downgraded:number, newThreats:number, baselineSize:number }|null}
 */
function applyDeltaMultiplier(threats, priorVersionSignatures) {
  if (!Array.isArray(threats)) return null;
  if (!priorVersionSignatures || typeof priorVersionSignatures.size !== 'number') return null;
  const baselineSize = priorVersionSignatures.size;
  if (baselineSize < MIN_PRIOR_VERSIONS_FOR_DECAY) {
    return { downgraded: 0, newThreats: 0, baselineSize };
  }

  const orderedVersions = [...priorVersionSignatures.keys()];
  const mostRecentPrior = orderedVersions[0];
  const mostRecentSigs = priorVersionSignatures.get(mostRecentPrior);

  let downgraded = 0;
  let newThreats = 0;
  for (const t of threats) {
    if (!t || typeof t !== 'object') continue;
    if (HIGH_CONFIDENCE_MALICE_TYPES.has(t.type)) continue;
    if (DELTA_IOC_EXEMPT.has(t.type)) continue;

    const sig = buildThreatSignature(t);
    if (!sig) continue;

    let presentCount = 0;
    for (const sigSet of priorVersionSignatures.values()) {
      if (sigSet.has(sig)) presentCount++;
    }
    t.deltaPresentInPrior = presentCount;

    if (mostRecentSigs && !mostRecentSigs.has(sig)) {
      t.deltaNew = true;
      newThreats++;
    }

    if (presentCount >= MIN_PRIOR_VERSIONS_FOR_DECAY) {
      // Stable pattern - downgrade severity. The reductions trail records the
      // decision so output formatters can show why the score dropped.
      if (t.severity !== 'LOW') {
        t.reductions = Array.isArray(t.reductions) ? t.reductions : [];
        t.reductions.push({ rule: 'delta_stable', from: t.severity, to: 'LOW' });
        t.severity = 'LOW';
        t.deltaStable = true;
        downgraded++;
      }
    }
  }
  return { downgraded, newThreats, baselineSize };
}

/**
 * From a raw npm packument (or anything with a `time` map keyed by version),
 * return the 3 most recently published versions strictly older than
 * currentVersion, ordered most-recent-first. Versions whose timestamp is
 * unparseable are skipped.
 */
function selectPriorVersions(packument, currentVersion, max = MIN_PRIOR_VERSIONS_FOR_DECAY) {
  if (!packument || !packument.time || typeof packument.time !== 'object') return [];
  const cur = packument.time[currentVersion];
  const cutoff = cur ? new Date(cur).getTime() : null;

  const ordered = [];
  for (const [version, ts] of Object.entries(packument.time)) {
    if (version === currentVersion) continue;
    if (version === 'created' || version === 'modified') continue;
    if (typeof ts !== 'string') continue;
    const t = new Date(ts).getTime();
    if (isNaN(t)) continue;
    if (cutoff !== null && t >= cutoff) continue;
    ordered.push({ version, t });
  }
  ordered.sort((a, b) => b.t - a.t);
  return ordered.slice(0, max).map(e => e.version);
}

/**
 * Build the priorVersionSignatures map for applyDeltaMultiplier by reading
 * the cache for each of the prior versions. Versions whose cache entry is
 * missing or expired are silently skipped so the caller still sees a useful
 * baseline as soon as the cache is partially populated.
 *
 * Returns Map<version, Set<signature>> ordered most-recent-first.
 */
function loadPriorVersionSignatures(packageName, currentVersion, packument) {
  const out = new Map();
  if (!packageName || !currentVersion || !packument) return out;
  const versions = selectPriorVersions(packument, currentVersion);
  for (const version of versions) {
    const sigs = loadCachedSignatures(packageName, version);
    if (sigs && sigs.size >= 0) out.set(version, sigs);
  }
  return out;
}

module.exports = {
  applyDeltaMultiplier,
  buildThreatSignature,
  computeSignatures,
  loadCachedSignatures,
  saveCachedSignatures,
  selectPriorVersions,
  loadPriorVersionSignatures,
  // Constants exported for tests
  CACHE_DIR,
  CACHE_TTL_MS,
  CACHE_MAX_ENTRIES,
  MIN_PRIOR_VERSIONS_FOR_DECAY,
  DELTA_IOC_EXEMPT
};
