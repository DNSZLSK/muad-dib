/**
 * Advanced npm registry signals for the FPR plan, Chantier 4.
 *
 * Computes four categorical signals on top of the basic metadata bundle :
 *
 *   - maintainer_change_recent   : a maintainer was added or replaced in the
 *                                  last 30 days (boost ; matches Shai-Hulud /
 *                                  Axios 2026 takeover patterns).
 *   - maintainer_change_within_days : days since the last maintainer change,
 *                                     or null if not detected.
 *   - publish_cadence_anomaly    : the latest inter-publish gap is more than
 *                                  3 sigma off the historical cadence (boost).
 *   - stable_ownership_2y        : the latest maintainer set has been the same
 *                                  for at least 2 years and the package has
 *                                  > 100 versions (suppression douce).
 *
 * These are intended to be consumed by `_factorFromMetadata` in src/scoring.js.
 * The first three are *boosts* (used as a safety net so suppressions in
 * Chantier 5 do not mask a recent account takeover). The fourth is the only
 * structural suppression and only fires on packages with substantial publish
 * history.
 *
 * Pure functions on the npm registry packument shape ; no network IO. Caller
 * passes the same `meta` object as `npm-registry.getPackageMetadata` already
 * fetches, so we never double-fetch.
 */

'use strict';

const MILLIS_PER_DAY = 24 * 60 * 60 * 1000;
const RECENT_CHANGE_DAYS = 30;
const STABLE_OWNERSHIP_DAYS = 2 * 365;
const STABLE_OWNERSHIP_MIN_VERSIONS = 100;
const CADENCE_MIN_VERSIONS = 6;
const CADENCE_SIGMA = 3;

function _daysBetween(a, b) {
  if (!(a instanceof Date) || !(b instanceof Date)) return null;
  return Math.floor((a.getTime() - b.getTime()) / MILLIS_PER_DAY);
}

function _toDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Extract maintainer names for a version object.
 * Returns a sorted lowercased array (set semantics) so two versions with the
 * same maintainers compared equal regardless of declaration order.
 */
function _maintainersFor(versionData) {
  if (!versionData) return [];
  const list = Array.isArray(versionData.maintainers) ? versionData.maintainers : [];
  const names = list
    .map(m => (m && typeof m.name === 'string') ? m.name.toLowerCase().trim() : null)
    .filter(Boolean);
  names.sort();
  return names;
}

function _equalMaintainerSets(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Order all version entries by publish time descending.
 * Returns array of { version, time: Date, maintainers: string[] }.
 */
function _orderedVersions(meta) {
  if (!meta || !meta.versions || !meta.time) return [];
  const out = [];
  for (const [version, versionData] of Object.entries(meta.versions)) {
    const t = _toDate(meta.time[version]);
    if (!t) continue;
    out.push({ version, time: t, maintainers: _maintainersFor(versionData) });
  }
  out.sort((a, b) => b.time.getTime() - a.time.getTime());
  return out;
}

/**
 * Detects whether a maintainer set changed (added or removed names) within
 * `windowDays` of the latest publish.
 *
 * Returns { changed, daysSinceChange } - daysSinceChange is null when no
 * change is detected within the window or when there is insufficient history.
 */
function detectRecentMaintainerChange(meta, windowDays = RECENT_CHANGE_DAYS) {
  const ordered = _orderedVersions(meta);
  if (ordered.length < 2) return { changed: false, daysSinceChange: null };

  const latest = ordered[0];
  if (latest.maintainers.length === 0) return { changed: false, daysSinceChange: null };

  for (let i = 1; i < ordered.length; i++) {
    const prev = ordered[i];
    const days = _daysBetween(latest.time, prev.time);
    if (days === null) continue;
    if (days > windowDays) {
      // No change within the window
      return { changed: false, daysSinceChange: null };
    }
    if (!_equalMaintainerSets(latest.maintainers, prev.maintainers)) {
      return { changed: true, daysSinceChange: days };
    }
  }
  // All within-window versions had identical maintainers
  return { changed: false, daysSinceChange: null };
}

/**
 * Detects whether the publish cadence has changed dramatically. Computes the
 * mean and stddev of historical inter-publish gaps (in days), then flags an
 * anomaly when the latest gap is more than `sigma` standard deviations from
 * the mean.
 *
 * Returns { anomaly, latestGapDays, meanGapDays, sigmaCount }.
 * Insufficient history (< CADENCE_MIN_VERSIONS) -> anomaly=false.
 */
function detectPublishCadenceAnomaly(meta, sigma = CADENCE_SIGMA) {
  const ordered = _orderedVersions(meta);
  if (ordered.length < CADENCE_MIN_VERSIONS) {
    return { anomaly: false, latestGapDays: null, meanGapDays: null, sigmaCount: null };
  }

  const gaps = [];
  for (let i = 0; i < ordered.length - 1; i++) {
    const days = _daysBetween(ordered[i].time, ordered[i + 1].time);
    if (days !== null && days >= 0) gaps.push(days);
  }
  if (gaps.length < CADENCE_MIN_VERSIONS - 1) {
    return { anomaly: false, latestGapDays: null, meanGapDays: null, sigmaCount: null };
  }

  const latestGap = gaps[0];
  const historical = gaps.slice(1); // exclude latest from the baseline
  const mean = historical.reduce((s, x) => s + x, 0) / historical.length;
  const variance = historical.reduce((s, x) => s + (x - mean) * (x - mean), 0) / historical.length;
  const stddev = Math.sqrt(variance);
  if (stddev === 0) {
    return { anomaly: false, latestGapDays: latestGap, meanGapDays: mean, sigmaCount: 0 };
  }
  const sigmaCount = Math.abs(latestGap - mean) / stddev;
  return {
    anomaly: sigmaCount > sigma,
    latestGapDays: latestGap,
    meanGapDays: mean,
    sigmaCount
  };
}

/**
 * Detects whether the package has stable ownership for >= 2 years and > 100
 * versions. This is the only structural suppression introduced in Chantier 4 -
 * paired with C5's mature stable cap, it lets us cap mature, well-owned
 * packages at MEDIUM while still surfacing maintainer change boosts above.
 */
function detectStableOwnership(meta, minDays = STABLE_OWNERSHIP_DAYS, minVersions = STABLE_OWNERSHIP_MIN_VERSIONS) {
  const ordered = _orderedVersions(meta);
  if (ordered.length < minVersions) return { stable: false, sinceDays: null };

  const latest = ordered[0];
  if (latest.maintainers.length === 0) return { stable: false, sinceDays: null };

  // Walk backwards until we find a version whose maintainer set differs
  // OR we exhaust history. Stable if the same set persists for >= minDays.
  let oldestSameSet = latest;
  for (let i = 1; i < ordered.length; i++) {
    if (_equalMaintainerSets(latest.maintainers, ordered[i].maintainers)) {
      oldestSameSet = ordered[i];
      continue;
    }
    break;
  }
  const sinceDays = _daysBetween(latest.time, oldestSameSet.time);
  return {
    stable: sinceDays !== null && sinceDays >= minDays,
    sinceDays
  };
}

/**
 * Computes the four advanced signals from a registry packument and returns
 * a flat object suitable for merging into the basic metadata bundle.
 */
function computeAdvancedRegistrySignals(meta) {
  const change = detectRecentMaintainerChange(meta);
  const cadence = detectPublishCadenceAnomaly(meta);
  const stable = detectStableOwnership(meta);
  return {
    maintainer_change_recent: change.changed,
    maintainer_change_within_days: change.daysSinceChange,
    publish_cadence_anomaly: cadence.anomaly,
    publish_cadence_sigma: cadence.sigmaCount,
    stable_ownership_2y: stable.stable,
    stable_ownership_since_days: stable.sinceDays
  };
}

module.exports = {
  computeAdvancedRegistrySignals,
  detectRecentMaintainerChange,
  detectPublishCadenceAnomaly,
  detectStableOwnership,
  RECENT_CHANGE_DAYS,
  STABLE_OWNERSHIP_DAYS,
  STABLE_OWNERSHIP_MIN_VERSIONS,
  CADENCE_MIN_VERSIONS,
  CADENCE_SIGMA
};
