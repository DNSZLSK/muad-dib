const { fetchPackageMetadata } = require('../temporal-analysis.js');

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const MS_PER_HOUR = 60 * 60 * 1000;
const BURST_WINDOW_MS = 24 * MS_PER_HOUR;      // 24h
const BURST_MIN_VERSIONS = 3;
const RAPID_WINDOW_MS = MS_PER_HOUR;            // 1h
const RAPID_MIN_VERSIONS = 2;
const DORMANT_THRESHOLD_MS = 180 * MS_PER_DAY;  // 6 months
const MIN_VERSIONS_FOR_ANALYSIS = 3;

/**
 * Analyze the publish frequency of an npm package.
 * @param {object} metadata - Full registry metadata from fetchPackageMetadata()
 * @returns {{ totalVersions: number, avgIntervalDays: number, stdDevDays: number, lastPublishedAt: string|null, publishHistory: Array<{version: string, date: string}> }}
 */
function analyzePublishFrequency(metadata) {
  const time = metadata && metadata.time;
  if (!time || typeof time !== 'object') {
    return {
      totalVersions: 0,
      avgIntervalDays: 0,
      stdDevDays: 0,
      lastPublishedAt: null,
      publishHistory: []
    };
  }

  const versions = metadata.versions || {};
  const entries = [];
  for (const [version, publishedAt] of Object.entries(time)) {
    if (version === 'created' || version === 'modified') continue;
    if (!versions[version]) continue;
    entries.push({ version, date: publishedAt });
  }

  // Sort chronologically (oldest first)
  entries.sort((a, b) => new Date(a.date) - new Date(b.date));

  if (entries.length === 0) {
    return {
      totalVersions: 0,
      avgIntervalDays: 0,
      stdDevDays: 0,
      lastPublishedAt: null,
      publishHistory: []
    };
  }

  // Calculate intervals between consecutive publications
  const intervals = [];
  for (let i = 1; i < entries.length; i++) {
    const diffMs = new Date(entries[i].date) - new Date(entries[i - 1].date);
    intervals.push(diffMs / MS_PER_DAY);
  }

  let avgIntervalDays = 0;
  let stdDevDays = 0;

  if (intervals.length > 0) {
    avgIntervalDays = intervals.reduce((sum, d) => sum + d, 0) / intervals.length;

    const variance = intervals.reduce((sum, d) => sum + (d - avgIntervalDays) ** 2, 0) / intervals.length;
    stdDevDays = Math.sqrt(variance);
  }

  return {
    totalVersions: entries.length,
    avgIntervalDays: Math.round(avgIntervalDays * 100) / 100,
    stdDevDays: Math.round(stdDevDays * 100) / 100,
    lastPublishedAt: entries[entries.length - 1].date,
    publishHistory: entries
  };
}

/**
 * Detect publish frequency anomalies for an npm package.
 * @param {string} packageName - npm package name
 * @returns {Promise<object>} Detection result with suspicious flag, findings, and stats
 */
async function detectPublishAnomaly(packageName) {
  let metadata;
  try {
    metadata = await fetchPackageMetadata(packageName);
  } catch {
    return {
      packageName,
      suspicious: false,
      anomalies: [],
      stats: { totalVersions: 0, avgIntervalDays: 0, stdDevDays: 0, lastPublishedAt: null, publishHistory: [] }
    };
  }

  if (!metadata || !metadata.time || !metadata.versions) {
    return {
      packageName,
      suspicious: false,
      anomalies: [],
      stats: { totalVersions: 0, avgIntervalDays: 0, stdDevDays: 0, lastPublishedAt: null, publishHistory: [] }
    };
  }

  const stats = analyzePublishFrequency(metadata);

  if (stats.totalVersions < MIN_VERSIONS_FOR_ANALYSIS) {
    return {
      packageName,
      suspicious: false,
      anomalies: [],
      stats
    };
  }

  const findings = [];
  const history = stats.publishHistory;

  // --- BURST: 3+ versions published within a 24h window ---
  for (let i = 0; i < history.length; i++) {
    const windowStart = new Date(history[i].date).getTime();
    const windowEnd = windowStart + BURST_WINDOW_MS;
    const inWindow = [];
    for (let j = i; j < history.length; j++) {
      const t = new Date(history[j].date).getTime();
      if (t <= windowEnd) {
        inWindow.push(history[j]);
      } else {
        break;
      }
    }
    if (inWindow.length >= BURST_MIN_VERSIONS) {
      const spanMs = new Date(inWindow[inWindow.length - 1].date) - new Date(inWindow[0].date);
      const spanHours = Math.round(spanMs / MS_PER_HOUR * 10) / 10;
      findings.push({
        type: 'publish_burst',
        severity: 'HIGH',
        description: `${inWindow.length} versions published in ${spanHours} hours (avg interval: ${stats.avgIntervalDays} days)`,
        versions: inWindow.map(e => e.version)
      });
      break; // report only the first (largest) burst window
    }
  }

  // --- DORMANT_SPIKE: 6+ months without publication, then new version ---
  if (history.length >= 2) {
    const lastDate = new Date(history[history.length - 1].date).getTime();
    const prevDate = new Date(history[history.length - 2].date).getTime();
    const gapMs = lastDate - prevDate;

    if (gapMs >= DORMANT_THRESHOLD_MS) {
      const gapDays = Math.round(gapMs / MS_PER_DAY);
      findings.push({
        type: 'dormant_spike',
        severity: 'HIGH',
        description: `Package dormant for ${gapDays} days, then new version published (avg interval: ${stats.avgIntervalDays} days)`,
        versions: [history[history.length - 2].version, history[history.length - 1].version]
      });
    }
  }

  // --- RAPID_SUCCESSION: 2+ versions in less than 1 hour ---
  for (let i = 0; i < history.length; i++) {
    const windowStart = new Date(history[i].date).getTime();
    const windowEnd = windowStart + RAPID_WINDOW_MS;
    const inWindow = [];
    for (let j = i; j < history.length; j++) {
      const t = new Date(history[j].date).getTime();
      if (t <= windowEnd) {
        inWindow.push(history[j]);
      } else {
        break;
      }
    }
    if (inWindow.length >= RAPID_MIN_VERSIONS) {
      const spanMs = new Date(inWindow[inWindow.length - 1].date) - new Date(inWindow[0].date);
      const spanMinutes = Math.round(spanMs / 60000);
      findings.push({
        type: 'rapid_succession',
        severity: 'MEDIUM',
        description: `${inWindow.length} versions published within ${spanMinutes} minutes`,
        versions: inWindow.map(e => e.version)
      });
      break; // report only the first rapid window
    }
  }

  return {
    packageName,
    suspicious: findings.length > 0,
    anomalies: findings,
    stats
  };
}

module.exports = {
  analyzePublishFrequency,
  detectPublishAnomaly,
  // Exported for testing
  MS_PER_DAY,
  MS_PER_HOUR,
  BURST_WINDOW_MS,
  BURST_MIN_VERSIONS,
  RAPID_WINDOW_MS,
  RAPID_MIN_VERSIONS,
  DORMANT_THRESHOLD_MS,
  MIN_VERSIONS_FOR_ANALYSIS
};
