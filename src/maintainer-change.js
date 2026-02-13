const { fetchPackageMetadata, getLatestVersions } = require('./temporal-analysis.js');

// Patterns that indicate generic/suspicious maintainer names
const GENERIC_NAME_PATTERNS = [
  /^npm-user-\w+$/i,
  /^user\d+$/i,
  /^test$/i,
  /^admin$/i,
  /^root$/i,
  /^default$/i,
  /^temp$/i,
  /^tmp$/i,
  /^owner$/i,
  /^maintainer$/i
];

const MIN_NAME_LENGTH = 3;
const DIGIT_RATIO_THRESHOLD = 0.5;

/**
 * Extract current maintainers from package metadata.
 * @param {object} metadata - Full registry metadata from fetchPackageMetadata()
 * @returns {{ current: Array<{name: string, email: string}>, count: number }}
 */
function getMaintainersHistory(metadata) {
  if (!metadata || !metadata.maintainers || !Array.isArray(metadata.maintainers)) {
    return { current: [], count: 0 };
  }

  const current = metadata.maintainers.map(m => ({
    name: m.name || '',
    email: m.email || ''
  }));

  return { current, count: current.length };
}

/**
 * Evaluate the risk level of a maintainer based on their name.
 * @param {{ name: string, email: string }} maintainer
 * @returns {{ riskLevel: string, reasons: string[] }}
 */
function analyzeMaintainerRisk(maintainer) {
  const reasons = [];
  const name = (maintainer && maintainer.name) || '';

  if (!name) {
    return { riskLevel: 'HIGH', reasons: ['Empty maintainer name'] };
  }

  // Check generic name patterns
  for (const pattern of GENERIC_NAME_PATTERNS) {
    if (pattern.test(name)) {
      reasons.push(`Generic name pattern: "${name}"`);
      break;
    }
  }

  // Check very short name
  if (name.length < MIN_NAME_LENGTH) {
    reasons.push(`Very short name (${name.length} chars)`);
  }

  // Check digit ratio
  const digitCount = (name.match(/\d/g) || []).length;
  const digitRatio = digitCount / name.length;
  if (digitRatio >= DIGIT_RATIO_THRESHOLD && name.length >= MIN_NAME_LENGTH) {
    reasons.push(`High digit ratio (${(digitRatio * 100).toFixed(0)}% digits)`);
  }

  if (reasons.length > 0) {
    return { riskLevel: 'HIGH', reasons };
  }

  return { riskLevel: 'LOW', reasons: [] };
}

/**
 * Get maintainers associated with a specific version from metadata.
 * Uses _npmUser (who published) and maintainers list from the version entry.
 * @param {object} versionData - metadata.versions[version]
 * @returns {{ publisher: {name: string, email: string}|null, maintainers: Array<{name: string, email: string}> }}
 */
function getVersionMaintainers(versionData) {
  if (!versionData) return { publisher: null, maintainers: [] };

  const publisher = versionData._npmUser
    ? { name: versionData._npmUser.name || '', email: versionData._npmUser.email || '' }
    : null;

  const maintainers = Array.isArray(versionData.maintainers)
    ? versionData.maintainers.map(m => ({ name: m.name || '', email: m.email || '' }))
    : [];

  return { publisher, maintainers };
}

/**
 * Detect maintainer changes between two versions.
 * @param {string} packageName - npm package name
 * @returns {Promise<object>} Detection result
 */
async function detectMaintainerChange(packageName) {
  const metadata = await fetchPackageMetadata(packageName);
  const maintainersInfo = getMaintainersHistory(metadata);
  const latest = getLatestVersions(metadata, 2);

  if (latest.length < 2) {
    return {
      packageName,
      suspicious: false,
      findings: [],
      maintainers: maintainersInfo
    };
  }

  const [newestEntry, previousEntry] = latest;
  const versions = metadata.versions || {};
  const newestData = versions[newestEntry.version];
  const previousData = versions[previousEntry.version];

  const newestMaint = getVersionMaintainers(newestData);
  const previousMaint = getVersionMaintainers(previousData);

  const findings = [];

  // Build name sets for comparison
  const previousNames = new Set(previousMaint.maintainers.map(m => m.name.toLowerCase()));
  const currentNames = new Set(newestMaint.maintainers.map(m => m.name.toLowerCase()));

  // Detect NEW_MAINTAINER: maintainers in newest that weren't in previous
  for (const m of newestMaint.maintainers) {
    if (m.name && !previousNames.has(m.name.toLowerCase())) {
      const risk = analyzeMaintainerRisk(m);
      findings.push({
        type: 'new_maintainer',
        severity: risk.riskLevel === 'HIGH' ? 'CRITICAL' : 'HIGH',
        maintainer: m,
        riskAssessment: risk,
        description: `New maintainer '${m.name}' added between v${previousEntry.version} and v${newestEntry.version}`
      });
    }
  }

  // Detect SUSPICIOUS_MAINTAINER: current maintainers with HIGH risk names
  for (const m of maintainersInfo.current) {
    const risk = analyzeMaintainerRisk(m);
    if (risk.riskLevel === 'HIGH') {
      // Avoid duplicate if already reported as new_maintainer
      const alreadyReported = findings.some(
        f => f.type === 'new_maintainer' && f.maintainer.name === m.name
      );
      if (!alreadyReported) {
        findings.push({
          type: 'suspicious_maintainer',
          severity: 'HIGH',
          maintainer: m,
          riskAssessment: risk,
          description: `Suspicious maintainer '${m.name}': ${risk.reasons.join(', ')}`
        });
      }
    }
  }

  // Detect SOLE_MAINTAINER_CHANGE: the only maintainer changed
  if (previousMaint.maintainers.length === 1 && newestMaint.maintainers.length === 1) {
    const prevName = previousMaint.maintainers[0].name.toLowerCase();
    const newName = newestMaint.maintainers[0].name.toLowerCase();
    if (prevName && newName && prevName !== newName) {
      const risk = analyzeMaintainerRisk(newestMaint.maintainers[0]);
      // Avoid duplicate if already reported as new_maintainer
      const alreadyReported = findings.some(
        f => f.type === 'new_maintainer' && f.maintainer.name.toLowerCase() === newName
      );
      if (!alreadyReported) {
        findings.push({
          type: 'sole_maintainer_change',
          severity: risk.riskLevel === 'HIGH' ? 'CRITICAL' : 'HIGH',
          maintainer: newestMaint.maintainers[0],
          previousMaintainer: previousMaint.maintainers[0],
          riskAssessment: risk,
          description: `Sole maintainer changed from '${previousMaint.maintainers[0].name}' to '${newestMaint.maintainers[0].name}'`
        });
      }
    }
  }

  // Detect publisher change (different _npmUser between versions)
  if (newestMaint.publisher && previousMaint.publisher) {
    const prevPublisher = previousMaint.publisher.name.toLowerCase();
    const newPublisher = newestMaint.publisher.name.toLowerCase();
    if (prevPublisher && newPublisher && prevPublisher !== newPublisher) {
      // Check if the new publisher is in the previous maintainers list
      if (!previousNames.has(newPublisher)) {
        const risk = analyzeMaintainerRisk(newestMaint.publisher);
        findings.push({
          type: 'new_publisher',
          severity: risk.riskLevel === 'HIGH' ? 'CRITICAL' : 'HIGH',
          maintainer: newestMaint.publisher,
          previousPublisher: previousMaint.publisher,
          riskAssessment: risk,
          description: `New publisher '${newestMaint.publisher.name}' (previously '${previousMaint.publisher.name}')`
        });
      }
    }
  }

  return {
    packageName,
    suspicious: findings.length > 0,
    findings,
    maintainers: maintainersInfo
  };
}

module.exports = {
  getMaintainersHistory,
  analyzeMaintainerRisk,
  detectMaintainerChange,
  getVersionMaintainers,
  GENERIC_NAME_PATTERNS,
  MIN_NAME_LENGTH,
  DIGIT_RATIO_THRESHOLD
};
