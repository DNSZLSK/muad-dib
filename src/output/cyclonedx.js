// P1b — CycloneDX 1.5 SBOM export.
//
// Maps muaddib scan results to CycloneDX vulnerabilities affecting the scanned
// package (root component). Consumed by SBOM-oriented pipelines: Dependency-
// Track, Anchore, Snyk, Trivy, GitHub Security, etc.
//
// Spec : https://cyclonedx.org/docs/1.5/json/
// Why 1.5 and not 1.6 : v1.5 has universal consumer support; v1.6 adds
// features (mldata, evidence) we don't use.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getRuleDomain } = require('../rules/index.js');

const SPEC_VERSION = '1.5';
const TOOL_NAME = 'muaddib';
const TOOL_VENDOR = 'muaddib';
const TOOL_URL = 'https://github.com/DNSZLSK/muad-dib';
const ROOT_BOM_REF = 'scanned-package';

const _muaddibVersion = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch {
    return '0.0.0';
  }
})();

/**
 * Map muaddib severity (uppercase) → CycloneDX severity (lowercase).
 * Unknown values fall to "info" (CycloneDX's mildest level).
 */
function severityToCycloneDX(severity) {
  switch (severity) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

/**
 * Build a package URL (purl) for the scanned component.
 * https://github.com/package-url/purl-spec
 *  - npm scoped:    pkg:npm/%40scope%2Fname@version
 *  - npm unscoped:  pkg:npm/name@version
 *  - generic fall:  pkg:generic/dirname@0.0.0
 *
 * When `hasPackageJson` is true we assume npm. PyPI / other ecosystems would
 * need a separate detector (out of scope for v1).
 */
function buildPurl(name, version, hasPackageJson) {
  const safeVersion = version || '0.0.0';
  if (!hasPackageJson) {
    return 'pkg:generic/' + encodeURIComponent(name || 'unknown') + '@' + encodeURIComponent(safeVersion);
  }
  if (name && name.startsWith('@') && name.includes('/')) {
    const slashIdx = name.indexOf('/');
    const scope = name.slice(0, slashIdx);
    const rest = name.slice(slashIdx + 1);
    return 'pkg:npm/' + encodeURIComponent(scope) + '/' + encodeURIComponent(rest) + '@' + encodeURIComponent(safeVersion);
  }
  return 'pkg:npm/' + encodeURIComponent(name || 'unknown') + '@' + encodeURIComponent(safeVersion);
}

/**
 * Read the scanned target's package.json (if present) to derive root identity.
 * Returns { name, version, hasPackageJson }.
 */
function resolveRootComponent(targetPath) {
  let name = null;
  let version = null;
  let hasPackageJson = false;
  if (targetPath && typeof targetPath === 'string') {
    try {
      const pkgPath = path.join(targetPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const data = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        if (typeof data.name === 'string' && data.name.length > 0) name = data.name;
        if (typeof data.version === 'string' && data.version.length > 0) version = data.version;
        hasPackageJson = true;
      }
    } catch {
      // ignore — fallback to dirname below
    }
  }
  if (!name) {
    // Last-resort fallback: dirname of the target
    try {
      name = targetPath ? path.basename(path.resolve(targetPath)) : 'unknown';
    } catch {
      name = 'unknown';
    }
  }
  if (!version) version = '0.0.0';
  return { name, version, hasPackageJson };
}

/**
 * Build the properties array for a vulnerability — exposes muaddib-specific
 * data (risk_domain, confidence, mitre, type, file, line) using a namespaced
 * key convention so consumers can filter/group on them without collisions.
 */
function vulnerabilityProperties(threat) {
  const props = [];
  const domain = threat.domain || getRuleDomain(threat.type);
  if (domain) props.push({ name: 'muaddib:risk_domain', value: String(domain) });
  if (threat.type) props.push({ name: 'muaddib:type', value: String(threat.type) });
  if (threat.confidence) props.push({ name: 'muaddib:confidence', value: String(threat.confidence) });
  if (threat.mitre) props.push({ name: 'muaddib:mitre', value: String(threat.mitre) });
  if (threat.file) props.push({ name: 'muaddib:file', value: String(threat.file) });
  if (threat.line) props.push({ name: 'muaddib:line', value: String(threat.line) });
  if (typeof threat.points === 'number') props.push({ name: 'muaddib:points', value: String(threat.points) });
  return props;
}

function vulnerabilityFromThreat(threat, idx) {
  const sev = severityToCycloneDX(threat.severity);
  const score = (typeof threat.points === 'number') ? threat.points : 0;
  return {
    'bom-ref': 'muaddib-vuln-' + idx,
    id: threat.rule_id || threat.type || ('MUADDIB-UNK-' + idx),
    source: { name: 'MUADDIB', url: TOOL_URL },
    description: threat.message || (threat.type || 'muaddib threat'),
    ratings: [
      {
        source: { name: 'MUADDIB' },
        severity: sev,
        method: 'other',
        score,
        vector: 'muaddib-confidence:' + (threat.confidence || 'medium')
      }
    ],
    affects: [{ ref: ROOT_BOM_REF }],
    properties: vulnerabilityProperties(threat)
  };
}

/**
 * Generate a CycloneDX 1.5 BOM document from a muaddib scan result.
 * @param {object} results - scan result object (must contain `threats`, `target`, optionally `timestamp`)
 * @returns {object} CycloneDX BOM ready to JSON.stringify
 */
function generateCycloneDX(results) {
  const target = (results && results.target) || '.';
  const timestamp = (results && results.timestamp) || new Date().toISOString();
  const root = resolveRootComponent(target);
  const purl = buildPurl(root.name, root.version, root.hasPackageJson);

  const threats = Array.isArray(results && results.threats) ? results.threats : [];
  const vulnerabilities = threats.map((t, i) => vulnerabilityFromThreat(t, i + 1));

  return {
    bomFormat: 'CycloneDX',
    specVersion: SPEC_VERSION,
    serialNumber: 'urn:uuid:' + crypto.randomUUID(),
    version: 1,
    metadata: {
      timestamp,
      tools: [
        {
          vendor: TOOL_VENDOR,
          name: TOOL_NAME,
          version: _muaddibVersion
        }
      ],
      component: {
        'bom-ref': ROOT_BOM_REF,
        type: 'library',
        name: root.name,
        version: root.version,
        purl
      }
    },
    vulnerabilities
  };
}

/**
 * Write the generated BOM to disk. Mirrors saveSARIF semantics.
 */
function saveCycloneDX(results, outputPath) {
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('Invalid output path for CycloneDX report');
  }
  const bom = generateCycloneDX(results);
  try {
    fs.writeFileSync(outputPath, JSON.stringify(bom, null, 2));
  } catch (e) {
    throw new Error('Failed to write CycloneDX report to ' + outputPath + ': ' + e.message, { cause: e });
  }
  return outputPath;
}

module.exports = {
  generateCycloneDX,
  saveCycloneDX,
  severityToCycloneDX,
  buildPurl,
  resolveRootComponent,
  SPEC_VERSION
};
