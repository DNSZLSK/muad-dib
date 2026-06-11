'use strict';

/**
 * PyPI maintainer / metadata checks — wires the existing ecosystem-agnostic
 * email-domain.js (MAINTAINER-005 MX + MAINTAINER-006 RDAP) onto PyPI
 * metadata returned by pypi-registry.js.
 *
 * Created v2.11.47. Mirror of how npm calls these from processor.js, but
 * for the PyPI side. We reuse the same threat types (`unclaimed_maintainer_email`,
 * `compromised_email_domain`) — they're conceptually identical, only the
 * registry context differs. We post-process the returned threats to swap the
 * `file` field (package.json → pyproject.toml) and tweak the message wording
 * so the operator sees "PyPI" not "npm" in the report.
 */

const {
  checkUnclaimedMaintainerEmail,
  checkCompromisedDomain
} = require('./email-domain.js');

/**
 * Adapt an npm-flavoured threat from email-domain.js to a PyPI-flavoured one.
 * Returns a new object (does not mutate the input).
 */
function adaptThreatToPyPI(threat, declarationFile) {
  if (!threat || typeof threat !== 'object') return threat;
  const adapted = { ...threat, file: declarationFile || 'pyproject.toml' };
  if (typeof threat.message === 'string') {
    adapted.message = threat.message
      .replace(/\bnpm\b/g, 'PyPI')
      .replace(/take over the account/g, 'take over the PyPI account');
  }
  return adapted;
}

/**
 * Entry point for PyPI maintainer-domain checks.
 *
 * @param {string} packageName - PyPI package name being scanned.
 * @param {object} pypiRegistryMeta - Output of getPyPIPackageMetadata().
 *   Must have shape { maintainer_emails: string[], created_at: ISO | null }.
 * @param {object} options - { resolveMx, fetchRdap, declarationFile } — first
 *   two are forwarded to email-domain.js (test injection); declarationFile is
 *   the path to display in threat.file (defaults to 'pyproject.toml').
 * @returns {Promise<Array>} threats array (empty if metadata is missing or
 *   the env opt-outs MUADDIB_EMAIL_DOMAIN_CHECK=0 / MUADDIB_RDAP_CHECK=0 are set).
 */
async function runPyPIMaintainerChecks(packageName, pypiRegistryMeta, options = {}) {
  if (!pypiRegistryMeta || typeof pypiRegistryMeta !== 'object') return [];
  if (!Array.isArray(pypiRegistryMeta.maintainer_emails) || pypiRegistryMeta.maintainer_emails.length === 0) {
    return [];
  }

  const declarationFile = options.declarationFile || 'pyproject.toml';
  // email-domain.js reads `meta.maintainer_emails` and `meta.created_at`.
  // The shape matches one-to-one with what pypi-registry.js returns.
  const helperMeta = {
    maintainer_emails: pypiRegistryMeta.maintainer_emails,
    created_at: pypiRegistryMeta.created_at
  };

  const threats = [];

  let mxThreats = [];
  try {
    mxThreats = await checkUnclaimedMaintainerEmail(helperMeta, {
      resolveMx: options.resolveMx
    });
  } catch { /* silent — same posture as email-domain.js */ }
  for (const t of mxThreats) threats.push(adaptThreatToPyPI(t, declarationFile));

  let rdapThreats = [];
  try {
    rdapThreats = await checkCompromisedDomain(helperMeta, {
      fetchRdap: options.fetchRdap,
      // PyPI created_at is the earliest release time (pypi-registry.js) =
      // first publish, so the V2 shadow comparison is valid on this side too.
      shadowCtx: { name: packageName, ecosystem: 'pypi' }
    });
  } catch { /* silent */ }
  for (const t of rdapThreats) threats.push(adaptThreatToPyPI(t, declarationFile));

  return threats;
}

module.exports = {
  runPyPIMaintainerChecks,
  // Exposed for unit tests
  _internal: { adaptThreatToPyPI }
};
