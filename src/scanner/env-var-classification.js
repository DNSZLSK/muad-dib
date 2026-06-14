'use strict';

// Environment-variable credential classification (shared leaf module).
// Extracted verbatim from dataflow.js so the SAME credential-vs-config distinction can
// gate every taint source — dataflow (scanner/dataflow.js) AND the module-graph cross-file
// taint (scanner/module-graph/annotate-tainted.js), which previously tainted ANY process.env
// read indiscriminately (config vars like STORYBOARD_SERVER_URL → false credential_exfil).
// No project dependencies → safe to require from any scanner, no cycles.

// System identity env vars used for fingerprinting/exfiltration
const SYSTEM_IDENTITY_ENVS = new Set([
  'USER', 'USERNAME', 'LOGNAME', 'HOME', 'HOSTNAME',
  'USERPROFILE', 'COMPUTERNAME', 'WHOAMI'
]);

// Env var prefixes for tool-internal configuration (not external credentials)
const SAFE_ENV_PREFIXES = ['MUADDIB_', 'npm_config_', 'npm_lifecycle_', 'npm_package_'];

// P6: Node.js runtime config env vars that are not credentials.
// NODE_TLS_REJECT_UNAUTHORIZED matches "AUTH" in "UNAUTHORIZED" → false positive.
// Real credential exfiltration targets API_KEY, TOKEN, SECRET, PASSWORD.
const DATAFLOW_SAFE_ENV_VARS = new Set([
  'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS',
  'NODE_ENV', 'NODE_PATH', 'NODE_DEBUG',
  'DEBUG', 'CI', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY',
  'LANG', 'TZ', 'PORT', 'HOST'
  // Note: HOME, USER, HOSTNAME stay sensitive — fingerprint exfiltration detection.
]);

// True when an env var name is a sensitive source (credential material OR system-identity
// fingerprinting). Config vars (URL/HOST/PORT/NODE_ENV/proxy/...) return false. This is the
// classification module-graph cross-file taint now shares (it formerly tainted every read).
function isSensitiveEnv(name) {
  const upper = name.toUpperCase();
  if (DATAFLOW_SAFE_ENV_VARS.has(upper)) return false;
  if (SYSTEM_IDENTITY_ENVS.has(upper)) return true;
  if (SAFE_ENV_PREFIXES.some(p => upper.startsWith(p))) return false;
  const sensitive = ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH', 'NPM', 'AWS', 'AZURE', 'GCP'];
  return sensitive.some(s => upper.includes(s));
}

// Audit 2026-05 DF-C4: credential-tier env vars distinguished from generic env_read.
// These represent authentication material (NPM_TOKEN, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY,
// STRIPE_API_KEY etc.) — strictly narrower than isSensitiveEnv. Sources of this type
// participate in hasHighRiskSource so credential exfil patterns are NOT downgraded by the
// HIGH→MEDIUM graduation. System identity vars (HOME, USER) remain plain env_read since
// they are fingerprinting signals, not credentials.
const KNOWN_CREDENTIAL_ENV_VARS = new Set([
  'NPM_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'NODE_AUTH_TOKEN',
  'CIRCLE_TOKEN', 'GITLAB_TOKEN', 'CARGO_REGISTRY_TOKEN', 'PYPI_TOKEN',
  'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_CLIENT_SECRET',
  'SENTRY_AUTH_TOKEN', 'NPM_AUTH_TOKEN', 'NPM_CONFIG_AUTHTOKEN'
]);

const CREDENTIAL_ENV_SUFFIX_RE = /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSPHRASE|CREDENTIAL|CREDENTIALS|API_KEY|ACCESS_KEY|ACCESS_KEY_ID|SECRET_KEY|PRIVATE_KEY|SIGNING_KEY|SESSION_TOKEN|REFRESH_TOKEN|AUTH_TOKEN)$/;

function isCredentialEnv(name) {
  const upper = name.toUpperCase();
  // System identity vars are fingerprinting, not credentials
  if (SYSTEM_IDENTITY_ENVS.has(upper)) return false;
  // Public keys are not credentials (e.g., SSH_PUBLIC_KEY, GPG_PUBLIC_KEY)
  if (upper.includes('PUBLIC_KEY') || upper.includes('PUBKEY')) return false;
  if (KNOWN_CREDENTIAL_ENV_VARS.has(upper)) return true;
  return CREDENTIAL_ENV_SUFFIX_RE.test(upper);
}

module.exports = {
  SYSTEM_IDENTITY_ENVS,
  SAFE_ENV_PREFIXES,
  DATAFLOW_SAFE_ENV_VARS,
  KNOWN_CREDENTIAL_ENV_VARS,
  CREDENTIAL_ENV_SUFFIX_RE,
  isSensitiveEnv,
  isCredentialEnv,
};
