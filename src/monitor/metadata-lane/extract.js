'use strict';
/**
 * Metadata lane: publish facts read from a full npm registry document (packument).
 * Pure: no network, no state. Input fields are publisher-controlled, so every field is
 * type-checked and a malformed document yields fewer facts, never an exception.
 *
 * A version counts only when it is in both `versions` and `time` (an unpublished version
 * stays in `time` only). Order is the publish date, not semver: a backport published after
 * a newer major has that major as its previous version. `time.created` and
 * `time.modified` are document timestamps, not versions: `created` is usually written a
 * fraction of a second before the first version, so it is never compared.
 */

const HOOKS = ['preinstall', 'install', 'postinstall'];
const OIDC_PUBLISHER = 'GitHub Actions';
const DEFAULT_MAX = 100;

const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function hooksOf(manifest) {
  const scripts = isObject(manifest) && isObject(manifest.scripts) ? manifest.scripts : {};
  const out = {};
  for (const h of HOOKS) if (typeof scripts[h] === 'string') out[h] = scripts[h];
  return out;
}

function hookChanges(before, after) {
  const a = hooksOf(before), b = hooksOf(after);
  const out = [];
  for (const h of HOOKS) {
    if (!(h in b)) continue;
    if (!(h in a)) out.push({ hook: h, kind: 'added' });
    else if (a[h] !== b[h]) out.push({ hook: h, kind: 'changed' });
  }
  return out;
}

function publisherOf(manifest) {
  const u = isObject(manifest) && isObject(manifest._npmUser) ? manifest._npmUser : null;
  const name = u && typeof u.name === 'string' && u.name ? u.name : '?';
  const oidc = !!(u && (isObject(u.trustedPublisher) || name === OIDC_PUBLISHER));
  return { publisher: name, oidc };
}

/**
 * @param {object} doc full registry document
 * @param {{ sinceMs?: number, max?: number }} [opts] keep versions published at or after
 *   sinceMs; at most max facts, the most recent ones
 * @returns {Array<{ name, version, publishedAt, publisher, oidc, firstPublish, notLatest,
 *   previousVersion, hookChanges: Array<{hook, kind}> }>}
 */
function extractPublishFacts(doc, opts = {}) {
  if (!isObject(doc) || !isObject(doc.versions) || !isObject(doc.time)) return [];
  const sinceMs = Number.isFinite(opts.sinceMs) ? opts.sinceMs : -Infinity;
  const max = Number.isInteger(opts.max) && opts.max > 0 ? opts.max : DEFAULT_MAX;
  const name = typeof doc.name === 'string' ? doc.name : '?';
  const distTags = isObject(doc['dist-tags']) ? doc['dist-tags'] : {};
  const latest = typeof distTags.latest === 'string' ? distTags.latest : null;

  const ordered = [];
  for (const v of Object.keys(doc.versions)) {
    if (!Object.prototype.hasOwnProperty.call(doc.time, v) || typeof doc.time[v] !== 'string') continue;
    const t = Date.parse(doc.time[v]);
    if (Number.isFinite(t)) ordered.push({ version: v, t });
  }
  ordered.sort((a, b) => a.t - b.t);

  const facts = [];
  for (let i = ordered.length - 1; i >= 0 && facts.length < max; i--) {
    const { version, t } = ordered[i];
    if (t < sinceMs) break;
    const manifest = doc.versions[version];
    const prev = i > 0 ? ordered[i - 1].version : null;
    facts.push({
      name,
      version,
      publishedAt: t,
      ...publisherOf(manifest),
      firstPublish: prev === null,
      notLatest: latest !== version,
      previousVersion: prev,
      hookChanges: hookChanges(prev === null ? null : doc.versions[prev], manifest)
    });
  }
  return facts;
}

module.exports = { extractPublishFacts, HOOKS };
