#!/usr/bin/env node
'use strict';

/**
 * Guard for npm `overrides` in package.json (CI `test` job, publish job, ci:local).
 *
 * Threat model. `overrides` rewrites what npm installs for a package anywhere in the
 * tree. npm only applies the overrides of the ROOT project, so ours never reach the
 * users of muaddib-scanner; the exposure is this repository and its CI. A change to
 * `overrides` can redirect a dependency to another package (`npm:evil@1` alias), a
 * tarball URL, a git repository or a local path, which the typosquat guard does not
 * look at. Second risk: an override that is no longer needed freezes a version and
 * is forgotten.
 *
 * Rules (any violation fails):
 *  1. Every override key is documented in REGISTRY below (reason, advisory, parents).
 *  2. Its value is a plain semver version or ^/~ range of the SAME package, equal to
 *     the documented spec: no alias, URL, git, file:, link:, `$ref`, nested object.
 *  3. Every instance of the package in package-lock.json resolves to a version that
 *     satisfies the spec (the lockfile was regenerated with the override).
 *  4. The override is still needed: at least one documented parent still declares a
 *     range that admits no patched version (none >= firstPatched). When every parent
 *     admits one, the guard fails and asks for the override to be removed: while an
 *     override exists, Dependabot does not reliably propose updates for that package.
 *
 * Usage: node scripts/check-overrides.js   (reads package.json + package-lock.json)
 */

const fs = require('fs');
const path = require('path');

// Each entry: why the override exists and when it can go. Reviewed like code.
const REGISTRY = {
  minimatch: {
    spec: '11.0.5',
    advisory: 'GHSA-g3hv-75wg-m249 (minimatch >=7.0.0 <11.0.1, globparts DoS)',
    reason: 'dev-only, via eslint and @eslint/config-array, which still declare ^10. 11.0.5 is the latest release older than the 7-day Dependabot cooldown at the time of the pin.',
    firstPatched: '11.0.1',
    parents: ['eslint', '@eslint/config-array']
  }
};

const PLAIN_SPEC_RE = /^[~^]?\d+\.\d+\.\d+$/;
const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)$/;

function parseVersion(v) {
  const m = VERSION_RE.exec(String(v || '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/**
 * Minimal satisfies() for the spec shapes this guard allows: exact, ^x.y.z, ~x.y.z.
 * Returns null for any other range shape (caller fails closed and asks for review).
 */
function satisfies(version, range) {
  const v = parseVersion(version);
  const r = String(range || '').trim();
  const base = parseVersion(r.replace(/^[~^]/, ''));
  if (!v || !base || !PLAIN_SPEC_RE.test(r)) return null;
  if (r[0] === '^') {
    if (cmp(v, base) < 0) return false;
    if (base[0] > 0) return v[0] === base[0];
    if (base[1] > 0) return v[0] === 0 && v[1] === base[1];
    return v[0] === 0 && v[1] === 0 && v[2] === base[2];
  }
  if (r[0] === '~') return cmp(v, base) >= 0 && v[0] === base[0] && v[1] === base[1];
  return cmp(v, base) === 0;
}

/**
 * Does `range` admit at least one version >= `minVersion`? (Would npm, left alone,
 * be able to pick a patched version?) Exact, ^ and ~ only; null for other shapes.
 */
function admitsAtLeast(range, minVersion) {
  const r = String(range || '').trim();
  const base = parseVersion(r.replace(/^[~^]/, ''));
  const min = parseVersion(minVersion);
  if (!base || !min || !PLAIN_SPEC_RE.test(r)) return null;
  if (r[0] !== '^' && r[0] !== '~') return cmp(base, min) >= 0;
  // Exclusive upper bound of the range.
  let upper;
  if (r[0] === '~') upper = [base[0], base[1] + 1, 0];
  else if (base[0] > 0) upper = [base[0] + 1, 0, 0];
  else if (base[1] > 0) upper = [0, base[1] + 1, 0];
  else upper = [0, 0, base[2] + 1];
  // Versions in [base, upper) that are >= min exist iff min < upper.
  return cmp(min, upper) < 0;
}

/** Versions of `name` resolved anywhere in a lockfile v2/v3 `packages` map. */
function lockedVersions(lock, name) {
  const out = [];
  for (const [key, entry] of Object.entries((lock && lock.packages) || {})) {
    if (key === `node_modules/${name}` || key.endsWith(`/node_modules/${name}`)) out.push({ key, version: entry && entry.version });
  }
  return out;
}

/** Range a parent package declares for `name` in the lockfile (first instance). */
function parentRange(lock, parent, name) {
  const entry = ((lock && lock.packages) || {})[`node_modules/${parent}`];
  if (!entry) return undefined;
  const deps = { ...(entry.dependencies || {}), ...(entry.optionalDependencies || {}), ...(entry.peerDependencies || {}) };
  return deps[name];
}

/**
 * @returns {string[]} violations (empty = pass)
 */
function checkOverrides(pkg, lock, registry = REGISTRY) {
  const problems = [];
  const overrides = (pkg && pkg.overrides) || {};
  for (const [name, value] of Object.entries(overrides)) {
    const doc = Object.prototype.hasOwnProperty.call(registry, name) ? registry[name] : null;
    if (!doc) {
      problems.push(`override "${name}" is not documented in scripts/check-overrides.js REGISTRY (reason, advisory, parents, removal condition)`);
      continue;
    }
    if (typeof value !== 'string' || !PLAIN_SPEC_RE.test(value)) {
      problems.push(`override "${name}" must be a plain semver version or ^/~ range of the same package, got ${JSON.stringify(value)} (aliases, URLs, git, file:, link:, $refs and nested overrides are refused)`);
      continue;
    }
    if (value !== doc.spec) {
      problems.push(`override "${name}" is "${value}" but the documented spec is "${doc.spec}": update the REGISTRY entry in the same change`);
      continue;
    }
    const locked = lockedVersions(lock, name);
    if (locked.length === 0) problems.push(`override "${name}": no instance in package-lock.json (regenerate the lockfile)`);
    for (const l of locked) {
      if (satisfies(l.version, value) !== true) problems.push(`override "${name}": ${l.key} is locked at ${l.version}, which does not satisfy ${value} (regenerate the lockfile)`);
    }
    const stillNeeded = [];
    for (const parent of doc.parents) {
      const range = parentRange(lock, parent, name);
      if (range === undefined) continue;
      const ok = admitsAtLeast(range, doc.firstPatched);
      if (ok === null) problems.push(`override "${name}": parent ${parent} declares "${range}", a range shape this guard cannot evaluate - review the override by hand`);
      else if (ok === false) stillNeeded.push(`${parent} ${range}`);
    }
    if (stillNeeded.length === 0 && !problems.some(p => p.startsWith(`override "${name}": parent`))) {
      problems.push(`override "${name}" is no longer needed: every documented parent now admits a version >= ${doc.firstPatched}. Remove it from package.json and from REGISTRY, then regenerate the lockfile (while it exists, Dependabot does not reliably propose updates for ${name})`);
    }
  }
  for (const name of Object.keys(registry)) {
    if (!Object.prototype.hasOwnProperty.call(overrides, name)) problems.push(`REGISTRY documents "${name}" but package.json has no such override: remove the stale entry`);
  }
  return problems;
}

function main() {
  const root = path.resolve(__dirname, '..');
  let pkg, lock;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  } catch (e) {
    console.error(`::error::check-overrides: cannot read package.json / package-lock.json: ${e.message}`);
    process.exit(1);
  }
  const problems = checkOverrides(pkg, lock);
  if (problems.length > 0) {
    console.error('::error::npm overrides guard failed');
    for (const p of problems) console.error(`  ${p}`);
    process.exit(1);
  }
  const n = Object.keys(pkg.overrides || {}).length;
  console.log(`package.json overrides: clean (${n} documented, plain spec, locked, still needed)`);
}

if (require.main === module) main();

module.exports = { checkOverrides, satisfies, admitsAtLeast, REGISTRY };
