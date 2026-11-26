'use strict';
// Real npm registry documents frozen for the monitor metadata lane (tests/samples/registry/).
// Each fixture is named in manifest.json with the property it was chosen for; this test
// checks that property on the document itself, so a replaced or mislabelled fixture fails
// here instead of silently weakening the tests built on it.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { test, assert } = require('../test-utils');

const DIR = path.join(__dirname, '..', 'samples', 'registry');
const HOOKS = ['preinstall', 'install', 'postinstall'];
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

function load(file) {
  const raw = zlib.gunzipSync(fs.readFileSync(path.join(DIR, file)));
  return { raw, doc: JSON.parse(raw.toString('utf8')) };
}
const hook = (doc, version, name) => {
  const s = doc.versions && doc.versions[version] && doc.versions[version].scripts;
  return s && typeof s[name] === 'string' ? s[name] : undefined;
};

// category -> check(doc, entry, raw): returns an error message, or null when the property holds
const CHECKS = {
  first_publish: (d) => Object.keys(d.versions || {}).length === 1 ? null : 'expected exactly one version',
  established_new_version: (d, e) => {
    const v = d.versions && d.versions[e.version];
    if (!v) return `version ${e.version} missing`;
    if (Object.keys(d.versions).length < 5) return 'expected at least 5 versions';
    return v._npmUser && v._npmUser.name !== 'GitHub Actions' && !v._npmUser.trustedPublisher ? null : 'expected a personal publisher';
  },
  oidc_trusted_publisher: (d, e) => (d.versions[e.version] && d.versions[e.version]._npmUser && d.versions[e.version]._npmUser.trustedPublisher) ? null : 'expected _npmUser.trustedPublisher',
  prerelease_not_latest: (d, e) => (d.versions[e.version] && /-/.test(e.version) && d['dist-tags'].latest !== e.version) ? null : 'expected a prerelease that is not latest',
  hook_added: (d, e) => (hook(d, e.transition.from, e.transition.hook) === undefined && hook(d, e.transition.to, e.transition.hook) !== undefined) ? null : `expected ${e.transition.hook} absent in ${e.transition.from} and present in ${e.transition.to}`,
  hook_changed: (d, e) => {
    const a = hook(d, e.transition.from, e.transition.hook), b = hook(d, e.transition.to, e.transition.hook);
    return a !== undefined && b !== undefined && a !== b ? null : `expected ${e.transition.hook} present in both ${e.transition.from} and ${e.transition.to}, with different text`;
  },
  unpublished_version: (d, e) => (d.time && d.time[e.unpublished] && !d.versions[e.unpublished]) ? null : `expected ${e.unpublished} in time but not in versions`,
  large_document: (d, e, raw) => raw.length > 2 * 1024 * 1024 ? null : `expected more than 2 MiB, got ${raw.length}`,
  large_document_abbreviated: (d) => (!('time' in d) && d.versions && Object.keys(d.versions).length > 0) ? null : 'expected an install-v1 document: versions, no time',
  large_document_version: (d, e) => (d.version === e.version && !('versions' in d)) ? null : `expected the single-version document of ${e.version}`,
  date_order_differs_from_semver: (d) => Date.parse(d.time['5.0.2']) > Date.parse(d.time['6.6.1']) ? null : 'expected 5.0.2 published after 6.6.1'
};
CHECKS.hook_added_established = CHECKS.hook_added;

function runRegistryFixturesTests() {
  console.log('\n=== REGISTRY FIXTURES (metadata lane) ===\n');
  const manifestPath = path.join(DIR, 'manifest.json');

  test('REGISTRY-FIXTURES: manifest lists every category the metadata lane tests use', () => {
    assert(fs.existsSync(manifestPath), 'registry fixtures manifest missing: ' + manifestPath);
    const cats = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).fixtures.map(f => f.category);
    const missing = Object.keys(CHECKS).filter(c => !cats.includes(c));
    assert(missing.length === 0, 'categories without a fixture: ' + missing.join(', '));
  });
  if (!fs.existsSync(manifestPath)) return;

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  for (const entry of manifest.fixtures) {
    test(`REGISTRY-FIXTURES: ${entry.category} (${entry.name}) has the property it was chosen for`, () => {
      const check = CHECKS[entry.category];
      assert(check, 'no check for category ' + entry.category);
      const { raw, doc } = load(entry.file);
      const err = check(doc, entry, raw);
      assert(err === null, `${entry.file}: ${err}`);
    });
  }

  test('REGISTRY-FIXTURES: no e-mail address other than the placeholder', () => {
    for (const entry of manifest.fixtures) {
      const found = (load(entry.file).raw.toString('utf8').match(EMAIL_RE) || []).filter(m => m !== 'user@example.invalid');
      assert(found.length === 0, `${entry.file}: ${found.length} address(es) not redacted`);
    }
  });
}

module.exports = { runRegistryFixturesTests };
