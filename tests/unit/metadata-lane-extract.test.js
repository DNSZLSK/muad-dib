'use strict';
// Metadata lane, step 1: publish facts read from a registry document (pure, no network).
// Every case runs on a real registry document (tests/samples/registry/).
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { test, assert } = require('../test-utils');

const DIR = path.join(__dirname, '..', 'samples', 'registry');
const load = (file) => JSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(DIR, file))).toString('utf8'));

function runMetadataLaneExtractTests() {
  console.log('\n=== METADATA LANE: PUBLISH FACTS ===\n');
  const { extractPublishFacts } = require('../../src/monitor/metadata-lane/extract');
  const factOf = (doc, version) => extractPublishFacts(doc, { max: 100000 }).find(f => f.version === version);

  const FIRST = load('codeo-engineering__licenserail--first_publish.json.gz');
  const WIX = load('wix__site-service-editor-context--established_new_version.json.gz');
  const PB = load('protobufjs--date_order.json.gz');
  const PRE = load('frondruntime__react--prerelease_not_latest.json.gz');
  const ES5 = load('es5-ext--hook_added_established.json.gz');
  const BCRYPT = load('bcrypt--hook_changed.json.gz');
  const OIDC = load('hyperneo__hyperneod-darwin-x64--oidc_trusted_publisher.json.gz');
  const TSV = load('ts-vibe--unpublished_version.json.gz');
  const ABBR = load('cezar-cli--abbreviated.json.gz');
  const LARGE = load('cezar-cli--large_document.json.gz');

  test('METADATA-EXTRACT: a single published version is a first publish with no previous version', () => {
    const facts = extractPublishFacts(FIRST);
    assert(facts.length === 1 && facts[0].firstPublish === true && facts[0].previousVersion === null, 'got ' + JSON.stringify(facts));
  });

  test('METADATA-EXTRACT: the first version is a first publish even when time.created precedes it', () => {
    assert(Date.parse(ES5.time.created) < Date.parse(ES5.time['0.1.0']), 'fixture precondition: created precedes 0.1.0');
    const f = factOf(ES5, '0.1.0');
    assert(f && f.firstPublish === true && f.previousVersion === null, 'got ' + JSON.stringify(f));
  });

  test('METADATA-EXTRACT: a new version of an established package has the previous version by date', () => {
    const w = factOf(WIX, '1.0.9');
    assert(w && w.firstPublish === false && w.previousVersion === '1.0.8', 'got ' + JSON.stringify(w));
    const p = factOf(PB, '5.0.2');
    assert(p && p.previousVersion === '6.6.1', 'previous by date is 6.6.1 (published just before), not the semver predecessor, got ' + JSON.stringify(p && p.previousVersion));
  });

  test('METADATA-EXTRACT: a version that is not the latest dist-tag is marked notLatest', () => {
    assert(factOf(PRE, '0.7.0-rc.0').notLatest === true, 'rc should be notLatest');
    assert(factOf(PRE, '0.7.0').notLatest === false, 'latest should not be notLatest');
  });

  test('METADATA-EXTRACT: install hooks added or changed against the previous version are listed', () => {
    const added = factOf(ES5, '0.10.54').hookChanges;
    assert(JSON.stringify(added) === JSON.stringify([{ hook: 'postinstall', kind: 'added' }]), 'es5-ext 0.10.54: got ' + JSON.stringify(added));
    const changed = factOf(BCRYPT, '6.0.0').hookChanges;
    assert(JSON.stringify(changed) === JSON.stringify([{ hook: 'install', kind: 'changed' }]), 'bcrypt 6.0.0: got ' + JSON.stringify(changed));
    const same = factOf(BCRYPT, '5.1.1').hookChanges;
    assert(Array.isArray(same) && same.length === 0, 'bcrypt 5.1.1 keeps the same install script: got ' + JSON.stringify(same));
  });

  test('METADATA-EXTRACT: OIDC trusted publishing is recognized; a personal publisher is not', () => {
    const o = factOf(OIDC, '0.62.1');
    assert(o && o.oidc === true && o.publisher === 'GitHub Actions', 'got ' + JSON.stringify(o));
    assert(factOf(WIX, '1.0.9').oidc === false, 'wix-ci-publisher is a personal account');
    // trustedPublisher is the authoritative field, whatever the publisher name.
    const renamed = JSON.parse(JSON.stringify(OIDC));
    renamed.versions['0.62.1']._npmUser.name = 'some-bot';
    assert(factOf(renamed, '0.62.1').oidc === true, 'trustedPublisher without the GitHub Actions name must stay OIDC');
  });

  test('METADATA-EXTRACT: an unpublished version is not a fact and not a previous version', () => {
    const facts = extractPublishFacts(TSV, { max: 1000 });
    assert(!facts.some(f => f.version === '2.0.0'), 'unpublished 2.0.0 must not be a fact');
    assert(factOf(TSV, '2.0.1').previousVersion === '1.4.3', 'previous of 2.0.1 skips the unpublished 2.0.0, got ' + factOf(TSV, '2.0.1').previousVersion);
  });

  test('METADATA-EXTRACT: a document without time (abbreviated) gives no fact', () => {
    assert(!('time' in ABBR), 'fixture precondition');
    const facts = extractPublishFacts(ABBR);
    assert(Array.isArray(facts) && facts.length === 0, 'got ' + facts.length);
  });

  test('METADATA-EXTRACT: only versions published at or after sinceMs are returned', () => {
    const since = Date.parse(WIX.time['1.0.8']);
    const facts = extractPublishFacts(WIX, { sinceMs: since });
    assert(JSON.stringify(facts.map(f => f.version).sort()) === JSON.stringify(['1.0.8', '1.0.9']), 'got ' + JSON.stringify(facts.map(f => f.version)));
  });

  test('METADATA-EXTRACT: at most max facts, the most recent ones', () => {
    const facts = extractPublishFacts(LARGE, { max: 5 });
    const newest = Object.keys(LARGE.versions).filter(v => LARGE.time[v]).sort((a, b) => Date.parse(LARGE.time[b]) - Date.parse(LARGE.time[a])).slice(0, 5);
    assert(facts.length === 5 && JSON.stringify(facts.map(f => f.version).sort()) === JSON.stringify(newest.sort()), 'got ' + JSON.stringify(facts.map(f => f.version)));
  });

  test('METADATA-EXTRACT: malformed fields do not throw (scripts not an object, no _npmUser, null input)', () => {
    const doc = JSON.parse(JSON.stringify(WIX));
    doc.versions['1.0.9'].scripts = 'install';
    delete doc.versions['1.0.9']._npmUser;
    const f = factOf(doc, '1.0.9');
    assert(f && f.publisher === '?' && f.oidc === false && Array.isArray(f.hookChanges), 'got ' + JSON.stringify(f));
    for (const bad of [null, undefined, 42, 'x', {}, { versions: 1, time: 2 }]) {
      const r = extractPublishFacts(bad);
      assert(Array.isArray(r) && r.length === 0, 'bad input ' + JSON.stringify(bad) + ' -> ' + JSON.stringify(r));
    }
  });
}

module.exports = { runMetadataLaneExtractTests };
