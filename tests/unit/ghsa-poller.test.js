'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert } = require('../test-utils');
const {
  parseAdvisory,
  pollGhsaOnce,
  loadGhsaCursor,
  buildGhsaPreAlertEmbed
} = require('../../src/ioc/ghsa-poller.js');

function adv(id, eco, name, updatedIso, withdrawn) {
  return {
    ghsa_id: id,
    type: 'malware',
    published_at: updatedIso,
    updated_at: updatedIso,
    withdrawn_at: withdrawn ? updatedIso : null,
    vulnerabilities: [{ package: { ecosystem: eco, name }, vulnerable_version_range: '>= 0' }]
  };
}

// Per-test temp files + capture harness.
function harness(fetchMap) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ghsa-'));
  const dispatched = [];
  const ledgered = [];
  return {
    dir,
    cursorFile: path.join(dir, 'cursor.json'),
    malwareFile: path.join(dir, 'malware.jsonl'),
    feedHealthFile: path.join(dir, 'feed-health.json'),
    dispatch: async (p) => { dispatched.push(p); },
    appendLedger: (e) => { ledgered.push(e); },
    fetchImpl: async (eco) => (fetchMap[eco] || []),
    dispatched,
    ledgered,
    cleanup() { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} },
    malwareRows() {
      try { return fs.readFileSync(this.malwareFile, 'utf8').split('\n').filter(Boolean).map(JSON.parse); }
      catch { return []; }
    }
  };
}

async function runGhsaPollerTests() {
  console.log('\n=== GHSA Active Poller Tests (Phase 2c part 2) ===\n');

  // ── parseAdvisory (pure) ──

  test('parseAdvisory: flattens vulnerabilities into per-package rows with withdrawn flag', () => {
    const rows = parseAdvisory({
      ghsa_id: 'GHSA-aaaa', published_at: '2026-06-01T00:00:00Z', updated_at: '2026-06-02T00:00:00Z',
      withdrawn_at: '2026-06-02T00:00:00Z',
      vulnerabilities: [
        { package: { ecosystem: 'npm', name: 'evil-pkg' }, vulnerable_version_range: '>= 0' },
        { package: { ecosystem: 'pypi', name: 'evil-py' }, vulnerable_version_range: '< 2.0' }
      ]
    });
    assert(rows.length === 2, 'two packages');
    assert(rows[0].name === 'evil-pkg' && rows[0].ecosystem === 'npm' && rows[0].withdrawn === true, 'npm row + withdrawn');
    assert(rows[1].name === 'evil-py' && rows[1].versionRange === '< 2.0', 'pypi row + range');
  });

  test('parseAdvisory: filters out non-target ecosystems and malformed entries', () => {
    const rows = parseAdvisory({
      ghsa_id: 'GHSA-bbbb', updated_at: '2026-06-02T00:00:00Z',
      vulnerabilities: [
        { package: { ecosystem: 'rubygems', name: 'gem-x' } }, // filtered (not npm/pypi)
        { package: null },                                      // malformed
        { package: { ecosystem: 'npm', name: 'ok' } }
      ]
    }, ['npm', 'pypi']);
    assert(rows.length === 1 && rows[0].name === 'ok', 'only the npm row survives');
    assert(parseAdvisory(null).length === 0 && parseAdvisory({}).length === 0, 'null/empty → []');
  });

  test('parseAdvisory: normalizes GHSA "pip" ecosystem to internal "pypi"', () => {
    const rows = parseAdvisory({
      ghsa_id: 'GHSA-pip', updated_at: '2026-06-02T00:00:00Z',
      vulnerabilities: [{ package: { ecosystem: 'pip', name: 'evil-py' }, vulnerable_version_range: '>= 0' }]
    }, ['npm', 'pypi']);
    assert(rows.length === 1 && rows[0].ecosystem === 'pypi' && rows[0].name === 'evil-py',
      'GHSA "pip" must be stored as "pypi" so the rest of the system stays consistent');
  });

  test('buildGhsaPreAlertEmbed: ecosystem-aware link (npm vs pypi)', () => {
    const npm = buildGhsaPreAlertEmbed({ ecosystem: 'npm', name: 'x', ghsa_id: 'GHSA-1', versionRange: '*' });
    const pypi = buildGhsaPreAlertEmbed({ ecosystem: 'pypi', name: 'y', ghsa_id: 'GHSA-2', versionRange: '*' });
    assert(JSON.stringify(npm).includes('npmjs.com/package/x'), 'npm link');
    assert(JSON.stringify(pypi).includes('pypi.org/project/y'), 'pypi link');
  });

  // ── pollGhsaOnce: seeding ──

  await asyncTest('pollGhsaOnce: first run SEEDS the denominator + cursor, with NO pre-alerts', async () => {
    const h = harness({ npm: [adv('GHSA-1', 'npm', 'mal-a', '2026-06-05T10:00:00Z')], pypi: [] });
    try {
      const r = await pollGhsaOnce({ ecosystems: ['npm', 'pypi'], fetchImpl: h.fetchImpl, dispatch: h.dispatch,
        appendLedger: h.appendLedger, cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      assert(r.seeded === true, 'first run is a seeding run');
      assert(h.dispatched.length === 0, 'no pre-alerts on the seeding run');
      assert(h.malwareRows().some(x => x.name === 'mal-a'), 'denominator seeded');
      assert(loadGhsaCursor(h.cursorFile) === '2026-06-05T10:00:00Z', 'cursor set to max updated_at');
    } finally { h.cleanup(); }
  });

  // ── pollGhsaOnce: fresh / withdrawn / already-seen ──

  await asyncTest('pollGhsaOnce: after seeding, a NEWER advisory pre-alerts; an older one is skipped', async () => {
    const h = harness({ npm: [adv('GHSA-1', 'npm', 'mal-a', '2026-06-05T10:00:00Z')], pypi: [] });
    try {
      await pollGhsaOnce({ fetchImpl: h.fetchImpl, dispatch: h.dispatch, appendLedger: h.appendLedger,
        cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile }); // seed (cursor=2026-06-05T10:00:00Z)

      // Next poll: one newer + the same older one.
      h.fetchImpl = async (eco) => eco === 'npm' ? [
        adv('GHSA-2', 'npm', 'mal-b', '2026-06-06T09:00:00Z'), // newer → fresh
        adv('GHSA-1', 'npm', 'mal-a', '2026-06-05T10:00:00Z')  // == cursor → skipped
      ] : [];
      const r = await pollGhsaOnce({ fetchImpl: h.fetchImpl, dispatch: h.dispatch, appendLedger: h.appendLedger,
        cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      assert(r.fresh === 1 && r.prealerted === 1, `exactly one fresh pre-alert, got fresh=${r.fresh} pre=${r.prealerted}`);
      assert(h.dispatched.length === 1 && JSON.stringify(h.dispatched[0]).includes('mal-b'), 'pre-alert names the fresh pkg');
      assert(loadGhsaCursor(h.cursorFile) === '2026-06-06T09:00:00Z', 'cursor advanced to newest');
    } finally { h.cleanup(); }
  });

  await asyncTest('pollGhsaOnce: a withdrawn fresh advisory is ledgered ghsa_gone and NOT pre-alerted', async () => {
    const h = harness({ npm: [adv('GHSA-1', 'npm', 'seed', '2026-06-01T00:00:00Z')], pypi: [] });
    try {
      await pollGhsaOnce({ fetchImpl: h.fetchImpl, dispatch: h.dispatch, appendLedger: h.appendLedger,
        cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile }); // seed

      h.fetchImpl = async (eco) => eco === 'npm' ? [adv('GHSA-9', 'npm', 'gone-pkg', '2026-06-07T00:00:00Z', true)] : [];
      const r = await pollGhsaOnce({ fetchImpl: h.fetchImpl, dispatch: h.dispatch, appendLedger: h.appendLedger,
        cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      assert(r.withdrawn === 1 && r.prealerted === 0, 'withdrawn counted, not pre-alerted');
      assert(h.dispatched.length === 0, 'no pre-alert for a withdrawn advisory');
      const led = h.ledgered.find(e => e.name === 'gone-pkg');
      assert(led && led.outcome === 'dropped' && led.source === 'ghsa_gone', 'ledgered as dropped/ghsa_gone');
    } finally { h.cleanup(); }
  });

  await asyncTest('pollGhsaOnce: pre-alert cap bounds the pings (catch-up storm guard)', async () => {
    const h = harness({ npm: [adv('GHSA-0', 'npm', 'seed', '2026-06-01T00:00:00Z')], pypi: [] });
    try {
      await pollGhsaOnce({ fetchImpl: h.fetchImpl, dispatch: h.dispatch, appendLedger: h.appendLedger,
        cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile }); // seed at 2026-06-01

      const many = [];
      for (let i = 0; i < 10; i++) many.push(adv(`GHSA-n${i}`, 'npm', `m${i}`, `2026-06-1${i % 10}T00:00:00Z`));
      h.fetchImpl = async (eco) => eco === 'npm' ? many : [];
      const r = await pollGhsaOnce({ prealertCap: 3, fetchImpl: h.fetchImpl, dispatch: h.dispatch,
        appendLedger: h.appendLedger, cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      assert(r.fresh === 10, `all 10 are fresh, got ${r.fresh}`);
      assert(r.prealerted === 3 && h.dispatched.length === 3, `cap=3 respected, got ${r.prealerted}`);
    } finally { h.cleanup(); }
  });

  await asyncTest('pollGhsaOnce: a fetch error never throws and does not advance the cursor', async () => {
    const h = harness({});
    try {
      // seed via a working fetch first
      h.fetchImpl = async (eco) => eco === 'npm' ? [adv('GHSA-1', 'npm', 'seed', '2026-06-05T10:00:00Z')] : [];
      await pollGhsaOnce({ fetchImpl: h.fetchImpl, dispatch: h.dispatch, appendLedger: h.appendLedger,
        cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      const cursorAfterSeed = loadGhsaCursor(h.cursorFile);

      // now both ecosystems error
      const failing = async () => { throw new Error('HTTP 503'); };
      const r = await pollGhsaOnce({ ecosystems: ['npm', 'pypi'], fetchImpl: failing, dispatch: h.dispatch,
        appendLedger: h.appendLedger, cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      assert(r.errors.length === 2, 'both ecosystems recorded an error');
      assert(r.fresh === 0 && r.prealerted === 0, 'nothing processed on a failed fetch');
      assert(loadGhsaCursor(h.cursorFile) === cursorAfterSeed, 'cursor unchanged after a failed poll');
    } finally { h.cleanup(); }
  });

  // ── Phase 4: crates.io (rust) ecosystem ──

  test('parseAdvisory: normalizes GHSA "rust" ecosystem to internal "crates"', () => {
    const rows = parseAdvisory({
      ghsa_id: 'GHSA-rust', updated_at: '2026-06-07T00:00:00Z',
      vulnerabilities: [{ package: { ecosystem: 'rust', name: 'evil-crate' }, vulnerable_version_range: '>= 0' }]
    }, ['npm', 'pypi', 'crates']);
    assert(rows.length === 1 && rows[0].ecosystem === 'crates' && rows[0].name === 'evil-crate',
      'GHSA "rust" must be stored as "crates"');
  });

  test('buildGhsaPreAlertEmbed: crates link points at crates.io', () => {
    const e = buildGhsaPreAlertEmbed({ ecosystem: 'crates', name: 'my-unique-clean-crate-xyz', ghsa_id: 'GHSA-c', versionRange: '*' });
    assert(JSON.stringify(e).includes('crates.io/crates/my-unique-clean-crate-xyz'), 'crates.io link');
  });

  test('buildGhsaPreAlertEmbed: a crates typosquat is flagged as an enrichment field', () => {
    const e = buildGhsaPreAlertEmbed({ ecosystem: 'crates', name: 'serdejson', ghsa_id: 'GHSA-c2', versionRange: '*' });
    const typo = e.embeds[0].fields.find(f => f.name === 'Typosquat');
    assert(typo && typo.value.includes('serde_json'), `expected Typosquat→serde_json, got ${JSON.stringify(typo)}`);
    // neg: a clean crate name carries no Typosquat field
    const clean = buildGhsaPreAlertEmbed({ ecosystem: 'crates', name: 'my-unique-clean-crate-xyz', ghsa_id: 'GHSA-c3', versionRange: '*' });
    assert(!clean.embeds[0].fields.some(f => f.name === 'Typosquat'), 'no Typosquat field on a clean crate name');
  });

  await asyncTest('pollGhsaOnce: crates ecosystem pre-alerts a fresh malicious crate (crates.io link + typosquat)', async () => {
    const h = harness({ npm: [], pypi: [], crates: [adv('GHSA-seed', 'rust', 'seed-crate', '2026-06-01T00:00:00Z')] });
    try {
      await pollGhsaOnce({ ecosystems: ['crates'], fetchImpl: h.fetchImpl, dispatch: h.dispatch,
        appendLedger: h.appendLedger, cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile }); // seed
      h.fetchImpl = async (eco) => eco === 'crates' ? [adv('GHSA-new', 'rust', 'reqwest2', '2026-06-07T00:00:00Z')] : [];
      const r = await pollGhsaOnce({ ecosystems: ['crates'], fetchImpl: h.fetchImpl, dispatch: h.dispatch,
        appendLedger: h.appendLedger, cursorFile: h.cursorFile, malwareFile: h.malwareFile, feedHealthFile: h.feedHealthFile });
      assert(r.fresh === 1 && r.prealerted === 1, `one fresh crates pre-alert, got fresh=${r.fresh} pre=${r.prealerted}`);
      const s = JSON.stringify(h.dispatched[0]);
      assert(s.includes('crates.io/crates/reqwest2'), 'pre-alert carries the crates.io link');
      assert(s.includes('Typosquat') && s.includes('reqwest'), 'pre-alert enriched with the reqwest typosquat');
    } finally { h.cleanup(); }
  });
}

module.exports = { runGhsaPollerTests };
