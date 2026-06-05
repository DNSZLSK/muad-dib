/**
 * P0b — Persist the recentlyScanned dedup Set across restarts.
 *
 * The dedup Set is in-memory only, so each of the ~10 daily OOM-restarts starts it
 * empty and re-scans the whole restored backlog (wasted work). saveRecentlyScanned /
 * loadRecentlyScanned persist it alongside the queue (60s timer + shutdown), with a
 * whole-file 24h freshness guard and a 50k cap (bounded resource, CLAUDE.md §2).
 *
 * Behavioral, not source-grep: every test calls the real functions and asserts the
 * Set mutation / return. fs is stubbed to an in-memory store so atomicWriteFileSync
 * (writeFileSync→renameSync) and the unlink/age paths run without touching real data/.
 */

const fs = require('fs');
const { test, assert } = require('../test-utils');
const { saveRecentlyScanned, loadRecentlyScanned } = require('../../src/monitor/state.js');

// In-memory fs keyed by basename: supports the full read/write/rename/unlink/exists
// surface that atomicWriteFileSync + loadRecentlyScanned touch.
function withMemFs(initial, fn) {
  const store = Object.assign({}, initial);
  const saved = {};
  for (const m of ['readFileSync', 'writeFileSync', 'renameSync', 'mkdirSync', 'existsSync', 'unlinkSync']) saved[m] = fs[m];
  const ow = console.warn, ol = console.log; console.warn = () => {}; console.log = () => {};
  const base = p => String(p).split(/[\\/]/).pop();
  fs.existsSync = p => base(p) in store;
  fs.readFileSync = (p) => { const b = base(p); if (b in store) return store[b]; const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; };
  fs.writeFileSync = (p, data) => { store[base(p)] = data; };
  fs.renameSync = (a, b) => { store[base(b)] = store[base(a)]; delete store[base(a)]; };
  fs.mkdirSync = () => {};
  fs.unlinkSync = (p) => { delete store[base(p)]; };
  try { return fn(store); }
  finally { for (const m of Object.keys(saved)) fs[m] = saved[m]; console.warn = ow; console.log = ol; }
}

const FILE = 'recently-scanned.json';

async function runRecentlyScannedPersistenceTests() {
  console.log('\n=== RECENTLY-SCANNED PERSISTENCE TESTS (P0b) ===\n');

  // POSITIVE: save → load round-trips every key.
  test('P0b: recentlyScanned round-trips through save → load', () => {
    withMemFs({}, () => {
      const src = new Set(['npm/a@1.0.0', 'pypi/b@2.0.0', 'npm/c@3.0.0']);
      saveRecentlyScanned(src);
      const dst = new Set();
      const n = loadRecentlyScanned(dst);
      assert(n === 3, `should restore 3 keys, got ${n}`);
      assert(dst.has('npm/a@1.0.0') && dst.has('pypi/b@2.0.0') && dst.has('npm/c@3.0.0'), 'all keys restored');
    });
  });

  // POSITIVE: an empty set removes the file (no stale dedup lingering on disk).
  test('P0b: saving an empty set removes the persisted file', () => {
    withMemFs({ [FILE]: JSON.stringify({ savedAt: new Date().toISOString(), count: 1, keys: ['npm/x@1'] }) }, (store) => {
      saveRecentlyScanned(new Set());
      assert(!(FILE in store), 'file should be removed when the set is empty');
    });
  });

  // NEGATIVE: a stale file (>24h) must NOT be restored (the set is cleared daily anyway).
  test('P0b: expired state (>24h) is ignored', () => {
    const old = new Date(Date.now() - 25 * 3600 * 1000).toISOString();
    withMemFs({ [FILE]: JSON.stringify({ savedAt: old, count: 2, keys: ['npm/a@1', 'npm/b@1'] }) }, () => {
      const dst = new Set();
      const n = loadRecentlyScanned(dst);
      assert(n === 0, `expired file must not restore, got ${n}`);
      assert(dst.size === 0, 'set stays empty on expired file');
    });
  });

  // NEGATIVE: corrupt JSON is a safe no-op (no throw).
  test('P0b: corrupt file is a safe no-op', () => {
    withMemFs({ [FILE]: '{not valid json' }, () => {
      const dst = new Set();
      const n = loadRecentlyScanned(dst);
      assert(n === 0, 'corrupt file restores nothing');
      assert(dst.size === 0, 'set stays empty');
    });
  });

  // NEGATIVE: missing file is a safe no-op.
  test('P0b: missing file is a safe no-op', () => {
    withMemFs({}, () => {
      const n = loadRecentlyScanned(new Set());
      assert(n === 0, 'missing file restores nothing');
    });
  });

  // BOUNDED: load caps the restored set at the persist max (CLAUDE.md §2 bounded resource).
  test('P0b: load caps the restored set at 50k (bounded resource)', () => {
    const keys = Array.from({ length: 50_005 }, (_, i) => `npm/p${i}@1.0.0`);
    withMemFs({ [FILE]: JSON.stringify({ savedAt: new Date().toISOString(), count: keys.length, keys }) }, () => {
      const dst = new Set();
      const n = loadRecentlyScanned(dst);
      assert(n === 50_000, `restored count should be capped at 50000, got ${n}`);
      assert(dst.size === 50_000, `set size should be 50000, got ${dst.size}`);
    });
  });

  console.log('  ✓ recentlyScanned persistence (P0b) tests passed');
}

module.exports = { runRecentlyScannedPersistenceTests };
