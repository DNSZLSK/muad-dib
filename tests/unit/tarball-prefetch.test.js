'use strict';

// Behavioral tests for capture-at-publish (src/monitor/tarball-prefetch.js).
// We exercise the real scheduling/pool logic and inject fake deps (download +
// cache + registry slots) so nothing touches the network or prod state. No
// source-greps — every assertion is on observed behaviour (downloads issued,
// cache writes, counters, bounds).

const { asyncTest, assert, cleanupTemp } = require('../test-utils');
const fs = require('fs');
const os = require('os');
const path = require('path');

async function runTarballPrefetchTests() {
  console.log('\n=== TARBALL PREFETCH (capture-at-publish) TESTS ===\n');

  const prefetch = require('../../src/monitor/tarball-prefetch.js');

  // Fake dependency set. `downloadToFile` writes real bytes into a real tmp
  // file (so the module's tmp-cleanup runs); `cacheTarball` records the call;
  // cache paths live under a real temp dir so the "already cached" probe works.
  function makeDeps(opts = {}) {
    const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-prefetch-test-'));
    const downloads = [];
    const cacheCalls = [];
    return {
      _cacheDir: cacheDir,
      _downloads: downloads,
      _cacheCalls: cacheCalls,
      tmpDir: os.tmpdir(),
      tarballCacheKey: (n, v) => `${n}-${v}`,
      tarballCachePath: (k) => path.join(cacheDir, `${k}.tgz`),
      acquireRegistrySlot: async () => {},
      releaseRegistrySlot: () => {},
      downloadToFile: async (url, dest) => {
        downloads.push({ url, dest });
        if (opts.failUrls && opts.failUrls.has(url)) {
          throw new Error(`HTTP 404 for ${url}`);
        }
        if (opts.gate) await opts.gate;
        fs.writeFileSync(dest, 'FAKE_TGZ_BYTES');
      },
      cacheTarball: (n, v, src, reason, retentionDays) => {
        cacheCalls.push({ n, v, reason, retentionDays });
      }
    };
  }

  function item(over = {}) {
    return {
      name: 'leo-sdk',
      version: '6.0.19',
      ecosystem: 'npm',
      tarballUrl: 'https://registry.npmjs.org/leo-sdk/-/leo-sdk-6.0.19.tgz',
      _cacheTrigger: { shouldCache: true, reason: 'first_publish', retentionDays: 7 },
      firstPublish: true,
      ...over
    };
  }

  // POSITIVE: an eligible first_publish item is captured into the cache with the
  // correct name/version/reason/retention.
  await asyncTest('captures an eligible first_publish tarball into the cache', async () => {
    prefetch._reset();
    const d = makeDeps();
    const r = prefetch.schedulePrefetch([item()], { deps: d, stats: {} });
    assert(r.scheduled === 1, `expected 1 scheduled, got ${r.scheduled}`);
    await prefetch._drain();
    assert(d._downloads.length === 1, `expected 1 download, got ${d._downloads.length}`);
    assert(d._cacheCalls.length === 1, `expected 1 cacheTarball call, got ${d._cacheCalls.length}`);
    const c = d._cacheCalls[0];
    assert(c.n === 'leo-sdk' && c.v === '6.0.19', 'name/version forwarded to cache');
    assert(c.reason === 'first_publish', `reason should be first_publish, got ${c.reason}`);
    assert(c.retentionDays === 7, `retentionDays should be 7, got ${c.retentionDays}`);
    cleanupTemp(d._cacheDir);
  });

  // NEGATIVE: items without a cache trigger are never captured (the ~108k/day
  // baseline traffic stays out of the prefetcher).
  await asyncTest('skips items without a cache trigger', async () => {
    prefetch._reset();
    const d = makeDeps();
    const r = prefetch.schedulePrefetch(
      [item({ _cacheTrigger: null, firstPublish: false })],
      { deps: d, stats: {} }
    );
    await prefetch._drain();
    assert(r.scheduled === 0, `expected 0 scheduled, got ${r.scheduled}`);
    assert(d._downloads.length === 0, 'no download for non-trigger item');
    assert(d._cacheCalls.length === 0, 'no cache write for non-trigger item');
    cleanupTemp(d._cacheDir);
  });

  // NEGATIVE: unresolved items (no tarballUrl or no version) cannot be keyed or
  // fetched, so they are skipped — never crash the ingestion path.
  await asyncTest('skips unresolved items (missing url or version)', async () => {
    prefetch._reset();
    const d = makeDeps();
    const r = prefetch.schedulePrefetch(
      [item({ tarballUrl: null }), item({ version: '' })],
      { deps: d, stats: {} }
    );
    await prefetch._drain();
    assert(r.scheduled === 0, `expected 0 scheduled, got ${r.scheduled}`);
    assert(d._downloads.length === 0, 'no download for unresolved items');
    cleanupTemp(d._cacheDir);
  });

  // DEDUP: the same name@version scheduled twice in one batch downloads once.
  await asyncTest('dedups identical name@version within a batch', async () => {
    prefetch._reset();
    const d = makeDeps();
    const r = prefetch.schedulePrefetch([item(), item()], { deps: d, stats: {} });
    assert(r.scheduled === 1, `expected 1 scheduled after dedup, got ${r.scheduled}`);
    await prefetch._drain();
    assert(d._downloads.length === 1, `expected 1 download after dedup, got ${d._downloads.length}`);
    cleanupTemp(d._cacheDir);
  });

  // ALREADY CACHED: if the tarball is already on disk, no re-download happens.
  await asyncTest('skips download when the tarball is already cached on disk', async () => {
    prefetch._reset();
    const d = makeDeps();
    fs.writeFileSync(d.tarballCachePath('leo-sdk-6.0.19'), 'PREEXISTING');
    const stats = {};
    prefetch.schedulePrefetch([item()], { deps: d, stats });
    await prefetch._drain();
    assert(d._downloads.length === 0, 'no download when already cached');
    assert(d._cacheCalls.length === 0, 'no re-cache when already cached');
    assert(stats.prefetchAlreadyCached === 1, `expected 1 already-cached, got ${stats.prefetchAlreadyCached}`);
    cleanupTemp(d._cacheDir);
  });

  // BOUND: a burst past MUADDIB_PREFETCH_MAX_INFLIGHT is dropped (counted), so a
  // 96-version Miasma-style burst cannot unbound network/disk.
  await asyncTest('drops captures past the in-flight cap (bounded)', async () => {
    prefetch._reset();
    process.env.MUADDIB_PREFETCH_CONCURRENCY = '1';
    process.env.MUADDIB_PREFETCH_MAX_INFLIGHT = '2';
    let release;
    const gate = new Promise(r => { release = r; });
    const d = makeDeps({ gate });
    const stats = {};
    const items = [
      item({ version: '1' }), item({ version: '2' }),
      item({ version: '3' }), item({ version: '4' })
    ];
    const r = prefetch.schedulePrefetch(items, { deps: d, stats });
    assert(r.scheduled === 2, `cap=2 → expected 2 scheduled, got ${r.scheduled}`);
    assert(stats.prefetchDropped === 2, `expected 2 dropped, got ${stats.prefetchDropped}`);
    release();
    await prefetch._drain();
    delete process.env.MUADDIB_PREFETCH_CONCURRENCY;
    delete process.env.MUADDIB_PREFETCH_MAX_INFLIGHT;
    cleanupTemp(d._cacheDir);
  });

  // GRACEFUL FAILURE: a download error (e.g. the version was already pulled) does
  // not throw, writes nothing to cache, and is counted — the scan path still runs.
  await asyncTest('download failure is graceful (no throw, no cache write, counted)', async () => {
    prefetch._reset();
    const failUrl = 'https://registry.npmjs.org/leo-sdk/-/leo-sdk-6.0.19.tgz';
    const d = makeDeps({ failUrls: new Set([failUrl]) });
    const stats = {};
    prefetch.schedulePrefetch([item()], { deps: d, stats });
    await prefetch._drain();
    assert(d._cacheCalls.length === 0, 'no cache write on download failure');
    assert(stats.prefetchFailed === 1, `expected 1 failure counted, got ${stats.prefetchFailed}`);
    cleanupTemp(d._cacheDir);
  });

  // KILL SWITCH: MUADDIB_PREFETCH=0 disables the feature entirely.
  await asyncTest('MUADDIB_PREFETCH=0 disables prefetch entirely', async () => {
    prefetch._reset();
    process.env.MUADDIB_PREFETCH = '0';
    const d = makeDeps();
    const r = prefetch.schedulePrefetch([item()], { deps: d, stats: {} });
    assert(r.scheduled === 0, 'disabled → nothing scheduled');
    await prefetch._drain();
    assert(d._downloads.length === 0, 'disabled → no downloads');
    delete process.env.MUADDIB_PREFETCH;
    cleanupTemp(d._cacheDir);
  });
}

module.exports = { runTarballPrefetchTests };
