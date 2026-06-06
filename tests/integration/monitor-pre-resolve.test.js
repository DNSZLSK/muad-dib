'use strict';

const { test, asyncTest, assert } = require('../test-utils');

async function runMonitorPreResolveTests() {
  console.log('\n=== MONITOR PRE-RESOLVE TESTS ===\n');

  const ingestion = require('../../src/monitor/ingestion.js');
  const { EventEmitter } = require('events');

  // ── HTTP absolute-deadline (wedge fix) ───────────────────────────────────
  // Node's `{ timeout }` option is socket-INACTIVITY only. A response whose body
  // trickles forever (heartbeats, or a feed that never sends 'end') keeps the
  // socket "active" so that timeout never fires and httpsGet (which resolves
  // only on 'end') hangs — wedging the poll loop. We inject a fake low-level
  // client (_deps.https) to exercise the real httpsGet/httpsPost deadline logic
  // without TLS, asserting it rejects AND destroys the socket.

  // A fake req whose .destroy(err) emits 'error' (mimics Node), tracking the err.
  function makeFakeReq(track) {
    const req = new EventEmitter();
    let destroyed = false;
    req.write = () => {};
    req.end = () => {};
    req.destroy = (err) => {
      if (destroyed) return;
      destroyed = true;
      if (track) track.destroyedWith = err || null, track.destroyed = true;
      if (req._onDestroy) req._onDestroy();
      if (err) req.emit('error', err);
    };
    return req;
  }

  await asyncTest('HTTP-DEADLINE: a normal response resolves and does NOT destroy the socket', async () => {
    const real = ingestion._deps.https;
    const track = { destroyed: false };
    const make = (cb) => {
      const req = makeFakeReq(track);
      const res = new EventEmitter();
      res.statusCode = 200;
      res.resume = () => {};
      setImmediate(() => { cb(res); res.emit('data', Buffer.from('{"ok":true}')); res.emit('end'); });
      return req;
    };
    ingestion._deps.https = { get: (_u, _o, cb) => make(cb), request: (_o, cb) => make(cb) };
    try {
      const body = await ingestion.httpsGet('https://example.test/ok', 1000, 1000);
      assert(body === '{"ok":true}', `body should round-trip, got ${body}`);
      assert(track.destroyed === false, 'a clean response must NOT destroy the socket (deadline cleared)');
    } finally {
      ingestion._deps.https = real;
    }
  });

  await asyncTest('HTTP-DEADLINE: a trickling body that never ends rejects within the absolute deadline', async () => {
    const real = ingestion._deps.https;
    const track = { destroyed: false };
    const make = (cb) => {
      const req = makeFakeReq(track);
      const res = new EventEmitter();
      res.statusCode = 200;
      res.resume = () => {};
      let timer;
      req._onDestroy = () => clearInterval(timer);
      setImmediate(() => {
        cb(res);
        timer = setInterval(() => res.emit('data', Buffer.from('.')), 5); // trickle forever, never 'end'
      });
      return req;
    };
    ingestion._deps.https = { get: (_u, _o, cb) => make(cb), request: (_o, cb) => make(cb) };
    const t0 = Date.now();
    let threw = null;
    try {
      await ingestion.httpsGet('https://example.test/trickle', 1000, 40); // 40ms deadline
    } catch (e) { threw = e; } finally {
      ingestion._deps.https = real;
    }
    const elapsed = Date.now() - t0;
    assert(threw !== null, 'trickling response should reject, not hang');
    assert(/deadline/i.test(threw.message), `error should mention deadline, got: ${threw && threw.message}`);
    assert(track.destroyed === true && track.destroyedWith, 'req.destroy(err) must be called to free the socket');
    assert(elapsed < 500, `should reject within ~deadline, took ${elapsed}ms`);
  });

  await asyncTest('HTTP-DEADLINE: a response exceeding MAX_RESPONSE_BYTES rejects and destroys the socket', async () => {
    const real = ingestion._deps.https;
    const track = { destroyed: false };
    const make = (cb) => {
      const req = makeFakeReq(track);
      const res = new EventEmitter();
      res.statusCode = 200;
      res.resume = () => {};
      // One oversized "chunk" — only .length matters; the cap branch destroys
      // before chunks.push, so we never allocate 64MB.
      setImmediate(() => { cb(res); res.emit('data', { length: ingestion.MAX_RESPONSE_BYTES + 1 }); });
      return req;
    };
    ingestion._deps.https = { get: (_u, _o, cb) => make(cb), request: (_o, cb) => make(cb) };
    let threw = null;
    try {
      await ingestion.httpsGet('https://example.test/huge', 1000, 1000);
    } catch (e) { threw = e; } finally {
      ingestion._deps.https = real;
    }
    assert(threw !== null, 'oversized response should reject');
    assert(/exceeded/i.test(threw.message), `error should mention exceeded, got: ${threw && threw.message}`);
    assert(track.destroyed === true, 'socket must be destroyed on overflow');
  });

  // ── Unit tests on the batch helpers ──────────────────────────────────────

  await asyncTest('PRE-RESOLVE npm: happy path sets tarballUrl + _npmInfo + stats', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async () => JSON.stringify({
      name: 'pkg-a',
      'dist-tags': { latest: '1.0.0' },
      versions: {
        '1.0.0': {
          version: '1.0.0',
          dist: { tarball: 'https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.0.tgz', unpackedSize: 12345 },
          scripts: { postinstall: 'node ./post.js' }
        }
      },
      time: { '1.0.0': new Date().toISOString() }
    });
    const items = [
      { name: 'pkg-a', version: '', ecosystem: 'npm', tarballUrl: null }
    ];
    const stats = {};
    try {
      await ingestion.preResolveNpmBatch(items, stats);
      assert(items[0].tarballUrl === 'https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.0.tgz',
        `tarballUrl should be set, got ${items[0].tarballUrl}`);
      assert(items[0].version === '1.0.0', `version should be 1.0.0, got ${items[0].version}`);
      assert(items[0].unpackedSize === 12345, `unpackedSize should be 12345, got ${items[0].unpackedSize}`);
      assert(items[0]._npmInfo && typeof items[0]._npmInfo === 'object',
        '_npmInfo should be attached for resolveTarballAndScan downstream logic');
      assert(stats.npmPreResolved === 1, `stats.npmPreResolved should be 1, got ${stats.npmPreResolved}`);
      assert(!stats.npmPreResolveFailed, `stats.npmPreResolveFailed should be falsy, got ${stats.npmPreResolveFailed}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE npm: failure leaves item untouched (lazy fallback preserved)', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async () => { throw new Error('simulated 404'); };
    const items = [
      { name: 'pkg-missing', version: '', ecosystem: 'npm', tarballUrl: null }
    ];
    const stats = {};
    try {
      await ingestion.preResolveNpmBatch(items, stats);
      assert(items[0].tarballUrl === null,
        `tarballUrl must stay null on failure (lazy fallback), got ${items[0].tarballUrl}`);
      assert(!items[0]._npmInfo,
        '_npmInfo must NOT be set on failure — absence is the signal for lazy fallback');
      assert(stats.npmPreResolveFailed === 1, `npmPreResolveFailed should be 1, got ${stats.npmPreResolveFailed}`);
      assert(!stats.npmPreResolved, `npmPreResolved should be falsy, got ${stats.npmPreResolved}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE npm: mixed batch (some succeed, some fail) — no item is lost', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('pkg-ok')) {
        return JSON.stringify({
          name: 'pkg-ok',
          'dist-tags': { latest: '1.0.0' },
          versions: {
            '1.0.0': { version: '1.0.0', dist: { tarball: 'https://x/pkg-ok-1.0.0.tgz' }, scripts: {} }
          },
          time: { '1.0.0': new Date().toISOString() }
        });
      }
      throw new Error('simulated registry error');
    };
    const items = [
      { name: 'pkg-ok', version: '', ecosystem: 'npm', tarballUrl: null },
      { name: 'pkg-bad', version: '', ecosystem: 'npm', tarballUrl: null }
    ];
    const stats = {};
    try {
      await ingestion.preResolveNpmBatch(items, stats);
      assert(items[0].tarballUrl !== null, 'pkg-ok should be resolved');
      assert(items[1].tarballUrl === null, 'pkg-bad should stay null (lazy fallback)');
      assert(items.length === 2, 'No item must be dropped from the batch');
      assert(stats.npmPreResolved === 1, `npmPreResolved=1 expected, got ${stats.npmPreResolved}`);
      assert(stats.npmPreResolveFailed === 1, `npmPreResolveFailed=1 expected, got ${stats.npmPreResolveFailed}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  // ── Stage 2.1 — _npmInfo reputation signals ──────────────────────────────

  await asyncTest('PRE-RESOLVE npm: _npmInfo carries age_days from time.created (Stage 2.1)', async () => {
    const realGet = ingestion._deps.httpsGet;
    // 200 days ago — easy to verify
    const created = new Date(Date.now() - 200 * 86_400_000).toISOString();
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('api.npmjs.org/downloads')) {
        return JSON.stringify({ downloads: 12345 });
      }
      return JSON.stringify({
        name: 'pkg-aged',
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': { version: '1.0.0', dist: { tarball: 'https://r/pkg-aged-1.0.0.tgz' }, scripts: {} } },
        time: { created, '1.0.0': new Date().toISOString() }
      });
    };
    const items = [{ name: 'pkg-aged', version: '', ecosystem: 'npm', tarballUrl: null }];
    try {
      await ingestion.preResolveNpmBatch(items, {});
      assert(items[0]._npmInfo, '_npmInfo must be set');
      assert(items[0]._npmInfo.age_days >= 199 && items[0]._npmInfo.age_days <= 201,
        `age_days should be ~200, got ${items[0]._npmInfo.age_days}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE npm: _npmInfo.version_count counts entries in versions (Stage 2.1)', async () => {
    const realGet = ingestion._deps.httpsGet;
    const now = new Date().toISOString();
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('api.npmjs.org/downloads')) return JSON.stringify({ downloads: 1 });
      return JSON.stringify({
        name: 'pkg-many',
        'dist-tags': { latest: '3.0.0' },
        versions: {
          '1.0.0': { version: '1.0.0', dist: { tarball: 'https://r/pkg-many-1.0.0.tgz' }, scripts: {} },
          '2.0.0': { version: '2.0.0', dist: { tarball: 'https://r/pkg-many-2.0.0.tgz' }, scripts: {} },
          '3.0.0': { version: '3.0.0', dist: { tarball: 'https://r/pkg-many-3.0.0.tgz' }, scripts: {} }
        },
        time: { created: now, '1.0.0': now, '2.0.0': now, '3.0.0': now }
      });
    };
    const items = [{ name: 'pkg-many', version: '', ecosystem: 'npm', tarballUrl: null }];
    try {
      await ingestion.preResolveNpmBatch(items, {});
      assert(items[0]._npmInfo.version_count === 3,
        `version_count should be 3, got ${items[0]._npmInfo.version_count}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE npm: _npmInfo.weekly_downloads stashed from api.npmjs.org (Stage 2.1)', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('api.npmjs.org/downloads')) {
        return JSON.stringify({ downloads: 42_000_000 });
      }
      return JSON.stringify({
        name: 'pkg-popular',
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': { version: '1.0.0', dist: { tarball: 'https://r/pkg-popular-1.0.0.tgz' }, scripts: {} } },
        time: { created: new Date().toISOString(), '1.0.0': new Date().toISOString() }
      });
    };
    const items = [{ name: 'pkg-popular', version: '', ecosystem: 'npm', tarballUrl: null }];
    try {
      await ingestion.preResolveNpmBatch(items, {});
      assert(items[0]._npmInfo.weekly_downloads === 42_000_000,
        `weekly_downloads should be 42M, got ${items[0]._npmInfo.weekly_downloads}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE npm: weekly_downloads failure → null (best-effort, not -1)', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('api.npmjs.org/downloads')) {
        throw new Error('test: simulated downloads endpoint failure');
      }
      return JSON.stringify({
        name: 'pkg-no-downloads',
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': { version: '1.0.0', dist: { tarball: 'https://r/pkg-no-downloads-1.0.0.tgz' }, scripts: {} } },
        time: { created: new Date().toISOString(), '1.0.0': new Date().toISOString() }
      });
    };
    const items = [{ name: 'pkg-no-downloads', version: '', ecosystem: 'npm', tarballUrl: null }];
    try {
      await ingestion.preResolveNpmBatch(items, {});
      assert(items[0]._npmInfo.weekly_downloads === null,
        `weekly_downloads on failure must be null (so triage treats it as missing, not 0), got ${items[0]._npmInfo.weekly_downloads}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE pypi: happy path sets tarballUrl + stats', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async () => JSON.stringify({
      info: { name: 'pypi-pkg-a', version: '2.0.0' },
      urls: [
        { url: 'https://files.pythonhosted.org/packages/.../pypi-pkg-a-2.0.0.tar.gz', packagetype: 'sdist', filename: 'pypi-pkg-a-2.0.0.tar.gz' }
      ]
    });
    const items = [
      { name: 'pypi-pkg-a', version: '2.0.0', ecosystem: 'pypi', tarballUrl: null }
    ];
    const stats = {};
    try {
      await ingestion.preResolvePyPIBatch(items, stats);
      assert(items[0].tarballUrl && items[0].tarballUrl.includes('pypi-pkg-a'),
        `tarballUrl should be set, got ${items[0].tarballUrl}`);
      assert(stats.pypiPreResolved === 1, `pypiPreResolved should be 1, got ${stats.pypiPreResolved}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE pypi: failure leaves item untouched (lazy fallback preserved)', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async () => { throw new Error('simulated PyPI 404'); };
    const items = [
      { name: 'pypi-missing', version: '0.0.0', ecosystem: 'pypi', tarballUrl: null }
    ];
    const stats = {};
    try {
      await ingestion.preResolvePyPIBatch(items, stats);
      assert(items[0].tarballUrl === null, `tarballUrl must stay null, got ${items[0].tarballUrl}`);
      assert(stats.pypiPreResolveFailed === 1, `pypiPreResolveFailed should be 1, got ${stats.pypiPreResolveFailed}`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  // ── Integration: pollNpmChanges now pre-resolves before pushing ──────────

  await asyncTest('PRE-RESOLVE integration: pollNpmChanges pushes items with tarballUrl after successful pre-resolve', async () => {
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('_changes')) {
        return JSON.stringify({
          last_seq: 200,
          results: [
            { id: 'pkg-resolves', deleted: false }
          ]
        });
      }
      // registry packument call (from preResolveNpmBatch → getNpmLatestTarball)
      return JSON.stringify({
        name: 'pkg-resolves',
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': { version: '1.0.0', dist: { tarball: 'https://r/pkg-resolves-1.0.0.tgz' }, scripts: {} }
        },
        time: { '1.0.0': new Date().toISOString() }
      });
    };
    const state = { npmLastSeq: 100 };
    const queue = [];
    const stats = {};
    try {
      const queued = await ingestion.pollNpmChanges(state, queue, stats);
      assert(queued === 1, `pollNpmChanges should queue 1 item, got ${queued}`);
      assert(queue.length === 1, `scanQueue should have 1 item, got ${queue.length}`);
      assert(queue[0].tarballUrl && queue[0].tarballUrl.includes('pkg-resolves'),
        `Item should reach queue with tarballUrl pre-set, got ${queue[0].tarballUrl}`);
      assert(queue[0]._npmInfo, '_npmInfo should be attached for downstream ATO/burst/fast-track');
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE integration: pollNpmChanges does NOT drop items when pre-resolve fails (lazy fallback path)', async () => {
    const realGet = ingestion._deps.httpsGet;
    let changesCallCount = 0;
    ingestion._deps.httpsGet = async (url) => {
      if (url.includes('_changes')) {
        changesCallCount++;
        return JSON.stringify({
          last_seq: 300,
          results: [{ id: 'pkg-lazy', deleted: false }]
        });
      }
      throw new Error('simulated registry outage');
    };
    const state = { npmLastSeq: 100 };
    const queue = [];
    const stats = {};
    try {
      const queued = await ingestion.pollNpmChanges(state, queue, stats);
      assert(queued === 1, `Item must still be queued even when pre-resolve fails, got queued=${queued}`);
      assert(queue.length === 1, `Item must reach scanQueue, got length=${queue.length}`);
      assert(queue[0].tarballUrl === null,
        `tarballUrl should be null → workers fall back to lazy getNpmLatestTarball, got ${queue[0].tarballUrl}`);
      assert(!queue[0]._npmInfo, '_npmInfo must be absent so the lazy path engages');
      assert(stats.npmPreResolveFailed === 1, `failure should be counted, got ${stats.npmPreResolveFailed}`);
      assert(changesCallCount === 1, '_changes URL should have been called exactly once');
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('PRE-RESOLVE integration: pollPyPIChangelog pre-resolves PyPI items', async () => {
    const realPost = ingestion._deps.httpsPost;
    const realGet = ingestion._deps.httpsGet;
    // Stub PyPI XML-RPC response for changelog_since_serial.
    // Serial must stay close to state.pypiLastSerial below — gap > PYPI_CATCHUP_MAX
    // would trigger the catch-up skip branch and queue nothing.
    ingestion._deps.httpsPost = async () => {
      return `<?xml version="1.0"?><methodResponse><params><param><value><array><data>
        <value><array><data>
          <value><string>pypi-test-pkg</string></value>
          <value><string>1.2.3</string></value>
          <value><int>1716800000</int></value>
          <value><string>new release</string></value>
          <value><int>1002</int></value>
        </data></array></value>
      </data></array></value></param></params></methodResponse>`;
    };
    // Stub PyPI JSON API (called by getPyPITarballUrl through preResolvePyPIBatch)
    ingestion._deps.httpsGet = async () => JSON.stringify({
      info: { name: 'pypi-test-pkg', version: '1.2.3' },
      urls: [
        { url: 'https://files.pythonhosted.org/packages/x/pypi-test-pkg-1.2.3.tar.gz', packagetype: 'sdist', filename: 'pypi-test-pkg-1.2.3.tar.gz' }
      ]
    });
    const state = { pypiLastSerial: 1000 };
    const queue = [];
    const stats = {};
    try {
      const queued = await ingestion.pollPyPIChangelog(state, queue, stats);
      assert(queued === 1, `pollPyPIChangelog should queue 1 item, got ${queued}`);
      assert(queue.length === 1, `scanQueue should have 1 item, got ${queue.length}`);
      assert(queue[0].tarballUrl && queue[0].tarballUrl.includes('pypi-test-pkg'),
        `PyPI item should reach queue with tarballUrl set, got ${queue[0].tarballUrl}`);
      assert(stats.pypiPreResolved === 1, `pypiPreResolved should be 1, got ${stats.pypiPreResolved}`);
    } finally {
      ingestion._deps.httpsPost = realPost;
      ingestion._deps.httpsGet = realGet;
    }
  });

  // ── Empty batch is a no-op (defensive) ───────────────────────────────────

  await asyncTest('PRE-RESOLVE: empty batch is a no-op (does not throw, does not call registry)', async () => {
    const realGet = ingestion._deps.httpsGet;
    let calls = 0;
    ingestion._deps.httpsGet = async () => { calls++; return '{}'; };
    const stats = {};
    try {
      await ingestion.preResolveNpmBatch([], stats);
      await ingestion.preResolvePyPIBatch([], stats);
      assert(calls === 0, `Empty batch must not call registry, got ${calls} call(s)`);
    } finally {
      ingestion._deps.httpsGet = realGet;
    }
  });
}

module.exports = { runMonitorPreResolveTests };
