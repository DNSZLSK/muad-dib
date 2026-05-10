'use strict';

const http = require('http');
const { test, asyncTest, assert } = require('../test-utils');

async function runMonitorFeedTests() {
  console.log('\n=== MONITOR FEED TESTS ===\n');

  const {
    buildMonitorDaily,
    buildMonitorWindow,
    buildMonitorAll,
    SUPPORTED_RANGES,
    _safeReadJson,
    _aggregateDays
  } = require('../../src/runtime/monitor-feed.js');

  const { startServer } = require('../../src/runtime/serve.js');

  // --- Unit: buildMonitorDaily ---

  test('MONITOR-FEED: buildMonitorDaily returns expected shape', () => {
    const out = buildMonitorDaily();
    assert(out && typeof out === 'object', 'returns object');
    assert(typeof out.generated_at === 'string', 'has generated_at');
    assert(typeof out.engineVersion === 'string', 'has engineVersion');
    assert(out.today && typeof out.today === 'object', 'has today');
    assert(typeof out.today.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(out.today.date), 'today.date is YYYY-MM-DD');
    assert(typeof out.today.scanned === 'number', 'today.scanned is number');
    assert(out.today.suspectByTier && typeof out.today.suspectByTier === 'object', 'has suspectByTier');
    assert(typeof out.today.suspectByTier.t1 === 'number', 'suspectByTier.t1 is number');
    assert(out.today.errorsByType && typeof out.today.errorsByType === 'object', 'has errorsByType');
    assert(out.monitor && typeof out.monitor === 'object', 'has monitor block');
  });

  // --- Unit: buildMonitorWindow ---

  test('MONITOR-FEED: buildMonitorWindow(7d) returns 7 days', () => {
    const out = buildMonitorWindow('7d');
    assert(out.range === '7d', 'range is 7d');
    assert(Array.isArray(out.byDay), 'byDay is array');
    assert(out.byDay.length === 7, `byDay has 7 entries, got ${out.byDay.length}`);
    assert(out.totals && typeof out.totals.scanned === 'number', 'totals.scanned is number');
    assert(typeof out.totals.fp_rate_avg === 'number', 'totals.fp_rate_avg is number');
  });

  test('MONITOR-FEED: buildMonitorWindow(30d) returns 30 days', () => {
    const out = buildMonitorWindow('30d');
    assert(out.byDay.length === 30, `byDay has 30 entries, got ${out.byDay.length}`);
  });

  test('MONITOR-FEED: buildMonitorWindow rejects invalid range', () => {
    let threw = false;
    try { buildMonitorWindow('invalid'); } catch { threw = true; }
    assert(threw, 'should throw on invalid range');
  });

  test('MONITOR-FEED: buildMonitorWindow rejects "all"', () => {
    let threw = false;
    try { buildMonitorWindow('all'); } catch { threw = true; }
    assert(threw, 'should throw on "all" (use /monitor/stats instead)');
  });

  // --- Unit: buildMonitorAll ---

  test('MONITOR-FEED: buildMonitorAll returns expected shape', () => {
    const out = buildMonitorAll();
    assert(out.allTime && typeof out.allTime === 'object', 'has allTime');
    assert(typeof out.allTime.total_scanned === 'number', 'allTime.total_scanned is number');
    assert(out.detectionStats && typeof out.detectionStats === 'object', 'has detectionStats');
    assert(typeof out.detectionStats.total === 'number', 'detectionStats.total is number');
  });

  // --- Unit: helpers ---

  test('MONITOR-FEED: _aggregateDays sums and averages fp_rate', () => {
    const out = _aggregateDays([
      { scanned: 100, clean: 80, suspect: 15, false_positive: 2, confirmed: 3, sandbox_inconclusive: 0, fp_rate: 0.4 },
      { scanned: 200, clean: 180, suspect: 15, false_positive: 1, confirmed: 4, sandbox_inconclusive: 0, fp_rate: 0.2 }
    ]);
    assert(out.scanned === 300, 'sum scanned');
    assert(out.clean === 260, 'sum clean');
    assert(out.suspect === 30, 'sum suspect');
    assert(out.false_positive === 3, 'sum false_positive');
    assert(out.confirmed === 7, 'sum confirmed');
    assert(out.fp_rate_avg === 0.3, `avg fp_rate, got ${out.fp_rate_avg}`);
  });

  test('MONITOR-FEED: _safeReadJson returns null for missing files', () => {
    assert(_safeReadJson('/path/that/does/not/exist/anywhere.json') === null, 'missing file returns null');
  });

  test('MONITOR-FEED: SUPPORTED_RANGES includes 7d and 30d', () => {
    assert(SUPPORTED_RANGES.has('7d'), '7d supported');
    assert(SUPPORTED_RANGES.has('30d'), '30d supported');
  });

  // --- Integration: HTTP server endpoints ---

  function getJson(port, path, headers = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path,
        method: 'GET',
        headers
      }, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(body); } catch { /* leave null */ }
          resolve({ status: res.statusCode, body, json });
        });
      });
      req.on('error', reject);
      req.setTimeout(3000, () => { req.destroy(); reject(new Error('timeout')); });
      req.end();
    });
  }

  function pickPort() {
    return 30000 + Math.floor(Math.random() * 5000);
  }

  function startEphemeralServer() {
    return new Promise((resolve, reject) => {
      const port = pickPort();
      const server = startServer({ port });
      server.on('listening', () => resolve({ server, port }));
      server.on('error', reject);
    });
  }

  await asyncTest('MONITOR-FEED HTTP: GET /monitor/daily returns 200', async () => {
    const { server, port } = await startEphemeralServer();
    try {
      const r = await getJson(port, '/monitor/daily');
      assert(r.status === 200, `status 200, got ${r.status}`);
      assert(r.json && r.json.today, 'response has today');
    } finally {
      server.close();
    }
  });

  await asyncTest('MONITOR-FEED HTTP: GET /monitor/window?range=7d returns 200', async () => {
    const { server, port } = await startEphemeralServer();
    try {
      const r = await getJson(port, '/monitor/window?range=7d');
      assert(r.status === 200, `status 200, got ${r.status}`);
      assert(r.json && Array.isArray(r.json.byDay) && r.json.byDay.length === 7, 'byDay has 7 entries');
    } finally {
      server.close();
    }
  });

  await asyncTest('MONITOR-FEED HTTP: GET /monitor/window?range=invalid returns 400', async () => {
    const { server, port } = await startEphemeralServer();
    try {
      const r = await getJson(port, '/monitor/window?range=invalid');
      assert(r.status === 400, `status 400, got ${r.status}`);
      assert(r.json && r.json.error === 'invalid_range', 'returns invalid_range error');
    } finally {
      server.close();
    }
  });

  await asyncTest('MONITOR-FEED HTTP: GET /monitor/window without range defaults to 7d', async () => {
    const { server, port } = await startEphemeralServer();
    try {
      const r = await getJson(port, '/monitor/window');
      assert(r.status === 200, `status 200, got ${r.status}`);
      assert(r.json.range === '7d', 'defaults to 7d');
    } finally {
      server.close();
    }
  });

  await asyncTest('MONITOR-FEED HTTP: GET /monitor/stats returns 200', async () => {
    const { server, port } = await startEphemeralServer();
    try {
      const r = await getJson(port, '/monitor/stats');
      assert(r.status === 200, `status 200, got ${r.status}`);
      assert(r.json && r.json.allTime, 'response has allTime');
    } finally {
      server.close();
    }
  });

  await asyncTest('MONITOR-FEED HTTP: unknown route returns 404 with monitor in error', async () => {
    const { server, port } = await startEphemeralServer();
    try {
      const r = await getJson(port, '/monitor/nope');
      assert(r.status === 404, `status 404, got ${r.status}`);
      assert(typeof r.json.error === 'string' && r.json.error.includes('/monitor/daily'), 'error mentions /monitor/daily route');
    } finally {
      server.close();
    }
  });

  await asyncTest('MONITOR-FEED HTTP: respects MUADDIB_FEED_TOKEN auth', async () => {
    const prev = process.env.MUADDIB_FEED_TOKEN;
    process.env.MUADDIB_FEED_TOKEN = 'test-token-monitor';
    try {
      const { server, port } = await startEphemeralServer();
      try {
        const noAuth = await getJson(port, '/monitor/daily');
        assert(noAuth.status === 401, `expected 401 without auth, got ${noAuth.status}`);

        const withAuth = await getJson(port, '/monitor/daily', { Authorization: 'Bearer test-token-monitor' });
        assert(withAuth.status === 200, `expected 200 with auth, got ${withAuth.status}`);
      } finally {
        server.close();
      }
    } finally {
      if (prev === undefined) delete process.env.MUADDIB_FEED_TOKEN;
      else process.env.MUADDIB_FEED_TOKEN = prev;
    }
  });
}

module.exports = { runMonitorFeedTests };
