'use strict';
// Metadata lane, step 2: publish facts fetched from the registry with bounded reads.
// The registry is simulated from real documents (tests/samples/registry/); the default HTTP
// reader is tested against a local HTTP server.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const http = require('http');
const { test, asyncTest, assert } = require('../test-utils');

const DIR = path.join(__dirname, '..', 'samples', 'registry');
const raw = (file) => zlib.gunzipSync(fs.readFileSync(path.join(DIR, file)));
const load = (file) => JSON.parse(raw(file).toString('utf8'));
const MiB = 1024 * 1024;

// Fake registry: routes keyed by "<accept>|<path>", body served as bytes. Honors maxBytes the
// way the real reader does (truncated, no body). Records every request.
function fakeRegistry(routes) {
  const requests = [];
  const httpGet = async (url, opts = {}) => {
    const accept = /install-v1/.test(opts.accept || '') ? 'abbr' : 'json';
    const p = new URL(url).pathname;
    requests.push(accept + '|' + p);
    const r = routes[accept + '|' + p] || routes['*|' + p];
    if (!r) return { status: 404, body: null, truncated: false };
    if (typeof r === 'number') return { status: r, body: null, truncated: false };
    if (typeof opts.maxBytes === 'number' && r.length > opts.maxBytes) return { status: 200, body: null, truncated: true };
    return { status: 200, body: r, truncated: false };
  };
  return { httpGet, requests };
}
function fakeLimiter() {
  const calls = { acquire: 0, release: 0, signal429: [] };
  return {
    calls,
    acquireRegistrySlot: async () => { calls.acquire++; },
    releaseRegistrySlot: () => { calls.release++; },
    signal429: (host) => { calls.signal429.push(host); }
  };
}
const versionDoc = (full, v) => Buffer.from(JSON.stringify(full.versions[v]));

async function runMetadataLaneFetchTests() {
  console.log('\n=== METADATA LANE: FETCH (bounded) ===\n');
  const { fetchPublishFacts, defaultHttpGet } = require('../../src/monitor/metadata-lane/fetch');
  const { extractPublishFacts } = require('../../src/monitor/metadata-lane/extract');
  const all = (doc) => extractPublishFacts(doc, { max: 100000 });

  const WIX = load('wix__site-service-editor-context--established_new_version.json.gz');
  const WIX_RAW = raw('wix__site-service-editor-context--established_new_version.json.gz');
  const LARGE = load('cezar-cli--large_document.json.gz');
  const LARGE_RAW = raw('cezar-cli--large_document.json.gz');
  const ABBR_RAW = raw('cezar-cli--abbreviated.json.gz');
  const V0200_RAW = raw('cezar-cli--version-0.20.0.json.gz');
  const US = load('underscore--tied_times.json.gz');
  const US_RAW = raw('underscore--tied_times.json.gz');
  const US_ABBR_RAW = raw('underscore--abbreviated.json.gz');

  const WIX_PATH = '/' + encodeURIComponent('@wix/site-service-editor-context');

  await asyncTest('METADATA-FETCH: a document under the cap is read in one request and gives the extract facts', async () => {
    const reg = fakeRegistry({ ['json|' + WIX_PATH]: WIX_RAW });
    const r = await fetchPublishFacts('@wix/site-service-editor-context', '1.0.9', { httpGet: reg.httpGet, limiter: fakeLimiter() });
    assert(r.status === 'ok' && r.source === 'full' && r.requests === 1, 'got ' + JSON.stringify({ status: r.status, source: r.source, requests: r.requests }));
    const f = r.facts.find(x => x.version === '1.0.9');
    const e = all(WIX).find(x => x.version === '1.0.9');
    assert(f && f.previousVersion === e.previousVersion && f.publishedAt === e.publishedAt && f.publishTimeSource === 'registry', 'fact: ' + JSON.stringify(f));
  });

  await asyncTest('METADATA-FETCH: a document over the cap falls back to the abbreviated and version documents, same facts as the full document', async () => {
    const e = all(LARGE).find(x => x.version === '0.20.0');
    const reg = fakeRegistry({
      'json|/cezar-cli': LARGE_RAW,
      'abbr|/cezar-cli': ABBR_RAW,
      'json|/cezar-cli/0.20.0': V0200_RAW,
      ['json|/cezar-cli/' + encodeURIComponent(e.previousVersion)]: versionDoc(LARGE, e.previousVersion)
    });
    const r = await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: reg.httpGet, limiter: fakeLimiter(), seenAt: 1794724200000 });
    assert(r.status === 'ok' && r.source === 'abbreviated' && r.requests === 4, 'got ' + JSON.stringify({ status: r.status, source: r.source, requests: r.requests, req: reg.requests }));
    const f = r.facts[0];
    assert(f.previousVersion === e.previousVersion, `previous ${f.previousVersion} vs full ${e.previousVersion}`);
    assert(JSON.stringify(f.hookChanges) === JSON.stringify(e.hookChanges) && f.firstPublish === false && f.publisher === e.publisher && f.oidc === e.oidc && f.notLatest === e.notLatest, 'fact: ' + JSON.stringify(f));
  });

  await asyncTest('METADATA-FETCH: the fallback has no publish date, only approximate times with their source', async () => {
    const e = all(LARGE).find(x => x.version === '0.20.0');
    const reg = fakeRegistry({
      'json|/cezar-cli': LARGE_RAW, 'abbr|/cezar-cli': ABBR_RAW, 'json|/cezar-cli/0.20.0': V0200_RAW,
      ['json|/cezar-cli/' + encodeURIComponent(e.previousVersion)]: versionDoc(LARGE, e.previousVersion)
    });
    const r = await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: reg.httpGet, limiter: fakeLimiter(), seenAt: 1794724200000 });
    const f = r.facts[0];
    assert(f.publishedAt === null && f.publishTimeSource === null && f.previousPublishedAt === null, 'no date may be guessed: ' + JSON.stringify(f));
    const src = Object.fromEntries((f.approxPublishTimes || []).map(a => [a.source, a.at]));
    assert(src.monitor_seen === 1794724200000 && src.abbreviated_modified === Date.parse(JSON.parse(ABBR_RAW).modified), 'approx: ' + JSON.stringify(f.approxPublishTimes));
  });

  await asyncTest('METADATA-FETCH: fallback previous version follows the publish order, ties included (underscore)', async () => {
    const facts = all(US);
    const routes = { 'json|/underscore': US_RAW, 'abbr|/underscore': US_ABBR_RAW };
    for (const v of Object.keys(US.versions)) routes['json|/underscore/' + encodeURIComponent(v)] = versionDoc(US, v);
    const reg = fakeRegistry(routes);
    let checked = 0;
    for (const e of facts) {
      const r = await fetchPublishFacts('underscore', e.version, { httpGet: reg.httpGet, limiter: fakeLimiter(), maxDocBytes: 1024 });
      assert(r.status === 'ok' && r.source === 'abbreviated', e.version + ': ' + r.status);
      assert(r.facts[0].previousVersion === e.previousVersion && r.facts[0].firstPublish === e.firstPublish, `${e.version}: previous ${r.facts[0].previousVersion} vs full ${e.previousVersion}`);
      checked++;
    }
    assert(checked === Object.keys(US.versions).length, 'checked ' + checked);
  });

  await asyncTest('METADATA-FETCH: an abbreviated document over its own cap is too_large, with no facts, and logged', async () => {
    const reg = fakeRegistry({ 'json|/cezar-cli': LARGE_RAW, 'abbr|/cezar-cli': ABBR_RAW });
    const lines = [];
    const realLog = console.log;
    console.log = (...a) => { lines.push(a.join(' ')); };
    let r;
    try {
      r = await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: reg.httpGet, limiter: fakeLimiter(), maxAbbrevBytes: 1 * MiB });
    } finally {
      console.log = realLog;
    }
    assert(r.status === 'too_large' && r.facts.length === 0 && r.requests === 2, 'got ' + JSON.stringify({ status: r.status, n: r.facts.length, requests: r.requests }));
    assert(lines.includes(`[LANE] TOO_LARGE: cezar-cli@0.20.0 abbreviated cap=${1 * MiB}`), 'lines: ' + JSON.stringify(lines));
  });

  await asyncTest('METADATA-FETCH: 404 is not_found, with no facts', async () => {
    const reg = fakeRegistry({});
    const r = await fetchPublishFacts('no-such-pkg-x', '1.0.0', { httpGet: reg.httpGet, limiter: fakeLimiter() });
    assert(r.status === 'not_found' && r.facts.length === 0 && r.requests === 1, 'got ' + JSON.stringify(r));
  });

  await asyncTest('METADATA-FETCH: 429 backs the registry off and is not retried', async () => {
    const lim = fakeLimiter();
    const reg = fakeRegistry({ 'json|/cezar-cli': 429 });
    const r = await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: reg.httpGet, limiter: lim });
    assert(r.status === 'rate_limited' && r.facts.length === 0 && reg.requests.length === 1, 'got ' + JSON.stringify({ status: r.status, req: reg.requests }));
    assert(lim.calls.signal429.length === 1 && lim.calls.signal429[0] === 'registry.npmjs.org', 'signal429: ' + JSON.stringify(lim.calls.signal429));
  });

  await asyncTest('METADATA-FETCH: a malformed body is an error, with no facts', async () => {
    const reg = fakeRegistry({ 'json|/cezar-cli': Buffer.from('{"name":"cezar-cli","versions":{') });
    const r = await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: reg.httpGet, limiter: fakeLimiter() });
    assert(r.status === 'error' && r.facts.length === 0, 'got ' + JSON.stringify(r));
  });

  await asyncTest('METADATA-FETCH: an invalid name makes no request; a scoped name is encoded', async () => {
    const reg = fakeRegistry({ ['json|' + WIX_PATH]: WIX_RAW });
    const bad = await fetchPublishFacts('../etc/passwd', '1.0.0', { httpGet: reg.httpGet, limiter: fakeLimiter() });
    assert(bad.status === 'invalid_name' && reg.requests.length === 0, 'got ' + JSON.stringify(bad));
    await fetchPublishFacts('@wix/site-service-editor-context', '1.0.9', { httpGet: reg.httpGet, limiter: fakeLimiter() });
    assert(reg.requests[0] === 'json|' + WIX_PATH, 'request: ' + reg.requests[0]);
  });

  await asyncTest('METADATA-FETCH: every request holds a registry slot and releases it, error paths included', async () => {
    const lim = fakeLimiter();
    const reg = fakeRegistry({ 'json|/cezar-cli': LARGE_RAW, 'abbr|/cezar-cli': ABBR_RAW, 'json|/cezar-cli/0.20.0': 500 });
    await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: reg.httpGet, limiter: lim });
    assert(lim.calls.acquire === reg.requests.length && lim.calls.release === lim.calls.acquire, 'calls ' + JSON.stringify(lim.calls) + ' requests ' + reg.requests.length);
  });

  await asyncTest('METADATA-FETCH: a document over 1 MiB logs its size and read times; a small one logs nothing', async () => {
    const lines = [];
    const realLog = console.log;
    console.log = (...a) => { lines.push(a.join(' ')); };
    try {
      const e = all(LARGE).find(x => x.version === '0.20.0');
      const big = fakeRegistry({
        'json|/cezar-cli': LARGE_RAW, 'abbr|/cezar-cli': ABBR_RAW, 'json|/cezar-cli/0.20.0': V0200_RAW,
        ['json|/cezar-cli/' + encodeURIComponent(e.previousVersion)]: versionDoc(LARGE, e.previousVersion)
      });
      await fetchPublishFacts('cezar-cli', '0.20.0', { httpGet: big.httpGet, limiter: fakeLimiter() });
      await fetchPublishFacts('@wix/site-service-editor-context', '1.0.9', { httpGet: fakeRegistry({ ['json|' + WIX_PATH]: WIX_RAW }).httpGet, limiter: fakeLimiter() });
    } finally {
      console.log = realLog;
    }
    const doc = lines.filter(l => l.startsWith('[LANE] DOC:'));
    assert(doc.length === 1, 'one line (the 2.4 MiB abbreviated document), got ' + JSON.stringify(doc));
    assert(/^\[LANE\] DOC: cezar-cli kind=abbreviated bytes=\d+ parseMs=\d+(\.\d+)? extractMs=\d+(\.\d+)?$/.test(doc[0]), 'line: ' + doc[0]);
  });

  test('METADATA-FETCH: the contract says a status without facts never lowers priority', () => {
    const { STATUSES_WITHOUT_FACTS } = require('../../src/monitor/metadata-lane/fetch');
    assert(JSON.stringify(STATUSES_WITHOUT_FACTS) === JSON.stringify(['error', 'invalid_name', 'not_found', 'rate_limited', 'too_large']), 'got ' + JSON.stringify(STATUSES_WITHOUT_FACTS));
  });

  // The real reader against a local server streaming 10 MiB: it stops at the cap.
  await asyncTest('METADATA-FETCH: the HTTP reader stops reading at the byte cap', async () => {
    const chunk = Buffer.alloc(64 * 1024, 0x61);
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      let sent = 0;
      const pump = () => {
        while (sent < 10 * MiB) {
          sent += chunk.length;
          if (!res.write(chunk)) { res.once('drain', pump); return; }
        }
        res.end();
      };
      res.on('error', () => {});
      pump();
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    try {
      const url = `http://127.0.0.1:${server.address().port}/x`;
      const r = await defaultHttpGet(url, { maxBytes: 2 * MiB, timeoutMs: 10000 });
      assert(r.status === 200 && r.truncated === true && r.body === null, 'got ' + JSON.stringify({ status: r.status, truncated: r.truncated }));
      assert(r.bytesRead <= 2 * MiB + 256 * 1024, 'read ' + r.bytesRead + ' bytes for a 2 MiB cap');
      const small = await defaultHttpGet(url, { maxBytes: 16 * MiB, timeoutMs: 10000 });
      assert(small.status === 200 && small.truncated === false && small.body.length === 10 * MiB, 'full read: ' + JSON.stringify({ t: small.truncated, n: small.body && small.body.length }));
    } finally {
      server.closeAllConnections && server.closeAllConnections();
      await new Promise(r => server.close(r));
    }
  });
}

module.exports = { runMetadataLaneFetchTests };
