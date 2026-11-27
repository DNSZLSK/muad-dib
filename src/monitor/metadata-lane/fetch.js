'use strict';
/**
 * Metadata lane: publish facts fetched from the npm registry, with bounded reads.
 *
 * - Full document when it fits in maxDocBytes: facts from extractPublishFacts (registry dates).
 * - Over that cap: the abbreviated document (install-v1: version list in publish order,
 *   dist-tags, no dates) within maxAbbrevBytes, then the single-version documents of the
 *   version and of its previous version. No date is guessed in this fallback.
 * - Every request holds a registry slot (shared limiter). A 429 backs the registry off and is
 *   not retried here: the caller decides.
 * - Bodies are read as a stream and the read stops at the cap (decompressed bytes).
 *
 * Contract: a status other than 'ok' carries no facts (STATUSES_WITHOUT_FACTS). The caller
 * treats such a package as unknown: it never lowers its priority and never skips it. A
 * document too large to read is a very popular package, which is a target.
 */

const { NPM_PACKAGE_REGEX } = require('../../shared/constants.js');
const { extractPublishFacts, factFromVersionDocs } = require('./extract.js');

const REGISTRY = 'https://registry.npmjs.org';
const ACCEPT_FULL = 'application/json';
const ACCEPT_ABBREVIATED = 'application/vnd.npm.install-v1+json';
const MiB = 1024 * 1024;
const DEFAULTS = { maxDocBytes: 2 * MiB, maxAbbrevBytes: 8 * MiB, maxVersionBytes: 1 * MiB, timeoutMs: 15000 };
const STATUSES_WITHOUT_FACTS = ['error', 'invalid_name', 'not_found', 'rate_limited', 'too_large'];
const VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$/;
// Documents read on the main thread: one journal line per document over this size, with the
// parse and extract times (reassessment threshold for a worker: p90 > 100 ms or max > 500 ms).
const LOG_DOC_MIN_BYTES = 1 * MiB;
const msSince = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;
function logDoc(name, kind, bytes, parseMs, extractMs) {
  if (bytes > LOG_DOC_MIN_BYTES) console.log(`[LANE] DOC: ${name} kind=${kind} bytes=${bytes} parseMs=${parseMs.toFixed(1)} extractMs=${extractMs.toFixed(1)}`);
}

/**
 * GET with a byte cap. Never throws.
 * @returns {Promise<{ status: number, body: Buffer|null, truncated: boolean, bytesRead: number }>}
 *   status 0 on a network error or timeout; truncated (body null) when the cap is reached.
 */
async function defaultHttpGet(url, { accept = ACCEPT_FULL, maxBytes = DEFAULTS.maxDocBytes, timeoutMs = DEFAULTS.timeoutMs, headers = {} } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let bytesRead = 0;
  try {
    const res = await fetch(url, { headers: { ...headers, accept }, signal: ctrl.signal });
    if (res.status !== 200) {
      try { await res.body?.cancel(); } catch { /* already closed */ }
      return { status: res.status, body: null, truncated: false, bytesRead };
    }
    const reader = res.body.getReader();
    const chunks = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesRead += value.length;
      if (bytesRead > maxBytes) {
        try { await reader.cancel(); } catch { /* already closed */ }
        ctrl.abort();
        return { status: 200, body: null, truncated: true, bytesRead };
      }
      chunks.push(value);
    }
    return { status: 200, body: Buffer.concat(chunks), truncated: false, bytesRead };
  } catch {
    return { status: 0, body: null, truncated: false, bytesRead };
  } finally {
    clearTimeout(timer);
  }
}

function defaultLimiter() {
  const l = require('../../shared/http-limiter.js');
  return { acquireRegistrySlot: l.acquireRegistrySlot, releaseRegistrySlot: l.releaseRegistrySlot, signal429: l.signal429 };
}

const parse = (buf) => { try { return JSON.parse(buf.toString('utf8')); } catch { return undefined; } };
const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

/**
 * @param {string} name package name
 * @param {string} version the version named by the registry feed
 * @param {{ httpGet?, limiter?, registry?, maxDocBytes?, maxAbbrevBytes?, maxVersionBytes?,
 *   timeoutMs?, sinceMs?, seenAt? }} [opts] seenAt: when the monitor saw the change (ms)
 * @returns {Promise<{ status: string, facts: object[], source: 'full'|'abbreviated'|null, requests: number }>}
 */
async function fetchPublishFacts(name, version, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const httpGet = o.httpGet || defaultHttpGet;
  const limiter = o.limiter || defaultLimiter();
  const registry = o.registry || REGISTRY;
  const host = new URL(registry).host;
  let requests = 0;
  const out = (status, facts = [], source = null) => ({ status, facts: status === 'ok' ? facts : [], source, requests });

  if (typeof name !== 'string' || !NPM_PACKAGE_REGEX.test(name) || typeof version !== 'string' || !VERSION_RE.test(version)) {
    return out('invalid_name');
  }

  const get = async (path, accept, maxBytes) => {
    requests++;
    await limiter.acquireRegistrySlot(host);
    try {
      const r = await httpGet(registry + path, { accept, maxBytes, timeoutMs: o.timeoutMs });
      if (r.status === 429) limiter.signal429(host);
      return r;
    } finally {
      limiter.releaseRegistrySlot(host);
    }
  };
  // Status of a failed response, or null when the response has a body to read.
  const failure = (r, onTruncated) => {
    if (r.status === 429) return 'rate_limited';
    if (r.status === 404) return 'not_found';
    if (r.status !== 200) return 'error';
    if (r.truncated) return onTruncated;
    return r.body ? null : 'error';
  };

  const docPath = '/' + encodeURIComponent(name);
  const full = await get(docPath, ACCEPT_FULL, o.maxDocBytes);
  const fullFailure = failure(full, 'fallback');
  if (fullFailure && fullFailure !== 'fallback') return out(fullFailure);
  if (!fullFailure) {
    const t0 = process.hrtime.bigint();
    const doc = parse(full.body);
    const parseMs = msSince(t0);
    if (!isObject(doc)) return out('error');
    const t1 = process.hrtime.bigint();
    const facts = extractPublishFacts(doc, { sinceMs: o.sinceMs });
    logDoc(name, 'full', full.body.length, parseMs, msSince(t1));
    return out('ok', facts, 'full');
  }

  // Fallback: version list in publish order, then the two single-version documents.
  const abbrRes = await get(docPath, ACCEPT_ABBREVIATED, o.maxAbbrevBytes);
  const abbrFailure = failure(abbrRes, 'too_large');
  // Counted in production to schedule the streamed read of the full document.
  if (abbrFailure === 'too_large') console.log(`[LANE] TOO_LARGE: ${name}@${version} abbreviated cap=${o.maxAbbrevBytes}`);
  if (abbrFailure) return out(abbrFailure);
  const ta = process.hrtime.bigint();
  const abbr = parse(abbrRes.body);
  const abbrParseMs = msSince(ta);
  if (!isObject(abbr) || !isObject(abbr.versions)) return out('error');
  const tb = process.hrtime.bigint();
  const order = Object.keys(abbr.versions);
  logDoc(name, 'abbreviated', abbrRes.body.length, abbrParseMs, msSince(tb));
  const i = order.indexOf(version);
  if (i < 0) return out('not_found');
  const prev = i > 0 ? order[i - 1] : null;

  const manifestOf = async (v) => {
    const r = await get(`${docPath}/${encodeURIComponent(v)}`, ACCEPT_FULL, o.maxVersionBytes);
    const f = failure(r, 'too_large');
    if (f) return { status: f };
    const m = parse(r.body);
    return isObject(m) ? { manifest: m } : { status: 'error' };
  };
  const cur = await manifestOf(version);
  if (cur.status) return out(cur.status);
  let prevManifest = null;
  if (prev !== null) {
    const p = await manifestOf(prev);
    if (p.status) return out(p.status);
    prevManifest = p.manifest;
  }

  const approxPublishTimes = [];
  if (Number.isFinite(o.seenAt)) approxPublishTimes.push({ at: o.seenAt, source: 'monitor_seen' });
  const modified = typeof abbr.modified === 'string' ? Date.parse(abbr.modified) : NaN;
  if (Number.isFinite(modified)) approxPublishTimes.push({ at: modified, source: 'abbreviated_modified' });

  const fact = factFromVersionDocs({
    name, version, versionOrder: order, distTags: abbr['dist-tags'],
    manifest: cur.manifest, prevManifest, approxPublishTimes
  });
  return fact ? out('ok', [fact], 'abbreviated') : out('error');
}

module.exports = { fetchPublishFacts, defaultHttpGet, STATUSES_WITHOUT_FACTS, DEFAULTS };
