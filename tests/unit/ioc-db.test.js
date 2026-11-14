'use strict';

/**
 * IOC database for npm installs (2026-11-14).
 *
 * The npm package ships no IOC data; the first-run download pointed at an asset no release had
 * carried since v2.10.44, so a fresh install scanned with no IOC (flatmap-stream@0.1.1 dependency:
 * score 0). The database now comes from the rolling `ioc-db` release, described by an
 * Ed25519-signed manifest. These tests use a throwaway key pair and a temp HOME: nothing touches
 * the real ~/.muaddib, nothing goes to the network.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { test, asyncTest, assert } = require('../test-utils');
const sig = require('../../src/ioc/ioc-db-signature.js');
const bootstrap = require('../../src/ioc/bootstrap.js');

const REPO = path.join(__dirname, '..', '..');

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  };
}

// A compact database with n wildcard entries (+ a marker name to find it after loading).
function compactWith(n, marker, updated = new Date().toISOString()) {
  const wildcards = [];
  for (let i = 0; i < n; i++) wildcards.push('ioc-db-test-pkg-' + i);
  if (marker) wildcards.push(marker);
  return { updated, defaultSeverity: 'critical', wildcards, versioned: {}, pypi_wildcards: [], pypi_versioned: {}, hashes: [], markers: [], files: [], severityOverrides: {} };
}

// Release as the publish job would produce it: gz asset, manifest, signature.
function release(compact, priv, overrides = {}) {
  const gz = zlib.gzipSync(Buffer.from(JSON.stringify(compact)));
  const sha256 = crypto.createHash('sha256').update(gz).digest('hex');
  const npmEntries = compact.wildcards.length + Object.keys(compact.versioned).length;
  const manifest = Object.assign({ format: 1, asset: 'iocs-compact-' + sha256.slice(0, 12) + '.json.gz', sha256, size: gz.length, npmEntries, builtAt: new Date().toISOString(), run: null }, overrides);
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  return { gz, manifest, manifestBytes, signature: sig.signManifest(manifestBytes, priv) };
}

// Seams: serve a release from memory; downloadAndDecompress semantics (gunzip to dest, digest of the gz).
function serve(rel, { assetBytes } = {}) {
  const served = [];
  const getBuffer = async (url) => {
    served.push(url);
    if (url.endsWith('ioc-db.manifest.json')) return rel.manifestBytes;
    if (url.endsWith('ioc-db.manifest.sig')) return Buffer.from(rel.signature);
    throw new Error('HTTP 404 downloading ' + url);
  };
  const download = async (url, dest) => {
    served.push(url);
    const gz = assetBytes || rel.gz;
    fs.writeFileSync(dest, zlib.gunzipSync(gz));
    return { sha256: crypto.createHash('sha256').update(gz).digest('hex'), bytes: gz.length };
  };
  return { getBuffer, download, served };
}

async function withHome(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-iocdb-'));
  const saved = process.env.MUADDIB_NO_REGISTRY_FETCH;
  delete process.env.MUADDIB_NO_REGISTRY_FETCH;
  try {
    bootstrap._setTestEnvironment({ homeDataDir: dir, localBundled: path.join(dir, 'none-a'), localCompact: path.join(dir, 'none-b') });
    bootstrap._resetEnsureIocsForTests();
    return await fn(dir);
  } finally {
    bootstrap._setTestEnvironment();
    bootstrap._setDownloadForTests();
    bootstrap._resetEnsureIocsForTests();
    if (saved === undefined) delete process.env.MUADDIB_NO_REGISTRY_FETCH; else process.env.MUADDIB_NO_REGISTRY_FETCH = saved;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function runIocDbTests() {
  console.log('\n=== IOC DATABASE (signed ioc-db release) ===\n');
  const k = keyPair();
  const other = keyPair();

  // --- signature: positive and negatives ---
  test('IOC-DB: a manifest signed with the key verifies', () => {
    const rel = release(compactWith(3), k.priv);
    const m = sig.verifyManifest(rel.manifestBytes, rel.signature, { publicKey: k.pub });
    assert(m.sha256 === rel.manifest.sha256, 'manifest returned');
  });

  for (const [label, mutate, expected] of [
    ['a manifest modified after signing', r => ({ bytes: Buffer.from(r.manifestBytes.toString().replace('"npmEntries":3', '"npmEntries":4')), s: r.signature }), /invalid/],
    ['a manifest signed with another key', r => ({ bytes: r.manifestBytes, s: sig.signManifest(r.manifestBytes, other.priv) }), /invalid/],
    ['a garbage signature', r => ({ bytes: r.manifestBytes, s: 'AAAA' }), /signature/]
  ]) {
    test(`IOC-DB: refuses ${label}`, () => {
      const r = release(compactWith(3), k.priv);
      const { bytes, s } = mutate(r);
      let err = null;
      try { sig.verifyManifest(bytes, s, { publicKey: k.pub }); } catch (e) { err = e; }
      assert(err && expected.test(err.message), 'expected refusal, got ' + (err && err.message));
    });
  }

  test('IOC-DB: refuses a validly signed manifest that is too old, dated in the future, or older than the installed copy (rollback)', () => {
    const day = 24 * 60 * 60 * 1000;
    const old = release(compactWith(3), k.priv, { builtAt: new Date(Date.now() - 31 * day).toISOString() });
    const future = release(compactWith(3), k.priv, { builtAt: new Date(Date.now() + 3 * day).toISOString() });
    const recent = release(compactWith(3), k.priv, { builtAt: new Date(Date.now() - 2 * day).toISOString() });
    const msg = (r, o) => { try { sig.verifyManifest(r.manifestBytes, r.signature, Object.assign({ publicKey: k.pub }, o)); return 'accepted'; } catch (e) { return e.message; } };
    assert(/too old/.test(msg(old)), 'old: ' + msg(old));
    assert(/future/.test(msg(future)), 'future: ' + msg(future));
    assert(/older than the installed copy/.test(msg(recent, { previousBuiltAt: new Date(Date.now() - day).toISOString() })), 'rollback accepted');
    assert(msg(recent, { previousBuiltAt: new Date(Date.now() - 3 * day).toISOString() }) === 'accepted', 'a newer manifest must be accepted');
  });

  test('IOC-DB: refuses an asset name that is not content-addressed (no path tricks)', () => {
    for (const asset of ['../iocs.json.gz', 'iocs-compact-0123456789ab/x.gz', 'iocs-compact.json.gz']) {
      const r = release(compactWith(3), k.priv, { asset });
      let err = null;
      try { sig.verifyManifest(r.manifestBytes, r.signature, { publicKey: k.pub }); } catch (e) { err = e; }
      assert(err && /asset name/.test(err.message), asset + ': ' + (err && err.message));
    }
  });

  test('IOC-DB: with no public key configured, every manifest is refused (fail closed)', () => {
    const r = release(compactWith(3), k.priv);
    const { IOC_DB_PUBLIC_KEY } = require('../../src/ioc/ioc-db-public-key.js');
    let err = null;
    try { sig.verifyManifest(r.manifestBytes, r.signature, IOC_DB_PUBLIC_KEY ? { publicKey: other.pub } : {}); } catch (e) { err = e; }
    assert(err, 'a manifest not signed by the configured key must be refused');
  });

  // --- bootstrap end to end (temp HOME, in-memory release) ---
  const N = sig.MIN_COMPACT_PACKAGES;

  await asyncTest('IOC-DB: first run downloads, verifies and installs the database and its manifest', () => withHome(async (dir) => {
    const rel = release(compactWith(N, 'ioc-db-marker'), k.priv);
    const srv = serve(rel);
    bootstrap._setDownloadForTests(srv.download, srv.getBuffer);
    bootstrap._setTestEnvironment({ homeDataDir: dir, localBundled: path.join(dir, 'x'), localCompact: path.join(dir, 'y'), publicKey: k.pub });
    const ok = await bootstrap.ensureIOCs();
    assert(ok === true, 'ensureIOCs must succeed');
    assert(srv.served.some(u => u.endsWith('/' + rel.manifest.asset)), 'the asset named by the manifest is downloaded: ' + srv.served.join(' '));
    assert(sig.countCompactPackages(path.join(dir, 'iocs-compact.json')) === N + 1, 'database installed');
    assert(JSON.parse(fs.readFileSync(path.join(dir, 'iocs-compact.json.manifest.json'), 'utf8')).sha256 === rel.manifest.sha256, 'manifest kept for anti-rollback');
  }));

  for (const [label, setup] of [
    ['an asset that does not match the signed manifest', (rel) => serve(rel, { assetBytes: zlib.gzipSync(Buffer.from(JSON.stringify(compactWith(N + 5)))) })],
    ['a manifest signed with another key', () => serve(release(compactWith(N), other.priv))],
    ['a signed database below the minimum size', () => serve(release(compactWith(10), k.priv))]
  ]) {
    await asyncTest(`IOC-DB: refuses ${label} and installs nothing`, () => withHome(async (dir) => {
      const rel = release(compactWith(N), k.priv);
      const srv = setup(rel);
      bootstrap._setDownloadForTests(srv.download, srv.getBuffer);
      bootstrap._setTestEnvironment({ homeDataDir: dir, localBundled: path.join(dir, 'x'), localCompact: path.join(dir, 'y'), publicKey: k.pub });
      const ok = await bootstrap.ensureIOCs();
      assert(ok === false, 'ensureIOCs must report no database');
      assert(!fs.existsSync(path.join(dir, 'iocs-compact.json')), 'nothing installed');
      assert(fs.readdirSync(dir).every(f => !f.endsWith('.download') && !f.endsWith('.tmp')), 'no staging file left: ' + fs.readdirSync(dir));
    }));
  }

  await asyncTest('IOC-DB: a failed refresh keeps the previous copy; a fresh copy is not re-downloaded', () => withHome(async (dir) => {
    const good = release(compactWith(N, 'kept'), k.priv);
    const srv = serve(good);
    bootstrap._setDownloadForTests(srv.download, srv.getBuffer);
    bootstrap._setTestEnvironment({ homeDataDir: dir, localBundled: path.join(dir, 'x'), localCompact: path.join(dir, 'y'), publicKey: k.pub });
    assert(await bootstrap.ensureIOCs() === true, 'first install');
    // fresh: no network at all
    bootstrap._resetEnsureIocsForTests();
    const before = srv.served.length;
    assert(await bootstrap.ensureIOCs() === true && srv.served.length === before, 'a copy younger than 24 h is used as is');
    // stale + tampered release: refused, old copy kept
    const old = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    fs.utimesSync(path.join(dir, 'iocs-compact.json'), old, old);
    const evil = serve(release(compactWith(N), other.priv));
    bootstrap._setDownloadForTests(evil.download, evil.getBuffer);
    bootstrap._resetEnsureIocsForTests();
    assert(await bootstrap.ensureIOCs() === true, 'previous copy still available');
    assert(fs.readFileSync(path.join(dir, 'iocs-compact.json'), 'utf8').includes('"kept"'), 'previous database untouched');
  }));

  // --- publish script round trip (build, sign, verify) ---
  test('IOC-DB: scripts/ioc-db.js build + sign produce a release the client accepts', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-iocdb-build-'));
    try {
      const compactPath = path.join(dir, 'c.json');
      fs.writeFileSync(compactPath, JSON.stringify(compactWith(N)));
      const out = path.join(dir, 'out');
      const b = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'ioc-db.js'), 'build', compactPath, out], { encoding: 'utf8' });
      assert(b.status === 0, 'build: ' + b.stderr);
      const s = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'ioc-db.js'), 'sign', out], { encoding: 'utf8', env: Object.assign({}, process.env, { IOC_DB_SIGNING_KEY: k.priv }) });
      assert(s.status === 0, 'sign: ' + s.stderr);
      const manifestBytes = fs.readFileSync(path.join(out, 'ioc-db.manifest.json'));
      const m = sig.verifyManifest(manifestBytes, fs.readFileSync(path.join(out, 'ioc-db.manifest.sig'), 'utf8'), { publicKey: k.pub });
      const gz = fs.readFileSync(path.join(out, m.asset));
      assert(crypto.createHash('sha256').update(gz).digest('hex') === m.sha256 && m.npmEntries === N, 'asset matches manifest');
      const tooSmall = path.join(dir, 'small.json');
      fs.writeFileSync(tooSmall, JSON.stringify(compactWith(5)));
      const r = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'ioc-db.js'), 'build', tooSmall, path.join(dir, 'o2')], { encoding: 'utf8' });
      assert(r.status !== 0, 'a gutted database must never be published');
      // A compact the scrape did not rewrite (the git copy, months old) must not be published as today's.
      const stale = path.join(dir, 'stale.json');
      fs.writeFileSync(stale, JSON.stringify(compactWith(N, null, '2026-08-20T10:09:38.576Z')));
      const st = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'ioc-db.js'), 'build', stale, path.join(dir, 'o3')], { encoding: 'utf8' });
      assert(st.status !== 0 && /not fresh/.test(st.stderr), 'a stale compact must be refused: ' + st.stderr);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  // --- local-only sources never reach the published compact ---
  test('IOC-DB: generateCompactIOCs drops entries whose only sources are local-only, keeps shared and legacy ones', () => {
    const { generateCompactIOCs, isLocalOnlyIOC } = require('../../src/ioc/updater.js');
    const full = {
      updated: new Date().toISOString(),
      sources: ['osv-malicious', 'osm'],
      packages: [
        { name: 'local-only-wild', version: '*', severity: 'critical', source: 'osm', sources: [{ name: 'osm' }] },
        { name: 'local-only-ver', version: '1.2.3', severity: 'high', sources: [{ name: 'osm' }] },
        { name: 'local-only-legacy-field', version: '*', source: 'osm' },
        { name: 'local-and-osv', version: '*', sources: [{ name: 'osm' }, { name: 'osv-malicious' }] },
        { name: 'aikido-only', version: '2.0.0', sources: [{ name: 'aikido' }] },
        { name: 'no-source-legacy', version: '*' }
      ],
      pypi_packages: [
        { name: 'py-local-only', version: '0.1', sources: [{ name: 'osm' }] },
        { name: 'py-shared', version: '*', sources: [{ name: 'osm' }, { name: 'osv-malicious-pypi' }] }
      ]
    };
    const c = generateCompactIOCs(full);
    const npmNames = new Set([...c.wildcards, ...Object.keys(c.versioned)]);
    for (const n of ['local-only-wild', 'local-only-ver', 'local-only-legacy-field']) assert(!npmNames.has(n), n + ' must not be published');
    for (const n of ['local-and-osv', 'aikido-only', 'no-source-legacy']) assert(npmNames.has(n), n + ' must be kept');
    assert(!c.severityOverrides || !c.severityOverrides['local-only-ver'], 'no severity override leaks the local-only entry');
    assert(!(c.pypi_versioned['py-local-only']) && c.pypi_wildcards.includes('py-shared'), 'PyPI: local-only dropped, shared kept');
    assert(!c.sources.includes('osm'), 'the published source list never names a local-only source: ' + c.sources);
    assert(isLocalOnlyIOC({ sources: [{ name: 'osm' }] }) && !isLocalOnlyIOC({}) && !isLocalOnlyIOC({ sources: ['osm', 'aikido'] }), 'isLocalOnlyIOC contract');
  });

  test('IOC-DB: scripts/ioc-db.js build refuses a compact file that declares a local-only source', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-iocdb-localonly-'));
    try {
      const p = path.join(dir, 'c.json');
      fs.writeFileSync(p, JSON.stringify(Object.assign(compactWith(N), { sources: ['osv-malicious', 'osm'] })));
      const r = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'ioc-db.js'), 'build', p, path.join(dir, 'out')], { encoding: 'utf8' });
      assert(r.status !== 0 && /local-only/.test(r.stderr), 'must refuse: ' + r.stderr);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  // --- loader reads the downloaded copy (subprocess: HOME is read at require time) ---
  test('IOC-DB: the IOC loader merges ~/.muaddib/data/iocs-compact.json', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-iocdb-home-'));
    try {
      fs.mkdirSync(path.join(home, '.muaddib', 'data'), { recursive: true });
      fs.writeFileSync(path.join(home, '.muaddib', 'data', 'iocs-compact.json'), JSON.stringify(compactWith(1, 'ioc-db-only-in-home-compact')));
      const code = "const u=require(process.argv[1]);const i=u.loadCachedIOCs();process.stdout.write(String(i.wildcardPackages.has('ioc-db-only-in-home-compact')))";
      const r = spawnSync(process.execPath, ['-e', code, path.join(REPO, 'src', 'ioc', 'updater.js')], { encoding: 'utf8', env: Object.assign({}, process.env, { HOME: home, USERPROFILE: home }) });
      assert(r.stdout.trim() === 'true', 'downloaded database not loaded: ' + r.stdout + r.stderr);
    } finally { fs.rmSync(home, { recursive: true, force: true }); }
  });
}

module.exports = { runIocDbTests };
