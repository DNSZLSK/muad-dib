#!/usr/bin/env node
'use strict';

/*
 * Build, sign and verify the ioc-db release assets (.github/workflows/ioc-db.yml).
 *
 *   node scripts/ioc-db.js build <iocs-compact.json> <outDir>
 *       -> outDir/iocs-compact.json.gz + outDir/ioc-db.manifest.json (unsigned)
 *   node scripts/ioc-db.js sign <outDir>      (key from env IOC_DB_SIGNING_KEY, publish job only)
 *       -> outDir/ioc-db.manifest.sig
 *   node scripts/ioc-db.js verify <outDir>    (embedded public key, same checks as the client)
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
// Dependency-free on purpose: the publish job holds the signing key and runs no npm install.
const { signManifest, verifyManifest, countCompactPackages, MIN_COMPACT_PACKAGES, MANIFEST_FORMAT } = require('../src/ioc/ioc-db-signature.js');

const MANIFEST = 'ioc-db.manifest.json';
const SIGNATURE = 'ioc-db.manifest.sig';

function fail(msg) { console.error('::error::' + msg); process.exit(1); }

// The scrape stamps `updated`; a compact file older than this was not rewritten by this run
// (failed or partial scrape, or the git copy) and must not be published as today's database.
const MAX_SOURCE_AGE_MS = 48 * 60 * 60 * 1000;

function build(compactPath, outDir) {
  let updated = NaN;
  try { updated = Date.parse(JSON.parse(fs.readFileSync(compactPath, 'utf8')).updated); } catch { /* unreadable: refused below */ }
  if (!Number.isFinite(updated) || Date.now() - updated > MAX_SOURCE_AGE_MS) {
    fail(`compact database is not fresh (updated: ${Number.isFinite(updated) ? new Date(updated).toISOString() : 'missing'}): the scrape did not rewrite it, refusing to publish`);
  }
  let declared = [];
  try { declared = JSON.parse(fs.readFileSync(compactPath, 'utf8')).sources || []; } catch { /* checked above */ }
  if (Array.isArray(declared) && declared.includes('osm')) {
    fail('compact database declares a local-only source: refusing to publish');
  }
  const n = countCompactPackages(compactPath);
  if (n < MIN_COMPACT_PACKAGES) fail(`compact database has ${n} npm entries, below ${MIN_COMPACT_PACKAGES}: refusing to publish`);
  fs.mkdirSync(outDir, { recursive: true });
  const gz = zlib.gzipSync(fs.readFileSync(compactPath), { level: 9 });
  const sha256 = crypto.createHash('sha256').update(gz).digest('hex');
  const asset = 'iocs-compact-' + sha256.slice(0, 12) + '.json.gz';
  fs.writeFileSync(path.join(outDir, asset), gz);
  const manifest = {
    format: MANIFEST_FORMAT,
    asset,
    sha256,
    size: gz.length,
    npmEntries: n,
    builtAt: new Date().toISOString(),
    run: process.env.GITHUB_RUN_ID || null
  };
  fs.writeFileSync(path.join(outDir, MANIFEST), JSON.stringify(manifest));
  console.log(`built ${asset}: ${gz.length} bytes, ${n} npm entries, sha256 ${sha256}`);
}

function sign(outDir) {
  const key = process.env.IOC_DB_SIGNING_KEY;
  if (!key) fail('IOC_DB_SIGNING_KEY is not set (ioc-db environment secret)');
  const sig = signManifest(fs.readFileSync(path.join(outDir, MANIFEST)), key);
  fs.writeFileSync(path.join(outDir, SIGNATURE), sig + '\n');
  console.log('manifest signed');
}

function verify(outDir) {
  const manifestBytes = fs.readFileSync(path.join(outDir, MANIFEST));
  const m = verifyManifest(manifestBytes, fs.readFileSync(path.join(outDir, SIGNATURE), 'utf8'));
  const gz = fs.readFileSync(path.join(outDir, m.asset));
  const sha = crypto.createHash('sha256').update(gz).digest('hex');
  if (sha !== m.sha256 || gz.length !== m.size) fail('asset does not match the signed manifest');
  console.log(`verified: ${m.npmEntries} npm entries, built ${m.builtAt}`);
}

const [cmd, a, b] = process.argv.slice(2);
try {
  if (cmd === 'build' && a && b) build(a, b);
  else if (cmd === 'sign' && a) sign(a);
  else if (cmd === 'verify' && a) verify(a);
  else fail('usage: ioc-db.js build <compact.json> <outDir> | sign <outDir> | verify <outDir>');
} catch (e) {
  fail(e.message);
}
