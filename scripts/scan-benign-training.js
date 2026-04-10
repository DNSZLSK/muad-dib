#!/usr/bin/env node
'use strict';

/**
 * MUAD'DIB — Curated Benign Training Scanner
 *
 * Downloads, extracts, and scans packages from datasets/benign/packages-npm.txt
 * (hand-curated list of ~600 popular legitimate packages) and writes ML
 * training records with label='curated_benign' to
 * data/ml-training-curated-benign.jsonl.
 *
 * Purpose: provide HIGH-SCORE negatives to the ML training set. Packages like
 * playwright-core, @salesforce/cli, webpack, next, electron trip behavioral
 * heuristics (lifecycle scripts, native bindings, eval, dynamic require) while
 * being verifiably legitimate. They are the only safe source of high-score
 * non-malicious training data — the monitor pipeline never labels high-score
 * records as 'clean' by construction, so without this script the model has
 * zero high-score negatives to learn from.
 *
 * Output is append-only and --resume safe: re-running with --resume skips
 * packages already written to the JSONL.
 *
 * Usage:
 *   node scripts/scan-benign-training.js               # scan all packages
 *   node scripts/scan-benign-training.js --limit 10    # test on first 10
 *   node scripts/scan-benign-training.js --resume      # skip already-scanned
 *   node scripts/scan-benign-training.js --refresh     # force re-download
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const BENIGN_LIST = path.join(ROOT, 'datasets', 'benign', 'packages-npm.txt');
const CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-training-tarballs');
const OUTPUT_PATH = path.join(ROOT, 'data', 'ml-training-curated-benign.jsonl');
const PACK_TIMEOUT_MS = 90000;
const SAFE_PKG_RE = /^(@[\w._-]+\/)?[\w._-]+$/;

// --- CLI args ---
const args = process.argv.slice(2);
function getFlagNum(name) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? parseInt(args[i + 1], 10) : 0;
}
const LIMIT = getFlagNum('--limit');
const RESUME = args.includes('--resume');
const REFRESH = args.includes('--refresh');

// --- Lazy-loaded scanner + feature extractor ---
let _run, _buildTrainingRecord, _clearFileListCache;
function loadScanner() {
  if (_run) return;
  _run = require('../src/index.js').run;
  _buildTrainingRecord = require('../src/ml/feature-extractor.js').buildTrainingRecord;
  try { _clearFileListCache = require('../src/utils.js').clearFileListCache; } catch { /* optional */ }
}

// --- Tarball helpers (minimal port from src/commands/evaluate.js:422-533) ---
function pkgToCacheName(pkg) {
  return pkg.replace(/\//g, '_').replace(/@/g, '_');
}

function extractTgz(tgzPath, destDir) {
  const compressed = fs.readFileSync(tgzPath);
  const tarData = zlib.gunzipSync(compressed);

  let offset = 0;
  while (offset + 512 <= tarData.length) {
    const header = tarData.subarray(offset, offset + 512);
    if (header.every(b => b === 0)) break;

    const name = header.subarray(0, 100).toString('utf8').replace(/\0+$/, '');
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0+$/, '').trim();
    const size = parseInt(sizeOctal, 8) || 0;
    const typeFlag = String.fromCharCode(header[156]);

    offset += 512;

    if (name && (typeFlag === '0' || typeFlag === '\0') && size > 0) {
      const resolved = path.resolve(destDir, name);
      const rel = path.relative(path.resolve(destDir), resolved);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        offset += Math.ceil(size / 512) * 512;
        continue; // path traversal guard
      }
      fs.mkdirSync(path.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, tarData.subarray(offset, offset + size));
    }
    offset += Math.ceil(size / 512) * 512;
  }
}

function downloadAndExtract(pkg) {
  const cacheName = pkgToCacheName(pkg);
  const pkgCacheDir = path.join(CACHE_DIR, cacheName);
  const extractedDir = path.join(pkgCacheDir, 'package');

  if (!REFRESH && fs.existsSync(extractedDir)) {
    return { dir: extractedDir, cached: true };
  }

  if (fs.existsSync(pkgCacheDir)) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  fs.mkdirSync(pkgCacheDir, { recursive: true });

  if (!SAFE_PKG_RE.test(pkg)) return { error: 'invalid package name' };

  let tgzFilename;
  try {
    const output = execSync(`npm pack ${pkg}`, {
      cwd: pkgCacheDir,
      encoding: 'utf8',
      timeout: PACK_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    tgzFilename = output.trim().split(/\r?\n/).pop().trim();
  } catch (err) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
    const msg = (err.stderr || err.message || '').toString().slice(0, 120).replace(/\s+/g, ' ');
    return { error: `npm pack failed: ${msg}` };
  }

  const tgzPath = path.join(pkgCacheDir, tgzFilename);
  if (!fs.existsSync(tgzPath)) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
    return { error: 'tgz not found after npm pack' };
  }

  try {
    extractTgz(tgzPath, pkgCacheDir);
  } catch (err) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
    return { error: 'extract failed: ' + err.message };
  }

  try { fs.unlinkSync(tgzPath); } catch { /* ignore */ }

  if (!fs.existsSync(extractedDir)) {
    return { error: 'no package dir after extract' };
  }
  return { dir: extractedDir, cached: false };
}

// --- Resume support ---
function loadExistingPackages() {
  if (!fs.existsSync(OUTPUT_PATH)) return new Set();
  const set = new Set();
  const content = fs.readFileSync(OUTPUT_PATH, 'utf8');
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (r.name) set.add(r.name);
    } catch { /* skip malformed */ }
  }
  return set;
}

// --- Main ---
async function main() {
  if (!fs.existsSync(BENIGN_LIST)) {
    console.error(`[FATAL] Benign list not found: ${BENIGN_LIST}`);
    process.exit(1);
  }

  let packages = fs.readFileSync(BENIGN_LIST, 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  console.log(`[benign-training] ${packages.length} packages in list`);

  if (LIMIT > 0) {
    packages = packages.slice(0, LIMIT);
    console.log(`[benign-training] Limiting to first ${LIMIT}`);
  }

  const existing = RESUME ? loadExistingPackages() : new Set();
  if (RESUME && existing.size > 0) {
    console.log(`[benign-training] Resume: ${existing.size} already in output, will skip`);
  }

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.mkdirSync(CACHE_DIR, { recursive: true });

  loadScanner();

  const stats = { total: packages.length, written: 0, skipped: 0, failed: 0, high_score: 0 };
  const start = Date.now();

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const progress = `[${i + 1}/${packages.length}]`;

    if (existing.has(pkg)) {
      stats.skipped++;
      continue;
    }

    // Download + extract
    const dl = downloadAndExtract(pkg);
    if (dl.error) {
      stats.failed++;
      console.log(`${progress} ${pkg} -> FAIL (${dl.error})`);
      continue;
    }

    // Scan
    let result;
    try {
      result = await _run(dl.dir, { _capture: true, deobfuscate: true });
    } catch (err) {
      stats.failed++;
      console.log(`${progress} ${pkg} -> SCAN FAIL (${err.message})`);
      if (_clearFileListCache) _clearFileListCache();
      continue;
    }

    // Read version from package.json
    let version = 'unknown';
    try {
      const pj = JSON.parse(fs.readFileSync(path.join(dl.dir, 'package.json'), 'utf8'));
      version = pj.version || 'unknown';
    } catch { /* keep 'unknown' */ }

    // Build training record
    const record = _buildTrainingRecord(result, {
      name: pkg,
      version,
      ecosystem: 'npm',
      label: 'curated_benign',
      tier: null,
      sandboxResult: null,
      registryMeta: {},
      unpackedSize: 0,
      npmRegistryMeta: null,
      fileCountTotal: 0,
      hasTests: false
    });

    // Append to JSONL (crash-resilient: every success is persisted immediately)
    fs.appendFileSync(OUTPUT_PATH, JSON.stringify(record) + '\n');
    stats.written++;

    const score = (result.summary && result.summary.riskScore) || 0;
    if (score >= 20) stats.high_score++;

    const elapsed = Math.round((Date.now() - start) / 1000);
    const tag = score >= 20 ? ' [HIGH-SCORE NEGATIVE]' : '';
    console.log(`${progress} ${pkg}@${version} -> score=${score}${tag} (${elapsed}s elapsed)`);

    // Memory management between scans
    if (_clearFileListCache) _clearFileListCache();
    if ((i + 1) % 25 === 0 && global.gc) {
      global.gc();
      const used = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      console.log(`  [memory] heap=${used}MB after ${i + 1} scans`);
    }
  }

  const durationMin = ((Date.now() - start) / 60000).toFixed(1);
  console.log('\n' + '='.repeat(60));
  console.log('SUMMARY');
  console.log('='.repeat(60));
  console.log(`  Total in list:       ${stats.total}`);
  console.log(`  Written to JSONL:    ${stats.written}`);
  console.log(`  High-score (>=20):   ${stats.high_score}  <- valuable negatives`);
  console.log(`  Skipped (resume):    ${stats.skipped}`);
  console.log(`  Failed (download/scan): ${stats.failed}`);
  console.log(`  Duration:            ${durationMin} min`);
  console.log(`  Output:              ${OUTPUT_PATH}`);
  console.log('');
  if (stats.high_score > 0) {
    console.log(`[OK] Got ${stats.high_score} high-score legitimate negatives.`);
    console.log(`     Merge with data/ml-training-relabeled.jsonl and retrain.`);
  } else {
    console.log(`[WARN] No high-score negatives produced — either the current rule set`);
    console.log(`       doesn't trip on any popular package (FPR already low), or the`);
    console.log(`       scans failed. Check failed count above.`);
  }
}

main().catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});
