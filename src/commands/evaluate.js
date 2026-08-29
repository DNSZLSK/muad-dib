/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * MUAD'DIB Evaluate — Scanner effectiveness measurement
 *
 * Measures TPR (Ground Truth), FPR (Benign), and ADR (Adversarial).
 * Saves versioned metrics to metrics/v{version}.json.
 *
 * Benign FPR: downloads real npm tarballs and scans actual source code
 * with all 13+ scanners (AST, dataflow, obfuscation, entropy, etc.).
 * Tarballs are cached in .muaddib-cache/benign-tarballs/ to avoid
 * re-downloading on every run.
 *
 * Memory: For large corpora (200+ packages), run with --expose-gc to enable
 * explicit GC between scans: node --expose-gc bin/muaddib.js evaluate
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync, execFileSync } = require('child_process');
const { run } = require('../index.js');
const { clearFileListCache } = require('../utils.js');
const { extractArchive } = require('../shared/download.js');

const ROOT = path.join(__dirname, '..', '..');
const GT_DIR = path.join(ROOT, 'tests', 'ground-truth');
const BENIGN_DIR = path.join(ROOT, 'datasets', 'benign');
const ADVERSARIAL_DIR = path.join(ROOT, 'datasets', 'adversarial');
const METRICS_DIR = path.join(ROOT, 'metrics');
const CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-tarballs');
const RANDOM_CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-random-tarballs');
const PYPI_CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-pypi');
const SCAN_CACHE_FILE = path.join(ROOT, '.muaddib-cache', 'evaluate-scan-cache.json');
const REGISTRY_CACHE_FILE = path.join(ROOT, '.muaddib-cache', 'eval-registry-cache.json');
const REGISTRY_CACHE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const HOLDOUT_DIRS = [
  path.join(ROOT, 'datasets', 'holdout-v2'),
  path.join(ROOT, 'datasets', 'holdout-v3'),
  path.join(ROOT, 'datasets', 'holdout-v4'),
  path.join(ROOT, 'datasets', 'holdout-v5'),
];

const GT_THRESHOLD = 3;
const BENIGN_THRESHOLD = 20;
const ADR_THRESHOLD = 20;  // v2.6.5: global threshold (aligned with BENIGN_THRESHOLD, no per-sample overfitting)
const PACK_TIMEOUT_MS = 30000;

// Validate npm package name to prevent shell injection (names come from our own datasets).
// The character class blocks every shell metacharacter (space ; | & $ ` quotes <> = \n);
// isSafePkgName additionally rejects argument injection (leading '-') and path specs
// ('.'/'..') — npm names legally cannot start with '-', '.' or '_', so no corpus regression.
const SAFE_PKG_RE = /^(@[\w._-]+\/)?[\w._-]+$/;
function isSafePkgName(pkg) {
  return SAFE_PKG_RE.test(pkg) && !pkg.startsWith('-') && pkg !== '.' && pkg !== '..';
}

// =========================================================================
// Scan result cache — avoids re-scanning when src/ hasn't changed
// =========================================================================

/**
 * Compute a fingerprint of all src/*.js files based on size + mtime,
 * plus key data files (IOCs, ground truth, benign list) so the cache
 * is invalidated when detection data changes — not only scanner code.
 */
function computeSrcFingerprint() {
  const srcDir = path.join(ROOT, 'src');
  const entries = [];
  const walk = (dir) => {
    let items;
    try { items = fs.readdirSync(dir); } catch { return; }
    for (const f of items) {
      const fp = path.join(dir, f);
      try {
        const st = fs.statSync(fp);
        if (st.isDirectory()) walk(fp);
        else if (f.endsWith('.js')) entries.push(`${path.relative(ROOT, fp)}:${st.size}:${Math.floor(st.mtimeMs)}`);
      } catch { /* skip */ }
    }
  };
  walk(srcDir);

  // Include key data files so IOC/dataset changes invalidate the cache
  const dataFiles = [
    path.join(ROOT, 'iocs-compact.json'),
    path.join(ROOT, 'tests', 'ground-truth', 'attacks.json'),
    path.join(ROOT, 'datasets', 'benign', 'packages-npm.txt'),
  ];
  for (const fp of dataFiles) {
    try {
      const st = fs.statSync(fp);
      entries.push(`${path.relative(ROOT, fp)}:${st.size}:${Math.floor(st.mtimeMs)}`);
    } catch { /* file may not exist */ }
  }

  // Include ground-truth sample directories (new/removed samples invalidate cache)
  const gtSamplesDir = path.join(ROOT, 'tests', 'ground-truth', 'samples');
  try {
    const dirs = fs.readdirSync(gtSamplesDir);
    entries.push(`gt-samples-count:${dirs.length}`);
  } catch { /* skip */ }

  entries.sort();
  return hashString(entries.join('|')).toString(36);
}

// In-memory scan result cache: { fingerprint, results: { relPath -> scanResult } }
let _scanCache = { fingerprint: null, results: Object.create(null) };

function loadScanCache() {
  try {
    if (!fs.existsSync(SCAN_CACHE_FILE)) return;
    const data = JSON.parse(fs.readFileSync(SCAN_CACHE_FILE, 'utf8'));
    const currentFP = computeSrcFingerprint();
    if (data.fingerprint === currentFP && data.results) {
      _scanCache = { fingerprint: currentFP, results: data.results };
      return Object.keys(data.results).length;
    }
    // Fingerprint mismatch → cache invalidated
    return 0;
  } catch { return 0; }
}

function saveScanCache() {
  try {
    _scanCache.fingerprint = computeSrcFingerprint();
    fs.mkdirSync(path.dirname(SCAN_CACHE_FILE), { recursive: true });
    fs.writeFileSync(SCAN_CACHE_FILE, JSON.stringify(_scanCache));
  } catch { /* best effort */ }
}

function getCachedResult(dir) {
  const key = path.relative(ROOT, dir);
  return _scanCache.results[key] || null;
}

function setCachedResult(dir, result) {
  const key = path.relative(ROOT, dir);
  // Store result with enough detail for ML feature extraction.
  // Previous version only stored riskScore + total — the ML classifier needs
  // fileScores, breakdown, severity counts, maxFileScore for its feature vector.
  const s = result.summary || {};
  _scanCache.results[key] = {
    summary: {
      riskScore: s.riskScore, total: s.total,
      critical: s.critical, high: s.high, medium: s.medium, low: s.low,
      maxFileScore: s.maxFileScore, packageScore: s.packageScore,
      globalRiskScore: s.globalRiskScore,
      fileScores: s.fileScores, breakdown: s.breakdown,
      reputationFactor: s.reputationFactor
    },
    threats: (result.threats || []).map(t => ({
      type: t.type, severity: t.severity, message: t.message, file: t.file
    }))
  };
}

// =========================================================================
// npm registry metadata cache — provides ML features (age, downloads, size, versions)
// Fetched once, cached 30 days. Only queried for packages in the ML T1 zone.
// =========================================================================

let _registryCache = {};

function loadRegistryCache() {
  try {
    if (fs.existsSync(REGISTRY_CACHE_FILE)) {
      _registryCache = JSON.parse(fs.readFileSync(REGISTRY_CACHE_FILE, 'utf8'));
    }
  } catch { _registryCache = {}; }
}

function saveRegistryCache() {
  try {
    fs.mkdirSync(path.dirname(REGISTRY_CACHE_FILE), { recursive: true });
    fs.writeFileSync(REGISTRY_CACHE_FILE, JSON.stringify(_registryCache));
  } catch { /* best effort */ }
}

/**
 * Fetch npm registry metadata for a package (age, downloads, version count, etc.)
 * Uses the same API as the monitor's getPackageMetadata() but with simpler caching.
 * @param {string} pkgName - npm package name
 * @returns {Promise<Object|null>} { age_days, weekly_downloads, version_count, author_package_count, has_repository, readme_size, unpackedSize }
 */
async function fetchRegistryMeta(pkgName) {
  // Check cache
  const cached = _registryCache[pkgName];
  if (cached && (Date.now() - cached._fetchedAt) < REGISTRY_CACHE_MAX_AGE_MS) {
    return cached;
  }

  try {
    const { getPackageMetadata } = require('../scanner/npm-registry.js');
    const meta = await getPackageMetadata(pkgName);
    if (!meta) return null;

    // getPackageMetadata() doesn't return unpackedSize — fetch it from the
    // registry's latest version dist metadata directly.
    let unpackedSize = 0;
    try {
      const https = require('https');
      const regData = await new Promise((resolve, _reject) => {
        const req = https.get(
          `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/latest`,
          { timeout: 5000, headers: { 'Accept': 'application/json' } },
          (res) => {
            if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
            let d = '';
            res.on('data', c => { d += c; });
            res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
          }
        );
        req.on('error', () => resolve(null));
        req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      });
      if (regData && regData.dist) {
        unpackedSize = regData.dist.unpackedSize || 0;
      }
    } catch { /* ignore */ }

    const entry = {
      age_days: meta.age_days || 0,
      weekly_downloads: meta.weekly_downloads || 0,
      version_count: meta.version_count || 0,
      author_package_count: meta.author_package_count || 0,
      has_repository: meta.has_repository || false,
      readme_size: meta.readme_size || 0,
      unpackedSize,
      _fetchedAt: Date.now()
    };
    _registryCache[pkgName] = entry;
    return entry;
  } catch {
    return null;
  }
}

// --- Holdout benign split ---
// Deterministic 70/30 split based on package name hash for overfitting detection.
// Training set: used for tuning FP reductions. Holdout: untouched validation set.
const BENIGN_HOLDOUT_RATIO = 0.3;

function hashString(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function isBenignHoldout(pkgName) {
  return (hashString(pkgName) % 100) < (BENIGN_HOLDOUT_RATIO * 100);
}

// --- Wilson score confidence interval ---
// For binomial proportions with small samples. z=1.96 for 95% CI.
function wilsonCI(successes, total, z = 1.96) {
  if (total === 0) return { lower: 0, upper: 0, center: 0 };
  const p = successes / total;
  const denom = 1 + z * z / total;
  const center = (p + z * z / (2 * total)) / denom;
  const margin = z * Math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom;
  return {
    lower: Math.max(0, center - margin),
    upper: Math.min(1, center + margin),
    center
  };
}

// v2.6.9: Replaced per-sample thresholds with flat sample list.
// All samples use global ADR_THRESHOLD (no per-sample overfitting).
// Vagues 1-4 removed: samples never committed to repo (43 missing directories).
// To be recreated in a structured red team / blue team exercise.
const ADVERSARIAL_SAMPLES = [
  // Vague 5 (27 samples)
  'async-iterator-exfil', 'console-override-exfil', 'cross-file-callback-exfil',
  'error-reporting-exfil', 'error-stack-exfil', 'event-emitter-exfil',
  'fn-return-exfil', 'getter-defineProperty-exfil', 'http-header-exfil',
  'import-map-poison', 'intl-polyfill-backdoor', 'net-time-exfil',
  'postmessage-exfil', 'process-title-exfil', 'promise-chain-exfil',
  'proxy-getter-dns-exfil', 'readable-stream-exfil', 'response-intercept-exfil',
  'setTimeout-eval-chain', 'setter-trap-exfil', 'sourcemap-payload',
  'stream-pipe-exfil', 'svg-payload-fetch', 'symbol-iterator-exfil',
  'toJSON-hijack', 'url-constructor-exfil', 'wasm-c2-payload',
  // Vague 6 — DPRK + Intent Graph (10 samples)
  'locale-config-sync', 'metrics-aggregator-lite', 'env-config-validator',
  'stream-transform-kit', 'cache-warmup-utils',
  'fn-return-eval', 'call-chain-eval', 'regex-source-require',
  'charcode-arithmetic', 'object-method-alias',
  // Vague 7 — Red Team campaigns (30 samples)
  // Campaign 1: DPRK/Lazarus Interview (5)
  'lazarus-interview-1', 'lazarus-interview-2', 'lazarus-interview-3',
  'lazarus-interview-4', 'lazarus-interview-5',
  // Campaign 2: GlassWorm Evolution (5)
  'glassworm-v6-1', 'glassworm-v6-2', 'glassworm-v6-3',
  'glassworm-v6-4', 'glassworm-v6-5',
  // Campaign 3: Dependency Confusion APT (5)
  'depconfusion-1', 'depconfusion-2', 'depconfusion-3',
  'depconfusion-4', 'depconfusion-5',
  // Campaign 4: Compromised Maintainer Backdoor (5)
  'maintainer-backdoor-1', 'maintainer-backdoor-2', 'maintainer-backdoor-3',
  'maintainer-backdoor-4', 'maintainer-backdoor-5',
  // Campaign 5: Anti-Scanner / DoS (5)
  'anti-scanner-1', 'anti-scanner-2', 'anti-scanner-3',
  'anti-scanner-4', 'anti-scanner-5',
  // Campaign 6: Emerging Techniques 2026 (5)
  'emerging-2026-1', 'emerging-2026-2', 'emerging-2026-3',
  'emerging-2026-4', 'emerging-2026-5',
];

const HOLDOUT_SAMPLES = [
  // holdout-v2 (10 samples)
  'conditional-os-payload', 'env-var-reconstruction',
  'github-workflow-inject', 'homedir-ssh-key-steal',
  'npm-cache-poison', 'npm-lifecycle-preinstall-curl',
  'process-env-proxy-getter', 'readable-stream-hijack',
  'setTimeout-chain', 'wasm-loader',
  // holdout-v3 (10 samples)
  'dns-txt-payload', 'electron-rce',
  'env-file-parse-exfil', 'git-credential-steal',
  'npm-hook-hijack', 'postinstall-reverse-shell',
  'require-cache-poison', 'steganography-payload',
  'symlink-escape', 'timezone-trigger',
  // holdout-v4 (10 samples — deobfuscation)
  'atob-eval', 'base64-require',
  'charcode-fetch', 'charcode-spread-homedir',
  'concat-env-steal', 'double-decode-exfil',
  'hex-array-exec', 'mixed-obfuscation-stealer',
  'nested-base64-concat', 'template-literal-hide',
  // holdout-v5 (10 samples — inter-module dataflow)
  'callback-exfil', 'class-method-exfil',
  'conditional-split', 'event-emitter-flow',
  'mixed-inline-split', 'named-export-steal',
  'reexport-chain', 'split-env-exfil',
  'split-npmrc-steal', 'three-hop-chain',
];

/**
 * Scan a directory silently and return the result.
 * Uses scan result cache when available (cache populated by loadScanCache).
 */
let _silentScanCount = 0;

async function silentScan(dir) {
  // Check cache first
  const cached = getCachedResult(dir);
  if (cached) return cached;

  try {
    const result = await run(dir, { _capture: true });
    setCachedResult(dir, result);

    // Aggressive cleanup between scans to prevent OOM during evaluate
    clearFileListCache(); // clears _fileListCache, _fileContentCache, _astCache

    _silentScanCount++;
    if (_silentScanCount % 20 === 0 && global.gc) {
      global.gc();
      const used = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      // Route memory log to stderr so --json output remains parseable
      process.stderr.write(`  [Memory] ${used} MB after ${_silentScanCount} scans\n`);
    }

    return result;
  } catch (err) {
    clearFileListCache();
    return { summary: { riskScore: 0, total: 0 }, threats: [], error: err.message };
  }
}

/**
 * 1. Ground Truth — scan real-world attack samples
 */
async function evaluateGroundTruth() {
  const attacksFile = path.join(GT_DIR, 'attacks.json');
  const data = JSON.parse(fs.readFileSync(attacksFile, 'utf8'));
  const allAttacks = data.attacks;
  const attacks = allAttacks.filter(a => a.expected.min_threats > 0);
  const totalAll = allAttacks.length; // includes browser-only out-of-scope

  const details = [];
  let detected = 0;
  let detectedAt20 = 0;
  let iocBased = 0;
  let heuristicOnly = 0;

  for (const attack of attacks) {
    const sampleDir = path.join(GT_DIR, attack.sample_dir);
    const result = await silentScan(sampleDir);
    const score = result.summary.riskScore;
    const isDetected = score >= GT_THRESHOLD;
    const isDetectedAt20 = score >= ADR_THRESHOLD;
    if (isDetected) detected++;
    if (isDetectedAt20) detectedAt20++;
    // Classify detection source: IOC-based vs heuristic-only
    const threats = result.threats || [];
    const hasIOC = threats.some(t => classifyDetectionSource(t) === 'ioc');
    if (isDetected) {
      if (hasIOC) iocBased++;
      else heuristicOnly++;
    }
    details.push({
      name: attack.name,
      id: attack.id,
      score,
      detected: isDetected,
      threshold: GT_THRESHOLD,
      threats: result.threats,
      _summary: result.summary
    });
  }

  const total = attacks.length;
  const tpr = total > 0 ? detected / total : 0;
  const tprAll = totalAll > 0 ? detected / totalAll : 0;
  const tprCI = wilsonCI(detected, total);
  const tprAt20 = total > 0 ? detectedAt20 / total : 0;
  const tprAt20CI = wilsonCI(detectedAt20, total);
  return { detected, detectedAt20, total, totalAll, tpr, tprAt20, tprAll, tprCI, tprAt20CI, iocBased, heuristicOnly, details };
}

// =========================================================================
// 2. Benign — download real tarballs and scan actual source code
// =========================================================================

/**
 * Convert a package name to a safe cache directory name.
 * @scoped/pkg → _scoped_pkg
 */
function pkgToCacheName(pkg) {
  return pkg.replace(/\//g, '_').replace(/@/g, '_');
}

/**
 * Extract a .tgz file using Node.js built-in zlib + minimal tar parser.
 * Only extracts regular files (type '0' or NUL).
 */
function extractTgz(tgzPath, destDir) {
  const compressed = fs.readFileSync(tgzPath);
  const tarData = zlib.gunzipSync(compressed);

  let offset = 0;
  while (offset + 512 <= tarData.length) {
    const header = tarData.subarray(offset, offset + 512);

    // Check for end-of-archive (two zero blocks)
    if (header.every(b => b === 0)) break;

    // Parse tar header
    const name = header.subarray(0, 100).toString('utf8').replace(/\0+$/, '');
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0+$/, '').trim();
    const size = parseInt(sizeOctal, 8) || 0;
    const typeFlag = String.fromCharCode(header[156]);

    offset += 512; // move past header

    if (name && (typeFlag === '0' || typeFlag === '\0') && size > 0) {
      // Regular file — extract it (with path traversal guard)
      const resolved = path.resolve(destDir, name);
      const rel = path.relative(path.resolve(destDir), resolved);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        offset += Math.ceil(size / 512) * 512;
        continue; // skip path traversal attempt
      }
      const filePath = resolved;
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      const fileData = tarData.subarray(offset, offset + size);
      fs.writeFileSync(filePath, fileData);
    }

    // Advance past data blocks (512-byte aligned)
    offset += Math.ceil(size / 512) * 512;
  }
}

/**
 * Download a package tarball via `npm pack` and extract with native Node.js.
 * Returns the path to the extracted package directory, or null on failure.
 * Uses a persistent cache to avoid re-downloading.
 */
function downloadAndExtract(pkg, options = {}) {
  const cacheName = pkgToCacheName(pkg);
  const pkgCacheDir = path.join(CACHE_DIR, cacheName);

  // Check cache first (unless refreshing)
  if (!options.refreshBenign && fs.existsSync(pkgCacheDir)) {
    const extractedDir = path.join(pkgCacheDir, 'package');
    if (fs.existsSync(extractedDir)) {
      return extractedDir;
    }
  }

  // Download via npm pack (cwd approach avoids Windows path issues)
  fs.mkdirSync(pkgCacheDir, { recursive: true });

  let tgzFilename;
  try {
    if (!isSafePkgName(pkg)) throw new Error('invalid package name');
    const output = execSync(`npm pack ${pkg}`, {
      cwd: pkgCacheDir,
      encoding: 'utf8',
      timeout: PACK_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    tgzFilename = output.trim().split(/\r?\n/).pop().trim();
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] npm pack ${pkg} failed: ${(err.stderr || err.message || '').slice(0, 200)}`);
    }
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  const tgzPath = path.join(pkgCacheDir, tgzFilename);
  if (!fs.existsSync(tgzPath)) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  // Extract tarball using native Node.js (no shell tar dependency)
  try {
    extractTgz(tgzPath, pkgCacheDir);
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] extract ${pkg} failed: ${(err.message || '').slice(0, 200)}`);
    }
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  // Clean up tarball to save space
  try { fs.unlinkSync(tgzPath); } catch { /* ignore */ }

  const extractedDir = path.join(pkgCacheDir, 'package');
  if (!fs.existsSync(extractedDir)) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  return extractedDir;
}

/**
 * Evaluate benign packages by downloading real source code and scanning it.
 */
async function evaluateBenign(options = {}) {
  const listFile = path.join(BENIGN_DIR, 'packages-npm.txt');
  let packages = fs.readFileSync(listFile, 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  // Apply limit if specified
  const limit = options.benignLimit || 0;
  if (limit > 0) {
    packages = packages.slice(0, limit);
  }

  fs.mkdirSync(CACHE_DIR, { recursive: true });

  const details = [];
  let flagged = 0;
  let skipped = 0;
  const total = packages.length;

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const progress = `[${i + 1}/${total}]`;

    // Progress indicator (overwrite line)
    if (!options.json && process.stdout.isTTY) {
      process.stdout.write(`\r  [2/3] Benign ${progress} ${pkg}${''.padEnd(40)}`);
    }

    let extractedDir;
    try {
      extractedDir = downloadAndExtract(pkg, options);
    } catch (err) {
      // v2.10.95: Windows EPERM on tarball extraction/cleanup should not kill evaluate.
      // Log as skip and continue with the next package.
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: `extract failed: ${err.code || err.message}` });
      skipped++;
      continue;
    }
    if (!extractedDir) {
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'download failed' });
      skipped++;
      continue;
    }

    let result;
    try {
      result = await silentScan(extractedDir);
    } catch (err) {
      // v2.10.95: scan failure (Windows EPERM on locked files, long paths) should
      // not kill evaluate — skip the package and continue.
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: `scan failed: ${err.code || err.message}` });
      skipped++;
      continue;
    }

    const score = result.summary.riskScore;
    const isFlagged = score >= BENIGN_THRESHOLD;
    if (isFlagged) flagged++;

    // Count JS files for size classification
    let jsFileCount = 0;
    try {
      const countJs = (dir, depth) => {
        if (depth > 10) return;
        for (const f of fs.readdirSync(dir)) {
          if (f === 'node_modules' || f === '.git') continue;
          const fp = path.join(dir, f);
          try {
            const st = fs.lstatSync(fp);
            if (st.isSymbolicLink()) continue;
            if (st.isDirectory()) countJs(fp, depth + 1);
            else if (f.endsWith('.js') || f.endsWith('.mjs') || f.endsWith('.cjs')) jsFileCount++;
          } catch { /* skip */ }
        }
      };
      countJs(extractedDir, 0);
    } catch { /* skip */ }

    const entry = { name: pkg, score, flagged: isFlagged, jsFiles: jsFileCount };

    // Include threat details for flagged packages (for debugging FPs)
    if (isFlagged && result.threats) {
      entry.threats = result.threats.map(t => ({
        type: t.type,
        severity: t.severity,
        message: t.message,
        file: t.file
      }));
    }

    // Store full summary for ML feature extraction (fileScores, breakdown, severity counts)
    entry._summary = result.summary || {};
    entry._fileCountTotal = jsFileCount;

    details.push(entry);
  }

  // Clear progress line
  if (!options.json && process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }

  const scanned = total - skipped;
  const fpr = scanned > 0 ? flagged / scanned : 0;

  // Stratified FPR by package size (JS file count)
  const sizeCategories = { small: { max: 10 }, medium: { max: 50 }, large: { max: 100 }, veryLarge: { max: Infinity } };
  const stratified = {};
  for (const [cat, { max }] of Object.entries(sizeCategories)) {
    const prev = cat === 'small' ? 0 : cat === 'medium' ? 10 : cat === 'large' ? 50 : 100;
    const catDetails = details.filter(d => !d.skipped && d.jsFiles > prev && d.jsFiles <= max);
    const catFlagged = catDetails.filter(d => d.flagged).length;
    stratified[cat] = { flagged: catFlagged, total: catDetails.length, fpr: catDetails.length > 0 ? catFlagged / catDetails.length : 0 };
  }

  // Holdout benign split: deterministic 70/30 for overfitting detection
  const holdoutDetails = details.filter(d => !d.skipped && isBenignHoldout(d.name));
  const trainingDetails = details.filter(d => !d.skipped && !isBenignHoldout(d.name));
  const holdoutFlagged = holdoutDetails.filter(d => d.flagged).length;
  const trainingFlagged = trainingDetails.filter(d => d.flagged).length;
  const holdoutSplit = {
    training: { flagged: trainingFlagged, total: trainingDetails.length, fpr: trainingDetails.length > 0 ? trainingFlagged / trainingDetails.length : 0 },
    holdout: { flagged: holdoutFlagged, total: holdoutDetails.length, fpr: holdoutDetails.length > 0 ? holdoutFlagged / holdoutDetails.length : 0 }
  };

  // Wilson 95% CI for FPR
  const fprCI = wilsonCI(flagged, scanned);

  return { flagged, total, scanned, skipped, fpr, fprCI, stratified, holdoutSplit, details };
}

// =========================================================================
// 2b. PyPI Benign — download real PyPI sdists and scan
// =========================================================================

/**
 * Download a PyPI package via pip download and extract.
 * Returns the path to the extracted package directory, or null on failure.
 */
function downloadAndExtractPyPI(pkg, options = {}) {
  const cacheName = pkgToCacheName(pkg);
  const pkgCacheDir = path.join(PYPI_CACHE_DIR, cacheName);

  // Check cache first
  if (!options.refreshBenign && fs.existsSync(pkgCacheDir)) {
    const entries = fs.readdirSync(pkgCacheDir).filter(e => {
      try { return fs.statSync(path.join(pkgCacheDir, e)).isDirectory(); } catch { return false; }
    });
    if (entries.length > 0) return path.join(pkgCacheDir, entries[0]);
  }

  fs.mkdirSync(pkgCacheDir, { recursive: true });

  // Download via pip. We prefer sdists (source) for richer scan coverage but
  // do NOT pass `--no-binary :all:` — that flag forces pip to prepare a build
  // environment (cython, meson, setuptools-build…) for compiled packages
  // (numpy/scipy/pandas/scikit-learn/…), which routinely times out the 30s
  // PACK_TIMEOUT and produces the 38% PyPI download-fail rate observed in
  // metrics/v2.11.47.json. Letting pip pick the best available distribution
  // gives us a wheel for compiled packages — extractable as ZIP, still
  // contains `.py` files that the python-source / python-ast scanners walk.
  try {
    execFileSync('pip', ['download', '--no-deps', '-d', pkgCacheDir, pkg], {
      encoding: 'utf8',
      timeout: PACK_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] pip download ${pkg} failed: ${(err.stderr || err.message || '').slice(0, 200)}`);
    }
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  // Find the downloaded archive — sdist (.tar.gz/.tgz) or wheel (.whl) or
  // legacy egg (.zip). All three are extractable by extractArchive() in
  // src/shared/download.js (tar.gz via _extractTarGzImpl, .whl/.zip via
  // adm-zip with zip-bomb / path-traversal guards).
  const archives = fs.readdirSync(pkgCacheDir).filter(f =>
    f.endsWith('.tar.gz') || f.endsWith('.tgz') || f.endsWith('.whl') || f.endsWith('.zip')
  );
  if (archives.length === 0) {
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  const archivePath = path.join(pkgCacheDir, archives[0]);
  let extractedRoot;
  try {
    extractedRoot = extractArchive(archivePath, pkgCacheDir);
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] extract PyPI ${pkg} (${archives[0]}) failed: ${(err.message || '').slice(0, 200)}`);
    }
    try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* Windows EPERM on locked files — ignore, continue */ }
    return null;
  }

  // Clean up archive
  try { fs.unlinkSync(archivePath); } catch { /* ignore */ }

  // extractArchive returns the single top-level dir for sdists (e.g.
  // `numpy-1.26.0/`) and the destDir itself for wheels (which have a flat
  // `{pkg}/`, `{pkg}-{ver}.dist-info/` layout — we want destDir so the
  // scanner walks both).
  if (extractedRoot && fs.existsSync(extractedRoot)) return extractedRoot;
  return pkgCacheDir;
}

/**
 * Evaluate benign PyPI packages (separate from npm FPR).
 */
async function evaluateBenignPyPI(options = {}) {
  const listFile = path.join(BENIGN_DIR, 'packages-pypi.txt');
  if (!fs.existsSync(listFile)) return null;

  let packages = fs.readFileSync(listFile, 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  if (packages.length === 0) return null;

  const limit = options.benignLimit || 0;
  if (limit > 0) packages = packages.slice(0, limit);

  fs.mkdirSync(PYPI_CACHE_DIR, { recursive: true });

  const details = [];
  let flagged = 0;
  let skipped = 0;
  const total = packages.length;

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const progress = `[${i + 1}/${total}]`;

    if (!options.json && process.stdout.isTTY) {
      process.stdout.write(`\r  [2b/4] PyPI Benign ${progress} ${pkg}${''.padEnd(40)}`);
    }

    let extractedDir;
    try {
      extractedDir = downloadAndExtractPyPI(pkg, options);
    } catch (err) {
      // v2.10.95: PyPI extraction failure (Windows EPERM, long paths) — skip, continue
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: `extract failed: ${err.code || err.message}` });
      skipped++;
      continue;
    }
    if (!extractedDir) {
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'download failed' });
      skipped++;
      continue;
    }

    let result;
    try {
      result = await silentScan(extractedDir);
    } catch (err) {
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: `scan failed: ${err.code || err.message}` });
      skipped++;
      continue;
    }

    const score = result.summary.riskScore;
    const isFlagged = score >= BENIGN_THRESHOLD;
    if (isFlagged) flagged++;

    const entry = { name: pkg, score, flagged: isFlagged };
    if (isFlagged && result.threats) {
      entry.threats = result.threats.map(t => ({
        type: t.type, severity: t.severity, message: t.message, file: t.file
      }));
    }
    details.push(entry);
  }

  if (!options.json && process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }

  const scanned = total - skipped;
  const fpr = scanned > 0 ? flagged / scanned : 0;
  return { flagged, total, scanned, skipped, fpr, details };
}

// =========================================================================
// 2c. Benign Random — npm stratified random sample (not curated)
// =========================================================================

/**
 * Evaluate benign random npm packages (separate corpus from curated).
 * Reads packages-npm-random.txt generated by scripts/sample-npm-random.js.
 * Reports FPR separately — this measures FPR on representative npm, not curated.
 */
async function evaluateBenignRandom(options = {}) {
  // FPR plan : allow swapping the corpus to test on a fresh random sample
  // (seed 2026 v2.txt etc.) without overwriting the seed-42 reference corpus.
  const listFile = options.corpusFile
    ? (path.isAbsolute(options.corpusFile) ? options.corpusFile : path.join(BENIGN_DIR, options.corpusFile))
    : path.join(BENIGN_DIR, 'packages-npm-random.txt');
  if (!fs.existsSync(listFile)) return null;

  let packages = fs.readFileSync(listFile, 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  if (packages.length === 0) return null;

  const limit = options.benignLimit || 0;
  if (limit > 0) packages = packages.slice(0, limit);

  fs.mkdirSync(RANDOM_CACHE_DIR, { recursive: true });

  const details = [];
  let flagged = 0;
  let skipped = 0;
  const total = packages.length;

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const progress = `[${i + 1}/${total}]`;

    if (!options.json && process.stdout.isTTY) {
      process.stdout.write(`\r  [2c/4] Benign Random ${progress} ${pkg}${''.padEnd(40)}`);
    }

    // Use separate cache directory for random corpus
    const cacheName = pkgToCacheName(pkg);
    const pkgCacheDir = path.join(RANDOM_CACHE_DIR, cacheName);
    let extractedDir;

    // Check cache
    if (!options.refreshBenign && fs.existsSync(pkgCacheDir)) {
      const ed = path.join(pkgCacheDir, 'package');
      if (fs.existsSync(ed)) {
        extractedDir = ed;
      }
    }

    // Download if not cached
    if (!extractedDir) {
      fs.mkdirSync(pkgCacheDir, { recursive: true });
      let tgzFilename;
      try {
        if (!isSafePkgName(pkg)) throw new Error('invalid package name');
        tgzFilename = execSync(`npm pack ${pkg}`, {
          cwd: pkgCacheDir,
          encoding: 'utf8',
          timeout: PACK_TIMEOUT_MS,
          stdio: ['pipe', 'pipe', 'pipe']
        }).trim().split(/\r?\n/).pop().trim();
      } catch {
        details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'download failed' });
        skipped++;
        try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
        continue;
      }

      const tgzPath = path.join(pkgCacheDir, tgzFilename);
      if (!fs.existsSync(tgzPath)) {
        details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'tgz not found' });
        skipped++;
        continue;
      }

      try {
        extractTgz(tgzPath, pkgCacheDir);
      } catch {
        details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'extract failed' });
        skipped++;
        try { fs.rmSync(pkgCacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
        continue;
      }

      try { fs.unlinkSync(tgzPath); } catch { /* ignore */ }
      extractedDir = path.join(pkgCacheDir, 'package');
      if (!fs.existsSync(extractedDir)) {
        details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'no package dir' });
        skipped++;
        continue;
      }
    }

    let result;
    try {
      result = await silentScan(extractedDir);
    } catch (err) {
      // v2.10.95: scan failure (Windows EPERM, long paths) — skip and continue
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: `scan failed: ${err.code || err.message}` });
      skipped++;
      continue;
    }

    const score = result.summary.riskScore;
    const isFlagged = score >= BENIGN_THRESHOLD;
    if (isFlagged) flagged++;

    const entry = { name: pkg, score, flagged: isFlagged };
    if (isFlagged && result.threats) {
      entry.threats = result.threats.map(t => ({
        type: t.type, severity: t.severity, message: t.message, file: t.file
      }));
    }
    details.push(entry);
  }

  if (!options.json && process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }

  const scanned = total - skipped;
  const fpr = scanned > 0 ? flagged / scanned : 0;
  const fprCI = wilsonCI(flagged, scanned);

  return { flagged, total, scanned, skipped, fpr, fprCI, details };
}

/**
 * 3. Adversarial — scan evasive malicious samples
 * Skips gracefully if datasets/adversarial/ directory is missing (local-only data).
 */
async function evaluateAdversarial() {
  const details = [];
  let detected = 0;
  const adversarialDirExists = fs.existsSync(ADVERSARIAL_DIR);

  // v2.6.5: Use global ADR_THRESHOLD for honest measurement (no per-sample overfitting)

  // --- Adversarial samples ---
  for (const name of ADVERSARIAL_SAMPLES) {
    const sampleDir = path.join(ADVERSARIAL_DIR, name);
    if (!adversarialDirExists || !fs.existsSync(sampleDir)) {
      details.push({ name, score: 0, threshold: ADR_THRESHOLD, detected: false, error: 'directory not found (local-only)', source: 'adversarial' });
      continue;
    }
    const result = await silentScan(sampleDir);
    const score = result.summary.riskScore;
    const isDetected = score >= ADR_THRESHOLD;
    if (isDetected) detected++;
    details.push({ name, score, threshold: ADR_THRESHOLD, detected: isDetected, source: 'adversarial',
      threats: result.threats, _summary: result.summary });
  }

  // --- Holdout samples (40) ---
  for (const name of HOLDOUT_SAMPLES) {
    let sampleDir = null;
    for (const hDir of HOLDOUT_DIRS) {
      const candidate = path.join(hDir, name);
      if (fs.existsSync(candidate)) { sampleDir = candidate; break; }
    }
    if (!sampleDir) {
      details.push({ name, score: 0, threshold: ADR_THRESHOLD, detected: false, error: 'directory not found', source: 'holdout' });
      continue;
    }
    const result = await silentScan(sampleDir);
    const score = result.summary.riskScore;
    const isDetected = score >= ADR_THRESHOLD;
    if (isDetected) detected++;
    details.push({ name, score, threshold: ADR_THRESHOLD, detected: isDetected, source: 'holdout',
      threats: result.threats, _summary: result.summary });
  }

  // Count only samples that exist on disk (exclude "directory not found")
  const available = details.filter(d => !d.error).length;
  const total = ADVERSARIAL_SAMPLES.length + HOLDOUT_SAMPLES.length;
  const adr = available > 0 ? detected / available : 0;

  // Cohort separation: adversarial vs holdout
  const advDetails = details.filter(d => d.source === 'adversarial');
  const holdDetails = details.filter(d => d.source === 'holdout');
  const advAvailable = advDetails.filter(d => !d.error).length;
  const holdAvailable = holdDetails.filter(d => !d.error).length;
  const advDetected = advDetails.filter(d => d.detected).length;
  const holdDetected = holdDetails.filter(d => d.detected).length;
  const cohorts = {
    adversarial: { detected: advDetected, available: advAvailable, adr: advAvailable > 0 ? advDetected / advAvailable : 0 },
    holdout: { detected: holdDetected, available: holdAvailable, adr: holdAvailable > 0 ? holdDetected / holdAvailable : 0 }
  };

  // Wilson 95% CI for ADR
  const adrCI = wilsonCI(detected, available);

  // Sensitivity curve: ADR at multiple thresholds
  const sensitivityThresholds = [5, 10, 15, 20, 25, 30, 40, 50, 60, 80];
  const sensitivity = sensitivityThresholds.map(t => {
    const det = details.filter(d => !d.error && d.score >= t).length;
    return { threshold: t, detected: det, available, adr: available > 0 ? det / available : 0 };
  });

  return { detected, total, available, adr, adrCI, cohorts, sensitivity, details };
}

// =========================================================================
// 4. Datadog Benchmark — TPR on full in-scope dataset (pure JSON read)
// =========================================================================

const DATADOG_BENCHMARK_FILE = path.join(ROOT, 'datasets', 'real-world', 'datadog-benchmark-results.json');
const DATADOG_TPR_THRESHOLD = 20;  // aligned with ADR/BENIGN threshold

/**
 * Evaluate TPR on the full Datadog benchmark in-scope dataset.
 * Pure JSON read — no re-scan, no download. Uses pre-computed scores
 * from datadog-benchmark-results.json. Updates automatically when
 * the benchmark file is re-generated after a VPS re-run.
 *
 * @returns {Object|null} TPR results with breakdowns, or null if file missing
 */
function evaluateDatadogTPR() {
  if (!fs.existsSync(DATADOG_BENCHMARK_FILE)) return null;

  const benchmark = JSON.parse(fs.readFileSync(DATADOG_BENCHMARK_FILE, 'utf8'));
  const inScope = benchmark.results.filter(r => r.status === 'scanned');
  if (inScope.length === 0) return null;

  let detected = 0;
  const byCategory = {};
  const scoreDistribution = { '0': 0, '1-9': 0, '10-19': 0, '20-49': 0, '50+': 0 };
  const detectedByBucket = { '0': 0, '1-9': 0, '10-19': 0, '20-49': 0, '50+': 0 };

  for (const r of inScope) {
    const score = r.score || 0;
    const isDetected = score >= DATADOG_TPR_THRESHOLD;
    if (isDetected) detected++;

    // Score bucket classification
    let bucket;
    if (score === 0) bucket = '0';
    else if (score <= 9) bucket = '1-9';
    else if (score <= 19) bucket = '10-19';
    else if (score <= 49) bucket = '20-49';
    else bucket = '50+';
    scoreDistribution[bucket]++;
    if (isDetected) detectedByBucket[bucket]++;

    // Per-category breakdown
    const cat = r.category || 'unknown';
    if (!byCategory[cat]) byCategory[cat] = { detected: 0, total: 0 };
    byCategory[cat].total++;
    if (isDetected) byCategory[cat].detected++;
  }

  const total = inScope.length;
  const tpr = total > 0 ? detected / total : 0;
  const tprCI = wilsonCI(detected, total);

  // Compute TPR per category
  for (const cat of Object.keys(byCategory)) {
    const c = byCategory[cat];
    c.tpr = c.total > 0 ? c.detected / c.total : 0;
    c.tprCI = wilsonCI(c.detected, c.total);
  }

  // Score bucket breakdown with detection rates
  const scoreBuckets = {};
  for (const bucket of Object.keys(scoreDistribution)) {
    scoreBuckets[bucket] = {
      total: scoreDistribution[bucket],
      detected: detectedByBucket[bucket],
      tpr: scoreDistribution[bucket] > 0 ? detectedByBucket[bucket] / scoreDistribution[bucket] : 0
    };
  }

  return {
    detected,
    total,
    tpr,
    tprCI,
    threshold: DATADOG_TPR_THRESHOLD,
    byCategory,
    scoreBuckets,
    benchmarkDate: benchmark.metadata && benchmark.metadata.scanned_at || null
  };
}

// =========================================================================
// 4b. OpenSSF Benchmark — TPR on OpenSSF malicious-packages dataset
// =========================================================================

const OSSF_BENCHMARK_FILE = path.join(ROOT, 'datasets', 'real-world', 'ossf-benchmark-results.json');
const OSSF_TPR_THRESHOLD = 20;

/**
 * Evaluate TPR on the OpenSSF malicious-packages benchmark.
 * Pure JSON read — uses pre-computed scores from ossf-benchmark-results.json.
 * Run `node scripts/ossf-benchmark.js` to generate the file.
 */
function evaluateOSSFTPR() {
  if (!fs.existsSync(OSSF_BENCHMARK_FILE)) return null;

  const benchmark = JSON.parse(fs.readFileSync(OSSF_BENCHMARK_FILE, 'utf8'));
  const inScope = benchmark.results.filter(r => r.status === 'scanned');
  if (inScope.length === 0) return null;

  let detected = 0;
  const bySource = {};
  const scoreDistribution = { '0': 0, '1-9': 0, '10-19': 0, '20-49': 0, '50+': 0 };
  const detectedByBucket = { '0': 0, '1-9': 0, '10-19': 0, '20-49': 0, '50+': 0 };
  const details = [];
  const misses = [];

  for (const r of inScope) {
    const score = r.score || 0;
    const isDetected = score >= OSSF_TPR_THRESHOLD;
    if (isDetected) detected++;

    // Score bucket
    let bucket;
    if (score === 0) bucket = '0';
    else if (score <= 9) bucket = '1-9';
    else if (score <= 19) bucket = '10-19';
    else if (score <= 49) bucket = '20-49';
    else bucket = '50+';
    scoreDistribution[bucket]++;
    if (isDetected) detectedByBucket[bucket]++;

    // Per-source breakdown
    const src = r.source || 'unknown';
    if (!bySource[src]) bySource[src] = { detected: 0, total: 0 };
    bySource[src].total++;
    if (isDetected) bySource[src].detected++;

    // Per-sample detail for triage
    const threatTypes = (r.threats || []).map(t => t.type);
    const detail = {
      name: r.name || r.package || 'unknown',
      score,
      source: src,
      detected: isDetected,
      threatCount: (r.threats || []).length,
      topThreats: threatTypes.slice(0, 5)
    };
    details.push(detail);
    if (!isDetected) misses.push(detail);
  }

  const total = inScope.length;
  const tpr = total > 0 ? detected / total : 0;
  const tprCI = wilsonCI(detected, total);

  for (const src of Object.keys(bySource)) {
    const s = bySource[src];
    s.tpr = s.total > 0 ? s.detected / s.total : 0;
    s.tprCI = wilsonCI(s.detected, s.total);
  }

  const scoreBuckets = {};
  for (const bucket of Object.keys(scoreDistribution)) {
    scoreBuckets[bucket] = {
      total: scoreDistribution[bucket],
      detected: detectedByBucket[bucket],
      tpr: scoreDistribution[bucket] > 0 ? detectedByBucket[bucket] / scoreDistribution[bucket] : 0
    };
  }

  // Miss analysis: group misses by pattern for triage prioritization
  const missPatterns = {};
  for (const m of misses) {
    const key = m.threatCount === 0 ? 'zero_threats' :
      m.topThreats.length === 1 ? m.topThreats[0] : 'multi_signal';
    if (!missPatterns[key]) missPatterns[key] = { count: 0, avgScore: 0, samples: [] };
    missPatterns[key].count++;
    missPatterns[key].avgScore += m.score;
    if (missPatterns[key].samples.length < 3) missPatterns[key].samples.push(m.name);
  }
  for (const p of Object.values(missPatterns)) {
    p.avgScore = p.count > 0 ? Math.round(p.avgScore / p.count * 10) / 10 : 0;
  }

  return {
    detected,
    total,
    tpr,
    tprCI,
    threshold: OSSF_TPR_THRESHOLD,
    bySource,
    scoreBuckets,
    missPatterns,
    misses,
    details,
    unavailable: benchmark.results.filter(r => r.status === 'unavailable').length,
    coverage: benchmark.metadata && benchmark.metadata.coverage || null,
    benchmarkDate: benchmark.metadata && benchmark.metadata.scanned_at || null
  };
}

/**
 * Cluster false positives by (rule type, normalized file pattern, is_bundle).
 *
 * Drives Chantier 1 of the FPR improvement plan : surface the dominant
 * FP buckets so subsequent chantiers (call-graph reachability, delta scanning,
 * mature gate, etc.) can target the right detections instead of guessing.
 *
 * Each cluster contains :
 *   - key : human-readable cluster identifier
 *   - count : number of FP occurrences across all corpora
 *   - rule_type : threat type
 *   - file_pattern : normalized path (digits, hashes, versions, basenames stripped)
 *   - is_bundle : whether the file matches BUNDLE_PATH_RE
 *   - severity_distribution : count by severity
 *   - corpus_distribution : count by corpus (curated/random/pypi)
 *   - examples : up to 5 (package, file, severity) tuples
 *
 * @param {Object} sources - { curated: details[], random: details[], pypi: details[] }
 * @returns {Object} { totalFps, totalUniqueClusters, topClusters, schema_version }
 */
function clusterFalsePositives(sources) {
  let BUNDLE_PATH_RE = null;
  try {
    BUNDLE_PATH_RE = require('../shared/bundle-detect.js').BUNDLE_PATH_RE;
  } catch { /* fallback : no bundle classification */ }

  const normalizeFilePattern = (file) => {
    if (!file || typeof file !== 'string') return '<no-file>';
    let p = file.replace(/\\/g, '/');
    // Strip leading "package/" prefix produced by tarball extraction
    p = p.replace(/^(?:[\w@.-]+\/)?package\//, '');
    // Replace hex hashes (>=6 chars) with <HASH>
    p = p.replace(/\b[a-f0-9]{6,40}\b/gi, '<HASH>');
    // Replace version-like tokens
    p = p.replace(/\bv?\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?\b/g, '<VER>');
    // Replace digit runs of length >=2
    p = p.replace(/\d{2,}/g, '<N>');
    // Normalize basename : last path segment becomes <NAME> if it's a filename
    const segs = p.split('/');
    if (segs.length > 0) {
      const last = segs[segs.length - 1];
      const m = /^(.+?)(\.\w+)$/.exec(last);
      if (m) {
        // Keep the structural suffix (.min.js, .esm.js, .bundle.js) but anonymize the stem
        const stem = m[1];
        const ext = m[2];
        const structuralSuffix = /\.(min|bundle|umd|esm|es|common|max|prod|production|iife|cjs|mjs)$/i.exec(stem);
        if (structuralSuffix) {
          segs[segs.length - 1] = '<NAME>' + structuralSuffix[0] + ext;
        } else {
          segs[segs.length - 1] = '<NAME>' + ext;
        }
      }
    }
    return segs.join('/');
  };

  const clusters = new Map();
  let totalFps = 0;

  const ingest = (details, corpus) => {
    if (!Array.isArray(details)) return;
    for (const entry of details) {
      if (!entry || !entry.flagged || !entry.threats) continue;
      for (const t of entry.threats) {
        if (!t || !t.type) continue;
        totalFps++;
        const filePattern = normalizeFilePattern(t.file);
        const isBundle = BUNDLE_PATH_RE && t.file ? BUNDLE_PATH_RE.test(t.file) : false;
        const key = `${t.type} | ${filePattern} | ${isBundle ? 'bundle' : 'src'}`;
        let c = clusters.get(key);
        if (!c) {
          c = {
            key,
            count: 0,
            rule_type: t.type,
            file_pattern: filePattern,
            is_bundle: isBundle,
            severity_distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
            corpus_distribution: { curated: 0, random: 0, pypi: 0 },
            packages: new Set(),
            examples: []
          };
          clusters.set(key, c);
        }
        c.count++;
        if (c.severity_distribution[t.severity] !== undefined) c.severity_distribution[t.severity]++;
        if (c.corpus_distribution[corpus] !== undefined) c.corpus_distribution[corpus]++;
        c.packages.add(entry.name);
        if (c.examples.length < 5) {
          c.examples.push({ package: entry.name, file: t.file || null, severity: t.severity });
        }
      }
    }
  };

  ingest(sources.curated || [], 'curated');
  ingest(sources.random || [], 'random');
  ingest(sources.pypi || [], 'pypi');

  // Materialize clusters, drop Set, sort by count desc
  const all = Array.from(clusters.values()).map(c => ({
    ...c,
    distinct_packages: c.packages.size,
    packages: undefined
  }));
  all.sort((a, b) => b.count - a.count);

  return {
    schema_version: 1,
    totalFps,
    totalUniqueClusters: all.length,
    topClusters: all.slice(0, 30)
  };
}

/**
 * Save metrics to metrics/v{version}.json
 */
function saveMetrics(report) {
  if (!fs.existsSync(METRICS_DIR)) {
    fs.mkdirSync(METRICS_DIR, { recursive: true });
  }
  const filename = `v${report.version}.json`;
  const filepath = path.join(METRICS_DIR, filename);
  fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
  return filepath;
}

// --- Corpus-dir evaluation (offline, re-scan at HEAD) -----------------------

const CORPUS_ARCHIVE_EXT = /\.(tgz|tar\.gz|tar|whl|zip)$/i;

function _corpusMaxSamples() {
  const raw = process.env.MUADDIB_CORPUS_MAX;
  const n = raw ? parseInt(raw, 10) : NaN;
  return (Number.isFinite(n) && n >= 1 && n <= 200_000) ? n : 5000;
}

// Derive "name@version" + first_seen for a sample from its sidecar metadata
// (src/monitor/tarball-archive.js writes `<name>-<version>.json`) or, failing
// that, from the filename and the file mtime.
function _corpusSampleMeta(archivePath, sidecar) {
  let name = null, version = null, firstSeen = null, label = null;
  if (sidecar) {
    name = sidecar.package || null;
    version = sidecar.version || null;
    firstSeen = sidecar.timestamp || sidecar.first_seen || null;
    if (sidecar.label === 'malicious' || sidecar.label === 'clean') label = sidecar.label;
  }
  if (!name || !version) {
    // "<sanitized-name>-<version>.<ext>" → split on the LAST hyphen group that
    // looks like a version. Best-effort; the sidecar is the authoritative source.
    const base = path.basename(archivePath).replace(CORPUS_ARCHIVE_EXT, '');
    const m = /^(.*)-(\d[\w.\-+]*)$/.exec(base);
    if (m) { name = name || m[1]; version = version || m[2]; }
    else { name = name || base; version = version || '0.0.0'; }
  }
  if (!firstSeen) {
    try { firstSeen = fs.statSync(archivePath).mtime.toISOString(); } catch { firstSeen = null; }
  }
  return { name, version, firstSeen, label };
}

// Three honest time buckets (relative to now): fresh (last 60d — never
// rule-tuned, the generalization proxy), current (2025-01-01 .. -60d), and
// historical (older). Unknown dates fall into "undated".
function _corpusTimeBucket(firstSeenISO) {
  if (!firstSeenISO) return 'undated';
  const t = Date.parse(firstSeenISO);
  if (!Number.isFinite(t)) return 'undated';
  const ageDays = (Date.now() - t) / 86_400_000;
  if (ageDays <= 60) return 'fresh';
  if (t >= Date.parse('2025-01-01T00:00:00Z')) return 'current';
  return 'historical';
}

/**
 * Evaluate an arbitrary local corpus of archived tarballs (e.g. the monitor
 * archive rsync'd to a workstation) by RE-SCANNING each at HEAD. Never a replay
 * of stored scores — this is the real, current counterpart the frozen
 * Datadog/OSSF benchmarks are not.
 *
 * Accepted layout (matches src/monitor/tarball-archive.js):
 *   <corpusDir>/ ** /<name>-<version>.tgz     ← re-scanned at HEAD
 *   <corpusDir>/ ** /<name>-<version>.json    ← optional sidecar {package,version,timestamp,score,label?}
 *   <corpusDir>/labels.json                   ← optional { "name@version": "malicious"|"clean" }
 *
 * Labels are OPTIONAL and honest: the archive stores a *score*, not a verdict.
 *   - With labels → TPR (malicious flagged ≥ threshold) + FPR (clean flagged),
 *     each time-stratified and with a Wilson CI.
 *   - Without → score distribution + flagged rate only.
 *
 * Bounded (CLAUDE.md): ≤ MUADDIB_CORPUS_MAX samples (default 5000); each archive
 * is extracted to a scratch dir and removed right after its scan, so the run
 * cannot itself fill the disk.
 */
async function evaluateCorpusDir(corpusDir, options = {}) {
  const jsonMode = options.json || false;
  if (!corpusDir || !fs.existsSync(corpusDir)) {
    throw new Error(`--corpus-dir not found: ${corpusDir}`);
  }
  const threshold = BENIGN_THRESHOLD;
  const maxSamples = _corpusMaxSamples();

  // Optional external label map (the review-loop output).
  let labelMap = Object.create(null);
  try {
    const lf = path.join(corpusDir, 'labels.json');
    if (fs.existsSync(lf)) labelMap = JSON.parse(fs.readFileSync(lf, 'utf8')) || Object.create(null);
  } catch { /* malformed labels.json — proceed unlabeled */ }

  // Discover archives (bounded, symlink-free, depth-capped).
  const archives = [];
  (function walk(dir, depth) {
    if (depth > 12 || archives.length >= maxSamples) return;
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (archives.length >= maxSamples) return;
      if (e.isSymbolicLink && e.isSymbolicLink()) continue;
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) { walk(fp, depth + 1); continue; }
      if (CORPUS_ARCHIVE_EXT.test(e.name)) archives.push(fp);
    }
  })(corpusDir, 0);

  // Unique work root per invocation — a deterministic path would collide across
  // back-to-back runs (and concurrent processes) when a prior extraction's
  // cleanup lags (Windows), corrupting the next scan. mkdtemp guarantees isolation.
  const cacheBase = path.join(ROOT, '.muaddib-cache');
  fs.mkdirSync(cacheBase, { recursive: true });
  const workRoot = fs.mkdtempSync(path.join(cacheBase, 'corpus-work-'));

  const details = [];
  let skipped = 0;
  const total = archives.length;

  for (let i = 0; i < archives.length; i++) {
    const archivePath = archives[i];
    if (!jsonMode && process.stdout.isTTY) {
      process.stdout.write(`\r  [corpus] [${i + 1}/${total}] ${path.basename(archivePath)}${''.padEnd(30)}`);
    }

    // Sidecar metadata (same basename, .json).
    let sidecar = null;
    try {
      const sc = archivePath.replace(CORPUS_ARCHIVE_EXT, '.json');
      if (sc !== archivePath && fs.existsSync(sc)) sidecar = JSON.parse(fs.readFileSync(sc, 'utf8'));
    } catch { /* ignore malformed sidecar */ }

    const meta = _corpusSampleMeta(archivePath, sidecar);
    const key = `${meta.name}@${meta.version}`;
    const label = meta.label || (labelMap[key] === 'malicious' || labelMap[key] === 'clean' ? labelMap[key] : null);
    const bucket = _corpusTimeBucket(meta.firstSeen);

    const scratch = path.join(workRoot, `s${i}-${sanitizeCorpusName(meta.name)}`);
    let extractedDir = null;
    try {
      fs.mkdirSync(scratch, { recursive: true });
      extractedDir = extractArchive(archivePath, scratch);
    } catch (err) {
      details.push({ name: meta.name, version: meta.version, key, label, bucket, firstSeen: meta.firstSeen, score: 0, flagged: false, skipped: true, error: `extract failed: ${err.code || err.message}` });
      skipped++;
      try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best-effort */ }
      continue;
    }

    let result;
    try {
      result = await silentScan(extractedDir || scratch);
    } catch (err) {
      details.push({ name: meta.name, version: meta.version, key, label, bucket, firstSeen: meta.firstSeen, score: 0, flagged: false, skipped: true, error: `scan failed: ${err.code || err.message}` });
      skipped++;
      try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best-effort */ }
      continue;
    }

    const score = (result && result.summary && Number.isFinite(result.summary.riskScore)) ? result.summary.riskScore : 0;
    const flagged = score >= threshold;
    const entry = { name: meta.name, version: meta.version, key, label, bucket, firstSeen: meta.firstSeen, score, flagged };
    if (flagged && result.threats) {
      entry.threats = result.threats.slice(0, 20).map(t => ({ type: t.type, severity: t.severity, file: t.file }));
    }
    details.push(entry);

    // Scratch cleanup — do NOT accumulate extracted trees across the corpus.
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best-effort */ }
  }

  if (!jsonMode && process.stdout.isTTY) process.stdout.write('\r' + ''.padEnd(80) + '\r');

  // Remove the per-invocation work root (per-sample scratch was already cleaned).
  try { fs.rmSync(workRoot, { recursive: true, force: true }); } catch { /* best-effort */ }

  const summary = _summarizeCorpus(details, threshold);
  const report = {
    version: require('../../package.json').version,
    date: new Date().toISOString(),
    mode: 'corpus-dir',
    corpusDir: path.resolve(corpusDir),
    threshold,
    total,
    scanned: total - skipped,
    skipped,
    ...summary
  };

  const stamp = report.date.replace(/[:.]/g, '-');
  const outDir = process.env.MUADDIB_CORPUS_OUT_DIR || METRICS_DIR;
  const outPath = path.join(outDir, `corpus-${stamp}.json`);
  try {
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  } catch { /* metrics write is best-effort */ }

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    _printCorpusReport(report, outPath);
  }
  return report;
}

function sanitizeCorpusName(name) {
  return String(name || 'pkg').replace(/^@/, '').replace(/\//g, '__').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
}

// Roll up score distribution, flagged rate, and (when labels exist) TPR/FPR —
// overall and per time bucket.
function _summarizeCorpus(details, threshold) {
  const scored = details.filter(d => !d.skipped);
  const dist = { '0': 0, '1-9': 0, '10-19': 0, '20-49': 0, '50+': 0 };
  for (const d of scored) {
    const s = d.score;
    if (s === 0) dist['0']++;
    else if (s <= 9) dist['1-9']++;
    else if (s <= 19) dist['10-19']++;
    else if (s <= 49) dist['20-49']++;
    else dist['50+']++;
  }
  const flagged = scored.filter(d => d.flagged).length;
  const flaggedRate = scored.length ? flagged / scored.length : 0;

  function labelStats(set) {
    const mal = set.filter(d => d.label === 'malicious');
    const clean = set.filter(d => d.label === 'clean');
    const detected = mal.filter(d => d.flagged).length;
    const falsePos = clean.filter(d => d.flagged).length;
    return {
      malicious: mal.length,
      detected,
      tpr: mal.length ? detected / mal.length : null,
      tprCI: mal.length ? wilsonCI(detected, mal.length) : null,
      clean: clean.length,
      falsePositives: falsePos,
      fpr: clean.length ? falsePos / clean.length : null,
      fprCI: clean.length ? wilsonCI(falsePos, clean.length) : null
    };
  }

  const byBucket = {};
  for (const b of ['fresh', 'current', 'historical', 'undated']) {
    const set = scored.filter(d => d.bucket === b);
    if (set.length === 0) continue;
    byBucket[b] = {
      total: set.length,
      flagged: set.filter(d => d.flagged).length,
      labeled: labelStats(set)
    };
  }

  const hasLabels = scored.some(d => d.label);
  return {
    scoreDistribution: dist,
    flagged,
    flaggedRate,
    labeled: hasLabels ? labelStats(scored) : null,
    byTimeBucket: byBucket,
    samples: details.slice(0, 500)
  };
}

function _printCorpusReport(r, outPath) {
  const bar = '='.repeat(56);
  console.log('');
  console.log(bar);
  console.log(`  MUAD'DIB corpus evaluation (re-scanned at HEAD, v${r.version})`);
  console.log(bar);
  console.log(`  Corpus     : ${r.corpusDir}`);
  console.log(`  Samples    : ${r.scanned} scanned, ${r.skipped} skipped (of ${r.total})`);
  console.log(`  Threshold  : score ≥ ${r.threshold}`);
  console.log(`  Flagged    : ${r.flagged}/${r.scanned}  (${(r.flaggedRate * 100).toFixed(1)}%)`);
  const d = r.scoreDistribution;
  console.log(`  Scores     : 0=${d['0']}  1-9=${d['1-9']}  10-19=${d['10-19']}  20-49=${d['20-49']}  50+=${d['50+']}`);
  if (r.labeled) {
    const L = r.labeled;
    if (L.tpr != null) console.log(`  TPR        : ${L.detected}/${L.malicious}  ${(L.tpr * 100).toFixed(1)}%  [${(L.tprCI.lower * 100).toFixed(1)}-${(L.tprCI.upper * 100).toFixed(1)}%]`);
    if (L.fpr != null) console.log(`  FPR        : ${L.falsePositives}/${L.clean}  ${(L.fpr * 100).toFixed(1)}%  [${(L.fprCI.lower * 100).toFixed(1)}-${(L.fprCI.upper * 100).toFixed(1)}%]`);
  } else {
    console.log(`  (no labels — provide labels.json or sidecar .label for TPR/FPR)`);
  }
  const buckets = Object.keys(r.byTimeBucket);
  if (buckets.length) {
    console.log(`  ${'-'.repeat(52)}`);
    for (const b of buckets) {
      const bk = r.byTimeBucket[b];
      let line = `  ${b.padEnd(10)} n=${bk.total}  flagged=${bk.flagged}`;
      if (bk.labeled && bk.labeled.tpr != null) line += `  TPR=${(bk.labeled.tpr * 100).toFixed(0)}%`;
      if (bk.labeled && bk.labeled.fpr != null) line += `  FPR=${(bk.labeled.fpr * 100).toFixed(0)}%`;
      console.log(line);
    }
  }
  console.log(bar);
  console.log(`  Saved: ${path.relative(ROOT, outPath)}`);
  console.log('');
}

/**
 * Main evaluate function
 *
 * Options:
 *   json             — JSON output mode
 *   benignLimit      — Only test first N benign packages
 *   refreshBenign    — Force re-download of all tarballs
 */
async function evaluate(options = {}) {
  const version = require('../../package.json').version;
  const jsonMode = options.json || false;

  // Corpus-dir mode: re-scan an arbitrary local archive at HEAD and return.
  // Skips the 8 static-corpus phases entirely — this is the measurement on YOUR
  // rapatriated captures, not the built-in benchmark set.
  if (options.corpusDir) {
    return evaluateCorpusDir(options.corpusDir, options);
  }

  // Load scan result cache (auto-invalidates when src/ changes)
  const cachedCount = options.refreshBenign ? 0 : loadScanCache();
  if (!jsonMode && cachedCount > 0) {
    console.log(`\n  [CACHE] ${cachedCount} cached scan results loaded (src/ unchanged)`);
  }

  if (!jsonMode) {
    console.log(`\n  MUAD'DIB Evaluation (v${version})\n`);
    console.log(`  [1/5] Ground Truth...`);
  }
  const groundTruth = await evaluateGroundTruth();

  if (!jsonMode) {
    console.log(`  [2/5] Benign npm packages (real source code)...`);
  }
  const benign = await evaluateBenign(options);

  if (!jsonMode) {
    console.log(`  [2b/5] Benign PyPI packages...`);
  }
  const benignPyPI = await evaluateBenignPyPI(options);

  if (!jsonMode) {
    console.log(`  [2c/5] Benign Random npm packages...`);
  }
  const benignRandom = await evaluateBenignRandom(options);

  if (!jsonMode) {
    console.log(`  [3/5] Adversarial samples...`);
  }
  const adversarial = await evaluateAdversarial();

  if (!jsonMode) {
    console.log(`  [4/5] Datadog benchmark TPR...`);
  }
  const datadogTPR = evaluateDatadogTPR();

  if (!jsonMode) {
    console.log(`  [4b/5] OpenSSF benchmark TPR...`);
  }
  const ossfTPR = evaluateOSSFTPR();

  // --- ML Classifier evaluation ---
  const mlEval = await evaluateMLClassifier(
    benign.details || [],
    groundTruth.details || [],
    adversarial.details || []
  );

  // Compute post-ML effective FPR: subtract T1 benign packages reclassified as clean by ML
  const fprAfterML = mlEval && benign.scanned > 0
    ? {
        flagged: benign.flagged - mlEval.mlCleanBenign,
        scanned: benign.scanned,
        fpr: (benign.flagged - mlEval.mlCleanBenign) / benign.scanned,
        fprCI: wilsonCI(benign.flagged - mlEval.mlCleanBenign, benign.scanned),
        mlCleanBenign: mlEval.mlCleanBenign,
        t1Benign: mlEval.t1Benign
      }
    : null;

  const fpClusters = clusterFalsePositives({
    curated: benign && benign.details,
    random: benignRandom && benignRandom.details,
    pypi: benignPyPI && benignPyPI.details
  });

  // Phase 0b: embed the operational coverage rollup from the live per-scan ledger
  // (monitor runtime) so each metrics snapshot carries the operational picture next to
  // the offline TPR/FPR. Best-effort + lazy require: on CI / a machine with no ledger,
  // computeLedgerRollup returns a zero rollup and regression-check treats it as a SKIP.
  let operational = null;
  try {
    operational = require('../monitor/state.js').computeLedgerRollup(null);
  } catch { /* monitor state unavailable — operational stays null (rétro-compatible) */ }

  const report = {
    version,
    date: new Date().toISOString(),
    headline: {
      tpr: groundTruth.tprAt20,
      tprThreshold: ADR_THRESHOLD,
      tprLabel: 'TPR@20 (alert rate — operational threshold)',
      tprDetected: groundTruth.detectedAt20,
      tprTotal: groundTruth.total,
      tprCI: groundTruth.tprAt20CI,
      tprAt3: groundTruth.tpr,
      tprAt3Label: 'TPR@3 (any signal — detection rate)',
    },
    groundTruth,
    benign,
    benignPyPI,
    benignRandom,
    adversarial,
    datadogTPR,
    ossfTPR,
    mlEvaluation: mlEval || null,
    fprAfterML: fprAfterML || null,
    operational,
    fpClusters
  };

  const metricsPath = saveMetrics(report);

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const tprPct = (groundTruth.tpr * 100).toFixed(1);
    const tprAllPct = (groundTruth.tprAll * 100).toFixed(1);
    const fprPct = (benign.fpr * 100).toFixed(1);
    const adrPct = (adversarial.adr * 100).toFixed(1);

    console.log('');
    const tprCIStr = groundTruth.tprCI ? ` [95% CI: ${(groundTruth.tprCI.lower * 100).toFixed(1)}-${(groundTruth.tprCI.upper * 100).toFixed(1)}%]` : '';
    const tprAt20Pct = (groundTruth.tprAt20 * 100).toFixed(1);
    const tprAt20CIStr = groundTruth.tprAt20CI ? ` [95% CI: ${(groundTruth.tprAt20CI.lower * 100).toFixed(1)}-${(groundTruth.tprAt20CI.upper * 100).toFixed(1)}%]` : '';
    console.log(`  TPR@20 (alert rate):   ${groundTruth.detectedAt20}/${groundTruth.total}  ${tprAt20Pct}%${tprAt20CIStr}  ← headline metric`);
    console.log(`  TPR@3  (any signal):   ${groundTruth.detected}/${groundTruth.total}  ${tprPct}%${tprCIStr}`);
    // Divergence warning: if TPR@3 and TPR@20 differ by >15 points, flag it
    const divergence = Math.abs(groundTruth.tpr - groundTruth.tprAt20) * 100;
    if (divergence > 15) {
      console.log(`  ⚠ WARNING: TPR@3 and TPR@20 diverge by ${divergence.toFixed(1)} points — ${groundTruth.detected - groundTruth.detectedAt20} samples score 3-19 (weak signal only)`);
    }
    console.log(`  TPR (all samples):     ${groundTruth.detected}/${groundTruth.totalAll}  ${tprAllPct}%  [includes ${groundTruth.totalAll - groundTruth.total} browser-only out-of-scope]`);
    console.log(`  TPR IOC-based:         ${groundTruth.iocBased}/${groundTruth.total}`);
    console.log(`  TPR heuristic-only:    ${groundTruth.heuristicOnly}/${groundTruth.total}`);
    const fprCIStr = benign.fprCI ? ` [95% CI: ${(benign.fprCI.lower * 100).toFixed(1)}-${(benign.fprCI.upper * 100).toFixed(1)}%]` : '';
    console.log(`  FPR (global):          ${benign.flagged}/${benign.scanned}  ${fprPct}%${fprCIStr}`);
    if (fprAfterML) {
      const fprAfterMLPct = (fprAfterML.fpr * 100).toFixed(1);
      const fprAfterMLCIStr = fprAfterML.fprCI ? ` [95% CI: ${(fprAfterML.fprCI.lower * 100).toFixed(1)}-${(fprAfterML.fprCI.upper * 100).toFixed(1)}%]` : '';
      console.log(`  FPR (after ML):        ${fprAfterML.flagged}/${fprAfterML.scanned}  ${fprAfterMLPct}%${fprAfterMLCIStr}  [ML: ${fprAfterML.mlCleanBenign}/${fprAfterML.t1Benign} T1 reclassified clean]`);
    }
    if (benign.holdoutSplit) {
      const hs = benign.holdoutSplit;
      console.log(`  FPR (training):        ${hs.training.flagged}/${hs.training.total}  ${(hs.training.fpr * 100).toFixed(1)}%  [70% tuning set]`);
      console.log(`  FPR (holdout):         ${hs.holdout.flagged}/${hs.holdout.total}  ${(hs.holdout.fpr * 100).toFixed(1)}%  [30% validation set]`);
    }
    if (benign.stratified) {
      for (const [cat, data] of Object.entries(benign.stratified)) {
        if (data.total > 0) {
          const label = cat === 'veryLarge' ? 'very large' : cat;
          const pct = (data.fpr * 100).toFixed(1);
          const sizeDesc = cat === 'small' ? '<10 JS files' : cat === 'medium' ? '10-50 files' : cat === 'large' ? '50-100 files' : '100+ files';
          console.log(`  FPR (${label.padEnd(10)}):  ${data.flagged}/${data.total}   ${pct}%   [${sizeDesc}]`);
        }
      }
    }
    if (benignPyPI) {
      const pypiPct = (benignPyPI.fpr * 100).toFixed(1);
      console.log(`  Benign PyPI (FPR):     ${benignPyPI.flagged}/${benignPyPI.scanned}  ${pypiPct}%  (${benignPyPI.skipped} skipped)`);
    }
    if (benignRandom) {
      const randomPct = (benignRandom.fpr * 100).toFixed(1);
      const randomCIStr = benignRandom.fprCI ? ` [95% CI: ${(benignRandom.fprCI.lower * 100).toFixed(1)}-${(benignRandom.fprCI.upper * 100).toFixed(1)}%]` : '';
      console.log(`  FPR (random npm):      ${benignRandom.flagged}/${benignRandom.scanned}  ${randomPct}%${randomCIStr}  (${benignRandom.skipped} skipped)`);
    }
    const adrCIStr = adversarial.adrCI ? ` [95% CI: ${(adversarial.adrCI.lower * 100).toFixed(1)}-${(adversarial.adrCI.upper * 100).toFixed(1)}%]` : '';
    console.log(`  ADR (threshold=${ADR_THRESHOLD}):   ${adversarial.detected}/${adversarial.available}  ${adrPct}%${adrCIStr}  (${adversarial.total - adversarial.available} missing)`);
    if (adversarial.cohorts) {
      const adv = adversarial.cohorts.adversarial;
      const hold = adversarial.cohorts.holdout;
      console.log(`  ADR (adversarial):     ${adv.detected}/${adv.available}  ${(adv.adr * 100).toFixed(1)}%`);
      console.log(`  ADR (holdout):         ${hold.detected}/${hold.available}  ${(hold.adr * 100).toFixed(1)}%`);
    }
    if (datadogTPR) {
      const ddPct = (datadogTPR.tpr * 100).toFixed(1);
      const ddCIStr = datadogTPR.tprCI ? ` [95% CI: ${(datadogTPR.tprCI.lower * 100).toFixed(1)}-${(datadogTPR.tprCI.upper * 100).toFixed(1)}%]` : '';
      console.log(`  Datadog TPR (n=${datadogTPR.total}): ${datadogTPR.detected}/${datadogTPR.total}  ${ddPct}%${ddCIStr}`);
      for (const [cat, data] of Object.entries(datadogTPR.byCategory)) {
        const catPct = (data.tpr * 100).toFixed(1);
        console.log(`    ${cat.padEnd(20)}: ${String(data.detected).padStart(5)}/${String(data.total).padStart(5)}  ${catPct}%`);
      }
      console.log(`  Datadog score distribution:`);
      for (const [bucket, data] of Object.entries(datadogTPR.scoreBuckets)) {
        const bPct = (data.tpr * 100).toFixed(1);
        console.log(`    score ${bucket.padEnd(5)}: ${String(data.detected).padStart(5)}/${String(data.total).padStart(5)} detected  ${bPct}%`);
      }
    }
    if (ossfTPR) {
      const ossfPct = (ossfTPR.tpr * 100).toFixed(1);
      const ossfCIStr = ossfTPR.tprCI ? ` [95% CI: ${(ossfTPR.tprCI.lower * 100).toFixed(1)}-${(ossfTPR.tprCI.upper * 100).toFixed(1)}%]` : '';
      console.log(`  OpenSSF TPR (n=${ossfTPR.total}): ${ossfTPR.detected}/${ossfTPR.total}  ${ossfPct}%${ossfCIStr}  (coverage: ${ossfTPR.coverage || 'N/A'})`);
      for (const [src, data] of Object.entries(ossfTPR.bySource)) {
        const srcPct = (data.tpr * 100).toFixed(1);
        console.log(`    ${src.padEnd(25)}: ${String(data.detected).padStart(5)}/${String(data.total).padStart(5)}  ${srcPct}%`);
      }
      if (ossfTPR.missPatterns && Object.keys(ossfTPR.missPatterns).length > 0) {
        console.log(`  OpenSSF miss patterns (${ossfTPR.misses.length} missed):`);
        const sorted = Object.entries(ossfTPR.missPatterns).sort((a, b) => b[1].count - a[1].count);
        for (const [pattern, data] of sorted) {
          console.log(`    ${pattern.padEnd(25)}: ${String(data.count).padStart(3)} samples  avg_score=${data.avgScore}  [${data.samples.join(', ')}]`);
        }
      }
      if (ossfTPR.misses && ossfTPR.misses.length > 0) {
        console.log(`  OpenSSF misses (score < ${ossfTPR.threshold}):`);
        const sortedMisses = ossfTPR.misses.slice().sort((a, b) => b.score - a.score);
        for (const m of sortedMisses.slice(0, 15)) {
          const threats = m.topThreats.length > 0 ? m.topThreats.join(', ') : 'none';
          console.log(`    ${m.name.padEnd(40).substring(0, 40)}: score ${String(m.score).padStart(2)}  [${m.source}]  threats: ${threats}`);
        }
        if (sortedMisses.length > 15) console.log(`    ... and ${sortedMisses.length - 15} more`);
      }
    }
    console.log('');

    // Show failed adversarial samples
    const missed = adversarial.details.filter(d => !d.detected);
    if (missed.length > 0) {
      console.log('  Adversarial misses:');
      for (const m of missed) {
        console.log(`    ${m.name}: score ${m.score} < threshold ${m.threshold}`);
      }
      console.log('');
    }

    // Show false positives with threat details
    const fps = benign.details.filter(d => d.flagged);
    if (fps.length > 0) {
      console.log('  False positives:');
      for (const fp of fps) {
        console.log(`    ${fp.name}: score ${fp.score}`);
        if (fp.threats) {
          for (const t of fp.threats) {
            console.log(`      [${t.severity}] ${t.type}: ${t.message}${t.file ? ' (' + t.file + ')' : ''}`);
          }
        }
      }
      console.log('');
    }

    console.log(`  Saved: ${path.relative(ROOT, metricsPath)}`);
    console.log('');
  }

  // Persist scan result cache for next run
  saveScanCache();

  return report;
}

/**
 * Evaluate ML classifier performance on existing bench results.
 * Replays the classifier on benign, ground-truth, and adversarial results
 * within the T1 zone (score 20-34). Verifies zero regression on GT/ADR.
 *
 * @param {Object} benignResults - array of { name, score, threats } from evaluateBenign
 * @param {Object} gtResults - array of { name, score, threats } from evaluateGroundTruth
 * @param {Object} adrResults - array of { name, score, threats } from evaluateAdversarial
 * @returns {Object} { t1Benign, t1GT, t1ADR, mlCleanBenign, mlCleanGT, mlCleanADR, fpReduction, gtSuppressed, adrSuppressed }
 */
async function evaluateMLClassifier(benignResults, gtResults, adrResults) {
  let classifyPackage, isModelAvailable;
  try {
    const classifier = require('../ml/classifier.js');
    classifyPackage = classifier.classifyPackage;
    isModelAvailable = classifier.isModelAvailable;
  } catch {
    console.log('\n[ML] Classifier module not found — skipping ML evaluation');
    return null;
  }

  if (!isModelAvailable()) {
    console.log('\n[ML] Model not available — skipping ML evaluation (stub mode)');
    return null;
  }

  console.log('\n--- ML Classifier Evaluation ---\n');

  // Filter to T1 zone (score 20-34)
  const inT1 = (r) => r.score >= 20 && r.score < 35;

  const t1Benign = (benignResults || []).filter(inT1);
  const t1GT = (gtResults || []).filter(inT1);
  const t1ADR = (adrResults || []).filter(inT1);

  let mlCleanBenign = 0;
  let mlCleanGT = 0;
  let mlCleanADR = 0;

  // Fetch npm registry metadata for T1 benign packages (needed for ML top features).
  // Only fetches for packages we'll actually classify — ~34 packages, ~7 seconds.
  loadRegistryCache();
  const t1BenignNames = (benignResults || []).filter(r => r.score >= 20 && r.score < 35).map(r => r.name);
  if (t1BenignNames.length > 0) {
    console.log(`  Fetching registry metadata for ${t1BenignNames.length} T1 benign packages...`);
    for (const name of t1BenignNames) {
      if (!_registryCache[name] || (Date.now() - _registryCache[name]._fetchedAt) >= REGISTRY_CACHE_MAX_AGE_MS) {
        await fetchRegistryMeta(name);
      }
    }
    saveRegistryCache();
    console.log(`  Registry cache: ${Object.keys(_registryCache).length} packages cached.`);
  }

  // Build a result+meta pair that matches the monitor's classifyPackage() input.
  // Uses the full summary (fileScores, breakdown, severity counts) and npm registry
  // metadata (age, downloads, size, versions) — same features the ML sees in prod.
  function buildMLInput(r) {
    const summary = r._summary || { riskScore: r.score, total: (r.threats || []).length };
    const result = { threats: r.threats || [], summary };
    const regMeta = _registryCache[r.name] || {};
    const meta = {
      fileCountTotal: r._fileCountTotal || r.jsFiles || 0,
      hasTests: false,
      unpackedSize: regMeta.unpackedSize || 0,
      registryMeta: {},
      npmRegistryMeta: {
        age_days: regMeta.age_days || 0,
        weekly_downloads: regMeta.weekly_downloads || 0,
        version_count: regMeta.version_count || 0,
        author_package_count: regMeta.author_package_count || 0,
        has_repository: regMeta.has_repository || false,
        readme_size: regMeta.readme_size || 0
      }
    };
    return { result, meta };
  }

  // Classify T1 benign (FP candidates — we WANT these classified as clean)
  for (const r of t1Benign) {
    const { result, meta } = buildMLInput(r);
    const ml = classifyPackage(result, meta);
    if (ml.prediction === 'clean') mlCleanBenign++;
  }

  // Classify T1 ground truth (must NOT be classified as clean — zero regression)
  const gtSuppressed = [];
  for (const r of t1GT) {
    const { result, meta } = buildMLInput(r);
    const ml = classifyPackage(result, meta);
    if (ml.prediction === 'clean') {
      mlCleanGT++;
      gtSuppressed.push(r.name);
    }
  }

  // Classify T1 adversarial (must NOT be classified as clean — zero regression)
  const adrSuppressedList = [];
  for (const r of t1ADR) {
    const { result, meta } = buildMLInput(r);
    const ml = classifyPackage(result, meta);
    if (ml.prediction === 'clean') {
      mlCleanADR++;
      adrSuppressedList.push(r.name);
    }
  }

  const fpReduction = t1Benign.length > 0
    ? Math.round((mlCleanBenign / t1Benign.length) * 100 * 10) / 10
    : 0;

  console.log(`  T1 Benign: ${t1Benign.length} packages, ${mlCleanBenign} ML-clean (${fpReduction}% FP reduction)`);
  console.log(`  T1 Ground Truth: ${t1GT.length} packages, ${mlCleanGT} ML-clean (MUST be 0)`);
  console.log(`  T1 Adversarial: ${t1ADR.length} packages, ${mlCleanADR} ML-clean (MUST be 0)`);

  if (mlCleanGT > 0) {
    console.log(`\n  [FAIL] GT suppressed by ML: ${gtSuppressed.join(', ')}`);
  }
  if (mlCleanADR > 0) {
    console.log(`\n  [FAIL] ADR suppressed by ML: ${adrSuppressedList.join(', ')}`);
  }
  if (mlCleanGT === 0 && mlCleanADR === 0) {
    console.log(`\n  [PASS] Zero regression on GT and ADR`);
  }

  return {
    t1Benign: t1Benign.length,
    t1GT: t1GT.length,
    t1ADR: t1ADR.length,
    mlCleanBenign,
    mlCleanGT,
    mlCleanADR,
    fpReduction,
    gtSuppressed: gtSuppressed.length,
    adrSuppressed: adrSuppressedList.length
  };
}

/**
 * Classify whether a detection was made via IOC lookup or heuristic analysis.
 * IOC-based: known malicious packages, PyPI IOCs, Shai-Hulud markers
 * Heuristic-based: AST patterns, dataflow, obfuscation, typosquat, etc.
 * @param {Object} threat - Threat object with type field
 * @returns {'ioc'|'heuristic'} Detection source classification
 */
const IOC_TYPES = new Set([
  'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker', 'ioc_match', 'dependency_ioc_match'
]);

function classifyDetectionSource(threat) {
  if (!threat || !threat.type) return 'heuristic';
  return IOC_TYPES.has(threat.type) ? 'ioc' : 'heuristic';
}

module.exports = {
  evaluate,
  evaluateCorpusDir,
  isSafePkgName,
  evaluateGroundTruth,
  evaluateBenign,
  evaluateBenignPyPI,
  evaluateBenignRandom,
  evaluateAdversarial,
  evaluateDatadogTPR,
  evaluateOSSFTPR,
  evaluateMLClassifier,
  saveMetrics,
  clusterFalsePositives,
  silentScan,
  classifyDetectionSource,
  ADVERSARIAL_SAMPLES,
  HOLDOUT_SAMPLES,
  GT_THRESHOLD,
  BENIGN_THRESHOLD,
  ADR_THRESHOLD,
  DATADOG_TPR_THRESHOLD,
  OSSF_TPR_THRESHOLD,
  extractTgz,
  wilsonCI,
  isBenignHoldout,
  computeSrcFingerprint,
  loadScanCache,
  saveScanCache
};
