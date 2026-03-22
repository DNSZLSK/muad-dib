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
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync, execFileSync } = require('child_process');
const { run } = require('../index.js');

const ROOT = path.join(__dirname, '..', '..');
const GT_DIR = path.join(ROOT, 'tests', 'ground-truth');
const BENIGN_DIR = path.join(ROOT, 'datasets', 'benign');
const ADVERSARIAL_DIR = path.join(ROOT, 'datasets', 'adversarial');
const METRICS_DIR = path.join(ROOT, 'metrics');
const CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-tarballs');
const RANDOM_CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-random-tarballs');
const PYPI_CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-pypi');
const SCAN_CACHE_FILE = path.join(ROOT, '.muaddib-cache', 'evaluate-scan-cache.json');
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

// Validate npm package name to prevent shell injection (names come from our own datasets)
const SAFE_PKG_RE = /^(@[\w._-]+\/)?[\w._-]+$/;

// =========================================================================
// Scan result cache — avoids re-scanning when src/ hasn't changed
// =========================================================================

/**
 * Compute a fingerprint of all src/*.js files based on size + mtime.
 * Changes when any scanner source file is modified.
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
  // Store minimal result: only what evaluate needs (score, total, threats summary)
  _scanCache.results[key] = {
    summary: { riskScore: result.summary.riskScore, total: result.summary.total },
    threats: (result.threats || []).map(t => ({
      type: t.type, severity: t.severity, message: t.message, file: t.file
    }))
  };
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
async function silentScan(dir) {
  // Check cache first
  const cached = getCachedResult(dir);
  if (cached) return cached;

  try {
    const result = await run(dir, { _capture: true });
    setCachedResult(dir, result);
    return result;
  } catch (err) {
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
      threshold: GT_THRESHOLD
    });
  }

  const total = attacks.length;
  const tpr = total > 0 ? detected / total : 0;
  const tprAll = totalAll > 0 ? detected / totalAll : 0;
  const tprCI = wilsonCI(detected, total);
  const tprAt20 = total > 0 ? detectedAt20 / total : 0;
  return { detected, detectedAt20, total, totalAll, tpr, tprAt20, tprAll, tprCI, iocBased, heuristicOnly, details };
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
    if (!SAFE_PKG_RE.test(pkg)) throw new Error('invalid package name');
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
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }

  const tgzPath = path.join(pkgCacheDir, tgzFilename);
  if (!fs.existsSync(tgzPath)) {
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }

  // Extract tarball using native Node.js (no shell tar dependency)
  try {
    extractTgz(tgzPath, pkgCacheDir);
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] extract ${pkg} failed: ${(err.message || '').slice(0, 200)}`);
    }
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }

  // Clean up tarball to save space
  try { fs.unlinkSync(tgzPath); } catch { /* ignore */ }

  const extractedDir = path.join(pkgCacheDir, 'package');
  if (!fs.existsSync(extractedDir)) {
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
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

    const extractedDir = downloadAndExtract(pkg, options);
    if (!extractedDir) {
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'download failed' });
      skipped++;
      continue;
    }

    const result = await silentScan(extractedDir);
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

  // Download sdist via pip
  try {
    execFileSync('pip', ['download', '--no-deps', '--no-binary', ':all:', '-d', pkgCacheDir, pkg], {
      encoding: 'utf8',
      timeout: PACK_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] pip download ${pkg} failed: ${(err.stderr || err.message || '').slice(0, 200)}`);
    }
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }

  // Find and extract the downloaded archive
  const archives = fs.readdirSync(pkgCacheDir).filter(f => f.endsWith('.tar.gz') || f.endsWith('.tgz'));
  if (archives.length === 0) {
    // Try .zip files
    const zips = fs.readdirSync(pkgCacheDir).filter(f => f.endsWith('.zip'));
    if (zips.length === 0) {
      fs.rmSync(pkgCacheDir, { recursive: true, force: true });
      return null;
    }
    // Skip zip extraction (not common for sdists) — mark as skipped
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }

  try {
    extractTgz(path.join(pkgCacheDir, archives[0]), pkgCacheDir);
  } catch (err) {
    if (process.env.MUADDIB_DEBUG) {
      console.error(`\n  [DEBUG] extract PyPI ${pkg} failed: ${(err.message || '').slice(0, 200)}`);
    }
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }

  // Clean up archive
  try { fs.unlinkSync(path.join(pkgCacheDir, archives[0])); } catch { /* ignore */ }

  // Find extracted directory
  const entries = fs.readdirSync(pkgCacheDir).filter(e => {
    try { return fs.statSync(path.join(pkgCacheDir, e)).isDirectory(); } catch { return false; }
  });
  if (entries.length === 0) {
    fs.rmSync(pkgCacheDir, { recursive: true, force: true });
    return null;
  }
  return path.join(pkgCacheDir, entries[0]);
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

    const extractedDir = downloadAndExtractPyPI(pkg, options);
    if (!extractedDir) {
      details.push({ name: pkg, score: 0, flagged: false, skipped: true, error: 'download failed' });
      skipped++;
      continue;
    }

    const result = await silentScan(extractedDir);
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
  const listFile = path.join(BENIGN_DIR, 'packages-npm-random.txt');
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
        if (!SAFE_PKG_RE.test(pkg)) throw new Error('invalid package name');
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

    const result = await silentScan(extractedDir);
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
    details.push({ name, score, threshold: ADR_THRESHOLD, detected: isDetected, source: 'adversarial' });
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
    details.push({ name, score, threshold: ADR_THRESHOLD, detected: isDetected, source: 'holdout' });
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

  const report = {
    version,
    date: new Date().toISOString(),
    groundTruth,
    benign,
    benignPyPI,
    benignRandom,
    adversarial,
    datadogTPR
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
    console.log(`  TPR (Node.js attacks): ${groundTruth.detected}/${groundTruth.total}  ${tprPct}%${tprCIStr}`);
    console.log(`  TPR (threshold=20):    ${groundTruth.detectedAt20}/${groundTruth.total}  ${tprAt20Pct}%`);
    console.log(`  TPR (all samples):     ${groundTruth.detected}/${groundTruth.totalAll}  ${tprAllPct}%  [includes ${groundTruth.totalAll - groundTruth.total} browser-only out-of-scope]`);
    console.log(`  TPR IOC-based:         ${groundTruth.iocBased}/${groundTruth.total}`);
    console.log(`  TPR heuristic-only:    ${groundTruth.heuristicOnly}/${groundTruth.total}`);
    const fprCIStr = benign.fprCI ? ` [95% CI: ${(benign.fprCI.lower * 100).toFixed(1)}-${(benign.fprCI.upper * 100).toFixed(1)}%]` : '';
    console.log(`  FPR (global):          ${benign.flagged}/${benign.scanned}  ${fprPct}%${fprCIStr}`);
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
function evaluateMLClassifier(benignResults, gtResults, adrResults) {
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

  // Classify T1 benign (FP candidates — we WANT these classified as clean)
  for (const r of t1Benign) {
    const fakeResult = { threats: r.threats || [], summary: { riskScore: r.score, total: (r.threats || []).length } };
    const ml = classifyPackage(fakeResult, {});
    if (ml.prediction === 'clean') mlCleanBenign++;
  }

  // Classify T1 ground truth (must NOT be classified as clean — zero regression)
  const gtSuppressed = [];
  for (const r of t1GT) {
    const fakeResult = { threats: r.threats || [], summary: { riskScore: r.score, total: (r.threats || []).length } };
    const ml = classifyPackage(fakeResult, {});
    if (ml.prediction === 'clean') {
      mlCleanGT++;
      gtSuppressed.push(r.name);
    }
  }

  // Classify T1 adversarial (must NOT be classified as clean — zero regression)
  const adrSuppressedList = [];
  for (const r of t1ADR) {
    const fakeResult = { threats: r.threats || [], summary: { riskScore: r.score, total: (r.threats || []).length } };
    const ml = classifyPackage(fakeResult, {});
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
  'known_malicious_package', 'pypi_malicious_package', 'shai_hulud_marker', 'ioc_match'
]);

function classifyDetectionSource(threat) {
  if (!threat || !threat.type) return 'heuristic';
  return IOC_TYPES.has(threat.type) ? 'ioc' : 'heuristic';
}

module.exports = {
  evaluate,
  evaluateGroundTruth,
  evaluateBenign,
  evaluateBenignPyPI,
  evaluateBenignRandom,
  evaluateAdversarial,
  evaluateDatadogTPR,
  evaluateMLClassifier,
  saveMetrics,
  silentScan,
  classifyDetectionSource,
  ADVERSARIAL_SAMPLES,
  HOLDOUT_SAMPLES,
  GT_THRESHOLD,
  BENIGN_THRESHOLD,
  ADR_THRESHOLD,
  DATADOG_TPR_THRESHOLD,
  extractTgz,
  wilsonCI,
  isBenignHoldout,
  computeSrcFingerprint,
  loadScanCache,
  saveScanCache
};
