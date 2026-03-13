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
const PYPI_CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-pypi');
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

const ADVERSARIAL_THRESHOLDS = {
  // Vague 1 (20 samples)
  'ci-trigger-exfil': 35,
  'delayed-exfil': 30,
  'docker-aware': 35,
  'staged-fetch': 35,
  'dns-chunk-exfil': 35,
  'string-concat-obfuscation': 30,
  'postinstall-download': 30,
  'dynamic-require': 40,
  'iife-exfil': 40,
  'conditional-chain': 30,
  'template-literal-obfuscation': 30,
  'proxy-env-intercept': 40,
  'nested-payload': 30,
  'dynamic-import': 30,
  'websocket-exfil': 30,
  'bun-runtime-evasion': 25,
  'preinstall-exec': 35,
  'remote-dynamic-dependency': 35,
  'github-exfil': 30,
  'detached-background': 35,
  // Vague 3 (5 samples)
  'ai-agent-weaponization': 35,
  'ai-config-injection': 30,
  'rdd-zero-deps': 35,
  'discord-webhook-exfil': 30,
  'preinstall-background-fork': 35,
  // Holdout → promoted (10 samples)
  'silent-error-swallow': 25,
  'double-base64-exfil': 30,
  'crypto-wallet-harvest': 25,
  'self-hosted-runner-backdoor': 20,
  'dead-mans-switch': 30,
  'fake-captcha-fingerprint': 20,
  'pyinstaller-dropper': 35,
  'gh-cli-token-steal': 30,
  'triple-base64-github-push': 30,
  'browser-api-hook': 20,
  // Audit bypass samples (v2.2.13)
  'indirect-eval-bypass': 10,
  'muaddib-ignore-bypass': 25,
  'mjs-extension-bypass': 100,
  // Vague 4 (5 samples)
  'git-hook-persistence': 10,
  'native-addon-camouflage': 25,
  'stego-png-payload': 35,
  'stegabin-vscode-persistence': 30,
  'mcp-server-injection': 25,
  // Vague 5 (27 samples — advanced evasion techniques)
  'async-iterator-exfil': 20,
  'console-override-exfil': 20,
  'cross-file-callback-exfil': 20,
  'error-reporting-exfil': 20,
  'error-stack-exfil': 20,
  'event-emitter-exfil': 20,
  'fn-return-exfil': 20,
  'getter-defineProperty-exfil': 20,
  'http-header-exfil': 20,
  'import-map-poison': 20,
  'intl-polyfill-backdoor': 20,
  'net-time-exfil': 20,
  'postmessage-exfil': 20,
  'process-title-exfil': 20,
  'promise-chain-exfil': 20,
  'proxy-getter-dns-exfil': 20,
  'readable-stream-exfil': 20,
  'response-intercept-exfil': 20,
  'setTimeout-eval-chain': 20,
  'setter-trap-exfil': 20,
  'sourcemap-payload': 20,
  'stream-pipe-exfil': 20,
  'svg-payload-fetch': 20,
  'symbol-iterator-exfil': 20,
  'toJSON-hijack': 20,
  'url-constructor-exfil': 20,
  'wasm-c2-payload': 20,
  // Vague 6 — DPRK + Intent Graph (10 samples)
  // Group A: pure API, multi-file, cross-file taint
  'locale-config-sync': 25,        // v2.6.1: class this.X + imported sink method
  'metrics-aggregator-lite': 25,   // v2.6.1: EventEmitter + ObjectExpression taint + this.method() sink
  'env-config-validator': 25,      // v2.6.1: imported sink method detection
  'stream-transform-kit': 25,     // v2.6.1: pipe chain cross-file flows
  'cache-warmup-utils': 25,
  // Group B: eval evasion techniques
  'fn-return-eval': 25,
  'call-chain-eval': 20,
  'regex-source-require': 25,
  'charcode-arithmetic': 25,
  'object-method-alias': 25
};

const HOLDOUT_THRESHOLDS = {
  // holdout-v2 (10 samples)
  'conditional-os-payload': 20, 'env-var-reconstruction': 25,
  'github-workflow-inject': 20, 'homedir-ssh-key-steal': 25,
  'npm-cache-poison': 20, 'npm-lifecycle-preinstall-curl': 25,
  'process-env-proxy-getter': 20, 'readable-stream-hijack': 20,
  'setTimeout-chain': 25, 'wasm-loader': 20,
  // holdout-v3 (10 samples)
  'dns-txt-payload': 25, 'electron-rce': 30,
  'env-file-parse-exfil': 20, 'git-credential-steal': 20,
  'npm-hook-hijack': 25, 'postinstall-reverse-shell': 35,
  'require-cache-poison': 20, 'steganography-payload': 15,
  'symlink-escape': 25, 'timezone-trigger': 30,
  // holdout-v4 (10 samples — deobfuscation)
  'atob-eval': 20, 'base64-require': 35,
  'charcode-fetch': 25, 'charcode-spread-homedir': 30,
  'concat-env-steal': 20, 'double-decode-exfil': 40,
  'hex-array-exec': 20, 'mixed-obfuscation-stealer': 30,
  'nested-base64-concat': 25, 'template-literal-hide': 40,
  // holdout-v5 (10 samples — inter-module dataflow)
  'callback-exfil': 3, 'class-method-exfil': 20,
  'conditional-split': 25, 'event-emitter-flow': 3,
  'mixed-inline-split': 20, 'named-export-steal': 20,
  'reexport-chain': 20, 'split-env-exfil': 20,
  'split-npmrc-steal': 20, 'three-hop-chain': 20
};

/**
 * Scan a directory silently and return the result
 */
async function silentScan(dir) {
  try {
    return await run(dir, { _capture: true });
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
    const output = execFileSync('npm', ['pack', pkg], {
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
    const isFlagged = score > BENIGN_THRESHOLD;
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
    const isFlagged = score > BENIGN_THRESHOLD;
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

/**
 * 3. Adversarial — scan evasive malicious samples
 * Skips gracefully if datasets/adversarial/ directory is missing (local-only data).
 */
async function evaluateAdversarial() {
  const details = [];
  let detected = 0;
  const adversarialDirExists = fs.existsSync(ADVERSARIAL_DIR);

  // v2.6.5: Use global ADR_THRESHOLD for honest measurement (no per-sample overfitting)
  // Legacy per-sample thresholds preserved in ADVERSARIAL_THRESHOLDS/HOLDOUT_THRESHOLDS for reference

  // --- Adversarial samples ---
  for (const name of Object.keys(ADVERSARIAL_THRESHOLDS)) {
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
  for (const name of Object.keys(HOLDOUT_THRESHOLDS)) {
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
  const total = Object.keys(ADVERSARIAL_THRESHOLDS).length + Object.keys(HOLDOUT_THRESHOLDS).length;
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

  if (!jsonMode) {
    console.log(`\n  MUAD'DIB Evaluation (v${version})\n`);
    console.log(`  [1/4] Ground Truth...`);
  }
  const groundTruth = await evaluateGroundTruth();

  if (!jsonMode) {
    console.log(`  [2/4] Benign npm packages (real source code)...`);
  }
  const benign = await evaluateBenign(options);

  if (!jsonMode) {
    console.log(`  [2b/4] Benign PyPI packages...`);
  }
  const benignPyPI = await evaluateBenignPyPI(options);

  if (!jsonMode) {
    console.log(`  [3/4] Adversarial samples...`);
  }
  const adversarial = await evaluateAdversarial();

  const report = {
    version,
    date: new Date().toISOString(),
    groundTruth,
    benign,
    benignPyPI,
    adversarial
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
    const adrCIStr = adversarial.adrCI ? ` [95% CI: ${(adversarial.adrCI.lower * 100).toFixed(1)}-${(adversarial.adrCI.upper * 100).toFixed(1)}%]` : '';
    console.log(`  ADR (threshold=${ADR_THRESHOLD}):   ${adversarial.detected}/${adversarial.available}  ${adrPct}%${adrCIStr}  (${adversarial.total - adversarial.available} missing)`);
    if (adversarial.cohorts) {
      const adv = adversarial.cohorts.adversarial;
      const hold = adversarial.cohorts.holdout;
      console.log(`  ADR (adversarial):     ${adv.detected}/${adv.available}  ${(adv.adr * 100).toFixed(1)}%`);
      console.log(`  ADR (holdout):         ${hold.detected}/${hold.available}  ${(hold.adr * 100).toFixed(1)}%`);
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

  return report;
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
  evaluateAdversarial,
  saveMetrics,
  silentScan,
  classifyDetectionSource,
  ADVERSARIAL_THRESHOLDS,
  HOLDOUT_THRESHOLDS,
  GT_THRESHOLD,
  BENIGN_THRESHOLD,
  ADR_THRESHOLD,
  extractTgz,
  wilsonCI,
  isBenignHoldout
};
