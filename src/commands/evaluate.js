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
const { execSync } = require('child_process');
const { run } = require('../index.js');

const ROOT = path.join(__dirname, '..', '..');
const GT_DIR = path.join(ROOT, 'tests', 'ground-truth');
const BENIGN_DIR = path.join(ROOT, 'datasets', 'benign');
const ADVERSARIAL_DIR = path.join(ROOT, 'datasets', 'adversarial');
const METRICS_DIR = path.join(ROOT, 'metrics');
const CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'benign-tarballs');

const GT_THRESHOLD = 3;
const BENIGN_THRESHOLD = 20;
const PACK_TIMEOUT_MS = 30000;

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
  'browser-api-hook': 20
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
  const attacks = data.attacks.filter(a => a.expected.min_threats > 0);

  const details = [];
  let detected = 0;

  for (const attack of attacks) {
    const sampleDir = path.join(GT_DIR, attack.sample_dir);
    const result = await silentScan(sampleDir);
    const score = result.summary.riskScore;
    const isDetected = score >= GT_THRESHOLD;
    if (isDetected) detected++;
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
  return { detected, total, tpr, details };
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
      // Regular file — extract it
      const filePath = path.join(destDir, name);
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
    const output = execSync(`npm pack ${pkg}`, {
      cwd: pkgCacheDir,
      encoding: 'utf8',
      timeout: PACK_TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    tgzFilename = output.trim().split('\n').pop().trim();
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
    .split('\n')
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

    const entry = { name: pkg, score, flagged: isFlagged };

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
  return { flagged, total, scanned, skipped, fpr, details };
}

/**
 * 3. Adversarial — scan evasive malicious samples
 */
async function evaluateAdversarial() {
  const details = [];
  let detected = 0;

  const sampleNames = Object.keys(ADVERSARIAL_THRESHOLDS);
  for (const name of sampleNames) {
    const sampleDir = path.join(ADVERSARIAL_DIR, name);
    if (!fs.existsSync(sampleDir)) {
      details.push({ name, score: 0, threshold: ADVERSARIAL_THRESHOLDS[name], detected: false, error: 'directory not found' });
      continue;
    }

    const result = await silentScan(sampleDir);
    const score = result.summary.riskScore;
    const threshold = ADVERSARIAL_THRESHOLDS[name];
    const isDetected = score >= threshold;
    if (isDetected) detected++;
    details.push({ name, score, threshold, detected: isDetected });
  }

  const total = sampleNames.length;
  const adr = total > 0 ? detected / total : 0;
  return { detected, total, adr, details };
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
    console.log(`  [1/3] Ground Truth...`);
  }
  const groundTruth = await evaluateGroundTruth();

  if (!jsonMode) {
    console.log(`  [2/3] Benign packages (real source code)...`);
  }
  const benign = await evaluateBenign(options);

  if (!jsonMode) {
    console.log(`  [3/3] Adversarial samples...`);
  }
  const adversarial = await evaluateAdversarial();

  const report = {
    version,
    date: new Date().toISOString(),
    groundTruth,
    benign,
    adversarial
  };

  const metricsPath = saveMetrics(report);

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const tprPct = (groundTruth.tpr * 100).toFixed(1);
    const fprPct = (benign.fpr * 100).toFixed(1);
    const adrPct = (adversarial.adr * 100).toFixed(1);

    console.log('');
    console.log(`  Ground Truth (TPR):  ${groundTruth.detected}/${groundTruth.total}  ${tprPct}%`);
    console.log(`  Benign (FPR):        ${benign.flagged}/${benign.scanned}  ${fprPct}%  (${benign.skipped} skipped)`);
    console.log(`  Adversarial (ADR):   ${adversarial.detected}/${adversarial.total}  ${adrPct}%`);
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

module.exports = {
  evaluate,
  evaluateGroundTruth,
  evaluateBenign,
  evaluateAdversarial,
  saveMetrics,
  silentScan,
  ADVERSARIAL_THRESHOLDS,
  GT_THRESHOLD,
  BENIGN_THRESHOLD
};
