/**
 * MUAD'DIB Evaluate — Scanner effectiveness measurement
 *
 * Measures TPR (Ground Truth), FPR (Benign), and ADR (Adversarial).
 * Saves versioned metrics to metrics/v{version}.json.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { run } = require('../index.js');

const ROOT = path.join(__dirname, '..', '..');
const GT_DIR = path.join(ROOT, 'tests', 'ground-truth');
const BENIGN_DIR = path.join(ROOT, 'datasets', 'benign');
const ADVERSARIAL_DIR = path.join(ROOT, 'datasets', 'adversarial');
const METRICS_DIR = path.join(ROOT, 'metrics');

const GT_THRESHOLD = 3;
const BENIGN_THRESHOLD = 20;

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
  'bun-runtime-evasion': 30,
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

/**
 * 2. Benign — scan popular npm packages for false positives
 */
async function evaluateBenign() {
  const listFile = path.join(BENIGN_DIR, 'packages-npm.txt');
  const packages = fs.readFileSync(listFile, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  const details = [];
  let flagged = 0;

  for (const pkg of packages) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-eval-'));
    try {
      // Create minimal project with this package as dependency
      const pkgJson = { name: 'eval-project', version: '1.0.0', dependencies: { [pkg]: '*' } };
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkgJson));

      // Create fake node_modules entry so dependency scanner picks it up
      const parts = pkg.split('/');
      const nmDir = path.join(tmpDir, 'node_modules', ...parts);
      fs.mkdirSync(nmDir, { recursive: true });
      fs.writeFileSync(path.join(nmDir, 'package.json'), JSON.stringify({ name: pkg, version: '999.0.0' }));

      const result = await silentScan(tmpDir);
      const score = result.summary.riskScore;
      const isFlagged = score > BENIGN_THRESHOLD;
      if (isFlagged) flagged++;
      details.push({ name: pkg, score, flagged: isFlagged });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  const total = packages.length;
  const fpr = total > 0 ? flagged / total : 0;
  return { flagged, total, fpr, details };
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
    console.log(`  [2/3] Benign packages...`);
  }
  const benign = await evaluateBenign();

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
    console.log(`  Benign (FPR):        ${benign.flagged}/${benign.total}  ${fprPct}%`);
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

    // Show false positives
    const fps = benign.details.filter(d => d.flagged);
    if (fps.length > 0) {
      console.log('  False positives:');
      for (const fp of fps) {
        console.log(`    ${fp.name}: score ${fp.score}`);
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
