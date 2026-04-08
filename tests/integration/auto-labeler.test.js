/**
 * Tests for the auto-labeler module (registry takedown-based ML label correction).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  test, asyncTest, assert, assertIncludes
} = require('../test-utils');

async function runAutoLabelerTests() {
  console.log('\n=== AUTO-LABELER TESTS ===\n');

  const {
    checkNpmStatus,
    checkPyPIStatus,
    computeNewLabel,
    relabelDataset,
    RELABELABLE,
    SURVIVAL_DAYS,
    DEFAULT_DELAY_MS
  } = require('../../src/monitor/auto-labeler.js');

  // ─── computeNewLabel: takedown signals ───

  test('RELABEL: security_takedown → confirmed_malicious', () => {
    const record = { label: 'suspect', score: 15, timestamp: '2026-01-01T00:00:00Z' };
    const result = computeNewLabel(record, { status: 'security_takedown' });
    assert(result !== null, 'Should return a label change');
    assert(result.label === 'confirmed_malicious', `Expected confirmed_malicious, got ${result.label}`);
    assert(result.source === 'npm_security_takedown', `Expected npm_security_takedown, got ${result.source}`);
  });

  test('RELABEL: security_takedown overrides any score', () => {
    // Even score=0 packages taken down by npm Security are malicious
    const result = computeNewLabel({ label: 'clean', score: 0, timestamp: '2026-01-01T00:00:00Z' }, { status: 'security_takedown' });
    assert(result !== null, 'Should return a label change');
    assert(result.label === 'confirmed_malicious', 'Score 0 + takedown = malicious');
  });

  test('RELABEL: removed + score >= 50 → confirmed_malicious', () => {
    const result = computeNewLabel({ label: 'suspect', score: 55, timestamp: '2026-01-01T00:00:00Z' }, { status: 'removed' });
    assert(result !== null, 'Should return a label change');
    assert(result.label === 'confirmed_malicious', `Expected confirmed_malicious, got ${result.label}`);
    assert(result.source === 'registry_removed_high_score', `Expected registry_removed_high_score, got ${result.source}`);
  });

  test('RELABEL: removed + score < 50 → removed_unlabeled', () => {
    const result = computeNewLabel({ label: 'suspect', score: 30, timestamp: '2026-01-01T00:00:00Z' }, { status: 'removed' });
    assert(result !== null, 'Should return a label change');
    assert(result.label === 'removed_unlabeled', `Expected removed_unlabeled, got ${result.label}`);
    assert(result.source === 'registry_removed_low_score', `Expected registry_removed_low_score, got ${result.source}`);
  });

  // ─── computeNewLabel: survival signals ───

  test('RELABEL: alive + age >= 30d + score < 20 → confirmed_benign', () => {
    const oldTimestamp = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString(); // 40 days ago
    const result = computeNewLabel({ label: 'suspect', score: 12, timestamp: oldTimestamp }, { status: 'alive' });
    assert(result !== null, 'Should return a label change');
    assert(result.label === 'confirmed_benign', `Expected confirmed_benign, got ${result.label}`);
    assert(result.source === 'survival_30d', `Expected survival_30d, got ${result.source}`);
  });

  test('RELABEL: alive + age >= 30d + score 20-34 → likely_benign', () => {
    const oldTimestamp = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString();
    const result = computeNewLabel({ label: 'suspect', score: 28, timestamp: oldTimestamp }, { status: 'alive' });
    assert(result !== null, 'Should return a label change');
    assert(result.label === 'likely_benign', `Expected likely_benign, got ${result.label}`);
    assert(result.source === 'survival_30d_moderate', `Expected survival_30d_moderate, got ${result.source}`);
  });

  test('RELABEL: alive + age >= 30d + score >= 35 → no change (sleeper risk)', () => {
    const oldTimestamp = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
    const result = computeNewLabel({ label: 'suspect', score: 45, timestamp: oldTimestamp }, { status: 'alive' });
    assert(result === null, 'Should return null (no change for high-score survivors)');
  });

  test('RELABEL: alive + age < 30d → no change (too early)', () => {
    const recentTimestamp = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const result = computeNewLabel({ label: 'suspect', score: 5, timestamp: recentTimestamp }, { status: 'alive' });
    assert(result === null, 'Should return null (too early to confirm benign)');
  });

  // ─── computeNewLabel: guard rails ───

  test('RELABEL: already confirmed_malicious → no change', () => {
    const result = computeNewLabel({ label: 'confirmed_malicious', score: 80, timestamp: '2026-01-01T00:00:00Z' }, { status: 'alive' });
    assert(result === null, 'Should not re-label already confirmed records');
  });

  test('RELABEL: already confirmed_benign → no change', () => {
    const result = computeNewLabel({ label: 'confirmed_benign', score: 5, timestamp: '2026-01-01T00:00:00Z' }, { status: 'removed' });
    assert(result === null, 'Should not re-label already confirmed records');
  });

  test('RELABEL: already fp → no change', () => {
    const result = computeNewLabel({ label: 'fp', score: 30, timestamp: '2026-01-01T00:00:00Z' }, { status: 'security_takedown' });
    assert(result === null, 'Should not re-label manually confirmed fp');
  });

  test('RELABEL: error status → no change', () => {
    const result = computeNewLabel({ label: 'suspect', score: 50, timestamp: '2026-01-01T00:00:00Z' }, { status: 'error' });
    assert(result === null, 'Should not relabel on registry errors');
  });

  // ─── relabelDataset: integration ───

  await asyncTest('RELABEL: relabelDataset writes output without modifying input', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'relabel-test-'));
    const inputPath = path.join(tmpDir, 'input.jsonl');
    const outputPath = path.join(tmpDir, 'output.jsonl');

    // Create test JSONL with a mix of labels
    const records = [
      { name: 'already-confirmed', ecosystem: 'npm', label: 'confirmed_malicious', score: 80, timestamp: '2026-01-01T00:00:00Z' },
      { name: 'already-confirmed', ecosystem: 'npm', label: 'confirmed_malicious', score: 80, timestamp: '2026-01-02T00:00:00Z' }
    ];
    fs.writeFileSync(inputPath, records.map(r => JSON.stringify(r)).join('\n'));
    const inputHash = fs.readFileSync(inputPath, 'utf8');

    await relabelDataset({ input: inputPath, output: outputPath, delayMs: 0 });

    // Input must be unchanged
    const afterHash = fs.readFileSync(inputPath, 'utf8');
    assert(inputHash === afterHash, 'Input file must not be modified');

    // Output must exist
    assert(fs.existsSync(outputPath), 'Output file must be created');

    // Cleanup
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  await asyncTest('RELABEL: dry-run does not write output', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'relabel-dry-'));
    const inputPath = path.join(tmpDir, 'input.jsonl');
    const outputPath = path.join(tmpDir, 'output.jsonl');

    fs.writeFileSync(inputPath, JSON.stringify({ name: 'test-pkg', ecosystem: 'npm', label: 'suspect', score: 10, timestamp: '2026-01-01T00:00:00Z' }) + '\n');

    await relabelDataset({ input: inputPath, output: outputPath, dryRun: true, delayMs: 0 });

    assert(!fs.existsSync(outputPath), 'Output file must NOT be created in dry-run mode');

    // Cleanup
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  // ─── Constants ───

  test('RELABEL: RELABELABLE contains expected labels', () => {
    assert(RELABELABLE.has('suspect'), 'suspect should be relabelable');
    assert(RELABELABLE.has('ml_clean'), 'ml_clean should be relabelable');
    assert(RELABELABLE.has('unconfirmed'), 'unconfirmed should be relabelable');
    assert(RELABELABLE.has('clean'), 'clean should be relabelable');
    assert(!RELABELABLE.has('confirmed_malicious'), 'confirmed_malicious should NOT be relabelable');
    assert(!RELABELABLE.has('fp'), 'fp should NOT be relabelable');
  });

  test('RELABEL: SURVIVAL_DAYS is 30', () => {
    assert(SURVIVAL_DAYS === 30, `Expected 30, got ${SURVIVAL_DAYS}`);
  });

  test('RELABEL: DEFAULT_DELAY_MS is 200 (5 req/s)', () => {
    assert(DEFAULT_DELAY_MS === 200, `Expected 200, got ${DEFAULT_DELAY_MS}`);
  });

  // ─── Module exports ───

  test('RELABEL: checkNpmStatus is exported', () => {
    assert(typeof checkNpmStatus === 'function', 'checkNpmStatus should be a function');
  });

  test('RELABEL: checkPyPIStatus is exported', () => {
    assert(typeof checkPyPIStatus === 'function', 'checkPyPIStatus should be a function');
  });

  // ─── CLI integration ───

  test('RELABEL: CLI command is wired in muaddib.js', () => {
    const cliSource = fs.readFileSync(path.join(__dirname, '..', '..', 'bin', 'muaddib.js'), 'utf8');
    assertIncludes(cliSource, "command === 'relabel'", 'CLI should handle relabel command');
    assertIncludes(cliSource, 'relabelDataset', 'CLI should call relabelDataset');
    assertIncludes(cliSource, '--dry-run', 'CLI should support --dry-run flag');
  });

  // ─── Daemon integration ───

  test('RELABEL: daemon integrates auto-relabel after daily report', () => {
    const daemonSource = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'monitor', 'daemon.js'), 'utf8');
    assertIncludes(daemonSource, 'auto-labeler', 'daemon.js should require auto-labeler');
    assertIncludes(daemonSource, 'Auto-relabel', 'daemon.js should log auto-relabel activity');
  });
}

module.exports = { runAutoLabelerTests };
