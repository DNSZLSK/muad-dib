'use strict';

const { test, assert } = require('../test-utils');
const {
  classifyDifferentiator,
  passesGate,
  leadStats,
  buildGhsaMap,
  detectionsFromLedger,
  tierRank,
  maxSeverity,
  earliestTs,
  backfillDetections
} = require('../../scripts/differentiator-audit.js');

const fs = require('fs');
const os = require('os');
const path = require('path');

// The real ingested-IOC type set (mirrors classify.js IOC_MATCH_TYPES).
const IOC = new Set([
  'known_malicious_package', 'known_malicious_hash', 'pypi_malicious_package',
  'shai_hulud_marker', 'shai_hulud_backdoor'
]);

function runDifferentiatorAuditTests() {
  console.log('\n=== Differentiator Audit Tests ===\n');

  test('classifyDifferentiator: net-new heuristic catch (not in GHSA) counts toward the headline', () => {
    const dets = [{ package: 'evil-a', version: '1.0.0', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['fetch_decrypt_exec'], severity: 'CRITICAL' }];
    const r = classifyDifferentiator(dets, new Map(), IOC);
    assert(r.counts.netNew === 1, `netNew=1, got ${r.counts.netNew}`);
    assert(r.differentiatorCount === 1, 'net-new is part of the differentiator');
    assert(r.counts.iocOnly === 0 && r.counts.ahead === 0, 'no other buckets');
  });

  test('classifyDifferentiator: ahead = heuristic catch BEFORE the advisory, lead computed', () => {
    const dets = [{ package: 'evil-b', version: '1.0.0', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['obfuscation', 'shell_exec'], severity: 'HIGH' }];
    const ghsa = new Map([['npm/evil-b', '2026-07-03T00:00:00Z']]); // advisory 48h later
    const r = classifyDifferentiator(dets, ghsa, IOC);
    assert(r.counts.ahead === 1, `ahead=1, got ${r.counts.ahead}`);
    assert(r.differentiatorCount === 1, 'ahead counts toward differentiator');
    assert(r.leadTime && Math.abs(r.leadTime.median - 48) < 1e-9, `lead median 48h, got ${r.leadTime && r.leadTime.median}`);
    assert(r.buckets.ahead[0].lead_time_hours === 48, 'per-rec lead stamped');
  });

  test('classifyDifferentiator: tied/behind = at/after advisory → NOT a differentiator (negative case)', () => {
    const dets = [
      { package: 'late-c', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-05T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' }, // after
      { package: 'tie-d', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-03T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' }   // exactly equal
    ];
    const ghsa = new Map([['npm/late-c', '2026-07-03T00:00:00Z'], ['npm/tie-d', '2026-07-03T00:00:00Z']]);
    const r = classifyDifferentiator(dets, ghsa, IOC);
    assert(r.counts.tiedOrBehind === 2, `tiedOrBehind=2, got ${r.counts.tiedOrBehind}`);
    assert(r.counts.ahead === 0, 'equal timestamp is not "ahead"');
    assert(r.differentiatorCount === 0, 'no lead → zero differentiator');
    assert(r.leadTime === null, 'no ahead detections → no lead stats');
  });

  test('classifyDifferentiator: ioc-only detection is EXCLUDED even when not in GHSA (negative case)', () => {
    const dets = [
      { package: 'ioc-e', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['known_malicious_package'], severity: 'CRITICAL' },
      { package: 'mixed-f', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['known_malicious_package', 'entropy_high'], severity: 'CRITICAL' }
    ];
    const r = classifyDifferentiator(dets, new Map(), IOC);
    assert(r.counts.iocOnly === 1, `pure-IOC excluded, got iocOnly=${r.counts.iocOnly}`);
    assert(r.counts.netNew === 1, 'a heuristic finding mixed in → still net-new (differentiator), got ' + r.counts.netNew);
    assert(r.differentiatorCount === 1, 'only the mixed one counts');
  });

  test('classifyDifferentiator: --since window skips detections seen before the anchor', () => {
    const dets = [
      { package: 'old-g', version: '1', ecosystem: 'npm', first_seen_at: '2026-05-01T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' },
      { package: 'new-h', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' }
    ];
    const r = classifyDifferentiator(dets, new Map(), IOC, { sinceMs: Date.parse('2026-06-01T00:00:00Z') });
    assert(r.counts.skipped === 1, `1 skipped, got ${r.counts.skipped}`);
    assert(r.total === 1 && r.counts.netNew === 1, 'only in-window detection classified');
  });

  test('classifyDifferentiator: dedup on eco/name@version + per-ecosystem breakdown', () => {
    const dets = [
      { package: 'dup-i', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' },
      { package: 'dup-i', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-02T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' }, // dup
      { package: 'py-j', version: '1', ecosystem: 'pypi', first_seen_at: '2026-07-01T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH' }
    ];
    const r = classifyDifferentiator(dets, new Map(), IOC);
    assert(r.total === 2, `dedup → 2 distinct, got ${r.total}`);
    assert(r.byEcosystem.npm.netNew === 1 && r.byEcosystem.pypi.netNew === 1, 'per-eco split');
  });

  test('classifyDifferentiator: empty input → zero, no crash, null lead', () => {
    const r = classifyDifferentiator([], new Map(), IOC);
    assert(r.total === 0 && r.differentiatorCount === 0 && r.leadTime === null, 'clean empty result');
  });

  test('leadStats: median for even and odd counts', () => {
    assert(leadStats([10, 20, 30]).median === 20, 'odd median');
    assert(leadStats([10, 20, 30, 40]).median === 25, 'even median = mean of middle two');
    assert(leadStats([]) === null, 'empty → null');
  });

  test('buildGhsaMap: earliest published_at wins, withdrawn/undated dropped', () => {
    const m = buildGhsaMap([
      { ecosystem: 'npm', name: 'x', published_at: '2026-07-05T00:00:00Z', withdrawn: false },
      { ecosystem: 'npm', name: 'x', published_at: '2026-07-01T00:00:00Z', withdrawn: false }, // earlier wins
      { ecosystem: 'npm', name: 'y', published_at: '2026-07-01T00:00:00Z', withdrawn: true },  // withdrawn dropped
      { ecosystem: 'npm', name: 'z', published_at: null }                                       // undated dropped
    ]);
    assert(m.get('npm/x') === '2026-07-01T00:00:00Z', 'earliest kept');
    assert(!m.has('npm/y') && !m.has('npm/z'), 'withdrawn + undated excluded');
  });

  test('earliestTs: min of a field, null on empty', () => {
    const t = earliestTs([
      { first_seen_at: '2026-07-05T00:00:00Z' },
      { first_seen_at: '2026-07-01T00:00:00Z' }
    ], 'first_seen_at');
    assert(t === Date.parse('2026-07-01T00:00:00Z'), 'earliest picked');
    assert(earliestTs([], 'first_seen_at') === null, 'empty → null');
  });

  // ── ledger source ──────────────────────────────────────────────────────

  test('detectionsFromLedger: keeps only suspect/confirmed, earliest ts, union types, max score, best tier', () => {
    const ledger = [
      { name: 'p', ecosystem: 'npm', ts: '2026-07-05T00:00:00Z', outcome: 'suspect', score: 30, tier: '2', maxSeverity: 'MEDIUM', types: ['obfuscation'] },
      { name: 'p', ecosystem: 'npm', ts: '2026-07-01T00:00:00Z', outcome: 'confirmed', score: 80, tier: '1a', maxSeverity: 'CRITICAL', types: ['shell_exec'] }, // earlier + stronger
      { name: 'q', ecosystem: 'npm', ts: '2026-07-02T00:00:00Z', outcome: 'clean', score: 0, types: [] } // filtered out
    ];
    const recs = detectionsFromLedger(ledger);
    assert(recs.length === 1, `only suspect/confirmed pkg kept, got ${recs.length}`);
    const p = recs[0];
    assert(p.first_seen_at === '2026-07-01T00:00:00Z', 'earliest suspect ts wins');
    assert(p.score === 80 && p.tier === '1a' && p.severity === 'CRITICAL', 'max score / best tier / max severity');
    assert(p.findings.sort().join(',') === 'obfuscation,shell_exec', 'union of types across scans');
  });

  test('detectionsFromLedger: empty / no-alert ledger → empty', () => {
    assert(detectionsFromLedger([]).length === 0, 'empty in → empty out');
    assert(detectionsFromLedger([{ name: 'x', outcome: 'dropped', ts: '2026-07-01T00:00:00Z' }]).length === 0, 'no alert outcome → empty');
  });

  test('tierRank / maxSeverity helpers', () => {
    assert(tierRank('1a') > tierRank('1b') && tierRank('1b') > tierRank('2') && tierRank('2') > tierRank('3'), 'tier ordering');
    assert(tierRank('nonsense') === 0, 'unknown tier → 0');
    assert(maxSeverity('MEDIUM', 'CRITICAL') === 'CRITICAL' && maxSeverity('HIGH', 'LOW') === 'HIGH', 'severity max');
  });

  // ── confidence gate ────────────────────────────────────────────────────

  test('classifyDifferentiator gate: --min-score sets low-score detections aside (gatedOut)', () => {
    const dets = [
      { package: 'strong', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['fetch_decrypt_exec'], score: 80 },
      { package: 'weak', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['prototype_pollution'], score: 22 } // FP-shaped
    ];
    const r = classifyDifferentiator(dets, new Map(), IOC, { gate: { minScore: 50 } });
    assert(r.counts.gatedOut === 1, `weak gated out, got ${r.counts.gatedOut}`);
    assert(r.counts.netNew === 1 && r.differentiatorCount === 1, 'only the strong one counts');
    assert(r.total === 1, 'gatedOut not counted in total');
  });

  test('classifyDifferentiator gate: --min-tier keeps tier>=bar only', () => {
    const dets = [
      { package: 'a', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['x'], tier: '1a' },
      { package: 'b', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['x'], tier: '3' }
    ];
    const r = classifyDifferentiator(dets, new Map(), IOC, { gate: { minTier: '1b' } });
    assert(r.counts.netNew === 1 && r.counts.gatedOut === 1, '1a passes tier>=1b, tier 3 gated');
  });

  test('classifyDifferentiator gate: --high-confidence requires an HC type (AND-combined)', () => {
    const hc = new Set(['fetch_decrypt_exec']);
    const dets = [
      { package: 'hc', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['fetch_decrypt_exec'], score: 90 },
      { package: 'nohc', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['high_entropy_string'], score: 90 }
    ];
    const r = classifyDifferentiator(dets, new Map(), IOC, { gate: { highConfidence: true, hcTypes: hc } });
    assert(r.counts.netNew === 1 && r.counts.gatedOut === 1, 'only the HC-typed detection passes');
    // negative: passesGate honors AND when multiple criteria given
    assert(passesGate({ score: 90, tier: '3', findings: ['fetch_decrypt_exec'] }, { minScore: 50, minTier: '1a', hcTypes: hc, highConfidence: true }) === false, 'tier 3 fails the AND even with score+HC');
  });

  test('classifyDifferentiator: no gate → nothing gated (backward compatible)', () => {
    const dets = [{ package: 'p', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['x'], score: 1, tier: '3' }];
    const r = classifyDifferentiator(dets, new Map(), IOC);
    assert(r.counts.gatedOut === 0 && r.counts.netNew === 1, 'no gate flags → raw behavior');
  });

  test('classifyDifferentiator: dependency_ioc_match is treated as ioc-only when the audit extends the set', () => {
    const iocExt = new Set([...IOC, 'dependency_ioc_match']);
    const dets = [{ package: 'dep', version: '1', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['dependency_ioc_match'], severity: 'HIGH' }];
    const r = classifyDifferentiator(dets, new Map(), iocExt);
    assert(r.counts.iocOnly === 1 && r.counts.netNew === 0, 'dependency_ioc_match excluded');
  });

  test('backfillDetections: stamps advisory_at + lead_time_hours only on matched lines', () => {
    const tmp = path.join(os.tmpdir(), `muaddib-diff-backfill-${process.pid}-${Date.now()}.jsonl`);
    const lines = [
      { package: 'evil-b', version: '1.0.0', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['obfuscation'], severity: 'HIGH', advisory_at: null, lead_time_hours: null },
      { package: 'evil-a', version: '1.0.0', ecosystem: 'npm', first_seen_at: '2026-07-01T00:00:00Z', findings: ['fetch_decrypt_exec'], severity: 'CRITICAL', advisory_at: null, lead_time_hours: null }
    ];
    fs.writeFileSync(tmp, lines.map(l => JSON.stringify(l)).join('\n') + '\n', 'utf8');
    try {
      const buckets = {
        ahead: [{ key: 'npm/evil-b@1.0.0', advisory_at: '2026-07-03T00:00:00Z', lead_time_hours: 48 }],
        tiedOrBehind: []
      };
      const patched = backfillDetections(tmp, buckets);
      assert(patched === 1, `1 line patched, got ${patched}`);
      const out = fs.readFileSync(tmp, 'utf8').trim().split('\n').map(l => JSON.parse(l));
      const b = out.find(e => e.package === 'evil-b');
      const a = out.find(e => e.package === 'evil-a');
      assert(b.advisory_at === '2026-07-03T00:00:00Z' && b.lead_time_hours === 48, 'matched line stamped');
      assert(a.advisory_at === null && a.lead_time_hours === null, 'unmatched line untouched');
    } finally {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    }
  });
}

module.exports = { runDifferentiatorAuditTests };
