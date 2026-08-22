'use strict';

const { test, assert } = require('../test-utils');
const {
  classifyDifferentiator,
  leadStats,
  buildGhsaMap,
  earliestDetectionTs,
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

  test('earliestDetectionTs: min first_seen_at, null on empty', () => {
    const t = earliestDetectionTs([
      { first_seen_at: '2026-07-05T00:00:00Z' },
      { first_seen_at: '2026-07-01T00:00:00Z' }
    ]);
    assert(t === Date.parse('2026-07-01T00:00:00Z'), 'earliest picked');
    assert(earliestDetectionTs([]) === null, 'empty → null');
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
