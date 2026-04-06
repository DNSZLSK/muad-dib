'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert } = require('../test-utils');

function runMLFeatureExtractorTests() {
  console.log('\n=== ML FEATURE EXTRACTOR TESTS ===\n');

  const { extractFeatures, buildTrainingRecord, TOP_THREAT_TYPES } = require('../../src/ml/feature-extractor');
  const { appendRecord, readRecords, getStats, relabelRecords, setTrainingFile, resetTrainingFile } = require('../../src/ml/jsonl-writer');

  // --- extractFeatures tests ---

  test('extractFeatures: returns all expected feature keys', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'HIGH', file: 'index.js', rule_id: 'AST-001' },
        { type: 'env_access', severity: 'MEDIUM', file: 'index.js', rule_id: 'AST-002' },
        { type: 'obfuscation_detected', severity: 'LOW', file: 'utils.js', rule_id: 'AST-003' }
      ],
      summary: {
        total: 3,
        critical: 0,
        high: 1,
        medium: 1,
        low: 1,
        riskScore: 25,
        maxFileScore: 20,
        packageScore: 5,
        globalRiskScore: 30,
        fileScores: { 'index.js': 20, 'utils.js': 3 },
        breakdown: [
          { rule: 'AST-001', type: 'suspicious_dataflow', points: 10, reason: 'test' },
          { rule: 'AST-002', type: 'env_access', points: 3, reason: 'test' },
          { rule: 'AST-003', type: 'obfuscation_detected', points: 1, reason: 'test' }
        ]
      }
    };

    const features = extractFeatures(result, { name: 'test-pkg', version: '1.0.0' });

    // Core scoring features
    assert(features.score === 25, `score should be 25, got ${features.score}`);
    assert(features.max_file_score === 20, `max_file_score should be 20, got ${features.max_file_score}`);
    assert(features.package_score === 5, `package_score should be 5, got ${features.package_score}`);

    // Severity counts
    assert(features.count_total === 3, `count_total should be 3, got ${features.count_total}`);
    assert(features.count_critical === 0, `count_critical should be 0, got ${features.count_critical}`);
    assert(features.count_high === 1, `count_high should be 1, got ${features.count_high}`);
    assert(features.count_medium === 1, `count_medium should be 1, got ${features.count_medium}`);
    assert(features.count_low === 1, `count_low should be 1, got ${features.count_low}`);

    // Distinct types
    assert(features.distinct_threat_types === 3, `distinct_threat_types should be 3, got ${features.distinct_threat_types}`);

    // Per-type counts
    assert(features.type_suspicious_dataflow === 1, `type_suspicious_dataflow should be 1`);
    assert(features.type_env_access === 1, `type_env_access should be 1`);
    assert(features.type_obfuscation_detected === 1, `type_obfuscation_detected should be 1`);
    assert(features.type_staged_payload === 0, `type_staged_payload should be 0`);
    assert(features.type_other === 0, `type_other should be 0 (all types are in TOP list)`);

    // Boolean signals
    assert(features.has_network_access === 1, `has_network_access should be 1 (suspicious_dataflow)`);
    assert(features.has_obfuscation === 1, `has_obfuscation should be 1`);
    assert(features.has_env_access === 1, `has_env_access should be 1`);
    assert(features.has_eval === 0, `has_eval should be 0`);
    assert(features.has_lifecycle_script === 0, `has_lifecycle_script should be 0`);
    assert(features.has_ioc_match === 0, `has_ioc_match should be 0`);

    // File distribution
    assert(features.file_count_with_threats === 2, `file_count_with_threats should be 2`);
    assert(features.file_score_max === 20, `file_score_max should be 20`);

    // Severity ratio
    assert(features.severity_ratio_high > 0.3 && features.severity_ratio_high < 0.4,
      `severity_ratio_high should be ~0.33, got ${features.severity_ratio_high}`);

    // Points concentration
    assert(features.max_single_points === 10, `max_single_points should be 10`);
  });

  test('extractFeatures: handles empty result', () => {
    const result = { threats: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 } };
    const features = extractFeatures(result, {});

    assert(features.score === 0, 'score should be 0');
    assert(features.count_total === 0, 'count_total should be 0');
    assert(features.distinct_threat_types === 0, 'distinct_threat_types should be 0');
    assert(features.has_network_access === 0, 'has_network_access should be 0');
    assert(features.file_count_with_threats === 0, 'file_count_with_threats should be 0');
    assert(features.severity_ratio_high === 0, 'severity_ratio_high should be 0');
  });

  test('extractFeatures: handles null/undefined result gracefully', () => {
    const features = extractFeatures(null, {});
    assert(features.score === 0, 'score should be 0 for null result');
    assert(features.count_total === 0, 'count_total should be 0 for null result');
  });

  test('extractFeatures: counts non-top types in type_other', () => {
    const result = {
      threats: [
        { type: 'some_unknown_type_xyz', severity: 'MEDIUM', file: 'x.js' },
        { type: 'some_unknown_type_xyz', severity: 'MEDIUM', file: 'y.js' },
        { type: 'another_unknown_type', severity: 'LOW', file: 'z.js' }
      ],
      summary: { total: 3, critical: 0, high: 0, medium: 2, low: 1 }
    };
    const features = extractFeatures(result, {});
    assert(features.type_other === 3, `type_other should be 3, got ${features.type_other}`);
    assert(features.type_suspicious_dataflow === 0, 'known type should be 0');
  });

  test('extractFeatures: has_ioc_match always 0 (excluded from ML to prevent circular leakage)', () => {
    const result = {
      threats: [
        { type: 'known_malicious_package', severity: 'CRITICAL', file: 'package.json' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 100 }
    };
    const features = extractFeatures(result, {});
    assert(features.has_ioc_match === 0, 'has_ioc_match should always be 0 (IOC leakage prevention)');
  });

  test('extractFeatures: detects sandbox findings', () => {
    const result = {
      threats: [
        { type: 'sandbox_suspicious_connection', severity: 'HIGH', file: 'index.js' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0 }
    };
    const features = extractFeatures(result, {});
    assert(features.has_sandbox_finding === 1, 'has_sandbox_finding should be 1');
  });

  test('extractFeatures: handles registry metadata', () => {
    const result = { threats: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 } };
    const meta = {
      unpackedSize: 50000,
      registryMeta: {
        dependencies: { lodash: '^4.0.0', express: '^4.18.0' },
        devDependencies: { jest: '^29.0.0' }
      }
    };
    const features = extractFeatures(result, meta);
    assert(features.unpacked_size_bytes === 50000, `unpacked_size_bytes should be 50000, got ${features.unpacked_size_bytes}`);
    assert(features.dep_count === 2, `dep_count should be 2, got ${features.dep_count}`);
    assert(features.dev_dep_count === 1, `dev_dep_count should be 1, got ${features.dev_dep_count}`);
  });

  test('extractFeatures: reputation factor from summary', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, reputationFactor: 0.5 }
    };
    const features = extractFeatures(result, {});
    assert(features.reputation_factor === 0.5, `reputation_factor should be 0.5, got ${features.reputation_factor}`);
  });

  // --- buildTrainingRecord tests ---

  test('buildTrainingRecord: includes identity + label + features', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'index.js' }],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 10, maxFileScore: 10, packageScore: 0 }
    };
    const record = buildTrainingRecord(result, {
      name: 'evil-pkg',
      version: '1.2.3',
      ecosystem: 'npm',
      label: 'suspect',
      tier: 1,
      sandboxResult: { score: 50, findings: [{ type: 'sandbox_exec_suspicious' }] }
    });

    // Identity
    assert(record.name === 'evil-pkg', 'name should match');
    assert(record.version === '1.2.3', 'version should match');
    assert(record.ecosystem === 'npm', 'ecosystem should match');
    assert(typeof record.timestamp === 'string', 'timestamp should be a string');

    // Label
    assert(record.label === 'suspect', 'label should be suspect');
    assert(record.tier === 1, 'tier should be 1');

    // Features (spot check)
    assert(record.score === 10, `score should be 10, got ${record.score}`);
    assert(record.count_high === 1, 'count_high should be 1');
    assert(record.type_env_access === 1, 'type_env_access should be 1');

    // Sandbox
    assert(record.sandbox_score === 50, `sandbox_score should be 50, got ${record.sandbox_score}`);
    assert(record.sandbox_finding_count === 1, `sandbox_finding_count should be 1, got ${record.sandbox_finding_count}`);
  });

  test('buildTrainingRecord: defaults for missing params', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 }
    };
    const record = buildTrainingRecord(result, { name: 'test' });

    assert(record.name === 'test', 'name should be test');
    assert(record.version === '', 'version should default to empty');
    assert(record.ecosystem === 'npm', 'ecosystem should default to npm');
    assert(record.label === 'suspect', 'label should default to suspect');
    assert(record.tier === null, 'tier should default to null');
    assert(record.sandbox_score === 0, 'sandbox_score should default to 0');
    assert(record.sandbox_finding_count === 0, 'sandbox_finding_count should default to 0');
  });

  // --- JSONL writer tests ---

  // Use a temp dir for JSONL tests to avoid polluting data/
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-ml-test-'));
  const tmpFile = path.join(tmpDir, 'test-training.jsonl');

  // Redirect writer to temp file
  setTrainingFile(tmpFile);

  test('JSONL writer: appendRecord writes valid JSONL', () => {
    const record = { name: 'test-pkg', version: '1.0.0', score: 42, label: 'clean' };
    appendRecord(record);

    const content = fs.readFileSync(tmpFile, 'utf8');
    const lines = content.trim().split('\n');
    assert(lines.length === 1, `Should have 1 line, got ${lines.length}`);

    const parsed = JSON.parse(lines[0]);
    assert(parsed.name === 'test-pkg', 'name should match');
    assert(parsed.score === 42, 'score should match');
    assert(parsed.label === 'clean', 'label should match');
  });

  test('JSONL writer: appendRecord appends multiple records', () => {
    appendRecord({ name: 'pkg2', version: '2.0.0', score: 80, label: 'suspect' });
    appendRecord({ name: 'pkg3', version: '3.0.0', score: 5, label: 'fp' });

    const content = fs.readFileSync(tmpFile, 'utf8');
    const lines = content.trim().split('\n');
    assert(lines.length === 3, `Should have 3 lines, got ${lines.length}`);

    const last = JSON.parse(lines[2]);
    assert(last.name === 'pkg3', 'last record name should be pkg3');
    assert(last.label === 'fp', 'last record label should be fp');
  });

  test('JSONL writer: readRecords returns all records', () => {
    const records = readRecords();
    assert(records.length === 3, `Should have 3 records, got ${records.length}`);
    assert(records[0].name === 'test-pkg', 'first record name should be test-pkg');
    assert(records[2].name === 'pkg3', 'third record name should be pkg3');
  });

  test('JSONL writer: getStats returns correct count and size', () => {
    const s = getStats();
    assert(s.recordCount === 3, `recordCount should be 3, got ${s.recordCount}`);
    assert(s.fileSizeBytes > 0, 'fileSizeBytes should be > 0');
  });

  test('JSONL writer: relabelRecords updates matching records', () => {
    const updated = relabelRecords('test-pkg', 'confirmed', 2);
    assert(updated === 1, `Should have updated 1 record, got ${updated}`);

    const records = readRecords();
    const relabeled = records.find(r => r.name === 'test-pkg');
    assert(relabeled.label === 'confirmed', `label should be confirmed, got ${relabeled.label}`);

    // Other records should be unchanged
    const other = records.find(r => r.name === 'pkg2');
    assert(other.label === 'suspect', `pkg2 label should still be suspect, got ${other.label}`);
  });

  test('JSONL writer: relabelRecords returns 0 for non-existent package', () => {
    const updated = relabelRecords('non-existent-pkg', 'fp', undefined, true);
    assert(updated === 0, `Should have updated 0 records, got ${updated}`);
  });

  // --- C1 Relabeling contamination fix tests ---

  test('C1: relabelRecords(pkg, "unconfirmed") succeeds', () => {
    // Reset to the original test file with test-pkg
    setTrainingFile(tmpFile);
    const updated = relabelRecords('test-pkg', 'unconfirmed');
    assert(updated === 1, `Should have updated 1 record, got ${updated}`);
    const records = readRecords();
    const r = records.find(rec => rec.name === 'test-pkg');
    assert(r.label === 'unconfirmed', `label should be unconfirmed, got ${r.label}`);
  });

  test('C1: relabelRecords(pkg, "fp") without manualReview is BLOCKED', () => {
    setTrainingFile(tmpFile);
    const updated = relabelRecords('test-pkg', 'fp');
    assert(updated === 0, `Should block fp without manualReview, got ${updated}`);
  });

  test('C1: relabelRecords(pkg, "fp", undefined, true) succeeds with manualReview', () => {
    setTrainingFile(tmpFile);
    const updated = relabelRecords('test-pkg', 'fp', undefined, true);
    assert(updated === 1, `Should allow fp with manualReview=true, got ${updated}`);
    const records = readRecords();
    const r = records.find(rec => rec.name === 'test-pkg');
    assert(r.label === 'fp', `label should be fp, got ${r.label}`);
  });

  test('C1: relabelRecords(pkg, "invalid_label") is BLOCKED', () => {
    setTrainingFile(tmpFile);
    const updated = relabelRecords('test-pkg', 'invalid_label');
    assert(updated === 0, `Should block invalid labels, got ${updated}`);
  });

  test('C1: relabelRecords(pkg, "confirmed", 3) succeeds (no regression)', () => {
    setTrainingFile(tmpFile);
    const updated = relabelRecords('test-pkg', 'confirmed', 3);
    assert(updated === 1, `Should allow confirmed with findingCount, got ${updated}`);
    const records = readRecords();
    const r = records.find(rec => rec.name === 'test-pkg');
    assert(r.label === 'confirmed', `label should be confirmed, got ${r.label}`);
  });

  test('JSONL writer: readRecords handles empty file', () => {
    const emptyFile = path.join(tmpDir, 'empty.jsonl');
    fs.writeFileSync(emptyFile, '', 'utf8');
    setTrainingFile(emptyFile);
    const records = readRecords();
    assert(records.length === 0, `Should have 0 records from empty file, got ${records.length}`);
  });

  test('JSONL writer: readRecords handles malformed lines gracefully', () => {
    const badFile = path.join(tmpDir, 'bad.jsonl');
    fs.writeFileSync(badFile, '{"valid": true}\n{not json\n{"also": "valid"}\n', 'utf8');
    setTrainingFile(badFile);
    const records = readRecords();
    assert(records.length === 2, `Should skip malformed line, got ${records.length}`);
  });

  test('JSONL writer: getStats returns 0 for non-existent file', () => {
    setTrainingFile(path.join(tmpDir, 'nope.jsonl'));
    const s = getStats();
    assert(s.recordCount === 0, 'recordCount should be 0');
    assert(s.fileSizeBytes === 0, 'fileSizeBytes should be 0');
  });

  // --- TOP_THREAT_TYPES coverage ---

  test('TOP_THREAT_TYPES contains at least 20 types', () => {
    assert(TOP_THREAT_TYPES.length >= 20, `TOP_THREAT_TYPES should have 20+ types, got ${TOP_THREAT_TYPES.length}`);
  });

  test('TOP_THREAT_TYPES has no duplicates', () => {
    const unique = new Set(TOP_THREAT_TYPES);
    assert(unique.size === TOP_THREAT_TYPES.length, 'TOP_THREAT_TYPES should have no duplicates');
  });

  // --- Feature vector stability ---

  test('Feature vector has consistent key count', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 10 }
    };
    const features = extractFeatures(result, {});
    const keys = Object.keys(features);
    // Core: 4 + Severity: 5 + Distinct: 1 + Per-type: 32 + Booleans: 10
    // + File dist: 3 + Ratios: 3 + Meta: 3 + Reputation: 1 + Enriched: 9 = 71
    assert(keys.length >= 64, `Feature vector should have 64+ keys, got ${keys.length}`);
  });

  // --- Enriched features (Phase 2a) ---

  test('extractFeatures: enriched registry features from npmRegistryMeta', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 10, fileScores: { 'x.js': 10 } }
    };
    const meta = {
      npmRegistryMeta: {
        age_days: 730,
        weekly_downloads: 100000,
        version_count: 25,
        author_package_count: 10,
        has_repository: true,
        readme_size: 5000
      },
      fileCountTotal: 20,
      hasTests: true
    };
    const features = extractFeatures(result, meta);
    assert(features.package_age_days === 730, `package_age_days should be 730, got ${features.package_age_days}`);
    assert(features.weekly_downloads === 100000, `weekly_downloads should be 100000, got ${features.weekly_downloads}`);
    assert(features.version_count === 25, `version_count should be 25, got ${features.version_count}`);
    assert(features.author_package_count === 10, `author_package_count should be 10, got ${features.author_package_count}`);
    assert(features.has_repository === 1, `has_repository should be 1, got ${features.has_repository}`);
    assert(features.readme_size === 5000, `readme_size should be 5000, got ${features.readme_size}`);
    assert(features.file_count_total === 20, `file_count_total should be 20, got ${features.file_count_total}`);
    assert(features.has_tests === 1, `has_tests should be 1, got ${features.has_tests}`);
  });

  test('extractFeatures: enriched features default to 0 when npmRegistryMeta absent', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 }
    };
    const features = extractFeatures(result, {});
    assert(features.package_age_days === 0, `package_age_days should default to 0`);
    assert(features.weekly_downloads === 0, `weekly_downloads should default to 0`);
    assert(features.version_count === 0, `version_count should default to 0`);
    assert(features.has_repository === 0, `has_repository should default to 0`);
    assert(features.readme_size === 0, `readme_size should default to 0`);
    assert(features.file_count_total === 0, `file_count_total should default to 0`);
    assert(features.has_tests === 0, `has_tests should default to 0`);
    assert(features.threat_density === 0, `threat_density should default to 0`);
  });

  test('extractFeatures: threat_density calculation', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH', file: 'a.js' },
        { type: 'env_access', severity: 'HIGH', file: 'a.js' },
        { type: 'env_access', severity: 'MEDIUM', file: 'b.js' }
      ],
      summary: { total: 3, critical: 0, high: 2, medium: 1, low: 0, riskScore: 20, fileScores: { 'a.js': 15, 'b.js': 5 } }
    };
    const features = extractFeatures(result, {});
    // 3 threats / 2 files with threats = 1.5
    assert(features.threat_density === 1.5, `threat_density should be 1.5, got ${features.threat_density}`);
  });

  test('buildTrainingRecord: enriched features key count >= 64', () => {
    const result = {
      threats: [{ type: 'env_access', severity: 'HIGH', file: 'x.js' }],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 10 }
    };
    const record = buildTrainingRecord(result, {
      name: 'test',
      version: '1.0.0',
      label: 'suspect',
      npmRegistryMeta: { age_days: 1, weekly_downloads: 1, version_count: 1, author_package_count: 1, has_repository: false, readme_size: 0 },
      fileCountTotal: 3,
      hasTests: false
    });
    const keys = Object.keys(record);
    // Identity (4) + label (2) + features (71) + sandbox (2) = 79
    assert(keys.length >= 70, `Record should have 70+ keys, got ${keys.length}`);
    assert(typeof record.package_age_days === 'number', 'should have package_age_days');
    assert(typeof record.threat_density === 'number', 'should have threat_density');
  });

  // Cleanup
  resetTrainingFile();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
}

module.exports = { runMLFeatureExtractorTests };
