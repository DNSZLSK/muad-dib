'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert } = require('../test-utils');

function runMLFeatureExtractorTests() {
  console.log('\n=== ML FEATURE EXTRACTOR TESTS ===\n');

  const {
    extractFeatures,
    buildTrainingRecord,
    TOP_THREAT_TYPES,
    networkDestinationFirstParty,
    installUrlGithubReleases,
    bundleWithoutInstallScripts,
    gitHookSourceLocal,
    typosquatScopedPackage,
    obfuscationWithoutVector,
    placeholderAntiDepConfusion,
    installScriptNoNetworkEgress,
    mcpServerEnvAccess,
    vendorCliSdk,
    aiAgentBot,
    vendorMinifiedBundle
  } = require('../../src/ml/feature-extractor');
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

  // --- Cluster FP contextual features (v2.10.96) ---
  //
  // Tests target the CRITICAL webhook zone (score >= 75): each positive
  // fixture is a realistic P1-scoring package, each negative fixture keeps
  // the same threat composition but changes the ONE signal that should
  // flip the feature.

  // Feature 1: network_destination_first_party — POSITIVE
  test('network_destination_first_party: TRUE on @anthropic-ai/* SDK via structured threat.urls (CRITICAL)', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'dist/index.js',
          message: 'Suspicious flow: credentials read + network send (fetch)',
          urls: ['https://api.anthropic.com/v1/messages'] },
        { type: 'env_access', severity: 'HIGH', file: 'dist/index.js',
          message: 'process.env.ANTHROPIC_API_KEY accessed' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 85 }
    };
    const meta = { name: '@anthropic-ai/sdk' };
    assert(networkDestinationFirstParty(result, meta) === true,
      'scoped SDK calling its own API host should be first-party');
    const features = extractFeatures(result, meta);
    assert(features.network_destination_first_party === 1, 'feature flag should be 1');
  });

  test('network_destination_first_party: TRUE on @openai/* with no host leak (scope fallback)', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'dist/client.js',
          message: 'Suspicious flow: credentials + network send (axios.post)' },
        { type: 'env_access', severity: 'HIGH', file: 'dist/client.js', message: 'process.env.OPENAI_API_KEY' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 80 }
    };
    const meta = { name: '@openai/sdk' };
    assert(networkDestinationFirstParty(result, meta) === true,
      'scoped SDK with no host leak should still be first-party via scope table');
  });

  test('network_destination_first_party: TRUE via registryMeta.homepage when scope absent', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'index.js',
          message: 'Suspicious flow: credentials + network send',
          urls: ['https://api.acme-corp.io/v1/events'] }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 78 }
    };
    const meta = { name: 'acme-corp-sdk', registryMeta: { homepage: 'https://acme-corp.io/docs' } };
    assert(networkDestinationFirstParty(result, meta) === true,
      'homepage host from registryMeta should authorise its own subdomain');
  });

  test('network_destination_first_party: TRUE on legacy record via message-URL regex fallback', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'dist/index.js',
          message: 'fetch("https://api.anthropic.com/v1/messages") with env credentials' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 82 }
    };
    const meta = { name: '@anthropic-ai/sdk' };
    assert(networkDestinationFirstParty(result, meta) === true,
      'pre-v2.10.96 JSONL records lack threat.urls — regex fallback must still match');
  });

  // Feature 1: network_destination_first_party — NEGATIVE
  test('network_destination_first_party: FALSE when structured urls point off-scope (CRITICAL exfil)', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'dist/index.js',
          message: 'Suspicious flow: credentials read + network send',
          urls: ['https://attacker-c2.xyz/api'] },
        { type: 'suspicious_domain', severity: 'HIGH', file: 'dist/index.js',
          message: 'Suspicious C2/exfiltration domain "attacker-c2.xyz" found in string literal.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 92 }
    };
    const meta = { name: '@anthropic-ai/sdk' };
    assert(networkDestinationFirstParty(result, meta) === false,
      'non-matching exfil host must not be classed as first-party');
  });

  test('network_destination_first_party: FALSE when no first-party candidate (unscoped, no homepage)', () => {
    const result = {
      threats: [
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'index.js',
          message: 'Suspicious flow: credentials + network' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 76 }
    };
    assert(networkDestinationFirstParty(result, { name: 'random-pkg' }) === false,
      'no scope + no homepage => cannot be first-party');
  });

  test('network_destination_first_party: FALSE when no network-adjacent threat', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js', message: 'obf' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    assert(networkDestinationFirstParty(result, { name: '@anthropic-ai/sdk' }) === false,
      'without a network signal the feature must stay off');
  });

  // Feature 2: install_url_github_releases — POSITIVE
  test('install_url_github_releases: TRUE on download_exec_binary with structured github urls (CRITICAL)', () => {
    const result = {
      threats: [
        { type: 'download_exec_binary', severity: 'CRITICAL', file: 'install.js',
          message: 'Download-execute pattern.',
          urls: [
            'https://github.com/esbuild/esbuild/releases/download/v0.20.0/esbuild-linux-x64.tgz',
            'https://objects.githubusercontent.com/release/12345/asset'
          ] }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 88 }
    };
    assert(installUrlGithubReleases(result) === true,
      'binary installer whose URLs are all github releases is Cluster A FP');
  });

  test('install_url_github_releases: TRUE on binary_dropper with a single objects.githubusercontent URL', () => {
    const result = {
      threats: [
        { type: 'binary_dropper', severity: 'CRITICAL', file: 'postinstall.js',
          message: 'chmod+x + exec/spawn in same file — binary dropper pattern.',
          urls: ['https://objects.githubusercontent.com/prisma/prisma/v5.0.0/binary'] }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 95 }
    };
    assert(installUrlGithubReleases(result) === true,
      'objects.githubusercontent.com alone is an accepted github release host');
  });

  test('install_url_github_releases: TRUE on legacy record via message-URL regex fallback', () => {
    const result = {
      threats: [
        { type: 'download_exec_binary', severity: 'CRITICAL', file: 'install.js',
          message: 'Download-execute pattern: curl https://github.com/foo/bar/releases/download/v1/asset.tgz then chmod' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 87 }
    };
    assert(installUrlGithubReleases(result) === true,
      'pre-v2.10.96 record without threat.urls should still pass via message regex');
  });

  // Feature 2: install_url_github_releases — NEGATIVE
  test('install_url_github_releases: FALSE when any suspicious_domain fires', () => {
    const result = {
      threats: [
        { type: 'download_exec_binary', severity: 'CRITICAL', file: 'install.js',
          message: 'Download-execute pattern.',
          urls: ['https://github.com/foo/bar/releases/download/v1/asset.tgz'] },
        { type: 'suspicious_domain', severity: 'HIGH', file: 'install.js',
          message: 'Suspicious C2/exfiltration domain "evil-c2.xyz" found in string literal.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 97 }
    };
    assert(installUrlGithubReleases(result) === false,
      'any flagged suspicious_domain must short-circuit this feature');
  });

  test('install_url_github_releases: FALSE when a non-github URL is also present', () => {
    const result = {
      threats: [
        { type: 'download_exec_binary', severity: 'CRITICAL', file: 'install.js',
          message: 'Download-execute pattern.',
          urls: [
            'https://github.com/foo/bar/releases/download/v1/asset.tgz',
            'https://cdn.attacker.io/stage2'
          ] }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 96 }
    };
    assert(installUrlGithubReleases(result) === false,
      'mixed github + non-github destinations should not satisfy the feature');
  });

  test('install_url_github_releases: FALSE without binary_dropper or download_exec_binary', () => {
    const result = {
      threats: [
        { type: 'curl_exec', severity: 'HIGH', file: 'index.js',
          message: 'curl github release',
          urls: ['https://github.com/foo/bar/releases/download/v1/asset'] }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 40 }
    };
    assert(installUrlGithubReleases(result) === false,
      'installer signal is required; plain curl_exec is not enough');
  });

  // Feature 3: bundle_without_install_scripts — POSITIVE
  test('bundle_without_install_scripts: TRUE when summary.fileSizes confirm >100KB bundle files (CRITICAL)', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: '_next/static/chunks/main-abc123.js',
          message: 'Heavy obfuscation pattern.' },
        { type: 'dangerous_call_function', severity: 'CRITICAL', file: 'dist/bundle.min.js',
          message: 'new Function(...) in minified bundle' }
      ],
      summary: {
        total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 82,
        fileSizes: {
          '_next/static/chunks/main-abc123.js': 420 * 1024,
          'dist/bundle.min.js': 260 * 1024
        }
      }
    };
    const meta = { registryMeta: { scripts: { test: 'jest', build: 'next build' } } };
    assert(bundleWithoutInstallScripts(result, meta) === true,
      'real >100KB sizes + no install hook => Cluster B');
  });

  test('bundle_without_install_scripts: TRUE on legacy record via bundle-path fallback when sizes absent', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js', message: 'minified' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    assert(bundleWithoutInstallScripts(result, { registryMeta: { scripts: {} } }) === true,
      'pre-v2.10.96 record with no fileSizes should fall back to path-shape heuristic');
  });

  // Feature 3: bundle_without_install_scripts — NEGATIVE
  test('bundle_without_install_scripts: FALSE when a threatened file is under 100KB (hand-written source in dist/)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/small-helper.js',
          message: 'eval(...) in source' }
      ],
      summary: {
        total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 80,
        fileSizes: { 'dist/small-helper.js': 4 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(bundleWithoutInstallScripts(result, meta) === false,
      'a payload planted in dist/ that is only a few KB must not be classed as a bundle');
  });

  test('bundle_without_install_scripts: FALSE when postinstall script is present', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js', message: 'minified' }
      ],
      summary: {
        total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 78,
        fileSizes: { 'dist/index.min.js': 300 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: { postinstall: 'node ./install.js' } } };
    assert(bundleWithoutInstallScripts(result, meta) === false,
      'any install hook invalidates the bundle-only pattern even with real bundle sizes');
  });

  test('bundle_without_install_scripts: FALSE when one threat file has no recorded size', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/bundle.min.js', message: 'minified' },
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'src/cli.js', message: 'eval(...)' }
      ],
      summary: {
        total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 85,
        fileSizes: { 'dist/bundle.min.js': 250 * 1024 } // src/cli.js absent
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(bundleWithoutInstallScripts(result, meta) === false,
      'missing per-file size for any threat file aborts the bundle claim (conservative)');
  });

  test('bundle_without_install_scripts: FALSE when registryMeta.scripts is not provided', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js', message: 'minified' }
      ],
      summary: {
        total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75,
        fileSizes: { 'dist/index.min.js': 250 * 1024 }
      }
    };
    assert(bundleWithoutInstallScripts(result, {}) === false,
      'missing registryMeta.scripts must not be optimistically treated as absent');
  });

  // ============================================================================
  // Feature 12 — vendor_minified_bundle (v2.11.27, weekly review 2026-05-22)
  // ============================================================================
  // Targets the @photoroom/ui (1.8MB UMD, 6 cascade types) and
  // @vkontakte/videoplayer-shared (32KB min, 4 cascade types) cluster.
  // Complements F1 by tolerating per-file co-occurrence (>=3 CASCADE_TYPES on
  // a single bundle file) and a 20KB floor instead of F1's 100KB blanket.

  // Feature 12 — POSITIVE
  test('vendor_minified_bundle: TRUE when >=3 cascade types fire on a 1.8MB UMD bundle (Photoroom-style)', () => {
    const result = {
      threats: [
        { type: 'credential_regex_harvest', severity: 'HIGH', file: 'dist/index.umd.js',
          message: 'regex /(token|password|secret)/ + network call' },
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.umd.js',
          message: 'eval() in minified bundle' },
        { type: 'dangerous_call_function', severity: 'CRITICAL', file: 'dist/index.umd.js',
          message: 'new Function() constructor in minified bundle' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/index.umd.js',
          message: '__proto__ assignment in framework reactivity helper' },
        { type: 'proxy_data_intercept', severity: 'HIGH', file: 'dist/index.umd.js',
          message: 'new Proxy({set,get}) + network call' },
        { type: 'remote_code_load', severity: 'HIGH', file: 'dist/index.umd.js',
          message: 'fetch + eval same file' }
      ],
      summary: {
        total: 6, critical: 2, high: 4, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.umd.js': 1.8 * 1024 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: { test: 'jest', build: 'rollup -c' } } };
    assert(vendorMinifiedBundle(result, meta) === true,
      '1.8MB UMD with 6 cascade types on one file, no install hook => F12 fires');
  });

  test('vendor_minified_bundle: TRUE on 32KB .min.js (vkontakte-style, below F1 100KB floor)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/videoplayer-shared.min.js',
          message: 'eval(...) in minified bundle' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/videoplayer-shared.min.js',
          message: '__proto__ assignment' },
        { type: 'proxy_data_intercept', severity: 'HIGH', file: 'dist/videoplayer-shared.min.js',
          message: 'new Proxy intercept' },
        { type: 'obfuscation_detected', severity: 'LOW', file: 'dist/videoplayer-shared.min.js',
          message: 'minified blob detected (score 60)' }
      ],
      summary: {
        total: 4, critical: 1, high: 2, medium: 0, low: 1, riskScore: 100,
        fileSizes: { 'dist/videoplayer-shared.min.js': 32 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === true,
      '32KB .min.js with 4 cascade types should match (above the 20KB floor) where F1 (100KB) fails');
  });

  test('vendor_minified_bundle: TRUE on legacy record without fileSizes (path-shape fallback)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'lib/index.esm.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'lib/index.esm.js' },
        { type: 'obfuscation_detected', severity: 'LOW', file: 'lib/index.esm.js' }
      ],
      summary: { total: 3, critical: 1, high: 1, medium: 0, low: 1, riskScore: 90 }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === true,
      'pre-v2.10.96 record without fileSizes should fall back to BUNDLE_FILE_RE / BUNDLE_PATH_RE');
  });

  // Feature 12 — NEGATIVE (veto signals — must preserve real detections)
  test('vendor_minified_bundle: FALSE when same-file ioc_match is present (event-stream / flatmap-stream style)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'proxy_data_intercept', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'ioc_match', severity: 'CRITICAL', file: 'dist/index.min.js',
          message: 'Known malicious string from event-stream incident' }
      ],
      summary: {
        total: 4, critical: 2, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 300 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'IOC hit on the same file as the cascade is a veto — bundle suspected of injection');
  });

  test('vendor_minified_bundle: FALSE when node_modules_write coexists (Shai-Hulud worm)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'remote_code_load', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'node_modules_write', severity: 'CRITICAL', file: 'dist/index.min.js',
          message: 'worm propagation: writeFileSync(node_modules/...)' }
      ],
      summary: {
        total: 4, critical: 2, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 500 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'Shai-Hulud worm signature must not be capped — node_modules_write is veto');
  });

  test('vendor_minified_bundle: FALSE when unicode_invisible_injection coexists (GlassWorm)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_function', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'remote_code_load', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'unicode_invisible_injection', severity: 'CRITICAL', file: 'dist/index.min.js',
          message: '47 invisible Unicode chars detected (zero-width, variation selectors)' }
      ],
      summary: {
        total: 4, critical: 2, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 250 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'GlassWorm pattern must not be capped — unicode_invisible_injection is veto');
  });

  test('vendor_minified_bundle: FALSE when intent_credential_exfil is package-level (Axios UNC1069 style)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'proxy_data_intercept', severity: 'HIGH', file: 'dist/index.min.js' },
        // Package-level intent (no t.file) → real campaign signal
        { type: 'intent_credential_exfil', severity: 'CRITICAL',
          message: 'cross-file dataflow: env credentials → network sink' }
      ],
      summary: {
        total: 4, critical: 2, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 600 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'package-level intent_credential_exfil (no t.file) is C3 veto — real campaign');
  });

  test('vendor_minified_bundle: FALSE when detached_credential_exfil coexists (DPRK / mini-Shai-Hulud 2026-05)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'credential_regex_harvest', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'detached_credential_exfil', severity: 'CRITICAL', file: 'dist/index.min.js',
          message: 'spawn detached + env + network' }
      ],
      summary: {
        total: 4, critical: 2, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 200 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'DPRK detached exfil signature must not be capped');
  });

  test('vendor_minified_bundle: FALSE when postinstall lifecycle script exists', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'proxy_data_intercept', severity: 'HIGH', file: 'dist/index.min.js' }
      ],
      summary: {
        total: 3, critical: 1, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 300 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: { postinstall: 'node ./install.js' } } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'any install hook invalidates the bundle-only pattern');
  });

  test('vendor_minified_bundle: FALSE when the cascade file is <20KB (hand-written eval dropped in dist/)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/small.js' },
        { type: 'remote_code_load', severity: 'HIGH', file: 'dist/small.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/small.js' }
      ],
      summary: {
        total: 3, critical: 1, high: 2, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/small.js': 4 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      '4KB file in dist/ with cascade is below the 20KB floor — likely planted payload');
  });

  test('vendor_minified_bundle: FALSE when only 2 cascade types fire (below MIN_TYPES=3 threshold)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js' }
      ],
      summary: {
        total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 90,
        fileSizes: { 'dist/index.min.js': 200 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      '<3 cascade types on the same file is not a vendor-bundle signature');
  });

  test('vendor_minified_bundle: FALSE when cascade fires on a non-bundle path (src/)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'src/index.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'src/index.js' },
        { type: 'proxy_data_intercept', severity: 'HIGH', file: 'src/index.js' }
      ],
      summary: {
        total: 3, critical: 1, high: 2, medium: 0, low: 0, riskScore: 90,
        fileSizes: { 'src/index.js': 200 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'cascade on source files (not dist/.min.js) is not a bundle signature');
  });

  test('vendor_minified_bundle: FALSE when env_access on sensitive var coexists (credential harvest)', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/index.min.js' },
        { type: 'remote_code_load', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'prototype_pollution', severity: 'HIGH', file: 'dist/index.min.js' },
        { type: 'env_access', severity: 'HIGH', file: 'dist/index.min.js',
          message: 'process.env.NPM_TOKEN read' }
      ],
      summary: {
        total: 4, critical: 1, high: 3, medium: 0, low: 0, riskScore: 100,
        fileSizes: { 'dist/index.min.js': 250 * 1024 }
      }
    };
    const meta = { registryMeta: { scripts: {} } };
    assert(vendorMinifiedBundle(result, meta) === false,
      'env_access on NPM_TOKEN inside the bundle is veto via hasBundleVetoSignal SENSITIVE_ENV_RE');
  });

  // Feature 4: git_hook_source_local — POSITIVE
  test('git_hook_source_local: TRUE when git_hooks_injection fires without any remote-fetch in same file (HIGH)', () => {
    const result = {
      threats: [
        { type: 'git_hooks_injection', severity: 'HIGH', file: 'bin/install-hooks.js',
          message: 'Git hook injection: writeFileSync() writes to .git/hooks/.' },
        { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
          message: 'Script "postinstall" detected: node bin/install-hooks.js' }
      ],
      summary: { total: 2, critical: 0, high: 1, medium: 1, low: 0, riskScore: 80 }
    };
    assert(gitHookSourceLocal(result) === true,
      'husky-style tooling: hook write with no network => local source');
  });

  test('git_hook_source_local: TRUE with CRITICAL-severity git hook write but no fetch', () => {
    const result = {
      threats: [
        { type: 'git_hooks_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Git hook injection: modifying global git template directory.' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 78 }
    };
    assert(gitHookSourceLocal(result) === true,
      'CRITICAL hook injection alone still satisfies the heuristic when no remote fetch fires');
  });

  // Feature 4: git_hook_source_local — NEGATIVE
  test('git_hook_source_local: FALSE when same file has remote_code_load', () => {
    const result = {
      threats: [
        { type: 'git_hooks_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Git hook injection: writeFileSync() writes to .git/hooks/.' },
        { type: 'remote_code_load', severity: 'CRITICAL', file: 'install.js',
          message: 'require() of remote URL.' }
      ],
      summary: { total: 2, critical: 2, high: 0, medium: 0, low: 0, riskScore: 95 }
    };
    assert(gitHookSourceLocal(result) === false,
      'remote code load in the hook-writing file => not a local source');
  });

  test('git_hook_source_local: FALSE when same file has suspicious_dataflow (network sink)', () => {
    const result = {
      threats: [
        { type: 'git_hooks_injection', severity: 'HIGH', file: 'bin/setup.js',
          message: 'Git hook injection: writeFileSync() writes to .git/hooks/.' },
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'bin/setup.js',
          message: 'Suspicious flow: credentials + network send (fetch)' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 90 }
    };
    assert(gitHookSourceLocal(result) === false,
      'network exfil from the same file invalidates local-source heuristic');
  });

  test('git_hook_source_local: FALSE when no git_hooks_injection threat is present', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/bundle.min.js', message: 'eval' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 80 }
    };
    assert(gitHookSourceLocal(result) === false,
      'feature must stay off when the triggering threat type is absent');
  });

  // --- Feature 5: typosquat_scoped_package ---

  test('typosquat_scoped_package: TRUE on @scope/* firing typosquat_detected (HIGH)', () => {
    const result = {
      threats: [
        { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json',
          message: 'Typosquat: "adapter-rubrik" close to popular "rubrik"' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 70 }
    };
    assert(typosquatScopedPackage(result, { name: '@company-internal/adapter-rubrik' }) === true,
      'scoped packages shadow their own namespace — not a typosquat of the unscoped twin');
  });

  test('typosquat_scoped_package: TRUE on pypi_typosquat_detected with scoped name', () => {
    const result = {
      threats: [
        { type: 'pypi_typosquat_detected', severity: 'CRITICAL', file: 'setup.py',
          message: 'PyPI typosquat suspect.' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 80 }
    };
    assert(typosquatScopedPackage(result, { name: '@vendor/sub-pkg' }) === true,
      'npm-style scoping accepted on pypi typosquat too (cross-ecosystem gate)');
  });

  test('typosquat_scoped_package: FALSE for unscoped package even when typosquat fires', () => {
    const result = {
      threats: [
        { type: 'typosquat_detected', severity: 'HIGH', file: 'package.json',
          message: 'Typosquat: "reactt" close to "react"' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 70 }
    };
    assert(typosquatScopedPackage(result, { name: 'reactt' }) === false,
      'unscoped typosquat is a real signal, feature must stay off');
  });

  test('typosquat_scoped_package: FALSE when no typosquat threat fires', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'dist/bundle.min.js', message: 'eval' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 80 }
    };
    assert(typosquatScopedPackage(result, { name: '@scope/pkg' }) === false,
      'scoped + no typosquat_detected => feature off');
  });

  // --- Feature 6: obfuscation_without_vector ---

  test('obfuscation_without_vector: TRUE on HIGH obfuscation with zero install/env/network', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/protected.js', message: 'obf' },
        { type: 'js_obfuscation_pattern', severity: 'HIGH', file: 'dist/protected.js', message: 'jsjiami pattern' },
        { type: 'high_entropy_string', severity: 'HIGH', file: 'dist/protected.js', message: 'entropy' }
      ],
      summary: { total: 3, critical: 0, high: 3, medium: 0, low: 0, riskScore: 78 }
    };
    assert(obfuscationWithoutVector(result) === true,
      'commercial obfuscator output without any runtime vector');
  });

  test('obfuscation_without_vector: TRUE on CRITICAL unicode_invisible_injection alone', () => {
    const result = {
      threats: [
        { type: 'unicode_invisible_injection', severity: 'CRITICAL', file: 'dist/strings.js',
          message: 'Invisible Unicode chars.' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 80 }
    };
    assert(obfuscationWithoutVector(result) === true,
      'obfuscation-family threat without env/network/install => still F6');
  });

  test('obfuscation_without_vector: FALSE when env_access co-fires (CRITICAL exfil candidate)', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/protected.js', message: 'obf' },
        { type: 'env_access', severity: 'CRITICAL', file: 'dist/protected.js', message: 'process.env.SECRET' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 88 }
    };
    assert(obfuscationWithoutVector(result) === false,
      'env read is a real vector — obfuscation around it is dangerous');
  });

  test('obfuscation_without_vector: FALSE when a lifecycle script threat fires', () => {
    const result = {
      threats: [
        { type: 'high_entropy_string', severity: 'HIGH', file: 'dist/protected.js', message: 'entropy' },
        { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
          message: 'Script "postinstall" detected: ...' }
      ],
      summary: { total: 2, critical: 0, high: 1, medium: 1, low: 0, riskScore: 75 }
    };
    assert(obfuscationWithoutVector(result) === false,
      'install script alongside obfuscation means a vector exists');
  });

  test('obfuscation_without_vector: FALSE when there is no obfuscation threat at all', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'src/index.js', message: 'eval' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 82 }
    };
    assert(obfuscationWithoutVector(result) === false,
      'no obfuscation family threat => feature off even if VECTOR types are absent');
  });

  // --- Feature 7: placeholder_anti_dep_confusion ---

  test('placeholder_anti_dep_confusion: TRUE on empty package with explicit description', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 }
    };
    const meta = {
      name: '@doctolib/reserved-name',
      registryMeta: {
        scripts: {},
        description: 'Placeholder package to prevent dependency confusion against internal @doctolib/* names.'
      }
    };
    assert(placeholderAntiDepConfusion(result, meta) === true,
      'explicit placeholder package published to reserve a namespace');
  });

  test('placeholder_anti_dep_confusion: TRUE with description from npmRegistryMeta fallback', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 }
    };
    const meta = {
      name: 'internal-tool',
      registryMeta: { scripts: {} },
      npmRegistryMeta: { description: 'Defensive registration — reserving this package name.' }
    };
    assert(placeholderAntiDepConfusion(result, meta) === true,
      'description resolution should fall back through registryMeta -> npmRegistryMeta');
  });

  test('placeholder_anti_dep_confusion: FALSE when description matches but HIGH threat fires', () => {
    const result = {
      threats: [
        { type: 'dangerous_call_eval', severity: 'CRITICAL', file: 'index.js', message: 'eval' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 80 }
    };
    const meta = {
      registryMeta: { scripts: {}, description: 'Prevents dependency confusion attacks.' }
    };
    assert(placeholderAntiDepConfusion(result, meta) === false,
      'a "placeholder" with runtime CRITICAL is actively malicious — feature must stay off');
  });

  test('placeholder_anti_dep_confusion: FALSE when description matches but install script is present', () => {
    const result = {
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 }
    };
    const meta = {
      registryMeta: {
        scripts: { postinstall: 'node ./audit.js' },
        description: 'Placeholder to reserve the namespace against dependency confusion.'
      }
    };
    assert(placeholderAntiDepConfusion(result, meta) === false,
      'a placeholder with an install hook is not actually empty — reject');
  });

  test('placeholder_anti_dep_confusion: FALSE when description does not mention the pattern', () => {
    const result = { threats: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0 } };
    const meta = { registryMeta: { scripts: {}, description: 'A lightweight HTTP client.' } };
    assert(placeholderAntiDepConfusion(result, meta) === false,
      'arbitrary descriptions must not trigger the feature');
  });

  // --- Feature 8: install_script_no_network_egress ---

  test('install_script_no_network_egress: TRUE on postinstall running local build with no network (MEDIUM)', () => {
    const result = {
      threats: [
        { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
          message: 'Script "postinstall" detected: npm run build && mkdir -p dist && chmod 755 bin/cli.js' }
      ],
      summary: { total: 1, critical: 0, high: 0, medium: 1, low: 0, riskScore: 35 }
    };
    const meta = { registryMeta: { scripts: { postinstall: 'npm run build && mkdir -p dist && chmod 755 bin/cli.js' } } };
    assert(installScriptNoNetworkEgress(result, meta) === true,
      'build-step postinstall without any egress threat is Cluster F8');
  });

  test('install_script_no_network_egress: TRUE with CRITICAL obfuscation but no egress type', () => {
    const result = {
      threats: [
        { type: 'js_obfuscation_pattern', severity: 'CRITICAL', file: 'dist/bundle.min.js',
          message: 'Heavy obfuscator output.' },
        { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
          message: 'Script "postinstall" detected: node scripts/echo-welcome.js' }
      ],
      summary: { total: 2, critical: 1, high: 0, medium: 1, low: 0, riskScore: 78 }
    };
    const meta = { registryMeta: { scripts: { postinstall: 'node scripts/echo-welcome.js' } } };
    assert(installScriptNoNetworkEgress(result, meta) === true,
      'CRITICAL obfuscation without egress does not disqualify F8 — script still cannot exfiltrate');
  });

  test('install_script_no_network_egress: FALSE when suspicious_dataflow fires (CRITICAL exfil)', () => {
    const result = {
      threats: [
        { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
          message: 'Script "postinstall": node ./steal.js' },
        { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'steal.js',
          message: 'credentials + fetch(...)' }
      ],
      summary: { total: 2, critical: 1, high: 0, medium: 1, low: 0, riskScore: 90 }
    };
    const meta = { registryMeta: { scripts: { postinstall: 'node ./steal.js' } } };
    assert(installScriptNoNetworkEgress(result, meta) === false,
      'any egress threat in the package disqualifies F8 — script can exfiltrate');
  });

  test('install_script_no_network_egress: FALSE when no install script declared', () => {
    const result = {
      threats: [
        { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/bundle.min.js', message: 'obf' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const meta = { registryMeta: { scripts: { build: 'webpack' } } };
    assert(installScriptNoNetworkEgress(result, meta) === false,
      'no install/preinstall/postinstall means Feature 8 does not apply (F1 or F6 territory)');
  });

  test('install_script_no_network_egress: FALSE when binary_dropper fires (github installer is F2)', () => {
    const result = {
      threats: [
        { type: 'binary_dropper', severity: 'CRITICAL', file: 'install.js',
          message: 'chmod+x + exec/spawn',
          urls: ['https://github.com/foo/bar/releases/download/v1/asset'] },
        { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
          message: 'postinstall: node install.js' }
      ],
      summary: { total: 2, critical: 1, high: 0, medium: 1, low: 0, riskScore: 88 }
    };
    const meta = { registryMeta: { scripts: { postinstall: 'node install.js' } } };
    assert(installScriptNoNetworkEgress(result, meta) === false,
      'binary_dropper is an egress type — this case belongs to F2, not F8');
  });

  // --- Feature 9: mcp_server_env_access (v2.11.21, audit week3 cluster) ---

  test('mcp_server_env_access: TRUE on legit MCP installer reading provider keys', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Writes MCP server entry to ~/.cursor/mcp.json with command and args.' },
        { type: 'env_access', severity: 'HIGH', file: 'install.js',
          message: 'Reads process.env.ANTHROPIC_API_KEY and process.env.OPENAI_API_KEY.' },
        { type: 'credential_regex_harvest', severity: 'HIGH', file: 'install.js',
          message: 'Matches BRAVE_API_KEY pattern in config template.' }
      ],
      summary: { total: 3, critical: 1, high: 2, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@roadmapfy/mcp-init',
      registryMeta: {
        scripts: {},
        keywords: ['mcp', 'claude', 'cursor'],
        description: 'Roadmapfy MCP installer'
      }
    };
    assert(mcpServerEnvAccess(result, meta) === true,
      'identity + mcp_config_injection + no lifecycle + provider keys only + no exfil = F9');
    const features = extractFeatures(result, meta);
    assert(features.mcp_server_env_access === 1, 'feature flag should be 1');
  });

  test('mcp_server_env_access: FALSE when package has no MCP identity', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'preinstall.js',
          message: 'Writes MCP server entry to .claude/mcp_servers.json.' },
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads process.env.ANTHROPIC_API_KEY.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 90 }
    };
    const meta = {
      name: 'innocent-helper',
      registryMeta: { scripts: {}, description: 'A small utility.' }
    };
    assert(mcpServerEnvAccess(result, meta) === false,
      'a non-MCP package injecting MCP config is a SANDWORM_MODE dropper — not F9');
  });

  test('mcp_server_env_access: FALSE when package has install lifecycle hook', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'preinstall.js',
          message: 'Writes MCP server entry to ~/.cursor/mcp.json.' },
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads process.env.ANTHROPIC_API_KEY.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 90 }
    };
    const meta = {
      name: '@vendor/mcp-server',
      registryMeta: {
        scripts: { preinstall: 'node preinstall.js' },
        description: 'MCP server bridge.'
      }
    };
    assert(mcpServerEnvAccess(result, meta) === false,
      'legit MCP installers are opt-in (npx) — a preinstall hook means malicious dropper');
  });

  test('mcp_server_env_access: FALSE when env_access cites a credential file (.npmrc)', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Writes to .mcp.json.' },
        { type: 'credential_regex_harvest', severity: 'CRITICAL', file: 'install.js',
          message: 'Reads ~/.npmrc to harvest npm tokens.' }
      ],
      summary: { total: 2, critical: 2, high: 0, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@vendor/mcp-installer',
      registryMeta: { scripts: {}, keywords: ['mcp'] }
    };
    assert(mcpServerEnvAccess(result, meta) === false,
      '.npmrc read is the SANDWORM_MODE harvest pattern — disqualify');
  });

  test('mcp_server_env_access: FALSE when exfil signal present (suspicious_domain)', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Writes MCP server entry.' },
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads ANTHROPIC_API_KEY.' },
        { type: 'suspicious_domain', severity: 'CRITICAL', file: 'install.js',
          message: 'POST to https://kaixin8.top/relay' }
      ],
      summary: { total: 3, critical: 2, high: 1, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@vendor/mcp-bridge',
      registryMeta: { scripts: {}, keywords: ['mcp'] }
    };
    assert(mcpServerEnvAccess(result, meta) === false,
      'any third-party exfil signal disqualifies F9 — legit MCP installers do not call back to attacker hosts');
  });

  test('mcp_server_env_access: FALSE when env_access cites an unknown all-caps var', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Writes .mcp.json.' },
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads process.env.WALLET_PRIVATE_KEY (not a known provider key).' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 90 }
    };
    const meta = {
      name: 'mcp-vendor-cli',
      registryMeta: { scripts: {}, description: 'MCP server for vendor X.' }
    };
    assert(mcpServerEnvAccess(result, meta) === false,
      'unknown env var (not in provider whitelist, not infra) — cannot vouch for legitimacy');
  });

  test('mcp_server_env_access: TRUE via bin/keywords identity (no name match)', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'cli.js',
          message: 'Writes mcp.json to user dirs.' },
        { type: 'env_access', severity: 'MEDIUM',
          message: 'Reads process.env.STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY.' }
      ],
      summary: { total: 2, critical: 1, high: 0, medium: 1, low: 0, riskScore: 80 }
    };
    const meta = {
      name: '@llamaventures/cli',
      registryMeta: {
        scripts: {},
        bin: { 'llamaventures-mcp-server': './bin/server.js' },
        description: 'Llama Ventures CLI'
      }
    };
    assert(mcpServerEnvAccess(result, meta) === true,
      'bin entry with mcp name segment satisfies identity check even when package name does not');
  });

  // --- Feature 10: vendor_cli_sdk (v2.11.23, audit week3 cluster, 96 FP) ---

  test('vendor_cli_sdk: TRUE on legit vendor CLI with bin + credential noise + homepage', () => {
    const result = {
      threats: [
        { type: 'credential_regex_harvest', severity: 'HIGH', file: 'src/auth.js',
          message: 'STRIPE_SECRET_KEY pattern matched in env read.' },
        { type: 'env_access', severity: 'MEDIUM', file: 'src/auth.js',
          message: 'Reads process.env.STRIPE_SECRET_KEY and PAYPAL_CLIENT_SECRET.' }
      ],
      summary: { total: 2, critical: 0, high: 1, medium: 1, low: 0, riskScore: 90 }
    };
    const meta = {
      name: 'nodebb-plugin-flawless-donations',
      registryMeta: {
        scripts: {},
        bin: { 'flawless-donations': './bin/cli.js' },
        homepage: 'https://github.com/example/flawless-donations'
      }
    };
    assert(vendorCliSdk(result, meta) === true,
      'bin + cred noise + homepage + no exfil + no lifecycle + no MCP = F10');
    const features = extractFeatures(result, meta);
    assert(features.vendor_cli_sdk === 1, 'feature flag should be 1');
  });

  test('vendor_cli_sdk: TRUE on scoped CLI without homepage (scope identity)', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads process.env.API_TOKEN at index.js:42.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 80 }
    };
    const meta = {
      name: '@vendor/cli',
      registryMeta: { scripts: {}, bin: './bin/vendor-cli.js' }
    };
    assert(vendorCliSdk(result, meta) === true,
      'scoped @vendor/cli with bin satisfies C7 even without homepage');
  });

  test('vendor_cli_sdk: FALSE when no bin entry (not a CLI)', () => {
    const result = {
      threats: [
        { type: 'credential_regex_harvest', severity: 'HIGH', message: 'API key in source.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const meta = {
      name: '@vendor/library',
      registryMeta: { scripts: {}, homepage: 'https://vendor.example.com' }
    };
    assert(vendorCliSdk(result, meta) === false,
      'a library without a bin entry is not a CLI — F10 does not apply');
  });

  test('vendor_cli_sdk: FALSE when install lifecycle hook present', () => {
    const result = {
      threats: [
        { type: 'credential_regex_harvest', severity: 'CRITICAL', message: 'API_TOKEN harvested.' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@vendor/cli',
      registryMeta: {
        scripts: { postinstall: 'node ./install.js' },
        bin: './bin/cli.js',
        homepage: 'https://vendor.example.com'
      }
    };
    assert(vendorCliSdk(result, meta) === false,
      'install lifecycle hook disqualifies — legit vendor CLIs are opt-in');
  });

  test('vendor_cli_sdk: FALSE when mcp_config_injection fires (F9 territory)', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', message: 'Writes .mcp.json.' },
        { type: 'env_access', severity: 'HIGH', message: 'Reads ANTHROPIC_API_KEY.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 90 }
    };
    const meta = {
      name: '@vendor/mcp-cli',
      registryMeta: { scripts: {}, bin: './bin/cli.js', homepage: 'https://mcp.vendor.com' }
    };
    assert(vendorCliSdk(result, meta) === false,
      'MCP packages must go through F9 not F10');
  });

  test('vendor_cli_sdk: FALSE when exfil signal present (suspicious_domain)', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH', message: 'Reads OAuth tokens from env.' },
        { type: 'suspicious_domain', severity: 'CRITICAL',
          message: 'POST to https://exfil.attacker.example' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@vendor/cli',
      registryMeta: { scripts: {}, bin: './bin/cli.js', homepage: 'https://vendor.example.com' }
    };
    assert(vendorCliSdk(result, meta) === false,
      'any third-party exfil signal disqualifies — could be a vendor-impersonating dropper');
  });

  test('vendor_cli_sdk: FALSE when credential file path in threat message (.npmrc)', () => {
    const result = {
      threats: [
        { type: 'credential_regex_harvest', severity: 'CRITICAL', file: 'cli.js',
          message: 'Reads ~/.npmrc to extract npm authToken.' }
      ],
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@vendor/cli',
      registryMeta: { scripts: {}, bin: './bin/cli.js', homepage: 'https://vendor.example.com' }
    };
    assert(vendorCliSdk(result, meta) === false,
      '.npmrc harvest is SANDWORM_MODE — disqualify');
  });

  test('vendor_cli_sdk: FALSE when no vendor identity (unscoped + no homepage)', () => {
    const result = {
      threats: [
        { type: 'credential_regex_harvest', severity: 'HIGH', message: 'API_TOKEN read.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const meta = {
      name: 'random-helper',
      registryMeta: { scripts: {}, bin: './bin/run.js' }
    };
    assert(vendorCliSdk(result, meta) === false,
      'unscoped name + no homepage = no vendor identity hint — too loose to cap');
  });

  // --- Feature 11: ai_agent_bot (v2.11.24, audit week3 cluster, 54 FP) ---

  test('ai_agent_bot: TRUE on multi-LLM orchestrator (gm-skill pattern)', () => {
    const result = {
      threats: [
        { type: 'dynamic_import', severity: 'MEDIUM', file: 'cli.js',
          message: 'Dynamic import in CLI dispatch.' },
        { type: 'env_access', severity: 'HIGH', file: 'cli.js',
          message: 'Reads HOME and writes logs to ~/.claude/gm-log/run.log.' },
        { type: 'remote_code_load', severity: 'HIGH', file: 'cli.js',
          message: 'spawn bun x rs-learn@latest — supply-chain risk but explicit orchestrator pattern.' }
      ],
      summary: { total: 3, critical: 0, high: 2, medium: 1, low: 0, riskScore: 88 }
    };
    const meta = {
      name: 'gm-skill',
      registryMeta: {
        scripts: {},
        dependencies: { '@anthropic-ai/sdk': '^0.30.0' },
        description: 'AI coding harness orchestrator'
      }
    };
    assert(aiAgentBot(result, meta) === true,
      'identity (name + deps) + agent path access + no exfil/MCP/lifecycle = F11');
    const features = extractFeatures(result, meta);
    assert(features.ai_agent_bot === 1, 'feature flag should be 1');
  });

  test('ai_agent_bot: TRUE via desc + agent path access (lazyclaw pattern)', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH', file: 'index.js',
          message: 'Reads ~/.claude/sessions/* for context replay.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const meta = {
      name: 'random-pkg-name',
      registryMeta: {
        scripts: {},
        description: 'Terminal CLI for multi-provider LLM (Anthropic/OpenAI/Gemini/Ollama).'
      }
    };
    assert(aiAgentBot(result, meta) === true,
      'description signal alone satisfies C1 identity; ~/.claude/sessions/ satisfies C6');
  });

  test('ai_agent_bot: FALSE when no AI agent identity (random helper)', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH', file: 'helper.js',
          message: 'Touches ~/.claude/somefile but for unrelated reasons.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 70 }
    };
    const meta = {
      name: 'random-helper',
      registryMeta: { scripts: {}, description: 'A small helper.' }
    };
    assert(aiAgentBot(result, meta) === false,
      'no identity signal (name/desc/keywords/deps) — F11 should not vouch');
  });

  test('ai_agent_bot: FALSE when install lifecycle hook present', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH', message: 'Reads ~/.claude/config.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const meta = {
      name: '@vendor/claude-agent',
      registryMeta: {
        scripts: { preinstall: 'node setup.js' },
        dependencies: { '@anthropic-ai/sdk': '^0.30.0' }
      }
    };
    assert(aiAgentBot(result, meta) === false,
      'preinstall lifecycle hook disqualifies — legit agents are opt-in (CLI invoke)');
  });

  test('ai_agent_bot: FALSE when mcp_config_injection fires (F9 territory)', () => {
    const result = {
      threats: [
        { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'install.js',
          message: 'Writes ~/.cursor/mcp.json with server config.' },
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads ~/.claude/settings.json.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 92 }
    };
    const meta = {
      name: 'gm-skill',
      registryMeta: { scripts: {}, dependencies: { '@anthropic-ai/sdk': '^0.30.0' } }
    };
    assert(aiAgentBot(result, meta) === false,
      'MCP packages go through F9 not F11');
  });

  test('ai_agent_bot: FALSE when suspicious_domain (third-party exfil)', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads ~/.claude/sessions/.' },
        { type: 'suspicious_domain', severity: 'CRITICAL', file: 'exfil.js',
          message: 'POST to https://exfil.attacker.com/agent-data' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: '@vendor/claude-agent',
      registryMeta: { scripts: {}, dependencies: { '@anthropic-ai/sdk': '^0.30.0' } }
    };
    assert(aiAgentBot(result, meta) === false,
      'third-party suspicious_domain blocks F11 — could be agent-impersonating exfil');
  });

  test('ai_agent_bot: FALSE when credential file path in message (.npmrc)', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads ~/.claude/sessions/.' },
        { type: 'credential_regex_harvest', severity: 'CRITICAL', file: 'steal.js',
          message: 'Harvests ~/.npmrc auth tokens.' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, riskScore: 95 }
    };
    const meta = {
      name: 'gm-skill',
      registryMeta: { scripts: {}, dependencies: { '@anthropic-ai/sdk': '^0.30.0' } }
    };
    assert(aiAgentBot(result, meta) === false,
      '.npmrc harvest is SANDWORM_MODE — disqualify');
  });

  test('ai_agent_bot: FALSE when no agent runtime path in any threat', () => {
    const result = {
      threats: [
        { type: 'env_access', severity: 'HIGH',
          message: 'Reads process.env.API_TOKEN at index.js:42.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const meta = {
      name: '@vendor/claude-agent',
      registryMeta: { scripts: {}, dependencies: { openai: '^4.0.0' } }
    };
    assert(aiAgentBot(result, meta) === false,
      'no ~/.claude/ or other agent runtime path in any threat → no positive operating signal');
  });

  // --- Feature vector integration ---

  test('extractFeatures: exposes all 11 cluster FP features as 0/1 integers', () => {
    const result = {
      threats: [
        { type: 'git_hooks_injection', severity: 'HIGH', file: 'bin/install.js',
          message: 'Git hook injection: writeFileSync() writes to .git/hooks/.' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, riskScore: 75 }
    };
    const features = extractFeatures(result, { name: 'husky-clone' });
    const keys = [
      'network_destination_first_party',
      'install_url_github_releases',
      'bundle_without_install_scripts',
      'git_hook_source_local',
      'typosquat_scoped_package',
      'obfuscation_without_vector',
      'placeholder_anti_dep_confusion',
      'install_script_no_network_egress',
      'mcp_server_env_access',
      'vendor_cli_sdk',
      'ai_agent_bot'
    ];
    for (const k of keys) {
      assert(features[k] === 0 || features[k] === 1, `${k} must be 0/1, got ${features[k]}`);
    }
    assert(features.git_hook_source_local === 1, 'hook w/o remote fetch -> 1');
    assert(features.network_destination_first_party === 0, 'no network signal -> 0');
    assert(features.install_script_no_network_egress === 0, 'no install script passed -> 0');
    assert(features.mcp_server_env_access === 0, 'no MCP identity -> 0');
    assert(features.vendor_cli_sdk === 0, 'no bin entry -> 0');
    assert(features.ai_agent_bot === 0, 'no agent identity -> 0');
  });

  // Cleanup
  resetTrainingFile();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
}

module.exports = { runMLFeatureExtractorTests };
