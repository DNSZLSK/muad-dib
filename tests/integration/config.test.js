/**
 * Configuration system tests (v2.9.7)
 *
 * Tests for .muaddibrc.json config loader, validator, and integration with scoring pipeline.
 * Covers: validation (7 tests), integration (8 tests) = 15 tests.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, assertNotIncludes, runScanDirect } = require('../test-utils');

const { loadConfigFile, validateConfig, resolveConfig, DEFAULTS } = require('../../src/config.js');
const { applyConfigOverrides, resetConfigOverrides, getSeverityWeights, getRiskThresholds, SEVERITY_WEIGHTS, RISK_THRESHOLDS } = require('../../src/scoring.js');
const { getMaxFileSize, setMaxFileSize, resetMaxFileSize, MAX_FILE_SIZE } = require('../../src/shared/constants.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-config-test-'));
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ok */ }
}

function runConfigTests() {
  console.log('\n=== CONFIG TESTS ===\n');

  // =============================================
  // VALIDATION TESTS (CONFIG-01 to CONFIG-07)
  // =============================================

  test('CONFIG-01: Valid config produces no errors', () => {
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = 80;
    raw.riskThresholds.high = 55;
    raw.riskThresholds.medium = 30;
    raw.maxFileSize = 20 * 1024 * 1024;
    raw.severityWeights = Object.create(null);
    raw.severityWeights.critical = 30;
    raw.severityWeights.high = 12;
    raw.severityWeights.medium = 4;
    raw.severityWeights.low = 1;
    const result = validateConfig(raw);
    assert(result.errors.length === 0, `Expected no errors, got: ${result.errors.join(', ')}`);
    assert(result.config !== null, 'Expected config to be non-null');
    assert(result.config.riskThresholds.critical === 80, 'critical threshold should be 80');
    assert(result.config.maxFileSize === 20 * 1024 * 1024, 'maxFileSize should be 20MB');
  });

  test('CONFIG-02: No config file returns null (defaults)', () => {
    const tmpDir = createTempDir();
    try {
      const result = resolveConfig(tmpDir, null);
      assert(result.config === null, 'Expected null config when no file exists');
      assert(result.errors.length === 0, 'Expected no errors');
      assert(result.warnings.length === 0, 'Expected no warnings');
    } finally {
      cleanup(tmpDir);
    }
  });

  test('CONFIG-03: __proto__ key produces error (prototype pollution)', () => {
    const raw = Object.create(null);
    raw['__proto__'] = { critical: 99 };
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected errors');
    assert(result.errors[0].includes('prototype pollution'), `Expected prototype pollution error, got: ${result.errors[0]}`);
  });

  test('CONFIG-04: Negative threshold produces error', () => {
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = -10;
    raw.riskThresholds.high = 50;
    raw.riskThresholds.medium = 25;
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected errors for negative threshold');
    assert(result.errors.some(e => e.includes('must be > 0')), `Expected > 0 error, got: ${result.errors.join(', ')}`);
  });

  test('CONFIG-05: Ordering violation (critical < high) produces error', () => {
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = 40;
    raw.riskThresholds.high = 50;
    raw.riskThresholds.medium = 25;
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected ordering violation error');
    assert(result.errors[0].includes('ordering violation'), `Expected ordering violation, got: ${result.errors[0]}`);
  });

  test('CONFIG-06: Non-numeric value produces error', () => {
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = 'high';
    raw.riskThresholds.high = 50;
    raw.riskThresholds.medium = 25;
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected error for non-numeric value');
    assert(result.errors.some(e => e.includes('finite number')), `Expected finite number error, got: ${result.errors.join(', ')}`);
  });

  test('CONFIG-07: Unknown key produces warning (not error), key ignored', () => {
    const raw = Object.create(null);
    raw.unknownKey = 'value';
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = 80;
    raw.riskThresholds.high = 55;
    raw.riskThresholds.medium = 30;
    const result = validateConfig(raw);
    assert(result.errors.length === 0, 'Expected no errors for unknown key');
    assert(result.warnings.some(w => w.includes('unknownKey')), 'Expected warning about unknownKey');
  });

  // =============================================
  // INTEGRATION TESTS (CONFIG-08 to CONFIG-15)
  // =============================================

  test('CONFIG-08: riskThresholds custom changes riskLevel classification', () => {
    // Apply config that makes thresholds very strict
    resetConfigOverrides();
    applyConfigOverrides({
      riskThresholds: { critical: 90, high: 70, medium: 50 }
    });
    const rt = getRiskThresholds();
    assert(rt.CRITICAL === 90, `Expected CRITICAL=90, got ${rt.CRITICAL}`);
    assert(rt.HIGH === 70, `Expected HIGH=70, got ${rt.HIGH}`);
    assert(rt.MEDIUM === 50, `Expected MEDIUM=50, got ${rt.MEDIUM}`);
    resetConfigOverrides();
  });

  test('CONFIG-09: Config reset after apply restores defaults (no state leak)', () => {
    applyConfigOverrides({
      severityWeights: { critical: 50, high: 20, medium: 5, low: 2 },
      riskThresholds: { critical: 90, high: 70, medium: 50 }
    });
    // Verify overrides applied
    assert(getSeverityWeights().CRITICAL === 50, 'Override should be applied');
    // Reset
    resetConfigOverrides();
    // Verify defaults restored
    const sw = getSeverityWeights();
    assert(sw.CRITICAL === 25, `Expected CRITICAL=25 after reset, got ${sw.CRITICAL}`);
    assert(sw.HIGH === 10, `Expected HIGH=10 after reset, got ${sw.HIGH}`);
    const rt = getRiskThresholds();
    assert(rt.CRITICAL === 75, `Expected CRITICAL threshold=75 after reset, got ${rt.CRITICAL}`);
  });

  test('CONFIG-10: --config path takes priority over .muaddibrc.json', () => {
    const tmpDir = createTempDir();
    try {
      // Create .muaddibrc.json in target dir
      const rcConfig = { riskThresholds: { critical: 80, high: 55, medium: 30 } };
      fs.writeFileSync(path.join(tmpDir, '.muaddibrc.json'), JSON.stringify(rcConfig));

      // Create explicit config file elsewhere
      const explicitConfig = { riskThresholds: { critical: 90, high: 70, medium: 50 } };
      const explicitPath = path.join(tmpDir, 'custom.json');
      fs.writeFileSync(explicitPath, JSON.stringify(explicitConfig));

      // Explicit --config should win
      const result = resolveConfig(tmpDir, explicitPath);
      assert(result.errors.length === 0, `Expected no errors, got: ${result.errors.join(', ')}`);
      assert(result.config.riskThresholds.critical === 90, `Expected critical=90 from explicit, got ${result.config.riskThresholds.critical}`);
    } finally {
      cleanup(tmpDir);
    }
  });

  test('CONFIG-11: maxFileSize override is respected', () => {
    const customSize = 5 * 1024 * 1024; // 5MB
    setMaxFileSize(customSize);
    assert(getMaxFileSize() === customSize, `Expected ${customSize}, got ${getMaxFileSize()}`);
    resetMaxFileSize();
    assert(getMaxFileSize() === MAX_FILE_SIZE, `Expected default after reset, got ${getMaxFileSize()}`);
  });

  test('CONFIG-12: Config > 10KB is rejected', () => {
    const tmpDir = createTempDir();
    try {
      // Create a config file > 10KB
      const bigConfig = { riskThresholds: { critical: 80, high: 55, medium: 30 } };
      // Pad with a large unknown string key
      bigConfig['_padding'] = 'x'.repeat(11 * 1024);
      const bigPath = path.join(tmpDir, 'big.json');
      fs.writeFileSync(bigPath, JSON.stringify(bigConfig));

      const result = resolveConfig(tmpDir, bigPath);
      assert(result.errors.length > 0, 'Expected error for large config');
      assert(result.errors[0].includes('10KB'), `Expected size error, got: ${result.errors[0]}`);
    } finally {
      cleanup(tmpDir);
    }
  });

  test('CONFIG-13: Malformed JSON produces clear error', () => {
    const tmpDir = createTempDir();
    try {
      const badPath = path.join(tmpDir, 'bad.json');
      fs.writeFileSync(badPath, '{ invalid json !!!');

      const result = resolveConfig(tmpDir, badPath);
      assert(result.errors.length > 0, 'Expected error for malformed JSON');
      assert(result.errors[0].includes('Failed to parse'), `Expected parse error, got: ${result.errors[0]}`);
    } finally {
      cleanup(tmpDir);
    }
  });

  test('CONFIG-14: Partial config merges with defaults', () => {
    // Only specify riskThresholds, severityWeights should use defaults
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = 85;
    raw.riskThresholds.high = 60;
    raw.riskThresholds.medium = 30;
    const result = validateConfig(raw);
    assert(result.errors.length === 0, `Expected no errors, got: ${result.errors.join(', ')}`);
    assert(result.config !== null, 'Expected config');
    assert(result.config.riskThresholds.critical === 85, 'Partial config should have custom critical');
    // severityWeights should NOT be in config (not specified)
    assert(result.config.severityWeights === undefined, 'severityWeights should not be in partial config');
  });

  test('CONFIG-15: severityWeights override changes computed score', () => {
    resetConfigOverrides();
    // Default: CRITICAL=25
    assert(getSeverityWeights().CRITICAL === 25, 'Default CRITICAL weight should be 25');

    // Apply custom weights
    applyConfigOverrides({
      severityWeights: { critical: 50, high: 20, medium: 5, low: 2 }
    });
    const sw = getSeverityWeights();
    assert(sw.CRITICAL === 50, `Expected CRITICAL=50, got ${sw.CRITICAL}`);
    assert(sw.HIGH === 20, `Expected HIGH=20, got ${sw.HIGH}`);
    assert(sw.MEDIUM === 5, `Expected MEDIUM=5, got ${sw.MEDIUM}`);
    assert(sw.LOW === 2, `Expected LOW=2, got ${sw.LOW}`);
    resetConfigOverrides();
  });

  // CONFIG-16: .muaddibrc.json auto-detection at target root
  test('CONFIG-16: .muaddibrc.json auto-detected at target root', () => {
    const tmpDir = createTempDir();
    try {
      const rcConfig = { riskThresholds: { critical: 85, high: 60, medium: 35 } };
      fs.writeFileSync(path.join(tmpDir, '.muaddibrc.json'), JSON.stringify(rcConfig));

      const result = resolveConfig(tmpDir, null);
      assert(result.errors.length === 0, `Expected no errors, got: ${result.errors.join(', ')}`);
      assert(result.config !== null, 'Expected config from auto-detected .muaddibrc.json');
      assert(result.config.riskThresholds.critical === 85, `Expected critical=85, got ${result.config.riskThresholds.critical}`);
      assert(result.warnings.some(w => w.includes('.muaddibrc.json')), 'Expected warning mentioning .muaddibrc.json');
    } finally {
      cleanup(tmpDir);
    }
  });

  // CONFIG-17: Relaxed thresholds produce warning
  test('CONFIG-17: Relaxed thresholds produce sensitivity warning', () => {
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds.critical = 95; // higher than default 75
    raw.riskThresholds.high = 70;     // higher than default 50
    raw.riskThresholds.medium = 40;   // higher than default 25
    const result = validateConfig(raw);
    assert(result.errors.length === 0, `Expected no errors, got: ${result.errors.join(', ')}`);
    assert(result.warnings.some(w => w.includes('sensitivity reduced')), 'Expected sensitivity reduced warning');
  });

  // CONFIG-18: Prototype pollution in nested key
  test('CONFIG-18: constructor key in nested object produces error', () => {
    const raw = Object.create(null);
    raw.riskThresholds = Object.create(null);
    raw.riskThresholds['constructor'] = 99;
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected error for constructor key');
    assert(result.errors[0].includes('prototype pollution'), 'Expected prototype pollution error');
  });

  // CONFIG-19: NaN and Infinity rejected
  test('CONFIG-19: NaN and Infinity values are rejected', () => {
    const raw1 = Object.create(null);
    raw1.maxFileSize = NaN;
    const r1 = validateConfig(raw1);
    assert(r1.errors.length > 0, 'Expected error for NaN maxFileSize');

    const raw2 = Object.create(null);
    raw2.maxFileSize = Infinity;
    const r2 = validateConfig(raw2);
    assert(r2.errors.length > 0, 'Expected error for Infinity maxFileSize');
  });

  // CONFIG-20: Integration - scan with config does not leak state
  asyncTest('CONFIG-20: Scan with configPath does not leak state to next scan', async () => {
    const tmpDir = createTempDir();
    try {
      // Create a minimal scannable project
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'config-test-pkg', version: '1.0.0' }));
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'module.exports = {};');

      // Create config with custom weights
      const configFile = path.join(tmpDir, 'custom.json');
      fs.writeFileSync(configFile, JSON.stringify({
        severityWeights: { critical: 50, high: 20, medium: 5, low: 2 }
      }));

      // Scan with config
      await runScanDirect(tmpDir, { configPath: configFile });

      // After scan, verify weights are back to defaults
      const sw = getSeverityWeights();
      assert(sw.CRITICAL === 25, `Expected CRITICAL=25 after scan reset, got ${sw.CRITICAL}`);
      assert(sw.HIGH === 10, `Expected HIGH=10 after scan reset, got ${sw.HIGH}`);
    } finally {
      cleanup(tmpDir);
    }
  });

  // CONFIG-21: maxFileSize below 1MB rejected
  test('CONFIG-21: maxFileSize below 1MB is rejected', () => {
    const raw = Object.create(null);
    raw.maxFileSize = 500 * 1024; // 500KB
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected error for maxFileSize < 1MB');
    assert(result.errors[0].includes('>= 1MB'), 'Expected >= 1MB error message');
  });

  // CONFIG-22: maxFileSize above 100MB rejected
  test('CONFIG-22: maxFileSize above 100MB is rejected', () => {
    const raw = Object.create(null);
    raw.maxFileSize = 200 * 1024 * 1024;
    const result = validateConfig(raw);
    assert(result.errors.length > 0, 'Expected error for maxFileSize > 100MB');
    assert(result.errors[0].includes('<= 100MB'), 'Expected <= 100MB error message');
  });
}

module.exports = { runConfigTests };
