const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes,
  runCommand, BIN
} = require('../test-utils');

async function runGroundTruthTests() {
  console.log('\n=== GROUND TRUTH TESTS ===\n');

  const { replay, loadAttacks, checkExpected } = require('../ground-truth/replay.js');

  test('GROUND-TRUTH: attacks.json loads and has attacks', () => {
    const data = loadAttacks();
    assert(data.version === '1.0', 'Version should be 1.0, got ' + data.version);
    assert(Array.isArray(data.attacks), 'attacks should be an array');
    assert(data.attacks.length >= 5, 'Should have at least 5 attacks, got ' + data.attacks.length);
  });

  test('GROUND-TRUTH: each attack has required fields', () => {
    const data = loadAttacks();
    const requiredFields = ['id', 'name', 'version', 'ecosystem', 'year', 'vector',
      'severity', 'description', 'source', 'sample_dir', 'expected'];
    for (const attack of data.attacks) {
      for (const field of requiredFields) {
        assert(attack[field] !== undefined, `Attack ${attack.id} missing field: ${field}`);
      }
      assert(attack.expected.min_threats !== undefined, `Attack ${attack.id} missing expected.min_threats`);
      assert(Array.isArray(attack.expected.rules), `Attack ${attack.id} expected.rules should be array`);
      assert(Array.isArray(attack.expected.severities), `Attack ${attack.id} expected.severities should be array`);
    }
  });

  test('GROUND-TRUTH: all sample directories exist', () => {
    const data = loadAttacks();
    const gtDir = path.join(__dirname, '..', 'ground-truth');
    for (const attack of data.attacks) {
      const sampleDir = path.join(gtDir, attack.sample_dir);
      assert(fs.existsSync(sampleDir), `Sample dir missing for ${attack.id}: ${sampleDir}`);
    }
  });

  test('GROUND-TRUTH: checkExpected passes when findings match', () => {
    const attack = {
      id: 'GT-TEST',
      name: 'test-pkg',
      expected: {
        min_threats: 1,
        rules: ['MUADDIB-DEP-001'],
        severities: ['CRITICAL'],
        scanners: ['dependencies']
      }
    };
    const result = {
      summary: { total: 2 },
      threats: [
        { rule_id: 'MUADDIB-DEP-001', severity: 'CRITICAL', type: 'known_malicious_package' },
        { rule_id: 'MUADDIB-DEP-001', severity: 'CRITICAL', type: 'known_malicious_package' }
      ]
    };
    const status = checkExpected(attack, result);
    assert(status.passed === true, 'Should pass when findings match');
    assert(status.matchedRules.includes('MUADDIB-DEP-001'), 'Should match rule');
    assert(status.matchedSeverities.includes('CRITICAL'), 'Should match severity');
  });

  test('GROUND-TRUTH: checkExpected fails when missing rule', () => {
    const attack = {
      id: 'GT-TEST',
      name: 'test-pkg',
      expected: {
        min_threats: 1,
        rules: ['MUADDIB-MISSING-001'],
        severities: ['HIGH'],
        scanners: []
      }
    };
    const result = {
      summary: { total: 1 },
      threats: [
        { rule_id: 'MUADDIB-PKG-001', severity: 'MEDIUM', type: 'lifecycle_script' }
      ]
    };
    const status = checkExpected(attack, result);
    assert(status.passed === false, 'Should fail when expected rule is missing');
    assert(status.details.some(d => d.includes('MUADDIB-MISSING-001')), 'Details should mention missing rule');
  });

  test('GROUND-TRUTH: checkExpected fails when too few threats', () => {
    const attack = {
      id: 'GT-TEST',
      name: 'test-pkg',
      expected: {
        min_threats: 5,
        rules: [],
        severities: [],
        scanners: []
      }
    };
    const result = {
      summary: { total: 2 },
      threats: [
        { rule_id: 'X', severity: 'HIGH', type: 'x' },
        { rule_id: 'Y', severity: 'MEDIUM', type: 'y' }
      ]
    };
    const status = checkExpected(attack, result);
    assert(status.passed === false, 'Should fail when too few threats');
    assert(status.details.some(d => d.includes('>= 5')), 'Details should mention threshold');
  });

  test('GROUND-TRUTH: checkExpected passes for out-of-scope (0 expected)', () => {
    const attack = {
      id: 'GT-TEST',
      name: 'test-pkg',
      expected: {
        min_threats: 0,
        rules: [],
        severities: [],
        scanners: []
      }
    };
    const result = {
      summary: { total: 0 },
      threats: []
    };
    const status = checkExpected(attack, result);
    assert(status.passed === true, 'Should pass when 0 expected and 0 found');
  });

  await asyncTest('GROUND-TRUTH: replay runs and all attacks pass', async () => {
    const result = await replay({ json: false });
    assert(typeof result.total === 'number', 'Result should have total');
    assert(typeof result.detected === 'number', 'Result should have detected');
    assert(typeof result.missed === 'number', 'Result should have missed');
    assert(typeof result.rate === 'number', 'Result should have rate');
    assert(result.missed === 0, `Expected 0 missed, got ${result.missed}. Failed: ${result.results.filter(r => !r.passed).map(r => r.id + ': ' + (r.details || []).join('; ')).join(' | ')}`);
    assert(result.total >= 5, 'Should replay at least 5 attacks, got ' + result.total);
  });

  test('GROUND-TRUTH: CLI replay command works', () => {
    const output = runCommand('replay --json');
    assert(output.length > 0, 'Should produce output');
    const parsed = JSON.parse(output);
    assert(parsed.total >= 5, 'JSON should have total >= 5');
    assert(typeof parsed.rate === 'number', 'JSON should have rate');
    assert(Array.isArray(parsed.results), 'JSON should have results array');
  });

  test('GROUND-TRUTH: CLI ground-truth alias works', () => {
    const output = runCommand('ground-truth --json');
    const parsed = JSON.parse(output);
    assert(parsed.total >= 5, 'Alias should also work, got total=' + parsed.total);
  });

  test('GROUND-TRUTH: CLI replay single attack works', () => {
    const output = runCommand('replay GT-001 --json');
    const parsed = JSON.parse(output);
    assert(parsed.total === 1, 'Should replay only 1 attack, got ' + parsed.total);
    assert(parsed.results[0].id === 'GT-001', 'Should be GT-001');
    assert(parsed.results[0].passed === true, 'GT-001 should pass');
  });
}

module.exports = { runGroundTruthTests };
