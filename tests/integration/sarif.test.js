const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, assertIncludes } = require('../test-utils');

async function runSarifTests() {
  console.log('\n=== SARIF TESTS ===\n');

  const { generateSARIF, saveSARIF } = require('../../src/sarif.js');

  // --- generateSARIF ---

  test('SARIF: generateSARIF returns valid SARIF structure', () => {
    const results = {
      threats: [
        { rule_id: 'MUADDIB-AST-001', severity: 'CRITICAL', message: 'Dangerous call', file: 'index.js', line: 10, confidence: 'high', mitre: 'T1059' },
        { rule_id: 'MUADDIB-AST-002', severity: 'HIGH', message: 'Suspicious require', file: 'lib.js', confidence: 'medium', mitre: 'T1129' }
      ]
    };
    const sarif = generateSARIF(results);
    assert(sarif.version === '2.1.0', 'Version should be 2.1.0');
    assert(sarif.$schema.includes('sarif-schema'), 'Should reference SARIF schema');
    assert(sarif.runs.length === 1, 'Should have 1 run');
    assert(sarif.runs[0].tool.driver.name === 'MUADDIB', 'Tool name should be MUADDIB');
    assert(sarif.runs[0].results.length === 2, 'Should have 2 results');
  });

  test('SARIF: generateSARIF maps severity to correct level', () => {
    const results = {
      threats: [
        { rule_id: 'R1', severity: 'CRITICAL', message: 'c', file: 'a.js' },
        { rule_id: 'R2', severity: 'HIGH', message: 'h', file: 'a.js' },
        { rule_id: 'R3', severity: 'MEDIUM', message: 'm', file: 'a.js' },
        { rule_id: 'R4', severity: 'LOW', message: 'l', file: 'a.js' }
      ]
    };
    const sarif = generateSARIF(results);
    assert(sarif.runs[0].results[0].level === 'error', 'CRITICAL -> error');
    assert(sarif.runs[0].results[1].level === 'error', 'HIGH -> error');
    assert(sarif.runs[0].results[2].level === 'warning', 'MEDIUM -> warning');
    assert(sarif.runs[0].results[3].level === 'note', 'LOW -> note');
  });

  test('SARIF: generateSARIF handles empty threats', () => {
    const sarif = generateSARIF({ threats: [] });
    assert(sarif.runs[0].results.length === 0, 'Should have 0 results');
  });

  test('SARIF: generateSARIF handles undefined threats', () => {
    const sarif = generateSARIF({});
    assert(sarif.runs[0].results.length === 0, 'Should handle missing threats');
  });

  test('SARIF: generateSARIF includes sandbox properties', () => {
    const results = {
      threats: [],
      sandbox: { score: 85, severity: 'CRITICAL', network: { dns_queries: ['evil.com'] } }
    };
    const sarif = generateSARIF(results);
    assert(sarif.runs[0].properties.sandbox, 'Should have sandbox properties');
    assert(sarif.runs[0].properties.sandbox.score === 85, 'Should include score');
    assert(sarif.runs[0].properties.sandbox.severity === 'CRITICAL', 'Should include severity');
  });

  test('SARIF: generateSARIF omits sandbox when not present', () => {
    const results = { threats: [] };
    const sarif = generateSARIF(results);
    assert(!sarif.runs[0].properties.sandbox, 'Should not have sandbox properties');
  });

  test('SARIF: generateSARIF result has location with URI and region', () => {
    const results = {
      threats: [{ rule_id: 'R1', severity: 'HIGH', message: 'test', file: 'src/index.js', line: 42 }]
    };
    const sarif = generateSARIF(results);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert(loc.artifactLocation.uri === 'src/index.js', 'URI should be the file');
    assert(loc.artifactLocation.uriBaseId === '%SRCROOT%', 'Base should be %SRCROOT%');
    assert(loc.region.startLine === 42, 'Line should be 42');
  });

  test('SARIF: generateSARIF defaults line to 1 when missing', () => {
    const results = {
      threats: [{ rule_id: 'R1', severity: 'HIGH', message: 'test', file: 'a.js' }]
    };
    const sarif = generateSARIF(results);
    assert(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine === 1, 'Default line should be 1');
  });

  test('SARIF: generateSARIF driver has rules array from RULES', () => {
    const sarif = generateSARIF({ threats: [] });
    const rules = sarif.runs[0].tool.driver.rules;
    assert(Array.isArray(rules), 'Rules should be array');
    assert(rules.length > 0, 'Should have rules');
    assert(rules[0].id, 'First rule should have id');
    assert(rules[0].name, 'First rule should have name');
  });

  // --- saveSARIF ---

  test('SARIF: saveSARIF writes JSON file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-test-'));
    const outputPath = path.join(tmpDir, 'report.sarif.json');
    const ret = saveSARIF({ threats: [] }, outputPath);
    assert(ret === outputPath, 'Should return output path');
    assert(fs.existsSync(outputPath), 'File should exist');
    const content = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
    assert(content.version === '2.1.0', 'Should be valid SARIF');
    try { fs.unlinkSync(outputPath); fs.rmdirSync(tmpDir); } catch {}
  });

  test('SARIF: saveSARIF throws for invalid path', () => {
    try {
      saveSARIF({}, null);
      assert(false, 'Should have thrown');
    } catch (e) {
      assertIncludes(e.message, 'Invalid output path', 'Should mention invalid path');
    }
  });

  test('SARIF: saveSARIF throws for empty string path', () => {
    try {
      saveSARIF({}, '');
      assert(false, 'Should have thrown');
    } catch (e) {
      assertIncludes(e.message, 'Invalid output path', 'Should mention invalid path');
    }
  });
}

module.exports = { runSarifTests };
