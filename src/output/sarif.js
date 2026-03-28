const fs = require('fs');
const path = require('path');
const { RULES } = require('../rules/index.js');

const pkgVersion = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch {
    return '0.0.0';
  }
})();

function sarifUri(filePath) {
  if (!filePath) return '';
  return filePath.split(/[/\\]/).map(encodeURIComponent).join('/');
}

function generateSARIF(results) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'MUADDIB',
            version: pkgVersion,
            informationUri: 'https://github.com/DNSZLSK/muad-dib',
            rules: Object.values(RULES).map(rule => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.description },
              fullDescription: { text: rule.description },
              helpUri: rule.references[0] || '',
              properties: {
                severity: rule.severity,
                confidence: rule.confidence,
                mitre: rule.mitre
              }
            }))
          }
        },
        properties: results.sandbox ? {
          sandbox: {
            score: results.sandbox.score,
            severity: results.sandbox.severity,
            network: results.sandbox.network || {}
          }
        } : {},
        results: (results.threats || []).map(threat => ({
          ruleId: threat.rule_id,
          level: sarifLevel(threat.severity),
          message: { text: threat.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: sarifUri(threat.file),
                  uriBaseId: '%SRCROOT%'
                },
                region: {
                  startLine: threat.line || 1
                }
              }
            }
          ],
          properties: {
            confidence: threat.confidence,
            mitre: threat.mitre
          }
        }))
      }
    ]
  };

  return sarif;
}

function sarifLevel(severity) {
  switch (severity) {
    case 'CRITICAL': return 'error';
    case 'HIGH': return 'error';
    case 'MEDIUM': return 'warning';
    case 'LOW': return 'note';
    default: return 'note';
  }
}

function saveSARIF(results, outputPath) {
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('Invalid output path for SARIF report');
  }
  const sarif = generateSARIF(results);
  try {
    fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2));
  } catch (e) {
    throw new Error(`Failed to write SARIF report to ${outputPath}: ${e.message}`);
  }
  return outputPath;
}

module.exports = { generateSARIF, saveSARIF };