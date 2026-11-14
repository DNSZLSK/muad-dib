/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

const fs = require('fs');
const path = require('path');
const { RULES, getRuleDomain } = require('../rules/index.js');
const { describe: describeIncomplete } = require('../shared/completeness.js');

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
            rules: Object.entries(RULES).map(([type, rule]) => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.description },
              fullDescription: { text: rule.description },
              helpUri: rule.references[0] || '',
              properties: {
                severity: rule.severity,
                confidence: rule.confidence,
                mitre: rule.mitre,
                // P0a — Risk Domains taxonomy. Either set explicitly on the rule
                // or resolved via getRuleDomain default (currently 'malware').
                risk_domain: getRuleDomain(type)
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
        // Incompleteness contract (architecture lot 1): an INCONCLUSIVE scan carries
        // one error-level tool notification per bound reached (SARIF Appendix I), so
        // SARIF consumers never read "no results" as "clean".
        ...(results.analysis ? { invocations: [sarifInvocation(results.analysis)] } : {}),
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
            mitre: threat.mitre,
            // P0a — per-result risk domain (resolved from threat.type).
            risk_domain: getRuleDomain(threat.type)
          }
        }))
      }
    ]
  };

  return sarif;
}

// SARIF 2.1.0 Appendix I ("Detecting incomplete result sets"): executionSuccessful
// false means the tool failed to start, exited with a failure code or crashed
// (§3.20.14) - not our case, the scan ran to the end. The standard signal that
// "the results cannot be assumed to be complete" is a toolExecutionNotification
// whose level is "error" (§3.20.21, §3.58.6). So: executionSuccessful stays true,
// one error-level notification per bound reached.
function sarifInvocation(analysis) {
  const incomplete = Array.isArray(analysis.incomplete) ? analysis.incomplete : [];
  const invocation = {
    executionSuccessful: true,
    properties: { analysisStatus: analysis.status }
  };
  if (incomplete.length > 0) {
    invocation.toolExecutionNotifications = incomplete.map(entry => ({
      level: 'error',
      descriptor: { id: `incomplete/${entry.component}/${entry.reason}` },
      message: { text: `Analysis incomplete: ${describeIncomplete(entry)}` }
    }));
  }
  return invocation;
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
    throw new Error(`Failed to write SARIF report to ${outputPath}: ${e.message}`, { cause: e });
  }
  return outputPath;
}

module.exports = { generateSARIF, saveSARIF };