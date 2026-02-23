const { test, assert, assertIncludes } = require('../test-utils');

async function runOutputFormatterTests() {
  console.log('\n=== OUTPUT FORMATTER TESTS ===\n');

  const { formatOutput } = require('../../src/output-formatter.js');

  // Helper to capture console.log output
  function captureOutput(fn) {
    const logs = [];
    const origLog = console.log;
    console.log = (...args) => logs.push(args.join(' '));
    try {
      fn();
    } finally {
      console.log = origLog;
    }
    return logs.join('\n');
  }

  // --- JSON output ---

  test('FORMATTER: JSON mode outputs valid JSON', () => {
    const result = { summary: { riskScore: 50, riskLevel: 'HIGH', total: 1 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, { json: true }, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '.'
      });
    });
    const parsed = JSON.parse(output);
    assert(parsed.summary.riskScore === 50, 'Should output correct riskScore');
  });

  // --- HTML output ---

  test('FORMATTER: HTML mode calls saveReport', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const htmlPath = path.join(os.tmpdir(), 'muaddib-fmt-test.html');
    const output = captureOutput(() => {
      formatOutput(result, { html: htmlPath }, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '.'
      });
    });
    assertIncludes(output, 'HTML report generated', 'Should confirm HTML generation');
    try { fs.unlinkSync(htmlPath); } catch {}
  });

  // --- SARIF output ---

  test('FORMATTER: SARIF mode calls saveSARIF', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const sarifPath = path.join(os.tmpdir(), 'muaddib-fmt-test.sarif');
    const output = captureOutput(() => {
      formatOutput(result, { sarif: sarifPath }, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '.'
      });
    });
    assertIncludes(output, 'SARIF report generated', 'Should confirm SARIF generation');
    try { fs.unlinkSync(sarifPath); } catch {}
  });

  // --- Explain mode: no threats ---

  test('FORMATTER: Explain mode with no threats', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, { explain: true }, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '[SCORE]', 'Should show score bar');
    assertIncludes(output, 'No threats detected', 'Should say no threats');
  });

  // --- Explain mode: with threats ---

  test('FORMATTER: Explain mode with threats shows details', () => {
    const result = { summary: { riskScore: 50, riskLevel: 'HIGH', total: 1 }, threats: [] };
    const enriched = [{
      severity: 'HIGH', rule_name: 'Dangerous Call', rule_id: 'MUADDIB-AST-001',
      file: 'index.js', confidence: 'HIGH', message: 'eval() detected',
      mitre: 'T1059', references: ['https://example.com'], playbook: 'Remove eval',
      count: 1
    }];
    const output = captureOutput(() => {
      formatOutput(result, { explain: true }, {
        spinner: null, sandboxData: null, mostSuspiciousFile: 'index.js',
        maxFileScore: 50, packageScore: 0, globalRiskScore: 50,
        deduped: [], enrichedThreats: enriched, pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, 'Rule ID', 'Should show Rule ID');
    assertIncludes(output, 'MUADDIB-AST-001', 'Should show rule ID value');
    assertIncludes(output, 'MITRE', 'Should show MITRE');
    assertIncludes(output, 'Playbook', 'Should show Playbook');
    assertIncludes(output, 'Max file:', 'Should show max file');
  });

  // --- Explain mode: with breakdown ---

  test('FORMATTER: Explain mode with breakdown shows contributors', () => {
    const result = { summary: { riskScore: 30, riskLevel: 'MEDIUM', total: 1 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, { explain: true, breakdown: true }, {
        spinner: null, sandboxData: null, mostSuspiciousFile: 'a.js',
        maxFileScore: 30, packageScore: 0, globalRiskScore: 40,
        deduped: [], enrichedThreats: [], pythonInfo: null,
        breakdown: [{ points: 10, reason: 'eval detected', rule: 'MUADDIB-AST-001' }],
        targetPath: '/test'
      });
    });
    assertIncludes(output, '[BREAKDOWN]', 'Should show breakdown header');
    assertIncludes(output, 'Global sum:', 'Should show global vs per-file diff');
  });

  // --- Normal mode: no threats ---

  test('FORMATTER: Normal mode with no threats', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, 'No threats detected', 'Should say no threats');
  });

  // --- Normal mode: with threats ---

  test('FORMATTER: Normal mode with threats and playbook', () => {
    const result = { summary: { riskScore: 50, riskLevel: 'HIGH', total: 1 }, threats: [] };
    const deduped = [{
      severity: 'HIGH', type: 'dangerous_call_eval', message: 'eval() detected',
      file: 'index.js', count: 2
    }];
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null, sandboxData: null, mostSuspiciousFile: 'index.js',
        maxFileScore: 50, packageScore: 0, globalRiskScore: 50,
        deduped, enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '[ALERT]', 'Should show alert');
    assertIncludes(output, 'x2', 'Should show count');
    assertIncludes(output, 'File:', 'Should show file');
  });

  // --- Python info ---

  test('FORMATTER: Normal mode with python info (no threats)', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [],
        pythonInfo: { dependencies: 5, files: ['requirements.txt'], threats: 0 },
        breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '[PYTHON]', 'Should show Python info');
    assertIncludes(output, '5 dependencies', 'Should show dep count');
    assertIncludes(output, 'No known malicious', 'Should say no malicious');
  });

  test('FORMATTER: Normal mode with python threats', () => {
    const result = { summary: { riskScore: 25, riskLevel: 'HIGH', total: 1 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 25, globalRiskScore: 25,
        deduped: [], enrichedThreats: [],
        pythonInfo: { dependencies: 3, files: ['setup.py'], threats: 2 },
        breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '2 malicious PyPI', 'Should show malicious count');
  });

  // --- Sandbox data ---

  test('FORMATTER: Normal mode with sandbox data (no findings)', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null,
        sandboxData: { package: 'test-pkg', score: 0, severity: 'NONE', findings: [] },
        mostSuspiciousFile: null, maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '[SANDBOX]', 'Should show sandbox header');
    assertIncludes(output, 'No suspicious behavior', 'Should say no findings');
  });

  test('FORMATTER: Normal mode with sandbox findings', () => {
    const result = { summary: { riskScore: 50, riskLevel: 'HIGH', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null,
        sandboxData: {
          package: 'evil-pkg', score: 80, severity: 'CRITICAL',
          findings: [{ severity: 'CRITICAL', type: 'network', detail: 'HTTP to evil.com' }]
        },
        mostSuspiciousFile: null, maxFileScore: 0, packageScore: 50, globalRiskScore: 50,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '[SANDBOX]', 'Should show sandbox header');
    assertIncludes(output, 'evil-pkg', 'Should show package name');
    assertIncludes(output, '1 finding', 'Should show finding count');
  });

  // --- Explain mode with sandbox ---

  test('FORMATTER: Explain mode with sandbox findings', () => {
    const result = { summary: { riskScore: 70, riskLevel: 'CRITICAL', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, { explain: true }, {
        spinner: null,
        sandboxData: {
          package: 'sus-pkg', score: 90, severity: 'CRITICAL',
          findings: [{ severity: 'HIGH', type: 'filesystem', detail: 'Wrote to /etc' }]
        },
        mostSuspiciousFile: null, maxFileScore: 0, packageScore: 70, globalRiskScore: 70,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, '[SANDBOX]', 'Should show sandbox in explain');
    assertIncludes(output, 'sus-pkg', 'Should show package name');
  });

  // --- With spinner (suppresses "Scanning" header) ---

  test('FORMATTER: Normal mode with spinner suppresses header', () => {
    const result = { summary: { riskScore: 0, riskLevel: 'NONE', total: 0 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: { succeed: () => {} }, sandboxData: null, mostSuspiciousFile: null,
        maxFileScore: 0, packageScore: 0, globalRiskScore: 0,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assert(!output.includes('[MUADDIB] Scanning'), 'With spinner, should not show Scanning header');
  });

  // --- Package score ---

  test('FORMATTER: Normal mode shows package-level score when > 0', () => {
    const result = { summary: { riskScore: 35, riskLevel: 'MEDIUM', total: 1 }, threats: [] };
    const output = captureOutput(() => {
      formatOutput(result, {}, {
        spinner: null, sandboxData: null, mostSuspiciousFile: 'index.js',
        maxFileScore: 25, packageScore: 10, globalRiskScore: 35,
        deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: '/test'
      });
    });
    assertIncludes(output, 'Package-level: +10', 'Should show package-level score');
  });
}

module.exports = { runOutputFormatterTests };
