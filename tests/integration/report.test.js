const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, assertIncludes } = require('../test-utils');

async function runReportTests() {
  console.log('\n=== REPORT TESTS ===\n');

  const { generateHTML, saveReport } = require('../../src/report.js');

  // --- generateHTML ---

  test('REPORT: generateHTML returns valid HTML with threats', () => {
    const results = {
      target: '/test/path',
      timestamp: '2025-01-01T00:00:00Z',
      threats: [
        { severity: 'CRITICAL', type: 'known_malicious', message: 'Malicious package', file: 'package.json', playbook: 'Remove immediately' },
        { severity: 'HIGH', type: 'suspicious_dataflow', message: 'Data exfiltration', file: 'index.js', playbook: 'Review code' }
      ],
      summary: { total: 2, critical: 1, high: 1, medium: 0 }
    };
    const html = generateHTML(results);
    assert(typeof html === 'string', 'Should return string');
    assertIncludes(html, '<!DOCTYPE html>', 'Should be valid HTML');
    assertIncludes(html, 'MUAD\'DIB', 'Should contain tool name');
    assertIncludes(html, 'known_malicious', 'Should contain threat type');
    assertIncludes(html, 'Malicious package', 'Should contain message');
    assertIncludes(html, '/test/path', 'Should contain target path');
    assertIncludes(html, '2025-01-01', 'Should contain timestamp');
    assertIncludes(html, '<table>', 'Should have a table for threats');
  });

  test('REPORT: generateHTML with no threats shows OK message', () => {
    const results = {
      target: '/clean/path',
      timestamp: '2025-01-01T00:00:00Z',
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0 }
    };
    const html = generateHTML(results);
    assertIncludes(html, 'No threats detected', 'Should show no threats message');
    assert(!html.includes('<table>'), 'Should not have a threat table');
  });

  test('REPORT: generateHTML with sandbox data', () => {
    const results = {
      target: '/test/path',
      timestamp: '2025-01-01T00:00:00Z',
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0 },
      sandbox: {
        package: 'test-pkg',
        score: 85,
        severity: 'CRITICAL',
        findings: [
          { severity: 'CRITICAL', type: 'sensitive_file_read', detail: 'Read .npmrc' }
        ],
        network: {
          dns_resolutions: [{ domain: 'evil.com', ip: '1.2.3.4' }],
          http_requests: [{ method: 'POST', host: 'evil.com', path: '/steal' }],
          tls_connections: [{ domain: 'evil.com', ip: '1.2.3.4', port: 443 }],
          blocked_connections: [{ ip: '5.6.7.8', port: 8080 }]
        }
      }
    };
    const html = generateHTML(results);
    assertIncludes(html, 'SANDBOX', 'Should have sandbox section');
    assertIncludes(html, 'test-pkg', 'Should show package name');
    assertIncludes(html, '85', 'Should show score');
    assertIncludes(html, 'sensitive_file_read', 'Should show finding type');
    assertIncludes(html, 'evil.com', 'Should show DNS resolution');
    assertIncludes(html, 'POST', 'Should show HTTP request');
    assertIncludes(html, 'TLS Connections', 'Should show TLS section');
    assertIncludes(html, 'Blocked Connections', 'Should show blocked section');
  });

  test('REPORT: generateHTML with sandbox but no findings', () => {
    const results = {
      target: '/test/path',
      timestamp: '2025-01-01T00:00:00Z',
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0 },
      sandbox: {
        package: 'safe-pkg',
        score: 0,
        severity: 'CLEAN',
        findings: [],
        network: null
      }
    };
    const html = generateHTML(results);
    assertIncludes(html, 'No suspicious behavior', 'Should show clean sandbox message');
  });

  test('REPORT: generateHTML escapes HTML in threat messages', () => {
    const results = {
      target: '/test',
      timestamp: '2025-01-01',
      threats: [
        { severity: 'HIGH', type: 'xss_test', message: '<script>alert("xss")</script>', file: 'bad.js', playbook: '' }
      ],
      summary: { total: 1, critical: 0, high: 1, medium: 0 }
    };
    const html = generateHTML(results);
    assert(!html.includes('<script>alert'), 'Should escape script tags');
    assertIncludes(html, '&lt;script&gt;', 'Should HTML-escape the message');
  });

  // --- saveReport ---

  test('REPORT: saveReport writes HTML file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-test-'));
    const outputPath = path.join(tmpDir, 'report.html');
    const results = {
      target: '/test',
      timestamp: '2025-01-01',
      threats: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0 }
    };
    const ret = saveReport(results, outputPath);
    assert(ret === outputPath, 'Should return output path');
    assert(fs.existsSync(outputPath), 'File should exist');
    const content = fs.readFileSync(outputPath, 'utf8');
    assertIncludes(content, '<!DOCTYPE html>', 'Should contain valid HTML');
    // Cleanup
    try { fs.unlinkSync(outputPath); fs.rmdirSync(tmpDir); } catch {}
  });

  test('REPORT: saveReport throws for invalid path', () => {
    try {
      saveReport({}, null);
      assert(false, 'Should have thrown');
    } catch (e) {
      assertIncludes(e.message, 'Invalid output path', 'Should mention invalid path');
    }
  });

  test('REPORT: saveReport throws for empty string path', () => {
    try {
      saveReport({}, '');
      assert(false, 'Should have thrown');
    } catch (e) {
      assertIncludes(e.message, 'Invalid output path', 'Should mention invalid path');
    }
  });
}

module.exports = { runReportTests };
