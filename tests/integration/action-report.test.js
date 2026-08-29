/**
 * GitHub Action reporter tests (scripts/action-report.cjs).
 *
 * The composite action (action.yml) runs a single `muaddib scan --json`, then
 * feeds the result file to this reporter, which writes the step's machine
 * outputs ($GITHUB_OUTPUT) and prints a human summary. These tests exercise the
 * reporter as a subprocess (behavior, not source text) with a temp
 * GITHUB_OUTPUT file, so they are independent of the runner's git/env state.
 *
 * Covers: positive (threats parsed + counted), clean (zeros), and the two
 * crash-resilience paths the action depends on (missing file, malformed JSON)
 * — a scanner crash must degrade to zeros, never to a reporter crash.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');
const { test, assert } = require('../test-utils');

const REPORTER = path.join(__dirname, '..', '..', 'scripts', 'action-report.cjs');

// Run the reporter against a JSON payload (object) written to a temp file, with
// GITHUB_OUTPUT pointed at a second temp file. Returns { outputs, code, stdout }.
function runReporter(payload, { writeRaw = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-action-report-'));
  const resultFile = path.join(dir, 'result.json');
  const outFile = path.join(dir, 'gh_output.txt');
  try {
    if (writeRaw !== null) {
      if (writeRaw !== 'MISSING') fs.writeFileSync(resultFile, writeRaw);
    } else {
      fs.writeFileSync(resultFile, JSON.stringify(payload));
    }
    fs.writeFileSync(outFile, '');

    let code = 0;
    let stdout = '';
    try {
      stdout = execFileSync('node', [REPORTER, resultFile], {
        env: { ...process.env, GITHUB_OUTPUT: outFile },
        encoding: 'utf8'
      });
    } catch (e) {
      code = e.status == null ? 1 : e.status;
      stdout = (e.stdout || '').toString();
    }

    const outputs = Object.create(null);
    for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
      const eq = line.indexOf('=');
      if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
    }
    return { outputs, code, stdout };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ok */ }
  }
}

function runActionReportTests() {
  console.log('\n=== ACTION REPORTER TESTS ===\n');

  test('ACTREP-01: threats result → correct severity-broken-down outputs', () => {
    const payload = {
      threats: [
        { severity: 'critical', type: 'remote_code_load', file: 'a.js', line: 3 },
        { severity: 'high', type: 'env_access', file: 'a.js' },
        { severity: 'high', type: 'sensitive_string', file: 'b.js' },
        { severity: 'medium', type: 'dangerous_call_function', file: 'b.js' },
        { severity: 'low', type: 'suspicious_dataflow', file: 'c.js' }
      ],
      summary: { riskScore: 100, riskLevel: 'CRITICAL', critical: 1, high: 2, medium: 1, low: 1 }
    };
    const { outputs, code } = runReporter(payload);
    assert(code === 0, `reporter must exit 0, got ${code}`);
    assert(outputs.risk_score === '100', `risk_score=100 expected, got ${outputs.risk_score}`);
    assert(outputs.risk_level === 'CRITICAL', `risk_level=CRITICAL expected, got ${outputs.risk_level}`);
    // The bug this replaces: grep '"threats":[' always reported 1. Real count is 5.
    assert(outputs.threats_count === '5', `threats_count=5 expected, got ${outputs.threats_count}`);
    assert(outputs.critical_count === '1', `critical_count=1 expected, got ${outputs.critical_count}`);
    assert(outputs.high_count === '2', `high_count=2 expected, got ${outputs.high_count}`);
  });

  test('ACTREP-02: clean result → all-zero outputs, SAFE level', () => {
    const payload = { threats: [], summary: { riskScore: 0, riskLevel: 'SAFE', critical: 0, high: 0, medium: 0, low: 0 } };
    const { outputs, code } = runReporter(payload);
    assert(code === 0, `reporter must exit 0, got ${code}`);
    assert(outputs.risk_score === '0', `risk_score=0 expected, got ${outputs.risk_score}`);
    assert(outputs.threats_count === '0', `threats_count=0 expected, got ${outputs.threats_count}`);
    assert(outputs.risk_level === 'SAFE', `risk_level=SAFE expected, got ${outputs.risk_level}`);
  });

  test('ACTREP-03: missing result file → zeros, exit 0 (scanner-crash resilience)', () => {
    const { outputs, code } = runReporter(null, { writeRaw: 'MISSING' });
    assert(code === 0, `reporter must not crash on missing file, got exit ${code}`);
    assert(outputs.risk_score === '0', `risk_score=0 expected, got ${outputs.risk_score}`);
    assert(outputs.threats_count === '0', `threats_count=0 expected, got ${outputs.threats_count}`);
    assert(outputs.risk_level === 'UNKNOWN', `risk_level=UNKNOWN expected, got ${outputs.risk_level}`);
  });

  test('ACTREP-04: malformed JSON → zeros, exit 0 (truncated-output resilience)', () => {
    const { outputs, code } = runReporter(null, { writeRaw: '{"threats":[{"sev' });
    assert(code === 0, `reporter must not crash on malformed JSON, got exit ${code}`);
    assert(outputs.risk_score === '0', `risk_score=0 expected, got ${outputs.risk_score}`);
    assert(outputs.threats_count === '0', `threats_count=0 expected, got ${outputs.threats_count}`);
  });

  test('ACTREP-05: threat list is capped so a huge result cannot flood the log', () => {
    const threats = [];
    for (let i = 0; i < 200; i++) threats.push({ severity: 'high', type: 'env_access', file: `f${i}.js` });
    const payload = { threats, summary: { riskScore: 100, riskLevel: 'CRITICAL', critical: 0, high: 200, medium: 0, low: 0 } };
    const { outputs, stdout } = runReporter(payload);
    assert(outputs.threats_count === '200', `threats_count=200 expected, got ${outputs.threats_count}`);
    assert(stdout.includes('and 175 more'), 'expected the "… and 175 more" cap line for 200 threats');
  });

  test('ACTREP-06: threats result prints a prefilled FP-report issue URL', () => {
    const payload = {
      target: 'node_modules/some-pkg',
      threats: [{ severity: 'high', type: 'env_access', file: 'index.js', line: 2 }],
      summary: { riskScore: 40, riskLevel: 'HIGH', critical: 0, high: 1, medium: 0, low: 0 }
    };
    const { stdout } = runReporter(payload);
    assert(stdout.includes('false positive? Report it'), 'expected the FP-report prompt line');
    assert(stdout.includes('github.com/DNSZLSK/muad-dib/issues/new'), 'expected a prefilled issue URL on the scanner repo');
    assert(stdout.includes('labels=false-positive'), 'expected the false-positive label in the URL');
    // The package name and fired rule must be carried into the prefill for triage.
    assert(stdout.includes('some-pkg'), 'expected scanned package name in the issue title');
    assert(stdout.includes('env_access'), 'expected the fired rule type in the prefilled body');
  });

  test('ACTREP-07: clean result prints no FP-report URL (nothing to dispute)', () => {
    const payload = { target: '.', threats: [], summary: { riskScore: 0, riskLevel: 'SAFE', critical: 0, high: 0, medium: 0, low: 0 } };
    const { stdout } = runReporter(payload);
    assert(!stdout.includes('issues/new'), 'clean scans must not print an FP-report URL');
  });
}

module.exports = { runActionReportTests };
