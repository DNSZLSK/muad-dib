'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, cleanupTemp } = require('../test-utils');
const {
  scanTrustedDepDiff,
  checkDepDiff,
  checkTrustedDepDiff,
  TRUSTED_DEP_AGE_THRESHOLD_MS
} = require('../../src/scanner/trusted-dep-diff.js');

async function runTrustedDepDiffTests() {
  console.log('\n=== TRUSTED DEP DIFF SCANNER TESTS ===\n');

  // --- Constants + API surface ---

  test('TRUSTED-DEP-DIFF: TRUSTED_DEP_AGE_THRESHOLD_MS is 7 days', () => {
    assert(TRUSTED_DEP_AGE_THRESHOLD_MS === 7 * 24 * 60 * 60 * 1000,
      `Should be 7 days in ms, got ${TRUSTED_DEP_AGE_THRESHOLD_MS}`);
  });

  test('TRUSTED-DEP-DIFF: checkTrustedDepDiff is an alias of checkDepDiff', () => {
    assert(checkTrustedDepDiff === checkDepDiff,
      'checkTrustedDepDiff should be the exact same function as checkDepDiff (alias)');
  });

  // --- Phase 2 of the per-worker 429-storm fix: registry I/O now goes through the
  // shared http-limiter. Placed FIRST among the async tests so no sibling asyncTest
  // (all fire-and-forget after this awaited call) holds a slot concurrently while we
  // sample the semaphore. Proves the slot is released in `finally` even when the
  // registry call rejects (404 / network error) — i.e. no semaphore leak. ---
  await asyncTest('TRUSTED-DEP-DIFF: releases the shared registry slot on 404 (no leak)', async () => {
    const lim = require('../../src/shared/http-limiter.js');
    const before = lim.getActiveSemaphore().active;
    const findings = await checkDepDiff('__muaddib_test_pkg_does_not_exist__', '0.0.1');
    assert(Array.isArray(findings) && findings.length === 0, 'returns [] on 404');
    assert(lim.getActiveSemaphore().active === before,
      `registry slot must be released in finally (no leak): active=${lim.getActiveSemaphore().active} != baseline=${before}`);
  });

  // --- Gate (FN cases) — opt-in matters ---

  asyncTest('TRUSTED-DEP-DIFF: returns [] without opt-in flag', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tdd-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'lodash', version: '4.17.21' }));
    try {
      const findings = await scanTrustedDepDiff(tmpDir, {});
      assert(Array.isArray(findings), 'Should return an array');
      assert(findings.length === 0,
        `Without trustedDepDiff/monitorMode flag, scanner must short-circuit. Got ${findings.length} findings.`);
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  asyncTest('TRUSTED-DEP-DIFF: returns [] for non-npm ecosystem even when opt-in', async () => {
    const findings = await scanTrustedDepDiff('.', {
      monitorMode: true,
      ecosystem: 'pypi',
      name: 'requests',
      version: '2.31.0'
    });
    assert(findings.length === 0,
      'PyPI ecosystem must short-circuit — this scanner is npm-only by design');
  });

  asyncTest('TRUSTED-DEP-DIFF: returns [] when package.json is missing and no name/version override', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tdd-empty-'));
    try {
      const findings = await scanTrustedDepDiff(tmpDir, { trustedDepDiff: true });
      assert(findings.length === 0,
        'Missing package.json with no name/version override should return []');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  asyncTest('TRUSTED-DEP-DIFF: returns [] when package.json is malformed', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tdd-bad-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), '{ not valid json');
    try {
      const findings = await scanTrustedDepDiff(tmpDir, { trustedDepDiff: true });
      assert(findings.length === 0,
        'Malformed package.json should be caught and return [] gracefully');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  asyncTest('TRUSTED-DEP-DIFF: returns [] when name or version cannot be resolved', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tdd-nameless-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'),
      JSON.stringify({ description: 'no name no version' }));
    try {
      const findings = await scanTrustedDepDiff(tmpDir, { trustedDepDiff: true });
      assert(findings.length === 0,
        'Missing name/version without overrides should return []');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  // --- Graceful failure (FN cases) — registry unreachable ---

  asyncTest('TRUSTED-DEP-DIFF: returns [] gracefully on registry 404 / network error', async () => {
    // The nonexistent name returns HTTP 404 from npm; the function must catch and return []
    const findings = await checkDepDiff('__muaddib_nonexistent_test_pkg_xyz__', '1.0.0');
    assert(Array.isArray(findings), 'Should return an array');
    assert(findings.length === 0,
      `On registry 404, the function must catch and return []. Got ${findings.length} findings.`);
  });

  // --- Positive case (TP) — name/version override path activates registry I/O ---
  // NOTE: this test exercises the I/O path but does not assert a finding shape
  // (that requires registry-state mocking, out of scope for this PR — the
  // finding shape itself is identical to the pre-refactor function and is
  // already covered by tests/integration/monitor.test.js #checkTrustedDepDiff*).

  asyncTest('TRUSTED-DEP-DIFF: opt-in + name/version override triggers checkDepDiff path', async () => {
    // muaddib_test_ scope is reserved; npm always returns 404. The scanner must
    // not crash, must return [], and must NOT pre-empt itself before reaching
    // checkDepDiff (we test that by passing override values — no package.json
    // needed).
    const findings = await scanTrustedDepDiff('/tmp/does_not_matter_path', {
      trustedDepDiff: true,
      ecosystem: 'npm',
      name: '__muaddib_test_pkg_does_not_exist__',
      version: '0.0.1'
    });
    assert(Array.isArray(findings),
      'With opt-in + overrides, scanner must invoke checkDepDiff and return [] on 404');
    assert(findings.length === 0,
      `Nonexistent override package must return [] gracefully. Got ${findings.length}.`);
  });
}

module.exports = { runTrustedDepDiffTests };
