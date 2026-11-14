'use strict';

/**
 * rule-test-coverage.test.js - every detection rule is named by at least one test.
 *
 * CLAUDE.md: "Chaque nouveau pattern doit avoir un test positif ET un test negatif".
 * This meta-test checks the machine-checkable half: each rule type in RULES and
 * PARANOID_RULES appears as a string literal in at least one test file. A rule nobody
 * names can be broken, weakened or deleted without any test noticing.
 *
 * It is a ratchet: the rules that have no named test today are listed in
 * KNOWN_UNTESTED with the reason; a NEW rule without a test fails, and an entry that
 * becomes tested (or whose rule is removed) fails too until it is deleted from the list.
 *
 * Not checked here, on purpose: negative tests. Measured 2026-11-13, a static search
 * for "absence" assertions found 38 of 239 named rules, while rules such as
 * lifecycle_script clearly have negative tests written over several lines or through
 * helpers. A static check would be wrong both ways. The sound evidence for negative
 * tests is mutation testing (a mutant that makes a rule over-fire must be killed);
 * that belongs to the scoring/test-audit harness (architecture lot 4).
 */

const fs = require('fs');
const path = require('path');
const { test, assert } = require('../test-utils');
const { RULES, PARANOID_RULES } = require('../../src/rules/index.js');

const TESTS_DIR = path.join(__dirname, '..');
const DATA_DIRS = new Set(['samples', 'fixtures', 'malware-samples', 'ground-truth', 'node_modules']);
const SELF = path.basename(__filename);

// Rules with no named test on 2026-11-13. Each entry is debt: write the test, then
// delete the entry (the stale-entry check below enforces it).
const KNOWN_UNTESTED = new Map([
  // package.js lifecycle-script patterns: exercised by fixture scans whose assertions
  // check other types or counts, never these names.
  ['curl_pipe_sh', 'package.js lifecycle pattern, no named assertion'],
  ['wget_pipe_sh', 'package.js lifecycle pattern, no named assertion'],
  ['npmrc_access', 'package.js lifecycle pattern, no named assertion'],
  ['github_token_access', 'package.js lifecycle pattern, no named assertion'],
  ['aws_credential_access', 'package.js lifecycle pattern, no named assertion'],
  ['base64_encoding', 'package.js lifecycle pattern, no named assertion'],
  // shell.js patterns.
  ['wget_chmod_exec', 'shell.js pattern, no named assertion'],
  ['netcat_shell', 'shell.js pattern, no named assertion'],
  ['shred_home', 'shell.js pattern, no named assertion'],
  ['curl_exfiltration', 'shell.js pattern, no named assertion'],
  ['ssh_access', 'shell.js pattern, no named assertion'],
  ['python_reverse_shell', 'shell.js pattern, no named assertion'],
  ['perl_reverse_shell', 'shell.js pattern, no named assertion'],
  ['fifo_reverse_shell', 'shell.js pattern, no named assertion'],
  // AST detectors.
  ['ide_persistence', 'ast-detectors (call-expression / post-walk), no named assertion'],
  ['shared_memory_ipc', 'ast-detectors post-walk, no named assertion'],
  ['udp_exfiltration', 'ast-detectors post-walk, no named assertion'],
  ['crontab_systemd_write', 'ast-detectors call-expression, no named assertion'],
  ['module_internals_hijack', 'ast-detectors assignment-expression, no named assertion'],
  ['callback_exec_rce', 'ast-detectors call-expression + sandbox compound trigger, no named assertion'],
  // Scoring-level and sandbox compound triggers.
  ['isolated_suspicious_file', 'emitted by scoring.js, no named assertion'],
  ['deep_suspicious_file', 'emitted by scoring.js, no named assertion'],
  ['lifecycle_script_dependency', 'sandbox compound trigger, no named assertion'],
  // Docker sandbox: built as 'sandbox_' + finding.type (pipeline/processor.js); only a
  // Docker run produces them, and the suite skips Docker tests on hosts without it.
  ['sandbox_sensitive_file_read', 'Docker sandbox only (sandbox_ + finding type)'],
  ['sandbox_sensitive_file_write', 'Docker sandbox only (sandbox_ + finding type)'],
  ['sandbox_suspicious_filesystem', 'Docker sandbox only (sandbox_ + finding type)'],
  ['sandbox_suspicious_dns', 'Docker sandbox only (sandbox_ + finding type)'],
  ['sandbox_suspicious_process', 'Docker sandbox only (sandbox_ + finding type)'],
  ['sandbox_unknown_process', 'Docker sandbox only (sandbox_ + finding type)'],
  ['sandbox_timeout', 'Docker sandbox only (sandbox_ + finding type)'],
  // Paranoid mode.
  ['network_access', 'paranoid rule, no named assertion'],
  ['sensitive_file_access', 'paranoid rule, no named assertion']
]);

function testSources(dir) {
  const out = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { if (!DATA_DIRS.has(e.name)) walk(p); }
      else if (e.name.endsWith('.js') && e.name !== SELF) out.push(fs.readFileSync(p, 'utf8'));
    }
  })(dir);
  return out.join('\n');
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isNamed(src, type) {
  return new RegExp(`['"\`]${escapeRe(type)}['"\`]`).test(src);
}

function allRuleTypes() {
  return [...Object.keys(RULES), ...Object.keys(PARANOID_RULES || {})];
}

function runRuleTestCoverageTests() {
  console.log('\n=== META: EVERY RULE IS NAMED BY A TEST ===\n');
  const src = testSources(TESTS_DIR);
  const types = allRuleTypes();

  test('META-RULES: every rule type is named by at least one test (or listed as known debt)', () => {
    const missing = types.filter(t => !isNamed(src, t) && !KNOWN_UNTESTED.has(t));
    assert(missing.length === 0,
      `${missing.length} rule(s) with no test naming them: ${missing.join(', ')}. ` +
      'Add a positive test that asserts the type (and a negative one), or, only for an existing gap, a KNOWN_UNTESTED entry with its reason.');
  });

  test('META-RULES: KNOWN_UNTESTED has no stale entry', () => {
    const all = new Set(types);
    const stale = [...KNOWN_UNTESTED.keys()].filter(t => !all.has(t) || isNamed(src, t));
    assert(stale.length === 0,
      `stale KNOWN_UNTESTED entries (rule removed, or now named by a test): ${stale.join(', ')}. Delete them.`);
  });

  test('META-RULES: the detector sees a named rule and misses an unnamed one', () => {
    assert(isNamed("assert(r.threats.some(t => t.type === 'env_access'))", 'env_access'), 'single quotes');
    assert(isNamed('hasType(r, "env_access")', 'env_access'), 'double quotes');
    assert(!isNamed("const x = 'env_access_extra';", 'env_access'), 'a longer name is not a match');
    assert(!isNamed('// env_access is mentioned in a comment', 'env_access'), 'unquoted mention is not a test');
  });
}

module.exports = { runRuleTestCoverageTests, KNOWN_UNTESTED };
