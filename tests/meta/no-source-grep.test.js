'use strict';

/**
 * no-source-grep.test.js — guard against the source-grep test anti-pattern.
 *
 * A "structural" test reads an implementation file (src/, bin/, docker/, deploy/) as
 * text and asserts a string is present in it. These tests break on a harmless rename
 * and pass when the logic is broken but the string is kept — so they give false
 * confidence. We are converting them to behavioral tests (see plan: behavioral-tests).
 *
 * MODE (Étape 0 → Étape 4):
 *   - Report mode (current): inventories every structural site, never fails. The list
 *     is the authoritative worklist for the conversion (Étape 3).
 *   - Guard mode (Étape 4): set GUARD_ENFORCED = true. The test then FAILS if any
 *     structural site exists outside ALLOWLIST — preventing the pattern from creeping
 *     back. ALLOWLIST should hold only the documented C4 integration shells that
 *     genuinely cannot be exercised without Docker/process/signal integration.
 */

const path = require('path');
const { test, assert } = require('../test-utils');
const { scanStructuralTests, groupByFile } = require('./structural-test-scanner');

// Flip to true in Étape 4 once the worklist is drained.
const GUARD_ENFORCED = false;

// Sites permitted to remain structural (documented C4 shells). Keyed by `file:line`.
// Empty for now; populated only with justified exceptions when the guard is enforced.
const ALLOWLIST = new Set([]);

function runNoSourceGrepTests() {
  console.log('\n=== META: SOURCE-GREP TEST INVENTORY ===\n');

  const testsRoot = path.join(__dirname, '..');
  const findings = scanStructuralTests(testsRoot);
  const grouped = groupByFile(findings);

  console.log(`  Structural (source-grep) assertions: ${findings.length} across ${grouped.length} files`);
  for (const g of grouped) {
    console.log(`    ${String(g.count).padStart(3)}  ${g.file}`);
  }
  if (process.env.MUADDIB_META_VERBOSE) {
    console.log('\n  --- detail (file:line variable <- target) ---');
    for (const f of findings) {
      console.log(`    ${f.file}:${f.line}  ${f.variable} <- ${f.target}  [${f.kind} ${JSON.stringify(f.substr)}]`);
    }
  }
  console.log('');

  if (GUARD_ENFORCED) {
    // Guard mode: fail on any site not explicitly allowlisted.
    test('META: no new source-grep tests (guard enforced)', () => {
      const offenders = findings.filter(f => !ALLOWLIST.has(`${f.file}:${f.line}`));
      assert(offenders.length === 0,
        `Found ${offenders.length} source-grep assertion(s) outside the allowlist. ` +
        `Test behavior, not source text. First few: ` +
        offenders.slice(0, 5).map(f => `${f.file}:${f.line} (${f.variable})`).join(', '));
    });
  } else {
    // Report mode: never fails; the inventory above is the conversion worklist.
    test('META: source-grep inventory generated (report mode — not yet enforced)', () => {
      assert(Array.isArray(findings), 'scanner should return an array of findings');
      console.log(`  [report mode] ${findings.length} structural sites logged for conversion ` +
        `(Étape 3). Guard activates in Étape 4 (set GUARD_ENFORCED = true).`);
    });
  }
}

module.exports = { runNoSourceGrepTests };
