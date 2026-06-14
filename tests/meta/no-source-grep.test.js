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

// Étape 4: enforced. The worklist is drained — every remaining structural site is an explicitly
// documented C4 exception in ALLOWLIST below. Any NEW (unlisted) source-grep now fails the suite.
const GUARD_ENFORCED = true;

// Sites permitted to remain structural (documented C4 exceptions). Keyed by `file:line`.
// Each is a structural assertion with NO behavioral equivalent on a host without Docker. The
// behaviorally-testable side of each contract IS converted (e.g. the Node-side docker-args /
// gVisor / canary-env wiring via buildDockerArgs; the memory-pressure + worker-pool decision
// functions; the preload /proc spoofing via the subprocess harness).
//
// NOTE: keyed by line number. If any allowlisted test file is edited, refresh these with:
//   MUADDIB_META_VERBOSE=1 node -e "require('./tests/meta/no-source-grep.test').runNoSourceGrepTests()"
const ALLOWLIST = new Set([
  // ── Bash scripts: executed only inside the Docker sandbox (sandbox-runner.sh) or on the VPS
  // (deploy/auto-update.sh). The script text IS the contract; real coverage is the Docker sandbox
  // integration test, which skips without Docker. No host-runnable behavioral equivalent.
  'tests/integration/sandbox-improvements.test.js:177',
  'tests/integration/sandbox-improvements.test.js:178',
  'tests/integration/sandbox-improvements.test.js:179',
  'tests/integration/sandbox-improvements.test.js:180',
  'tests/integration/sandbox-improvements.test.js:181',
  'tests/integration/sandbox-improvements.test.js:182',
  'tests/integration/sandbox-improvements.test.js:188',
  'tests/integration/sandbox-improvements.test.js:195',
  'tests/integration/sandbox-improvements.test.js:276',
  'tests/integration/sandbox-improvements.test.js:283',
  'tests/integration/sandbox-improvements.test.js:285',
  'tests/integration/sandbox-improvements.test.js:287',
  'tests/integration/sandbox-improvements.test.js:294',
  'tests/integration/sandbox-improvements.test.js:296',
  'tests/integration/sandbox-improvements.test.js:303',
  'tests/integration/sandbox-improvements.test.js:304',
  'tests/integration/sandbox-improvements.test.js:368',
  'tests/integration/sandbox-improvements.test.js:377',
  'tests/integration/sandbox-improvements.test.js:379',
  'tests/integration/sandbox-improvements.test.js:381',
  'tests/sandbox/gvisor.test.js:376',
  'tests/sandbox/gvisor.test.js:377',
  'tests/sandbox/gvisor.test.js:379',
  'tests/sandbox/gvisor.test.js:386',
  'tests/sandbox/gvisor.test.js:387',
  'tests/integration/monitor-memory.test.js:487',
  'tests/integration/monitor-memory.test.js:488',
  'tests/integration/monitor-memory.test.js:490',
  'tests/integration/monitor-memory.test.js:491',
  'tests/integration/monitor-memory.test.js:492',

  // ── Docker container teardown / timeout control-flow: the sandbox kill-ladder (docker kill/rm,
  // force-resolve INCONCLUSIVE) and the timeout branch only execute against a live container.
  'tests/integration/monitor-memory.test.js:631',
  'tests/integration/monitor-memory.test.js:632',
  'tests/sandbox/sandbox.test.js:997',
  'tests/sandbox/sandbox.test.js:998',

  // ── Sandbox report parsing: sandbox/index.js parses real container stdout (lastIndexOf the report
  // delimiter); the report only exists from a Docker run. (Docker-args side is buildDockerArgs-tested.)
  'tests/integration/v266-fixes.test.js:45',

  // ── Daemon-loop integration: auto-relabel after the daily report + ingestion poll() queue-depth
  // backpressure (skip + seq-safety) run inside the long-lived monitor daemon loop. The decision
  // functions they build on are tested behaviorally (computeMemoryPressure, getMemoryPressureLevel,
  // relabelDataset, checkNpmStatus).
  'tests/integration/auto-labeler.test.js:197',
  'tests/integration/auto-labeler.test.js:198',
  'tests/integration/monitor-memory.test.js:78',
  'tests/integration/monitor-memory.test.js:79',
  'tests/integration/monitor-memory.test.js:80',

  // ── Cross-module metadata-cache reuse: npm-registry reuses temporal-analysis's _metadataCache to
  // avoid duplicate registry fetches (perf). A behavioral test is network-coupled/flaky because
  // getPackageMetadata still fetches downloads/author; the cache lifecycle is tested via clearMetadataCache.
  'tests/integration/monitor.test.js:9537',
  'tests/integration/monitor.test.js:9538',

  // ── "Must-not-contain" security/cleanup absence guards: no behavioral way to observe the absence
  // of a never-taken code path. Complements eslint-plugin-security. (No shell exec in the version
  // path; all monitor data-file writes go through atomicWriteFileSync; dead SCANNER_TIMEOUT/SCAN_TIMEOUT
  // stays removed.)
  'tests/integration/gap-remediation.test.js:246',
  'tests/integration/gap-remediation.test.js:247',
  'tests/integration/audit-fixes.test.js:534',
  'tests/integration/v266-fixes.test.js:70',
  'tests/integration/v266-fixes.test.js:71',

  // ── Error-logging hygiene / resource cleanup: debug-gated module-graph error logging (debugLog,
  // no empty catch) and module-graph timer cleanup are not observable without a debug harness; the
  // graph's correct behavior is covered by tests/scanner/module-graph.test.js.
  'tests/integration/audit-fixes.test.js:1195',
  'tests/integration/audit-fixes.test.js:1196',
  'tests/integration/v266-fixes.test.js:53',
]);

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
