'use strict';

/**
 * no-orphan-tests.test.js — guard against test files that `npm test` never runs.
 *
 * Test audit 2026-11 found 9 *.test.js files (~110 tests) unreachable from the runners:
 * four written in v2.11.7 and never registered (17 of their 53 tests failed: the features
 * they specify were never implemented), five audit reproducers whose "FIXED" guards
 * protected nothing because they never ran. A test that does not run is worse than no
 * test: it reads as coverage.
 *
 * Rule: every tests/**\/*.test.js must be reachable, through relative require() chains,
 * from tests/run-tests.js (npm test) or tests/run-tests-integration.js (npm run
 * test:integration). Exceptions live in ALLOWLIST, each with its reason; an entry that
 * becomes reachable or disappears must be removed (stale entries fail too).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, assert } = require('../test-utils');

const TESTS_DIR = path.join(__dirname, '..');
const RUNNERS = ['run-tests.js', 'run-tests-integration.js'];
// Data directories: fixtures and samples, never test modules.
const DATA_DIRS = new Set(['samples', 'fixtures', 'malware-samples', 'ground-truth']);

const ALLOWLIST = new Map([
  // Standalone audit reproducers (own runner + process.exit, run by hand): the FIXED guards
  // must be ported into the suite; the reproducers asserting a still-open bug cannot be
  // registered until the bug is fixed (they would lock the bug in).
  ['audit-2026-05/dataflow-findings.test.js', 'standalone audit reproducer, to port'],
  ['audit-2026-05/reachability-findings.test.js', 'standalone audit reproducer, RC-C2/RC-H1..H3 still open'],
  ['audit-2026-05/scoring-critical-findings.test.js', 'standalone audit reproducer, SC-C2.b/SC-C3 still open'],
]);

const toPosix = p => p.split(path.sep).join('/');

function listTestFiles(testsDir) {
  const out = [];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!DATA_DIRS.has(e.name) && e.name !== 'node_modules') walk(p); }
      else if (e.name.endsWith('.test.js')) out.push(toPosix(path.relative(testsDir, p)));
    }
  })(testsDir);
  return out.sort();
}

// Files reachable from the runners through relative require() calls (transitively, so a
// test module registered by a helper still counts).
function reachableFrom(testsDir, runners) {
  const seen = new Set();
  const stack = runners.map(r => path.join(testsDir, r)).filter(f => fs.existsSync(f));
  while (stack.length) {
    const file = stack.pop();
    const rel = toPosix(path.relative(testsDir, file));
    if (seen.has(rel)) continue;
    seen.add(rel);
    let src;
    try { src = fs.readFileSync(file, 'utf8'); } catch { continue; }
    for (const m of src.matchAll(/require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) {
      let target = path.resolve(path.dirname(file), m[1]);
      if (!target.endsWith('.js')) target += '.js';
      if (target.startsWith(testsDir + path.sep) && fs.existsSync(target)) stack.push(target);
    }
  }
  return seen;
}

function findOrphanTestFiles(testsDir, runners = RUNNERS) {
  const reached = reachableFrom(testsDir, runners);
  return listTestFiles(testsDir).filter(f => !reached.has(f));
}

// A runner that requires a test module without ever calling what it imports runs nothing:
// the modules only export run* functions. Reports, per runner, each binding imported from
// a *.test module that is never referenced again, and each bare require of a *.test module.
const TEST_REQUIRE_RE = /(?:const\s+(?:\{([^}]*)\}|([A-Za-z_$][\w$]*))\s*=\s*)?require\(\s*['"](\.{1,2}\/[^'"]*\.test(?:\.js)?)['"]\s*\)\s*;?/g;

function findUncalledTestImports(testsDir, runners = RUNNERS) {
  const out = [];
  for (const runner of runners) {
    const file = path.join(testsDir, runner);
    if (!fs.existsSync(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    const rest = src.replace(TEST_REQUIRE_RE, ' ');
    for (const m of src.matchAll(TEST_REQUIRE_RE)) {
      const names = m[1] !== undefined
        ? m[1].split(',').map(s => s.trim().split(/\s*:\s*/).pop()).filter(Boolean)
        : m[2] ? [m[2]] : [];
      if (names.length === 0) { out.push(`${runner}: bare require('${m[3]}')`); continue; }
      for (const n of names) {
        if (!new RegExp(`(^|[^\\w$])${n.replace(/\$/g, '\\$')}(?![\\w$])`).test(rest)) out.push(`${runner}: ${n} from '${m[3]}'`);
      }
    }
  }
  return out;
}

function runNoOrphanTestsTests() {
  console.log('\n=== META: NO ORPHAN TEST FILES ===\n');

  test('META-ORPHAN: every *.test.js is reachable from a runner (or allowlisted with a reason)', () => {
    const orphans = findOrphanTestFiles(TESTS_DIR).filter(f => !ALLOWLIST.has(f));
    assert(orphans.length === 0,
      `test files never run by npm test / test:integration (register them in tests/run-tests.js): ${orphans.join(', ')}`);
  });

  test('META-ORPHAN: allowlist has no stale entry (file gone or now registered)', () => {
    const orphans = new Set(findOrphanTestFiles(TESTS_DIR));
    const stale = [...ALLOWLIST.keys()].filter(f => !orphans.has(f));
    assert(stale.length === 0, `remove these ALLOWLIST entries, they are no longer orphan: ${stale.join(', ')}`);
  });

  test('META-ORPHAN: detector finds an unregistered file and follows require chains', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-orphan-'));
    try {
      fs.mkdirSync(path.join(root, 'unit'));
      fs.mkdirSync(path.join(root, 'samples'));
      fs.writeFileSync(path.join(root, 'run-tests.js'), "require('./unit/direct.test');\nrequire('./helper');\n");
      fs.writeFileSync(path.join(root, 'helper.js'), "require('./unit/via-helper.test.js');\n");
      fs.writeFileSync(path.join(root, 'unit', 'direct.test.js'), '');
      fs.writeFileSync(path.join(root, 'unit', 'via-helper.test.js'), '');
      fs.writeFileSync(path.join(root, 'unit', 'forgotten.test.js'), '');
      fs.writeFileSync(path.join(root, 'samples', 'fixture.test.js'), ''); // data dir, ignored
      const orphans = findOrphanTestFiles(root, ['run-tests.js']);
      assert(orphans.length === 1 && orphans[0] === 'unit/forgotten.test.js',
        `expected only unit/forgotten.test.js, got ${JSON.stringify(orphans)}`);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('META-ORPHAN: every run* function a runner imports from a test module is called', () => {
    const uncalled = findUncalledTestImports(TESTS_DIR);
    assert(uncalled.length === 0,
      `required but never called, so these tests never run: ${uncalled.join('; ')}`);
  });

  test('META-ORPHAN: detector flags a test module that is required but never called', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-uncalled-'));
    try {
      fs.writeFileSync(path.join(root, 'run-tests.js'), [
        "const { runCalled } = require('./a.test');",
        "const { runForgotten } = require('./b.test');",
        "const { runAliased: runAlias } = require('./c.test');",
        "const runDefault = require('./d.test');",
        "require('./e.test');",
        "const { getCounters } = require('./test-utils');",
        '(async () => {',
        "  await timed('a', runCalled);",
        '  await runAlias();',
        '  runDefault();',
        '})();',
        ''
      ].join('\n'));
      const uncalled = findUncalledTestImports(root, ['run-tests.js']);
      assert(JSON.stringify(uncalled) === JSON.stringify([
        "run-tests.js: runForgotten from './b.test'",
        "run-tests.js: bare require('./e.test')"
      ]), `expected b.test (never called) and e.test (bare require), got ${JSON.stringify(uncalled)}`);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
}

module.exports = { runNoOrphanTestsTests, findOrphanTestFiles, findUncalledTestImports };
