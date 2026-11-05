// Audit interne 2026-05-17 - Phase 3 monorepo - Tests reproducteurs.
//
// CONVENTION : tests asserts le comportement APRES fix (Sprint 3).
// - Test PASSE = scanMonorepo emet bien monorepo_detected pour les 4 managers
// - Test ECHOUERA si la detection est retiree ou regressee
//
// Registered in tests/run-tests.js (test audit 2026-11: this file was the only coverage of
// the monorepo scanner and never ran). Still runnable alone:
//   node tests/audit-2026-05/monorepo-findings.test.js
//
// Rapport : muaddib-prompt-docs/archive/audits/2026-05-internal-v2.11.15.md (Phase 3, MR-C1).
//
// Auteur : Claude Opus 4.7 (1M context) sous direction Kewin Poszalski
// Date   : 2026-05-17

const fs = require('fs');
const os = require('os');
const path = require('path');

const { test, getCounters } = require('../test-utils.js');
const { scanMonorepo } = require('../../src/scanner/monorepo.js');

function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || 'assertEq'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// Each test creates its own temp tree and removes it, whatever the outcome.
function withTempDir(filesByRel, fn) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-mr-c1-'));
  try {
    for (const rel of Object.keys(filesByRel)) {
      const abs = path.join(tmp, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, filesByRel[rel]);
    }
    return fn(tmp);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function runAuditMonorepoFindingsTests() {
  console.log('\n=== AUDIT 2026-05 Phase 3 - monorepo - findings ===\n');

  test('MR-C1.a: pkg.workspaces=["packages/*"] -> manager=yarn (FIXED)', () => withTempDir({
    'package.json': JSON.stringify({
      name: 'audit-monorepo-yarn',
      version: '1.0.0',
      workspaces: ['packages/*']
    })
  }, tmp => {
    const threats = scanMonorepo(tmp);
    assertEq(threats.length, 1, `FIXED : 1 threat monorepo_detected attendu, got ${threats.length}`);
    const t = threats[0];
    assertEq(t.type, 'monorepo_detected', 'type=monorepo_detected');
    assertEq(t.severity, 'MEDIUM', 'severity=MEDIUM');
    assertEq(t.manager, 'yarn', 'manager=yarn (npm workspaces share this field)');
    assertEq(t.workspaceCount, 1, 'workspaceCount=1 (le glob compte comme 1 entree)');
    assertEq(t.file, 'package.json', 'file=package.json');
  }));

  test('MR-C1.b: pnpm-workspace.yaml avec 3 packages -> manager=pnpm (FIXED)', () => withTempDir({
    'package.json': JSON.stringify({ name: 'audit-monorepo-pnpm', version: '1.0.0' }),
    'pnpm-workspace.yaml':
`packages:
  - packages/a
  - packages/b
  - apps/web
`
  }, tmp => {
    const threats = scanMonorepo(tmp);
    assertEq(threats.length, 1, `FIXED : 1 threat attendu, got ${threats.length}`);
    const t = threats[0];
    assertEq(t.manager, 'pnpm', 'manager=pnpm');
    assertEq(t.workspaceCount, 3, 'workspaceCount=3 (lignes -)');
    assertEq(t.file, 'pnpm-workspace.yaml', 'file=pnpm-workspace.yaml');
  }));

  test('MR-C1.c: lerna.json {packages:["packages/*","apps/*"]} -> manager=lerna (FIXED)', () => withTempDir({
    'package.json': JSON.stringify({ name: 'audit-monorepo-lerna', version: '1.0.0' }),
    'lerna.json': JSON.stringify({ version: 'independent', packages: ['packages/*', 'apps/*'] })
  }, tmp => {
    const threats = scanMonorepo(tmp);
    assertEq(threats.length, 1, `FIXED : 1 threat attendu, got ${threats.length}`);
    const t = threats[0];
    assertEq(t.manager, 'lerna', 'manager=lerna');
    assertEq(t.workspaceCount, 2, 'workspaceCount=2');
    assertEq(t.file, 'lerna.json', 'file=lerna.json');
  }));

  test('MR-C1.d: turbo.json + pkg.workspaces -> manager=turbo (FIXED)', () => withTempDir({
    'package.json': JSON.stringify({
      name: 'audit-monorepo-turbo',
      version: '1.0.0',
      workspaces: ['apps/*', 'packages/*']
    }),
    'turbo.json': JSON.stringify({ pipeline: { build: {} } })
  }, tmp => {
    const threats = scanMonorepo(tmp);
    assertEq(threats.length, 1, `FIXED : 1 threat attendu, got ${threats.length}`);
    const t = threats[0];
    assertEq(t.manager, 'turbo', 'manager=turbo (turbo.json present + workspaces declares)');
    assertEq(t.workspaceCount, 2, 'workspaceCount=2');
    assertEq(t.file, 'turbo.json', 'file=turbo.json');
  }));

  test('MR-C1.neg: package simple (pas de workspaces) -> 0 threat (FIXED)', () => withTempDir({
    'package.json': JSON.stringify({ name: 'audit-simple-pkg', version: '1.0.0' }),
    'index.js': 'module.exports = 1;'
  }, tmp => {
    const threats = scanMonorepo(tmp);
    assertEq(threats.length, 0, `FIXED : 0 threat sur package simple, got ${threats.length}`);
  }));
}

module.exports = { runAuditMonorepoFindingsTests };

if (require.main === module) {
  runAuditMonorepoFindingsTests();
  const c = getCounters();
  console.log(`\n=== Resultat : ${c.passed} PASS / ${c.failed} FAIL ===`);
  for (const f of c.failures) console.log(`  - ${f.name}: ${f.error}`);
  process.exit(c.failed > 0 ? 1 : 0);
}
