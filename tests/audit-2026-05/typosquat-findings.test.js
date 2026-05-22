// AUDIT 2026-05 Phase 2 — typosquat scanner — findings repro.
// Run: node tests/audit-2026-05/typosquat-findings.test.js
//
// RT-C1 (Critical) — typosquat scanner did not catch boundary-squat sub-dependencies
// like `plain-crypto-js` (Axios UNC1069 March 2026). Audit fixture
// `tests/samples/red-team-2026/4-axios-unc1069` previously scored 3 LOW
// (only lifecycle_script fired). After fix, must escalate to >= 35 HIGH and the
// compound `dependency_typosquat_require` must fire CRITICAL.

if (!process.env.MUADDIB_NO_REGISTRY_FETCH) {
  process.env.MUADDIB_NO_REGISTRY_FETCH = '1';
}

const path = require('path');
const { asyncTest, assert, runScanDirect, getCounters } = require('../test-utils.js');

async function run() {
  console.log('=== AUDIT 2026-05 Phase 2 - typosquat scanner - findings ===\n');
  console.log("Chaque test asserts le comportement APRES fix (FIXED). PASS aujourd'hui = correction prouvee.\n");

  // ────────────────────────────────────────────────────────────────────────
  // RT-C1 - typosquat scanner extended to detect boundary-squat sub-dependencies
  // ────────────────────────────────────────────────────────────────────────
  console.log('--- RT-C1: dependency boundary-squat (Axios UNC1069 March 2026) ---');

  await asyncTest('RT-C1.a: 4-axios-unc1069 fixture → dependency_typosquat HIGH + _used MEDIUM + compound CRITICAL (FIXED)', async () => {
    const fixture = path.resolve(__dirname, '..', 'samples', 'red-team-2026', '4-axios-unc1069');
    const result = await runScanDirect(fixture);

    const types = (result.threats || []).map(t => t.type);
    assert(types.includes('dependency_typosquat'),
      `FIXED : dependency_typosquat HIGH doit etre emis. Types: ${JSON.stringify(types)}`);
    assert(types.includes('dependency_typosquat_used'),
      `FIXED : dependency_typosquat_used MEDIUM doit etre emis (require/import dans bootstrap.js). Types: ${JSON.stringify(types)}`);
    assert(types.includes('dependency_typosquat_require'),
      `FIXED : compound dependency_typosquat_require CRITICAL doit firer. Types: ${JSON.stringify(types)}`);

    const compound = result.threats.find(t => t.type === 'dependency_typosquat_require');
    assert(compound.severity === 'CRITICAL',
      `FIXED : compound severity doit etre CRITICAL, got ${compound.severity}`);

    // Score gate: previous fixture state was 3 LOW (silent — under webhook P1 = 35).
    // After fix, MUST be HIGH+ with score >= 35 so production alerts fire.
    const score = result.summary && result.summary.riskScore;
    const level = result.summary && result.summary.riskLevel;
    assert(score >= 35,
      `FIXED : riskScore doit etre >= 35 (etait 3 LOW avant fix). Got ${score}.`);
    assert(level === 'HIGH' || level === 'CRITICAL',
      `FIXED : riskLevel doit etre HIGH ou CRITICAL. Got ${level} (score ${score}).`);
  });

  await asyncTest('RT-C1.b: react-router (benign boundary token) → pas de dependency_typosquat (no FP)', async () => {
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-rt-c1-fp-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      name: 'benign-app',
      version: '1.0.0',
      dependencies: { 'react-router': '^6.0.0', 'lodash-es': '^4.0.0', 'babel-core': '^6.0.0' }
    }));
    try {
      const result = await runScanDirect(tmpDir);
      const types = (result.threats || []).map(t => t.type);
      assert(!types.includes('dependency_typosquat'),
        `FIXED : LEGIT_BOUNDARY_TOKENS doit filtrer react-router/lodash-es/babel-core. Threats: ${JSON.stringify(types)}`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('RT-C1.c: pure declared dep typosquat sans require → dependency_typosquat fire, mais PAS le compound', async () => {
    const fs = require('fs');
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-rt-c1-decl-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      name: 'declared-only',
      version: '1.0.0',
      dependencies: { 'plain-crypto-js': '*' }
    }));
    // No source file with require → no dependency_typosquat_used → compound shouldn't fire
    try {
      const result = await runScanDirect(tmpDir);
      const types = (result.threats || []).map(t => t.type);
      assert(types.includes('dependency_typosquat'),
        `FIXED : dependency_typosquat doit firer meme sans require. Types: ${JSON.stringify(types)}`);
      assert(!types.includes('dependency_typosquat_require'),
        `FIXED : compound NE doit PAS firer sans require evidence. Types: ${JSON.stringify(types)}`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  const c = getCounters();
  console.log('');
  console.log(`=== Resultat : ${c.passed} PASS / ${c.failed} FAIL ===`);
  if (c.failed > 0) {
    console.log('\nFAILURES :');
    for (const f of c.failures) {
      console.log(`  - ${f.name}: ${f.error}`);
    }
    process.exit(1);
  }
}

run().catch(e => {
  console.error('Erreur fatale :', e);
  process.exit(1);
});
