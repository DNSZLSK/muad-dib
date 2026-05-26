// Track C — validate: scan every newly added GT sample, compare
// observed risk score with the value annotated in attacks.json.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const attacks = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'ground-truth', 'attacks.json'), 'utf8')).attacks;
const newOnes = attacks.filter(a => /^GT-(068|069|07[0-9]|08[0-3])$/.test(a.id));

const fails = [];
for (const a of newOnes) {
  const dir = path.join(ROOT, 'tests', 'ground-truth', a.sample_dir);
  let out;
  try {
    out = execFileSync('node', [path.join(ROOT, 'bin', 'muaddib.js'), 'scan', dir, '--json'], {
      env: { ...process.env, MUADDIB_NO_REGISTRY_FETCH: '1' },
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (e) {
    out = e.stdout ? e.stdout.toString() : '';
  }
  let s = { riskScore: 0, globalRiskScore: 0 };
  let firedRules = [];
  try {
    const j = JSON.parse(out);
    s = j.summary || s;
    firedRules = [...new Set((j.threats || []).map(t => t.rule_id).filter(Boolean))];
  } catch {}
  const expected = a.expected || {};
  const observed = s.riskScore || 0;
  const passTpr3 = observed >= 3;
  const passTpr20 = observed >= 20;
  const tierTarget = expected.tpr_tier || 'tpr20';
  const meetsTier =
    tierTarget === 'tpr20' ? passTpr20 :
    tierTarget === 'tpr3' ? passTpr3 :
    passTpr3;
  // expected.rules: at least 1 must fire
  const expectedRules = (expected.rules || []);
  const missedRules = expectedRules.filter(r => !firedRules.includes(r));
  const hitAnyExpected = expectedRules.length === 0 || expectedRules.some(r => firedRules.includes(r));

  const status = meetsTier && hitAnyExpected ? 'OK' : 'FAIL';
  const annotatedScore = expected.score_typical;
  const drift = annotatedScore != null ? observed - annotatedScore : null;
  console.log(
    `${status} ${a.id} ${a.ecosystem.padEnd(4)} risk=${String(observed).padStart(3)} (annot=${annotatedScore}, drift=${drift ?? '?'}) tier=${tierTarget}` +
    ` rules-missing=[${missedRules.join(',')}] fired=[${firedRules.join(',')}]`
  );
  if (status === 'FAIL') fails.push({ id: a.id, observed, expected: annotatedScore, missedRules, firedRules });
}

console.log('\nFailed:', fails.length, '/', newOnes.length);
if (fails.length) {
  console.log(JSON.stringify(fails, null, 2));
  process.exit(1);
}
