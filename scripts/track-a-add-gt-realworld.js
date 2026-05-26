// Track A — append real-world malware tarballs (verdict=MALWARE from the
// internal security-review benchmark in data/all-review-results.json) to
// the ground truth. Each new entry: ecosystem npm, year 2026, sample_dir
// pointing at the extracted package/, description seeded from the review
// `reasoning`, expected.score_typical measured by scanning the extracted
// sample.
//
// Usage:
//   node scripts/track-a-add-gt-realworld.js <gt-id> <sample-dir-name> [<key=value>...]
//
// Looks up `package@version` in all-review-results.json by combining the
// sample-dir-name with the version found in package.json. Optional
// key=value pairs override defaults (severity, vector, etc.).

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const ATTACKS = path.join(ROOT, 'tests', 'ground-truth', 'attacks.json');
const REVIEWS = path.join(ROOT, 'data', 'all-review-results.json');

const [gtId, sampleDir, ...overrides] = process.argv.slice(2);
if (!gtId || !sampleDir) {
  console.error('Usage: node scripts/track-a-add-gt-realworld.js <gt-id> <sample-dir-name> [key=value ...]');
  process.exit(2);
}

const fullSampleDir = path.join(ROOT, 'tests', 'ground-truth', 'samples', sampleDir);
if (!fs.existsSync(fullSampleDir)) {
  console.error('sample dir not found:', fullSampleDir);
  process.exit(2);
}

const pkg = JSON.parse(fs.readFileSync(path.join(fullSampleDir, 'package.json'), 'utf8'));
const reviewData = JSON.parse(fs.readFileSync(REVIEWS, 'utf8'));
const reviewKey = `${pkg.name}@${pkg.version}`;
const review = reviewData.results.find(r => r.package === reviewKey);

// Scan to capture score + rules
let scanOut;
try {
  scanOut = execFileSync('node', [path.join(ROOT, 'bin', 'muaddib.js'), 'scan', fullSampleDir, '--json'], {
    env: { ...process.env, MUADDIB_NO_REGISTRY_FETCH: '1' },
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
} catch (e) { scanOut = e.stdout ? e.stdout.toString() : ''; }
const j = JSON.parse(scanOut);
const riskScore = (j.summary && j.summary.riskScore) || 0;
const firedRules = [...new Set((j.threats || []).map(t => t.rule_id).filter(Boolean))];
const severities = [...new Set((j.threats || []).map(t => t.severity).filter(Boolean))];
const tier = riskScore >= 20 ? 'tpr20' : 'tpr3';

// Default field values (overridable via CLI key=value)
const defaults = {
  severity: severities.includes('CRITICAL') ? 'CRITICAL' : (severities.includes('HIGH') ? 'HIGH' : 'MEDIUM'),
  vector: ['real_world_2026', 'security_review_verified'],
  mitre: ['T1195.002', 'T1059.007'],
  scanners: ['package', 'ast'],
};
for (const ov of overrides) {
  const [k, ...vparts] = ov.split('=');
  const v = vparts.join('=');
  if (k === 'vector' || k === 'mitre' || k === 'scanners') defaults[k] = v.split(',');
  else defaults[k] = v;
}

const entry = {
  id: gtId,
  name: pkg.name,
  version: pkg.version,
  ecosystem: 'npm',
  year: 2026,
  vector: defaults.vector,
  severity: defaults.severity,
  description: review
    ? `Real-world malware (security-review verdict: ${review.verdict}, ${review.review_type}, ${review.day}). ${review.reasoning.slice(0, 800)}`
    : `Real-world npm tarball — verdict not in review benchmark (likely post-2026-05-24 or out-of-scope). Manual annotation required.`,
  source: 'data/all-review-results.json (' + reviewData.meta.period + ')' + (review ? ' — verdict ' + review.verdict : ''),
  mitre: defaults.mitre,
  sample_dir: `samples/${sampleDir}/`,
  expected: {
    min_threats: 1,
    rules: firedRules.slice(0, 6),
    severities: severities,
    scanners: defaults.scanners,
    score_typical: riskScore,
    tpr_tier: tier,
  },
};

const data = JSON.parse(fs.readFileSync(ATTACKS, 'utf8'));
if (data.attacks.some(a => a.id === gtId)) {
  console.error('GT id already exists:', gtId);
  process.exit(2);
}
data.attacks.push(entry);
fs.writeFileSync(ATTACKS, JSON.stringify(data, null, 2) + '\n', 'utf8');
console.log('added', gtId, '→', pkg.name + '@' + pkg.version, 'risk=' + riskScore, 'tier=' + tier, 'rules=' + firedRules.length);
