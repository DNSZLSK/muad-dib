// Track C helper: scan each PYSRC/PYAST fixture and emit score + distinct rule IDs.
// Used to pick which fixtures to promote into the ground truth.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const FIXTURE_DIRS = [
  path.join(ROOT, 'tests', 'samples', 'python-source'),
  path.join(ROOT, 'tests', 'samples', 'python-ast'),
];

const rows = [];
for (const baseDir of FIXTURE_DIRS) {
  const family = path.basename(baseDir);
  for (const name of fs.readdirSync(baseDir).sort()) {
    const fp = path.join(baseDir, name);
    if (!fs.statSync(fp).isDirectory()) continue;
    let out;
    try {
      out = execFileSync('node', [path.join(ROOT, 'bin', 'muaddib.js'), 'scan', fp, '--json'], {
        env: { ...process.env, MUADDIB_NO_REGISTRY_FETCH: '1' },
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (e) {
      // muaddib exits non-zero when threats found; capture stdout anyway
      out = e.stdout ? e.stdout.toString() : '';
    }
    let score = 0;
    let globalScore = 0;
    let maxFileScore = 0;
    let rules = [];
    try {
      const j = JSON.parse(out);
      const s = j.summary || {};
      score = s.riskScore || 0;
      globalScore = s.globalRiskScore || 0;
      maxFileScore = s.maxFileScore || 0;
      const threats = j.threats || [];
      const set = new Set();
      for (const t of threats) {
        const id = t.rule_id || t.ruleId || t.rule || t.id || t.type || '';
        if (id) set.add(id);
      }
      rules = [...set];
    } catch (e) {
      rules = ['<parse-error>'];
    }
    rows.push({ family, name, score, globalScore, maxFileScore, rules });
    const scoreCol = String(score).padStart(3);
    const gCol = String(globalScore).padStart(3);
    process.stderr.write(`[risk=${scoreCol} global=${gCol}] ${family}/${name} → ${rules.slice(0, 4).join(', ')}${rules.length > 4 ? ` (+${rules.length - 4})` : ''}\n`);
  }
}

console.log(JSON.stringify(rows, null, 2));
