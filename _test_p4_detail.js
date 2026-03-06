const { run } = require('./src/index.js');
const path = require('path');
const fs = require('fs');

const packages = [
  'next', 'gatsby', 'sails', 'webpack', 'jasmine', 'karma', 'knex',
  'eslint', 'lerna', 'recoil', 'mathjs', 'nodemailer', 'ses'
];

const CACHE_DIR = '.muaddib-cache/benign-tarballs';
const SEVERITY_WEIGHTS = { CRITICAL: 25, HIGH: 10, MEDIUM: 3, LOW: 1 };

(async () => {
  for (const pkg of packages) {
    const cacheName = pkg.replace(/\//g, '-').replace(/^@/, '');
    const dir = path.join(CACHE_DIR, cacheName, 'package');
    if (!fs.existsSync(dir)) continue;
    try {
      const result = await run(dir, { _capture: true });
      const score = result.summary.riskScore;
      if (score <= 20) continue; // Only show FPs
      console.log(`\n=== ${pkg} (score: ${score}) ===`);
      console.log(`  maxFile: ${result.summary.maxFileScore}, crossBonus: ${result.summary.crossFileBonus || 0}, pkgScore: ${result.summary.packageScore}`);
      console.log(`  mostSuspicious: ${result.summary.mostSuspiciousFile}`);

      // Group by severity
      const byType = {};
      for (const t of result.threats) {
        const key = `${t.severity}:${t.type}`;
        if (!byType[key]) byType[key] = { severity: t.severity, type: t.type, count: 0, files: new Set(), points: 0 };
        byType[key].count++;
        byType[key].files.add(t.file);
        byType[key].points += SEVERITY_WEIGHTS[t.severity] || 0;
      }

      // Sort by points descending
      const sorted = Object.values(byType).sort((a, b) => b.points - a.points);
      for (const entry of sorted.slice(0, 8)) {
        console.log(`  ${entry.severity.padEnd(8)} ${entry.type.padEnd(30)} x${entry.count} = ${entry.points}pts  files: ${[...entry.files].slice(0, 2).join(', ')}`);
      }
    } catch (e) {
      console.log(`ERR ${pkg}: ${e.message}`);
    }
  }
})();
