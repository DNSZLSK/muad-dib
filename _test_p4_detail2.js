const { run } = require('./src/index.js');
const path = require('path');
const fs = require('fs');

const packages = ['next', 'webpack', 'jasmine', 'knex', 'eslint', 'lerna', 'nodemailer'];
const CACHE_DIR = '.muaddib-cache/benign-tarballs';

(async () => {
  for (const pkg of packages) {
    const cacheName = pkg.replace(/\//g, '-').replace(/^@/, '');
    const dir = path.join(CACHE_DIR, cacheName, 'package');
    if (!fs.existsSync(dir)) continue;
    try {
      const result = await run(dir, { _capture: true });
      const score = result.summary.riskScore;
      console.log(`\n=== ${pkg} (score: ${score}) ===`);
      console.log(`  maxFile: ${result.summary.maxFileScore}, crossBonus: ${result.summary.crossFileBonus || '(not in summary)'}, pkgScore: ${result.summary.packageScore}`);
      console.log(`  mostSuspicious: ${result.summary.mostSuspiciousFile}`);

      // Show high-value threats (MEDIUM+)
      const highValue = result.threats.filter(t => t.severity !== 'LOW');
      for (const t of highValue) {
        console.log(`  ${t.severity.padEnd(8)} ${t.type.padEnd(30)} ${(t.file || '').substring(0, 60)}`);
      }
      // Count LOWs
      const lowCount = result.threats.filter(t => t.severity === 'LOW').length;
      console.log(`  + ${lowCount} LOW threats`);
    } catch (e) {
      console.log(`ERR ${pkg}: ${e.message}`);
    }
  }
})();
