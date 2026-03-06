const { run } = require('./src/index.js');

const packages = [
  'next', 'gatsby', 'sails', 'stencil', 'webpack', '@swc/core',
  'vitest', 'jasmine', 'karma', 'knex', 'eslint', 'lerna',
  '@changesets/cli', 'recoil', 'mathjs', 'nodemailer', 'ses', 'jspdf'
];

const CACHE_DIR = '.muaddib-cache/benign-tarballs';
const path = require('path');
const fs = require('fs');

(async () => {
  const results = [];
  for (const pkg of packages) {
    const cacheName = pkg.replace(/\//g, '-').replace(/^@/, '');
    const dir = path.join(CACHE_DIR, cacheName, 'package');
    if (!fs.existsSync(dir)) {
      console.log(`SKIP ${pkg} (not cached)`);
      continue;
    }
    try {
      const result = await run(dir, { _capture: true });
      const score = result.summary.riskScore;
      const flagged = score > 20;
      console.log(`${flagged ? 'FP' : 'OK'}  ${String(score).padStart(3)} ${pkg}`);
      if (flagged) results.push(pkg);
    } catch (e) {
      console.log(`ERR ${pkg}: ${e.message}`);
    }
  }
  console.log(`\n${results.length} FPs remaining: ${results.join(', ')}`);
})();
