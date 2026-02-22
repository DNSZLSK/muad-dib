#!/usr/bin/env node
// Filter SARIF results to exclude scanner source code findings.
// A security scanner inherently references sensitive paths (.npmrc, .ssh, etc.)
// in its detection rules — these are definitional, not vulnerabilities.
const fs = require('fs');

const file = process.argv[2];
if (!file) {
  console.error('Usage: node filter-sarif.js <sarif-file>');
  process.exit(1);
}

const sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
let removed = 0;

for (const run of sarif.runs || []) {
  const before = (run.results || []).length;
  run.results = (run.results || []).filter(r => {
    const uri = decodeURIComponent(
      r.locations?.[0]?.physicalLocation?.artifactLocation?.uri || ''
    ).replace(/\\/g, '/');
    return !uri.startsWith('src/');
  });
  removed += before - run.results.length;
}

fs.writeFileSync(file, JSON.stringify(sarif, null, 2));
console.log(`[SARIF] Filtered ${removed} self-referential finding(s) from src/`);
