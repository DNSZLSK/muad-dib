const { run } = require('./src/index.js');
const path = require('path');

(async () => {
  const dir = path.join('datasets/adversarial/ai-agent-weaponization');
  const result = await run(dir, { _capture: true });
  console.log('Score:', result.summary.riskScore);
  console.log('MaxFile:', result.summary.maxFileScore, 'Pkg:', result.summary.packageScore);
  for (const t of result.threats) {
    console.log(`  ${t.severity.padEnd(8)} ${t.type.padEnd(30)} ${(t.file || '').substring(0, 50)}`);
  }
})();
