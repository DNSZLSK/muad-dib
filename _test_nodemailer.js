const { run } = require('./src/index.js');
const path = require('path');

(async () => {
  const dir = path.join('.muaddib-cache/benign-tarballs/nodemailer/package');
  const result = await run(dir, { _capture: true });

  console.log('Score:', result.summary.riskScore);

  // Show all suspicious_dataflow threats with full message
  for (const t of result.threats) {
    if (t.severity !== 'LOW') {
      console.log(`\n${t.severity} ${t.type} [${t.file}]`);
      console.log(`  ${t.message}`);
    }
  }
})();
