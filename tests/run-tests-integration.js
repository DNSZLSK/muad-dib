const { getCounters } = require('./test-utils');

// Slow integration tests that scan real malware samples
// These are excluded from `npm test` because they take 20+ minutes.
// Run via: npm run test:integration

const { runGroundTruthTests } = require('./integration/ground-truth.test');
const { runEvaluateTests } = require('./integration/evaluate.test');

(async () => {
  const start = Date.now();

  console.log('Running integration tests (ground truth + evaluate)...\n');

  await runGroundTruthTests();
  await runEvaluateTests();

  // Results
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  const { passed, failed, skipped, failures } = getCounters();

  console.log('\n========================================');
  console.log(`INTEGRATION: ${passed} passed, ${failed} failed, ${skipped} skipped (${elapsed}s)`);
  console.log('========================================\n');

  if (failures.length > 0) {
    console.log('Failures:');
    failures.forEach(f => {
      console.log(`  - ${f.name}: ${f.error}`);
    });
    console.log('');
  }

  process.exit(failed > 0 ? 1 : 0);
})();
