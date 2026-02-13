const { getCounters } = require('./test-utils');

// Scanner tests
const { runAstTests } = require('./scanner/ast.test');
const { runShellTests } = require('./scanner/shell.test');
const { runObfuscationTests } = require('./scanner/obfuscation.test');
const { runDataflowTests } = require('./scanner/dataflow.test');
const { runPackageTests } = require('./scanner/package.test');
const { runTyposquatTests } = require('./scanner/typosquat.test');
const { runDependencyTests } = require('./scanner/dependency.test');
const { runHashTests } = require('./scanner/hash.test');
const { runEntropyTests } = require('./scanner/entropy.test');
const { runPythonTests } = require('./scanner/python.test');

// IOC tests
const { runUpdaterTests } = require('./ioc/updater.test');

// Report tests
const { runWebhookTests } = require('./report/webhook.test');

// Sandbox tests
const { runSandboxTests } = require('./sandbox/sandbox.test');

// Integration tests
const { runCliTests } = require('./integration/cli.test');
const { runMonitorTests } = require('./integration/monitor.test');

// Temporal analysis tests
const { runTemporalAnalysisTests } = require('./temporal/temporal-analysis.test');
const { runTemporalAstDiffTests } = require('./temporal/temporal-ast-diff.test');

(async () => {
  // Run all test suites sequentially to preserve output ordering
  await runAstTests();
  await runShellTests();
  await runObfuscationTests();
  await runDataflowTests();
  await runPackageTests();
  await runTyposquatTests();
  await runCliTests();
  await runUpdaterTests();
  await runDependencyTests();
  await runHashTests();
  await runWebhookTests();
  await runPythonTests();
  await runSandboxTests();
  await runEntropyTests();
  await runMonitorTests();
  await runTemporalAnalysisTests();
  await runTemporalAstDiffTests();

  // Results
  const { passed, failed, skipped, failures } = getCounters();

  console.log('\n========================================');
  console.log(`RESULTS: ${passed} passed, ${failed} failed, ${skipped} skipped`);
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
