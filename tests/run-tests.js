const { getCounters } = require('./test-utils');

// Scanner tests (fast — pure unit tests, no process spawns)
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
const { runAIConfigTests } = require('./scanner/ai-config.test');
const { runDeobfuscateTests } = require('./scanner/deobfuscate.test');
const { runModuleGraphTests } = require('./scanner/module-graph.test');
const { runReachabilityTests } = require('./scanner/reachability.test');
const { runGitHubActionsTests } = require('./scanner/github-actions.test');
const { runNpmRegistryTests } = require('./scanner/npm-registry.test');
const { runAstNegativeTests } = require('./scanner/ast-negative.test');
const { runAstBypassRegressionTests } = require('./scanner/ast-bypass-regression.test');
const { runIntentGraphTests } = require('./scanner/intent-graph.test');

// Utility tests
const { runUtilsTests } = require('./utils.test');

// IOC tests
const { runUpdaterTests } = require('./ioc/updater.test');
const { runScraperTests } = require('./ioc/scraper.test');

// Report tests
const { runWebhookTests } = require('./report/webhook.test');

// Sandbox tests
const { runSandboxTests } = require('./sandbox/sandbox.test');
const { runGvisorTests } = require('./sandbox/gvisor.test');
const { runPreloadTests } = require('./unit/preload.test');
const { runMLFeatureExtractorTests } = require('./unit/ml-feature-extractor.test');
const { runMLClassifierTests } = require('./unit/ml-classifier.test');
const { runLlmDetectiveTests } = require('./unit/llm-detective.test');
const { runTarballArchiveTests } = require('./unit/tarball-archive.test');
const { runSandboxPreloadTests } = require('./integration/sandbox-preload.test');

// Integration tests (fast subset — CLI, monitor, diff)
const { runCliTests } = require('./integration/cli.test');
const { runMonitorTests } = require('./integration/monitor.test');
const { runDiffTests } = require('./integration/diff.test');
const { runOutputFormatterTests } = require('./integration/output-formatter.test');
const { runSafeInstallTests } = require('./integration/safe-install.test');
const { runDownloadTests } = require('./integration/download.test');
const { runDaemonWatchTests } = require('./integration/daemon-watch.test');
const { runReportTests } = require('./integration/report.test');
const { runHooksInitTests } = require('./integration/hooks-init.test');
const { runSarifTests } = require('./integration/sarif.test');
const { runAuditFixTests } = require('./integration/audit-fixes.test');
const { runScoringHardeningTests } = require('./integration/scoring-hardening.test');
const { runGroundTruthSmokeTests } = require('./integration/ground-truth-smoke.test');
const { runV266FixesTests } = require('./integration/v266-fixes.test');
const { runEvaluationSmokeTests } = require('./integration/evaluation-smoke.test');
const { runCompoundScoringTests } = require('./integration/compound-scoring.test');
const { runGapRemediationTests } = require('./integration/gap-remediation.test');
const { runConfigTests } = require('./integration/config.test');
const { runBenignRandomTests } = require('./integration/benign-random.test');
const { runAuditV2RemediationTests } = require('./integration/audit-v2-remediation.test');
const { runMLPipelineTests } = require('./integration/ml-pipeline.test');
const runAuditV3BypassTests = require('./integration/audit-v3-bypasses.test');
const { runSandboxImprovementTests } = require('./integration/sandbox-improvements.test');
const { runBlueTeamV8bTests } = require('./integration/blue-team-v8b.test');
const { runHealthcheckTests } = require('./integration/healthcheck.test');
const { runMonitorWiringTests } = require('./integration/monitor-wiring.test');
const { runDeferredSandboxTests } = require('./integration/deferred-sandbox.test');

// Temporal analysis tests
const { runTemporalAnalysisTests } = require('./temporal/temporal-analysis.test');
const { runTemporalAstDiffTests } = require('./temporal/temporal-ast-diff.test');
const { runPublishAnomalyTests } = require('./temporal/publish-anomaly.test');
const { runMaintainerChangeTests } = require('./temporal/maintainer-change.test');
const { runCanaryTokensTests } = require('./temporal/canary-tokens.test');
const { runTemporalRunnerTests } = require('./temporal/temporal-runner.test');

// NOTE: ground-truth.test.js and evaluate.test.js are EXCLUDED from npm test
// because they scan 51+ real samples (takes 20+ minutes).
// Run them via: npm run test:integration

async function timed(name, fn) {
  const t0 = Date.now();
  await fn();
  const s = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  [suite ${name}: ${s}s]\n`);
}

(async () => {
  const start = Date.now();

  // Scanner unit tests
  await timed('ast', runAstTests);
  await timed('shell', runShellTests);
  await timed('obfuscation', runObfuscationTests);
  await timed('dataflow', runDataflowTests);
  await timed('package', runPackageTests);
  await timed('typosquat', runTyposquatTests);

  // Integration tests (CLI spawns processes but uses small fixtures)
  await timed('cli', runCliTests);

  // IOC / report / sandbox
  await timed('updater', runUpdaterTests);
  await timed('dependency', runDependencyTests);
  await timed('hash', runHashTests);
  await timed('webhook', runWebhookTests);
  await timed('python', runPythonTests);
  await timed('sandbox', runSandboxTests);
  await timed('gvisor', runGvisorTests);
  await timed('preload', runPreloadTests);
  await timed('sandbox-preload', runSandboxPreloadTests);
  await timed('entropy', runEntropyTests);

  // Monitor + diff
  await timed('monitor', runMonitorTests);
  await timed('diff', runDiffTests);

  // Temporal analysis
  await timed('temporal-analysis', runTemporalAnalysisTests);
  await timed('temporal-ast-diff', runTemporalAstDiffTests);
  await timed('publish-anomaly', runPublishAnomalyTests);
  await timed('maintainer-change', runMaintainerChangeTests);
  await timed('canary-tokens', runCanaryTokensTests);

  // Scanner unit tests (continued)
  await timed('ai-config', runAIConfigTests);
  await timed('deobfuscate', runDeobfuscateTests);
  await timed('module-graph', runModuleGraphTests);
  await timed('reachability', runReachabilityTests);
  await timed('github-actions', runGitHubActionsTests);
  await timed('npm-registry', runNpmRegistryTests);
  await timed('ast-negative', runAstNegativeTests);
  await timed('ast-bypass-regression', runAstBypassRegressionTests);

  // IOC scraper tests (Phase 3)
  await timed('scraper', runScraperTests);

  // New integration tests (Phase 2+3)
  await timed('output-formatter', runOutputFormatterTests);
  await timed('safe-install', runSafeInstallTests);
  await timed('download', runDownloadTests);
  await timed('temporal-runner', runTemporalRunnerTests);
  await timed('daemon-watch', runDaemonWatchTests);
  await timed('report', runReportTests);
  await timed('hooks-init', runHooksInitTests);
  await timed('sarif', runSarifTests);

  // Audit fix tests
  await timed('audit-fixes', runAuditFixTests);

  // Scoring hardening tests (v2.5.13)
  await timed('scoring-hardening', runScoringHardeningTests);

  // Intent graph tests (v2.6.0)
  await timed('intent-graph', runIntentGraphTests);

  // v2.6.6 bug fix verification + scanner hardening tests
  await timed('v266-fixes', runV266FixesTests);

  // Ground truth smoke tests (5 representative samples, fast)
  await timed('ground-truth-smoke', runGroundTruthSmokeTests);

  // Evaluation methodology smoke tests (v2.6.9)
  await timed('evaluation-smoke', runEvaluationSmokeTests);

  // Compound scoring tests (v2.9.2)
  await timed('compound-scoring', runCompoundScoringTests);

  // GAP remediation tests (v2.9.6)
  await timed('gap-remediation', runGapRemediationTests);

  // Config system tests (v2.9.7)
  await timed('config', runConfigTests);

  // Benign random corpus tests (v2.9.7)
  await timed('benign-random', runBenignRandomTests);

  // Audit v2 remediation tests (v2.9.9)
  await timed('audit-v2-remediation', runAuditV2RemediationTests);

  // ML feature extraction tests (v2.8.7)
  await timed('ml-feature-extractor', runMLFeatureExtractorTests);

  // ML classifier tests (v2.10.0)
  await timed('ml-classifier', runMLClassifierTests);
  await timed('llm-detective', runLlmDetectiveTests);

  // Tarball archive tests
  await timed('tarball-archive', runTarballArchiveTests);

  // ML pipeline integration tests (v2.10.0)
  await timed('ml-pipeline', runMLPipelineTests);

  // Audit v3 bypass fix tests
  await timed('audit-v3-bypasses', runAuditV3BypassTests);

  // Sandbox improvements tests (v2.10.2)
  await timed('sandbox-improvements', runSandboxImprovementTests);

  // Blue Team v8b detection tests
  await timed('blue-team-v8b', runBlueTeamV8bTests);

  // Healthcheck tests
  await timed('healthcheck', runHealthcheckTests);

  // Monitor wiring tests (post-refactoring regression guard, v2.10.30)
  await timed('monitor-wiring', runMonitorWiringTests);

  // Deferred sandbox queue tests (v2.10.46)
  await timed('deferred-sandbox', runDeferredSandboxTests);

  // Utility tests
  await timed('utils', runUtilsTests);

  // Results
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  const { passed, failed, skipped, failures } = getCounters();

  console.log('\n========================================');
  console.log(`RESULTS: ${passed} passed, ${failed} failed, ${skipped} skipped (${elapsed}s)`);
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
