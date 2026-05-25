// Test environment hardening — MUST be set BEFORE any scanner module is required.
// Reason: since v2.11.9 the FPR-plan gates are default ON, which means each scan
// triggers a `getPackageMetadata()` fetch to the npm registry to populate
// MATURE_CAP / METADATA_FACTOR / DELTA_MODE. Test fixtures use synthetic package
// names ("evil-pkg", "test-foo", etc.) that 404 on npm with a 1-2s timeout per
// fetch. On a CI run with hundreds of scan-based tests this adds 15+ minutes of
// pointless network round-trips. We force NO_REGISTRY_FETCH=1 here so tests
// stay fast and offline-clean. Individual tests that need the registry path
// can still set their own env via runScan options or sub-process env.
//
// Per-CLI-user usage is unaffected: this hardening only applies when the
// in-process test runner imports the scanner modules.
if (!process.env.MUADDIB_NO_REGISTRY_FETCH) {
  process.env.MUADDIB_NO_REGISTRY_FETCH = '1';
}

const { getCounters } = require('./test-utils');

// Scanner tests (fast — pure unit tests, no process spawns)
const { runAstTests } = require('./scanner/ast.test');
const { runShellTests } = require('./scanner/shell.test');
const { runObfuscationTests } = require('./scanner/obfuscation.test');
const { runBundleDetectTests } = require('./scanner/bundle-detect.test');
const { runDataflowTests } = require('./scanner/dataflow.test');
const { runPackageTests } = require('./scanner/package.test');
const { runTyposquatTests } = require('./scanner/typosquat.test');
const { runDependencyTests } = require('./scanner/dependency.test');
const { runIocStringsTests } = require('./scanner/ioc-strings.test');
const { runAntiForensicTests } = require('./scanner/anti-forensic.test');
const { runStubPackageTests } = require('./scanner/stub-package.test');
const { runHashTests } = require('./scanner/hash.test');
const { runEntropyTests } = require('./scanner/entropy.test');
const { runPythonTests } = require('./scanner/python.test');
const { runPythonSourceTests } = require('./scanner/python-source.test');
const { runPythonAstTests } = require('./scanner/python-ast.test');
const { runAIConfigTests } = require('./scanner/ai-config.test');
const { runDeobfuscateTests } = require('./scanner/deobfuscate.test');
const { runModuleGraphTests } = require('./scanner/module-graph.test');
const { runReachabilityTests } = require('./scanner/reachability.test');
const { runGitHubActionsTests } = require('./scanner/github-actions.test');
const { runNpmRegistryTests } = require('./scanner/npm-registry.test');
const { runReleaseZeroTests } = require('./scanner/release-zero.test');
const { runSilentStealthTests } = require('./scanner/silent-stealth.test');
const { runSensitiveFilesCoverageTests } = require('./scanner/sensitive-files-coverage.test');
const { runEmailDomainTests } = require('./scanner/email-domain.test');
const { runRdapCompromisedDomainTests } = require('./scanner/rdap-compromised-domain.test');
const { runRiskDomainsTests } = require('./scanner/risk-domains.test');
const { runCyclonedxTests } = require('./scanner/cyclonedx.test');
const { runAstNegativeTests } = require('./scanner/ast-negative.test');
const { runAstBypassRegressionTests } = require('./scanner/ast-bypass-regression.test');
const { runIntentGraphTests } = require('./scanner/intent-graph.test');
const { runTrustedDepDiffTests } = require('./scanner/trusted-dep-diff.test');

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
const { runFpClustersTests } = require('./unit/fp-clusters.test');
const { runRegressionCheckTests } = require('./unit/regression-check.test');
const { runRegistrySignalsTests } = require('./unit/registry-signals.test');
const { runMatureStableCapTests } = require('./unit/mature-stable-cap.test');
const { runReachabilityFunctionsTests } = require('./unit/reachability-functions.test');
const { runDeltaMultiplierTests } = require('./unit/delta-multiplier.test');
const { runConfidenceTiersTests } = require('./unit/confidence-tiers.test');
const { runCompoundTighteningTests } = require('./unit/compound-tightening.test');
const { runStagedRemoteLoaderTests } = require('./unit/staged-remote-loader.test');
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
const { runSingleFireCriticalFloorTests } = require('./integration/single-fire-critical-floor.test');
const { runDecayAggregationTests } = require('./integration/decay-aggregation.test');
const { runCompoundReplacementTests } = require('./integration/compound-replacement.test');
const { runReputationFactorTests } = require('./integration/reputation-factor.test');
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
const { runMonitorMemoryTests } = require('./integration/monitor-memory.test');
const { runOomDetectionsJsonlTests } = require('./integration/oom-detections-jsonl.test');
const { runAutoLabelerTests } = require('./integration/auto-labeler.test');

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
  await timed('bundle-detect', runBundleDetectTests);
  await timed('dataflow', runDataflowTests);
  await timed('package', runPackageTests);
  await timed('typosquat', runTyposquatTests);

  // Integration tests (CLI spawns processes but uses small fixtures)
  await timed('cli', runCliTests);

  // IOC / report / sandbox
  await timed('updater', runUpdaterTests);
  await timed('dependency', runDependencyTests);
  await timed('ioc-strings', runIocStringsTests);
  await timed('anti-forensic', runAntiForensicTests);
  await timed('stub-package', runStubPackageTests);
  await timed('hash', runHashTests);
  await timed('webhook', runWebhookTests);
  await timed('python', runPythonTests);
  await timed('python-source', runPythonSourceTests);
  await timed('python-ast', runPythonAstTests);
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
  await timed('release-zero', runReleaseZeroTests);
  await timed('silent-stealth', runSilentStealthTests);
  await timed('sensitive-files-coverage', runSensitiveFilesCoverageTests);
  await timed('email-domain', runEmailDomainTests);
  await timed('rdap-compromised-domain', runRdapCompromisedDomainTests);
  await timed('risk-domains', runRiskDomainsTests);
  await timed('cyclonedx', runCyclonedxTests);
  await timed('ast-negative', runAstNegativeTests);
  await timed('ast-bypass-regression', runAstBypassRegressionTests);
  await timed('trusted-dep-diff', runTrustedDepDiffTests);

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

  // Hybrid v3 Phase 1: single-fire critical floor
  await timed('single-fire-critical-floor', runSingleFireCriticalFloorTests);

  // Hybrid v3 Phase 2: per-type bounded decay aggregation
  await timed('decay-aggregation', runDecayAggregationTests);

  // Hybrid v3 Phase 3: compound-replacement (no additive double-count)
  await timed('compound-replacement', runCompoundReplacementTests);

  // Hybrid v3 Phase 4: metadata-first reputation factor
  await timed('reputation-factor', runReputationFactorTests);

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

  // FP cluster aggregation (FPR Improvement Plan - Chantier 1)
  await timed('fp-clusters', runFpClustersTests);

  // Regression check helpers (FPR Improvement Plan - Chantier 8)
  await timed('regression-check', runRegressionCheckTests);

  // Advanced npm registry signals (FPR Improvement Plan - Chantier 4)
  await timed('registry-signals', runRegistrySignalsTests);

  // Mature stable cap (FPR Improvement Plan - Chantier 5)
  await timed('mature-stable-cap', runMatureStableCapTests);

  // Function-level reachability (FPR Improvement Plan - Chantier 2)
  await timed('reachability-functions', runReachabilityFunctionsTests);

  // Delta-aware decay multiplier (FPR Improvement Plan - Chantier 3)
  await timed('delta-multiplier', runDeltaMultiplierTests);

  // Multi-tier confidence (FPR Improvement Plan - Chantier 6)
  await timed('confidence-tiers', runConfidenceTiersTests);

  // Compound precision tightening (FPR Improvement Plan - Chantier 7)
  await timed('compound-tightening', runCompoundTighteningTests);

  // Staged remote loader compound (chai-* / poxios-chain campaign 2026-05)
  await timed('staged-remote-loader', runStagedRemoteLoaderTests);

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

  // Monitor memory management tests (OOM prevention)
  await timed('monitor-memory', runMonitorMemoryTests);

  // OOM detections JSONL fix (append-only persistence, streaming reads, migration)
  await timed('oom-detections-jsonl', runOomDetectionsJsonlTests);

  // Auto-labeler tests (registry takedown-based ML label correction)
  await timed('auto-labeler', runAutoLabelerTests);

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
