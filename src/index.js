const { isPackageLevelThreat, computeGroupScore } = require('./scoring.js');
const { resetAll } = require('./scan-context.js');
const { initialize } = require('./pipeline/initializer.js');
const { execute } = require('./pipeline/executor.js');
const { process: processThreats } = require('./pipeline/processor.js');
const { output } = require('./pipeline/outputter.js');

async function run(targetPath, options = {}) {
  // Phase 1: Initialization (validate, IOCs, config, Python detection)
  const { pythonDeps, configApplied, configResult, warnings } = await initialize(targetPath, options);

  // Phase 2: Execute all scanners
  const { threats, scannerErrors } = await execute(targetPath, options, pythonDeps, warnings);

  // Phase 3: Process threats (sandbox, dedup, compounds, FP reduction, intent, scoring)
  const processed = await processThreats(threats, targetPath, options, pythonDeps, warnings, scannerErrors);
  const { result } = processed;

  // _capture mode: return result directly without printing (used by diff.js)
  if (options._capture) {
    resetAll();
    return result;
  }

  // Phase 4: Output (CLI formatting, webhook, exit code)
  const exitCode = await output(result, options, processed);

  // Clear all per-scan mutable state
  resetAll();

  return exitCode;
}

module.exports = { run, isPackageLevelThreat, computeGroupScore };
