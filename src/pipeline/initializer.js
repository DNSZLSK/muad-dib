const fs = require('fs');
const { setExtraExcludes } = require('../utils.js');
const { detectPythonProject } = require('../scanner/python.js');
const { ensureIOCs } = require('../ioc/bootstrap.js');
const { checkIOCStaleness } = require('../ioc/updater.js');
const { resolveConfig } = require('../config.js');
const { applyConfigOverrides } = require('../scoring.js');
const { setMaxFileSize } = require('../shared/constants.js');

/**
 * Initialize scan pipeline: validate target, load IOCs, apply config, detect Python deps.
 * @param {string} targetPath - Directory to scan
 * @param {object} options - CLI options
 * @returns {Promise<{pythonDeps: Array, configApplied: boolean, configResult: object, warnings: string[]}>}
 */
async function initialize(targetPath, options) {
  // Validate targetPath exists and is a directory
  if (!targetPath || !fs.existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }
  if (!fs.statSync(targetPath).isDirectory()) {
    throw new Error(`Target path is not a directory: ${targetPath}`);
  }

  // Ensure IOCs are downloaded (first run only, graceful failure)
  await ensureIOCs();

  // Check IOC freshness — warn if database is older than 30 days
  const iocStalenessWarning = checkIOCStaleness(30);

  // Apply --exclude dirs for this scan
  if (options.exclude && options.exclude.length > 0) {
    setExtraExcludes(options.exclude, targetPath);
  }

  // Load custom configuration (.muaddibrc.json or --config)
  let configApplied = false;
  const configResult = resolveConfig(targetPath, options.configPath || null);
  if (configResult.errors.length > 0) {
    for (const err of configResult.errors) console.error(`[CONFIG ERROR] ${err}`);
    throw new Error('Invalid configuration file.');
  }
  if (configResult.config) {
    applyConfigOverrides(configResult.config);
    if (configResult.config.maxFileSize) setMaxFileSize(configResult.config.maxFileSize);
    configApplied = true;
  }

  // Detect Python project (synchronous, fast file reads)
  const pythonDeps = detectPythonProject(targetPath);

  // Collect warnings
  const warnings = [];
  if (iocStalenessWarning) warnings.push(iocStalenessWarning);
  if (configResult.warnings.length > 0) {
    for (const w of configResult.warnings) warnings.push(`[CONFIG] ${w}`);
  }

  return { pythonDeps, configApplied, configResult, warnings };
}

module.exports = { initialize };
