/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

const { isPackageLevelThreat, computeGroupScore } = require('./scoring.js');
const { resetAll } = require('./scan-context.js');
const { initialize } = require('./pipeline/initializer.js');
const { execute } = require('./pipeline/executor.js');
const { process: processThreats } = require('./pipeline/processor.js');
const { output } = require('./pipeline/outputter.js');

async function run(targetPath, options = {}) {
  try {
    // Phase 1: Initialization (validate, IOCs, config, Python detection)
    const { pythonDeps, warnings } = await initialize(targetPath, options);

    // Phase 2: Execute all scanners
    const { threats, scannerErrors } = await execute(targetPath, options, pythonDeps, warnings);

    // Phase 3: Process threats (sandbox, dedup, compounds, FP reduction, intent, scoring)
    const processed = await processThreats(threats, targetPath, options, pythonDeps, warnings, scannerErrors);
    const { result } = processed;

    // _capture mode: return result directly without printing (used by diff.js)
    if (options._capture) {
      return result;
    }

    // Phase 4: Output (CLI formatting, webhook, exit code)
    const exitCode = await output(result, options, processed);

    return exitCode;
  } finally {
    // Clear all per-scan mutable state — even on exception
    resetAll();
  }
}

module.exports = { run, isPackageLevelThreat, computeGroupScore };
