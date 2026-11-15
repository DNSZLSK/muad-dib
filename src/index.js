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
const { withScanRecord } = require('./shared/completeness.js');
const { initialize } = require('./pipeline/initializer.js');
const { execute } = require('./pipeline/executor.js');
const { process: processThreats } = require('./pipeline/processor.js');
const { output } = require('./pipeline/outputter.js');

// Scans of one process run one after the other (architecture lot 2). Several modules keep
// per-scan state at module level (exclusions, config overrides, file-size cap, file-list and
// AST caches; see scan-context.js), and the end of a scan resets it: a scan that ended while
// another was running (`muaddib watch` re-scans on a change without waiting, the daemon
// scans several directories) reset the other one's exclusions and config mid-analysis. The
// scanners are synchronous, so running scans side by side only interleaved them and saved
// no time. A failed scan does not block the next one. Each scan also keeps its own
// incompleteness record (AsyncLocalStorage).
let _scanQueue = Promise.resolve();

function run(targetPath, options = {}) {
  const result = _scanQueue.then(() => withScanRecord(() => runScan(targetPath, options)));
  _scanQueue = result.then(() => {}, () => {});
  return result;
}

async function runScan(targetPath, options = {}) {
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
