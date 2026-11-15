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

const path = require('path');
const { isDevFile, findJsFiles, forEachSafeFile } = require('../utils.js');
const { looksBinaryString } = require('./binary-sniff.js');
const { markIncomplete } = require('./completeness.js');

// Files reachable from the package entry points (main, bin, exports, module, browser,
// lifecycle targets, and what they require or spawn) are EXECUTED code, so the dev-file
// filter must not drop them. isDevFile skips tools/, build/, docs/, examples/, fixtures/,
// compiler/, benchmark* and any *test.js / *spec.js: a reverse shell set as
// "main": "latest.js" or "main": "tools/index.js", or as a bin in docs/, scored 0.
// Unreachable files keep the filter.
// Not done here (measured 2026-11-08): also scanning the reachable files of dist/, build/,
// out/ and output/ (excluded by findJsFiles). On the validation sample it pushed agent/CLI
// tools to >= 75 through the same imprecise rules as RC-H1 (detached_process,
// mcp_config_injection, ci_environment_probe) with no TP gained; it waits for those rules.
const MAX_EXECUTED_FILES = 500;
let _executedCache = { target: null, rel: new Set() };

function executedFiles(targetPath) {
  if (_executedCache.target === targetPath) return _executedCache.rel;
  const rel = new Set();
  try {
    // Lazy require: reachability -> module-graph pulls acorn; keep this module light.
    const { computeReachableFiles } = require('../scanner/reachability.js');
    const { reachableFiles } = computeReachableFiles(targetPath);
    for (const r of reachableFiles) {
      const p = String(r).split(path.sep).join('/');
      if (p.split('/').includes('node_modules')) continue;
      rel.add(p);
      if (rel.size >= MAX_EXECUTED_FILES) break;
    }
  } catch {
    // Reachability failure: keep the plain dev-file filter (previous behavior).
  }
  _executedCache = { target: targetPath, rel };
  return rel;
}

/**
 * Shared scanner wrapper: iterates JS files, runs analyzeFileFn on original + deobfuscated code,
 * deduplicates findings by type::message key.
 * @param {string} targetPath - Root directory to scan
 * @param {Function} analyzeFileFn - (content, filePath, basePath) => threats[]
 * @param {object} [options]
 * @param {Function} [options.deobfuscate] - Deobfuscation function
 * @param {string[]} [options.excludedFiles] - Relative paths to skip
 * @param {boolean} [options.skipDevFiles=true] - Whether to skip dev/test files
 * @returns {Array} Combined threats
 */
function analyzeWithDeobfuscation(targetPath, analyzeFileFn, options = {}) {
  const files = findJsFiles(targetPath);
  const executed = executedFiles(targetPath);
  const component = options.component || 'analyzeWithDeobfuscation';
  const byteBudget = Number.isFinite(options.byteBudget) && options.byteBudget >= 0 ? options.byteBudget : null;

  // Work budget (architecture lot 2). The scanners are synchronous, so a timer cannot
  // interrupt them, and a clock would make the verdict depend on the machine: the budget is
  // the number of source characters analyzed, checked before each file, so a package stops
  // at the same file everywhere. Executed files are analyzed first, so padding the package
  // with large decoy files cannot push the code that runs past the budget. Findings are
  // reassembled in the original file order, so the output does not depend on the
  // processing order. The hard wall-clock bound is one level up (hard-timeout.js, monitor
  // worker).
  const order = files.map((file, index) => ({ file, index, rel: path.relative(targetPath, file).replace(/\\/g, '/') }));
  order.sort((a, b) => (executed.has(a.rel) ? 0 : 1) - (executed.has(b.rel) ? 0 : 1) || a.index - b.index);
  const indexOf = new Map(order.map(o => [o.file, o.index]));
  const perFile = new Array(files.length);
  let analyzedChars = 0;
  let overBudget = false;
  let fileErrors = 0;
  // Once a file that would have been analyzed is skipped, the remaining files are not even read.
  const shouldStop = () => overBudget;

  forEachSafeFile(order.map(o => o.file), (file, content) => {
    const relativePath = path.relative(targetPath, file).replace(/\\/g, '/');

    if (options.excludedFiles && options.excludedFiles.includes(relativePath)) return;
    if (options.skipDevFiles !== false && isDevFile(relativePath) && !executed.has(relativePath)) return;
    if (byteBudget !== null && analyzedChars >= byteBudget) {
      overBudget = true;
      return;
    }

    // .d.ts files: strip TypeScript declaration syntax before JS parsing.
    // Legitimate .d.ts files contain only type declarations (no executable code).
    // Any require/exec/network calls in a .d.ts are high-confidence malicious payload hiding.
    let effectiveContent = content;
    if (file.endsWith('.d.ts')) {
      effectiveContent = content.split('\n').map(line => {
        const trimmed = line.trim();
        // Strip lines that are pure TypeScript declarations (Acorn can't parse these)
        if (/^export\s+declare\s+/.test(trimmed)) return '// [ts-stripped]';
        if (/^declare\s+(function|class|const|let|var|type|interface|enum|namespace|module|global)\s/.test(trimmed)) return '// [ts-stripped]';
        if (/^(export\s+)?(type|interface)\s/.test(trimmed)) return '// [ts-stripped]';
        return line;
      }).join('\n');
    }

    // Ingestion guard: a source-extension file whose bytes are actually binary (a payload
    // carrier disguised as source) is not JS - skip the parse instead of handing acorn
    // megabytes of binary that yield no AST and burn the parse budget. binary-source.js
    // reports the finding (it also reaches dist/ where this shared path does not).
    if (looksBinaryString(effectiveContent)) return;
    analyzedChars += effectiveContent.length;

    // One file that throws (measured: a 7.5 MB member-expression chain overflows the stack
    // in the walk) used to reject the whole scanner and drop the findings of every other
    // file. It now costs only that file, and the scan is INCONCLUSIVE.
    let fileThreats;
    try {
      // Analyze original code first (preserves obfuscation-detection rules)
      fileThreats = analyzeFileFn(effectiveContent, file, targetPath);
    } catch {
      fileErrors++;
      return;
    }
    const out = fileThreats.slice();

    // Also analyze deobfuscated code for additional findings hidden by obfuscation
    if (typeof options.deobfuscate === 'function') {
      let result = null;
      try {
        result = options.deobfuscate(effectiveContent);
      } catch { /* deobfuscation failed - skip */ }
      if (result && result.transforms.length > 0) {
        let deobThreats = null;
        try {
          deobThreats = analyzeFileFn(result.code, file, targetPath);
        } catch {
          fileErrors++;
        }
        if (deobThreats) {
          const existingKeys = new Set(fileThreats.map(t => `${t.type}::${t.message}`));
          for (const dt of deobThreats) {
            if (!existingKeys.has(`${dt.type}::${dt.message}`)) {
              out.push(dt);
            }
          }
        }
      }
    }
    perFile[indexOf.get(file)] = out;
  }, { shouldStop });

  if (overBudget) {
    markIncomplete(component, 'work-budget', { limit: byteBudget, observed: analyzedChars });
  }
  if (fileErrors > 0) {
    markIncomplete(component, 'file-error', { observed: fileErrors });
  }
  const threats = [];
  for (const fileThreats of perFile) {
    if (fileThreats) threats.push(...fileThreats);
  }
  return threats;
}

module.exports = { analyzeWithDeobfuscation, executedFiles };
