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
 */
'use strict';

// Oracle for the parser-divergence finding: does the running Node.js accept this source?
// Threat model: a file Node runs but acorn rejects is invisible to the AST and dataflow
// scanners (safeParse returns null, only four regex fallbacks remain).
//
// Syntax check only, nothing is executed: `node --check` compiles without running.
// The content goes through stdin with an explicit --input-type. Passing a file path is NOT
// reliable: on Node 24, `node --check file.js` returns 0 for ANY .js containing ESM syntax,
// even when the rest of the file is invalid (verified: `import a from "b"; foo(` -> 0).
// stdin also keeps package.json "type" and the file name out of the decision.
// Empty environment: no NODE_OPTIONS (--require / --import) can be injected into the child.

const { spawnSync } = require('child_process');

// Bounded resources: one or two short-lived processes per file acorn rejects. Budget per scan,
// reset by the AST scanner at the start of each scan.
const MAX_CHECKS_PER_SCAN = 50;
const CHECK_TIMEOUT_MS = 5000;
let _remaining = MAX_CHECKS_PER_SCAN;

const CHILD_ENV = process.platform === 'win32' && process.env.SystemRoot
  ? { SystemRoot: process.env.SystemRoot }
  : {};

function resetNodeSyntaxBudget() {
  _remaining = MAX_CHECKS_PER_SCAN;
}

/**
 * @param {string} code
 * @returns {boolean|null} true = accepted as an ES module or as CommonJS, false = rejected
 *   by both, null = not checked (budget exhausted, timeout, spawn failure).
 */
function nodeAcceptsSyntax(code) {
  if (typeof code !== 'string') return null;
  if (_remaining <= 0) return null;
  _remaining--;
  let unchecked = false;
  for (const inputType of ['module', 'commonjs']) {
    const r = spawnSync(process.execPath, ['--check', '--input-type=' + inputType], {
      input: code,
      env: CHILD_ENV,
      timeout: CHECK_TIMEOUT_MS,
      windowsHide: true,
      stdio: ['pipe', 'ignore', 'ignore']
    });
    if (r.error || r.signal) { unchecked = true; continue; }
    if (r.status === 0) return true;
  }
  return unchecked ? null : false;
}

module.exports = { nodeAcceptsSyntax, resetNodeSyntaxBudget, MAX_CHECKS_PER_SCAN };
