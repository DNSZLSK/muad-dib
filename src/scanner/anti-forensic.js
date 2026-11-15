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

'use strict';

// ── Anti-forensic compound AST scanner ──
//
// Catches the Axios / csec autodelete family pattern in source code, even
// when the YARA-style string IOC scanner misses (e.g. an attacker rotates
// the XOR key away from `OrDeR_7077`). Detects the COMBINATION inside a
// single file:
//
//   1. XOR loop:    a for/while body containing `^` BinaryExpression
//                   with at least one literal-derived operand (charCodeAt
//                   on a string literal, an array of byte literals, etc.)
//   2. Self-delete: fs.unlink{,Sync} of __filename / module.filename /
//                   path inside `node_modules/<pkg>/...` / module.path,
//                   OR fs.rename{,Sync} to .md/.bak/.tmp/.txt/.log extension
//   3. Decoy write: fs.writeFile{,Sync} to a path ending in
//                   .md|.bak|.tmp|.txt|.log (e.g. package.md replacing
//                   the tampered package.json)
//
// Severity ladder (per file):
//   - 3 of 3   → CRITICAL +50 (anti_forensic_xor_autodelete)
//   - 2 of 3   → HIGH     +25 (anti_forensic_partial)
//   - <= 1     → no fire
//
// Why severity ladder: the csec autodelete documented in
// project_detection_gap_csec_xor_autodelete (XOR + new Function +
// self-delete to exfil .env/.ssh/.npmrc, score 19 today) hits patterns
// 1+2; the Axios setup.js hits all three. Both must escalate to
// CRITICAL territory after this rule fires.

const fs = require('fs');
const path = require('path');
const walk = require('acorn-walk');
const { safeParse } = require('../shared/constants.js');
const { findFiles } = require('../utils.js');
const { getMaxFileSize } = require('../shared/constants.js');
const { markIncomplete } = require('../shared/completeness.js');
const { budgetOrder } = require('../shared/analyze-helper.js');
const { readBudget, budgetStop, stopDetails } = require('../shared/scan-budget.js');

const SCAN_EXTENSIONS = ['.js', '.cjs', '.mjs'];
const DECOY_EXT_RE = /\.(?:md|bak|tmp|txt|log)$/i;
const SELF_PATH_HINTS_RE = /node_modules\/[^/]+\/(?:setup|install|index|main|preinstall|postinstall)\.(?:c|m)?js/i;

function isFsCall(node, methodNames) {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (!callee || callee.type !== 'MemberExpression' || !callee.property) return false;
  const propName = callee.property.name || (callee.property.value);
  if (!methodNames.includes(propName)) return false;
  // Object can be `fs`, `fsp`, or `fs.promises`; we accept any identifier or
  // member expression — the scanner is intentionally permissive on the
  // receiver because malware regularly aliases `const fsp = require('fs').promises`.
  return true;
}

function literalEndsWith(node, regex) {
  if (!node) return false;
  if (node.type === 'Literal' && typeof node.value === 'string') return regex.test(node.value);
  if (node.type === 'TemplateLiteral' && node.quasis && node.quasis.length === 1) {
    return regex.test(node.quasis[0].value && (node.quasis[0].value.cooked || node.quasis[0].value.raw) || '');
  }
  return false;
}

function isSelfReference(node) {
  if (!node) return false;
  // __filename
  if (node.type === 'Identifier' && node.name === '__filename') return true;
  // module.filename / module.path / module.id
  if (node.type === 'MemberExpression' && node.object && node.object.type === 'Identifier' &&
      node.object.name === 'module' && node.property && (node.property.name === 'filename' || node.property.name === 'path' || node.property.name === 'id')) return true;
  // path.join(...) where one of the args is __filename — common pattern
  if (node.type === 'CallExpression' && node.callee && node.callee.type === 'MemberExpression' &&
      node.callee.object && node.callee.object.name === 'path' &&
      Array.isArray(node.arguments) && node.arguments.some(isSelfReference)) return true;
  // Literal containing a node_modules path hint
  if (node.type === 'Literal' && typeof node.value === 'string' && SELF_PATH_HINTS_RE.test(node.value)) return true;
  if (node.type === 'TemplateLiteral' && node.quasis && node.quasis.length === 1) {
    const v = node.quasis[0].value && (node.quasis[0].value.cooked || node.quasis[0].value.raw) || '';
    if (SELF_PATH_HINTS_RE.test(v)) return true;
  }
  return false;
}

function literalDerivedOperand(node) {
  // charCodeAt on a string literal or template literal
  if (node && node.type === 'CallExpression' && node.callee && node.callee.type === 'MemberExpression' &&
      node.callee.property && (node.callee.property.name === 'charCodeAt' || node.callee.property.name === 'codePointAt')) {
    const obj = node.callee.object;
    if (obj && (obj.type === 'Literal' || obj.type === 'TemplateLiteral' || obj.type === 'Identifier')) return true;
  }
  // Member access on an Identifier that may resolve to a string/array constant.
  // We accept Identifier-based accesses as a heuristic; combined with other
  // signals (XOR + self-delete) the FP ratio stays acceptable.
  if (node && node.type === 'MemberExpression' && node.object && node.object.type === 'Identifier') return true;
  // Literal-only XOR (e.g. data ^ 0x42)
  if (node && node.type === 'Literal' && typeof node.value === 'number') return true;
  return false;
}

function analyzeFile(content) {
  const ast = safeParse(content);
  if (!ast) return null;

  const evidence = { xorLoop: null, selfDelete: null, decoyWrite: null };

  // Iterative pre-order walk (architecture lot 2): acorn-walk's recursive() spends stack
  // frames per nesting level, so a 5 000-link member chain in the payload file overflowed
  // the stack and the file's evidence was lost. Each entry carries whether it sits inside a
  // loop body, so a XOR found at any depth is attributed to its enclosing loop. Same
  // semantics and visit order as the former recursive walk (loop body first, then the
  // other parts, which keep the enclosing context: the former walk visited a for statement's
  // init / test / update after leaving the loop), so the evidence recorded is the same. The
  // former walk never visited a while / do-while condition nor the left / right of
  // for-in / for-of; they are now visited (enclosing context), so a self-delete or decoy
  // write placed there is no longer missed.
  const stack = [[ast, ast.type, false]];
  const pushChildren = (node, type, inLoop) => {
    const kids = [];
    if (type === 'ForStatement') {
      kids.push([node.body, true]);
      for (const k of [node.init, node.test, node.update]) if (k) kids.push([k, inLoop]);
    } else if (type === 'ForInStatement' || type === 'ForOfStatement') {
      kids.push([node.body, true], [node.left, inLoop], [node.right, inLoop]);
    } else if (type === 'WhileStatement' || type === 'DoWhileStatement') {
      kids.push([node.body, true], [node.test, inLoop]);
    } else {
      const base = walk.base[type];
      if (!base) return;
      base(node, null, (child, _st, override) => { kids.push([child, inLoop, override]); });
    }
    for (let i = kids.length - 1; i >= 0; i--) {
      const [child, childInLoop, override] = kids[i];
      if (child) stack.push([child, override || child.type, childInLoop]);
    }
  };

  while (stack.length > 0) {
    const [node, type, inLoop] = stack.pop();
    // An override frame (Expression, Statement, Pattern...) only forwards to the node's own
    // type: visit the node once, on its own frame.
    if (type === node.type) visit(node, inLoop);
    pushChildren(node, type, inLoop);
  }

  function visit(node, inLoop) {
    if (node.type === 'BinaryExpression') {
      if (!evidence.xorLoop && node.operator === '^' && inLoop) {
        if (literalDerivedOperand(node.left) || literalDerivedOperand(node.right)) {
          evidence.xorLoop = { line: node.loc && node.loc.start && node.loc.start.line };
        }
      }
      return;
    }
    if (node.type === 'AssignmentExpression') {
      // Catch `out[i] ^= key[...]` style mutations
      if (!evidence.xorLoop && node.operator === '^=' && inLoop) {
        if (literalDerivedOperand(node.right)) {
          evidence.xorLoop = { line: node.loc && node.loc.start && node.loc.start.line };
        }
      }
      return;
    }
    if (node.type !== 'CallExpression') return;
    {
      // Self-delete: fs.unlink / unlinkSync on __filename or self path hint
      if (!evidence.selfDelete && isFsCall(node, ['unlink', 'unlinkSync'])) {
        if (node.arguments && node.arguments.length > 0 && isSelfReference(node.arguments[0])) {
          evidence.selfDelete = { line: node.loc && node.loc.start && node.loc.start.line, kind: 'unlink' };
        }
      }
      // Self-delete via rename to a non-executable extension
      if (!evidence.selfDelete && isFsCall(node, ['rename', 'renameSync'])) {
        if (node.arguments && node.arguments.length >= 2) {
          const oldPath = node.arguments[0];
          const newPath = node.arguments[1];
          if (isSelfReference(oldPath) && literalEndsWith(newPath, DECOY_EXT_RE)) {
            evidence.selfDelete = { line: node.loc && node.loc.start && node.loc.start.line, kind: 'rename' };
          }
        }
      }
      // Decoy write: writeFile / writeFileSync to a path ending in .md/.bak/...
      if (!evidence.decoyWrite && isFsCall(node, ['writeFile', 'writeFileSync'])) {
        if (node.arguments && node.arguments.length > 0 && literalEndsWith(node.arguments[0], DECOY_EXT_RE)) {
          evidence.decoyWrite = { line: node.loc && node.loc.start && node.loc.start.line };
        }
      }
    }
  }

  const count = (evidence.xorLoop ? 1 : 0) + (evidence.selfDelete ? 1 : 0) + (evidence.decoyWrite ? 1 : 0);
  if (count === 0) return null;
  return { evidence, count };
}

async function scanAntiForensic(targetPath, options = {}) {
  const threats = [];
  if (!fs.existsSync(targetPath)) return threats;
  // Work budget in source characters (architecture lot 2), deterministic: see analyze-helper.js.
  // Only the files that pass the cheap pre-filter below are parsed, so only they count.
  const budget = readBudget(options);
  let analyzedChars = 0;
  let fileErrors = 0;

  const sourceFiles = findFiles(targetPath, { extensions: SCAN_EXTENSIONS });
  const nodeModulesPath = path.join(targetPath, 'node_modules');
  const nodeModulesFiles = fs.existsSync(nodeModulesPath)
    ? findFiles(nodeModulesPath, { extensions: SCAN_EXTENSIONS, excludedDirs: ['.git', '.muaddib-cache'] })
    : [];
  const allFiles = sourceFiles.concat(nodeModulesFiles);

  // Executed files first, closest to an entry point first (budgetOrder), node_modules last;
  // findings are reassembled in the original file order.
  const perFile = new Map();
  for (const filePath of budgetOrder(targetPath, sourceFiles).map(o => o.file).concat(nodeModulesFiles)) {
    let content;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > getMaxFileSize()) continue;
      content = fs.readFileSync(filePath, 'utf8');
    } catch { continue; }
    if (!content) continue;
    // Cheap pre-filter: skip files that have no `^` operator and no fs.unlink/rename
    // call. Avoids parsing benign minified bundles.
    if (!/[^=!<>]\^[^=]/.test(content) && !/\b(?:unlink|rename)(?:Sync)?\b/.test(content)) continue;
    const stopReason = budgetStop(budget, analyzedChars);
    if (stopReason) {
      markIncomplete('scanAntiForensic', stopReason, stopDetails(stopReason, budget, analyzedChars));
      break;
    }
    analyzedChars += content.length;
    let result;
    try {
      result = analyzeFile(content);
    } catch {
      // A file that throws costs only that file (the walk itself is iterative).
      fileErrors++;
      continue;
    }
    if (!result) continue;
    const rel = path.relative(targetPath, filePath);
    if (result.count >= 3) {
      perFile.set(filePath, {
        type: 'anti_forensic_xor_autodelete',
        severity: 'CRITICAL',
        message: `Anti-forensic compound (XOR + self-delete + decoy write) in single file: ${rel}`,
        file: rel,
        evidence: JSON.stringify(result.evidence)
      });
    } else if (result.count === 2) {
      perFile.set(filePath, {
        type: 'anti_forensic_partial',
        severity: 'HIGH',
        message: `Anti-forensic partial (2 of 3 patterns) in single file: ${rel}`,
        file: rel,
        evidence: JSON.stringify(result.evidence)
      });
    }
  }
  for (const f of allFiles) if (perFile.has(f)) threats.push(perFile.get(f));
  if (fileErrors > 0) markIncomplete('scanAntiForensic', 'file-error', { observed: fileErrors });
  return threats;
}

module.exports = { scanAntiForensic, analyzeFile, SCAN_EXTENSIONS };
