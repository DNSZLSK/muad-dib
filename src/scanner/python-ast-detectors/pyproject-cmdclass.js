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

// PYAST-001 parity for pyproject.toml. setuptools reads command overrides from
// `[tool.setuptools.cmdclass]` exactly like `setup(cmdclass={...})`: the class runs
// during `pip install` / build. pybitjs@0.1.0 (2026-08) declared build_py + develop
// there and wrote a .pth hook that launches an obfuscated main.js; setup.py-only
// detection never saw it.
//
// Minimal TOML key-path reader (no dependency): it only resolves the dotted path of
// every key, so every spelling of the same declaration reaches the same path:
//   [tool.setuptools.cmdclass] develop = "x"
//   [tool.setuptools] cmdclass = { develop = "x" }
//   [tool] setuptools.cmdclass.develop = "x"
//   tool.setuptools.cmdclass.develop = "x"         (top level)
//   [ tool . "setuptools" . 'cmdclass' ] "develop" = "x"

const fs = require('fs');
const path = require('path');

const { INSTALL_TIME_COMMANDS } = require('./handle-setup-call.js');

const MAX_PYPROJECT_SIZE = 256 * 1024;
const CMDCLASS_PATH = 'tool.setuptools.cmdclass';

// Split a dotted TOML key into segments, honoring "..." and '...' quoting.
function splitKey(raw) {
  const segs = [];
  let cur = '';
  let quote = null;
  for (const ch of raw) {
    if (quote) {
      if (ch === quote) quote = null; else cur += ch;
    } else if (ch === '"' || ch === '\'') {
      quote = ch;
    } else if (ch === '.') {
      segs.push(cur.trim()); cur = '';
    } else {
      cur += ch;
    }
  }
  segs.push(cur.trim());
  return segs.filter(s => s.length > 0);
}

// Remove a trailing # comment that is not inside a string.
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === '\'') quote = ch;
    else if (ch === '#') return line.slice(0, i);
  }
  return line;
}

// Index of the first top-level `=` (outside quotes), or -1.
function findAssign(s) {
  let quote = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === '\'') quote = ch;
    else if (ch === '=') return i;
  }
  return -1;
}

// Keys of a single-line inline table `{ a = "x", "b" = "y" }` (top level only).
function inlineTableKeys(value) {
  const v = value.trim();
  if (!v.startsWith('{')) return [];
  const body = v.slice(1, v.lastIndexOf('}') === -1 ? v.length : v.lastIndexOf('}'));
  const keys = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  const parts = [];
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === '\'') quote = ch;
    else if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) { parts.push(body.slice(start, i)); start = i + 1; }
  }
  parts.push(body.slice(start));
  for (const p of parts) {
    const eq = findAssign(p);
    if (eq > 0) keys.push(splitKey(p.slice(0, eq)));
  }
  return keys;
}

/**
 * Split TOML into statements: a newline ends a statement only outside strings
 * (including multi-line """ / ''' strings) and outside [ ] / { } nesting. Comments
 * are dropped. Without this, a line such as `[project]` inside a multi-line string or
 * `[1]` inside a multi-line array would be read as a table header and hide the keys
 * that follow it (evasion).
 */
function splitStatements(content) {
  const out = [];
  let cur = '';
  let depth = 0;
  let str = null; // '"', "'", '"""', "'''"
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (str) {
      if ((str === '"' || str === '"""') && ch === '\\') { cur += ch + (content[i + 1] || ''); i++; continue; }
      if (str.length === 3 && content.startsWith(str, i)) { cur += str; i += 2; str = null; continue; }
      if (str.length === 1 && ch === str) { cur += ch; str = null; continue; }
      if (str.length === 1 && ch === '\n') { str = null; } // unterminated single-line string
      cur += ch;
      continue;
    }
    if (content.startsWith('"""', i) || content.startsWith('\'\'\'', i)) { str = content.substr(i, 3); cur += str; i += 2; continue; }
    if (ch === '"' || ch === '\'') { str = ch; cur += ch; continue; }
    if (ch === '#') { while (i < content.length && content[i] !== '\n') i++; i--; continue; }
    if (ch === '[' || ch === '{') depth++;
    else if ((ch === ']' || ch === '}') && depth > 0) depth--;
    if (ch === '\n' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * Return the set of command names declared under tool.setuptools.cmdclass.
 */
function extractCmdclassCommands(content) {
  const commands = new Set();
  let table = [];
  for (const rawLine of splitStatements(content)) {
    const line = stripComment(rawLine).replace(/\r/g, '').trim();
    if (!line) continue;
    const header = /^\[\[?(.+?)\]\]?$/.exec(line);
    if (header && findAssign(line) === -1) {
      table = splitKey(header[1]);
      continue;
    }
    const eq = findAssign(line);
    if (eq <= 0) continue;
    const full = table.concat(splitKey(line.slice(0, eq)));
    const value = line.slice(eq + 1);
    const candidates = [full];
    for (const k of inlineTableKeys(value)) candidates.push(full.concat(k));
    for (const c of candidates) {
      const p = c.join('.');
      if (p.startsWith(CMDCLASS_PATH + '.') && c.length === 4) commands.add(c[3]);
    }
  }
  return commands;
}

function scanPyprojectCmdclass(targetPath) {
  const file = path.join(targetPath, 'pyproject.toml');
  let content;
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size === 0 || st.size > MAX_PYPROJECT_SIZE) return [];
    content = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  const declared = extractCmdclassCommands(content);
  const installRelated = [...declared].filter(c => INSTALL_TIME_COMMANDS.has(c));
  if (installRelated.length === 0) return [];
  const severity = installRelated.includes('install') || installRelated.includes('develop') ? 'CRITICAL' : 'HIGH';
  const relFile = path.relative(targetPath, file);
  return [{
    type: 'pyast_setup_cmdclass_override',
    severity,
    message: `${relFile}: [tool.setuptools.cmdclass] overrides ${installRelated.join(', ')} - install-time RCE vector (same as setup(cmdclass=...); pybitjs 2026-08).`,
    file: relFile
  }];
}

module.exports = { scanPyprojectCmdclass, _internal: { extractCmdclassCommands } };
