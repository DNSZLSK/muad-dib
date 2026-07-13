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

/**
 * binary_masquerading_as_source scanner (MUADDIB-BINSRC-001).
 *
 * Flags a file with a SOURCE extension whose bytes are actually binary — an executable,
 * archive, compressed blob, or custom container. This closes a real blind spot: the shared
 * `findFiles` excludes `dist/`, `build/`, `out/`, `output/` (bundler output), so the AST /
 * dataflow / entropy scanners never look there — yet that is exactly where a disguised
 * native payload hides (jscrambler@8.14.0 shipped its 7.8 MB native-binary container as
 * `dist/intro.js`, which every text scanner skipped). This scanner DELIBERATELY descends
 * into those dirs and reads only an 8 KB prefix per file, so it catches a multi-MB carrier
 * regardless of the 10 MB parse cap.
 *
 * FP≈0: minified/bundled `dist/*.js` is still printable text (low control-byte ratio, no leading
 * control byte); a lone NUL delimiter is tolerated — only dense binary content trips it. Severity
 * HIGH (not single-fire): on its
 * own it does not cross the alert threshold; it stacks with the install-hook signal, which
 * the COMPOUND-020 `install_native_drop_exec` correlator escalates to CRITICAL.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');
const { sniffBinaryBuffer } = require('../shared/binary-sniff.js');

const SOURCE_EXTS = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts'];
// Keep node_modules/.git out, but INCLUDE dist/build/out/output — payloads hide there and
// the default EXCLUDED_DIRS skips them.
const SCAN_EXCLUDED_DIRS = ['node_modules', '.git', '.muaddib-cache'];
const SNIFF_BYTES = 8192;

function scanBinarySource(targetPath) {
  const threats = [];
  if (!targetPath) return threats;

  let files;
  try {
    files = findFiles(targetPath, { extensions: SOURCE_EXTS, excludedDirs: SCAN_EXCLUDED_DIRS });
  } catch { return threats; }

  for (const file of files) {
    let buf;
    try {
      const fd = fs.openSync(file, 'r');
      try {
        const b = Buffer.alloc(SNIFF_BYTES);
        const n = fs.readSync(fd, b, 0, SNIFF_BYTES, 0);
        buf = b.subarray(0, n);
      } finally {
        fs.closeSync(fd);
      }
    } catch { continue; }

    const verdict = sniffBinaryBuffer(buf);
    if (!verdict.binary) continue;

    const rel = path.relative(targetPath, file).replace(/\\/g, '/');
    let sizeStr = '';
    try {
      const mb = fs.statSync(file).size / (1024 * 1024);
      if (mb >= 0.1) sizeStr = ` (${mb.toFixed(1)} MB)`;
    } catch { /* size best-effort */ }

    threats.push({
      type: 'binary_masquerading_as_source',
      severity: 'HIGH',
      confidence: 'high',
      file: rel,
      message: `File "${rel}" has a source extension but its content is ${verdict.format} — ${verdict.reason}${sizeStr}. A .js/.ts file that is actually binary is a payload carrier disguised as source (e.g. jscrambler@8.14.0 dist/intro.js) and evades text-based static analysis.`,
      mitre: 'T1027.002'
    });
  }

  return threats;
}

module.exports = { scanBinarySource, SOURCE_EXTS };
