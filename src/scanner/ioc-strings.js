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

// ── String IOC scanner (YARA-style) ──
//
// Scans every source file under targetPath for literal substrings flagged
// in iocs/string-iocs.yaml. Designed to catch supply-chain malware that
// reuses unique stagers / XOR keys / RAT command names across campaigns
// (e.g. Axios npm 2026-03 dropped 8 such artifacts in setup.js, and the
// XOR key `OrDeR_7077` is shared with the documented csec autodelete
// family — see project_axios_2026_yara.md and project_detection_gap_csec_xor_autodelete.md).
//
// Why YARA-style strings instead of expanding the existing AST scanner:
// modern malware (2026) defeats sandboxes by design (hardware fingerprinting,
// C2-side detection, in-memory eval with keys from response headers). Static
// string IOCs are the only layer that wins regardless of execution. Cf.
// feedback_static_over_dynamic.md.
//
// Severity: rule entry severity is CRITICAL by default. The YAML file may
// override per-string. Single match = full score (these strings are unique
// by construction — see inclusion criteria documented at the top of
// iocs/string-iocs.yaml).

const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');
const { findFiles } = require('../utils.js');
const { getMaxFileSize } = require('../shared/constants.js');

// Source extensions worth scanning. We include common build artifacts
// (.cjs, .mjs) plus TypeScript and Python because the same campaigns
// often span ecosystems.
const SCAN_EXTENSIONS = ['.js', '.cjs', '.mjs', '.ts', '.tsx', '.py'];

// Per-file cap on number of distinct string-IOC matches reported. One
// rule fire per (file, string) tuple is enough; multiple matches in the
// same file would inflate the report without adding signal.
const MAX_MATCHES_PER_FILE = 10;

// Per-scan cap on total findings. Prevents an adversarial sample (e.g.
// a benign repository that happens to contain a writeup quoting all the
// IOCs) from flooding the report.
const MAX_TOTAL_FINDINGS = 200;

async function scanIocStrings(targetPath) {
  const threats = [];
  const iocs = loadCachedIOCs();
  const stringIocs = Array.isArray(iocs.stringIocs) ? iocs.stringIocs : [];
  if (stringIocs.length === 0) return threats;

  if (!fs.existsSync(targetPath)) return threats;

  // Pre-build a flat list of {literal, meta} for fast iteration.
  // Single substring match is decisive (per inclusion criteria), so a
  // simple String.includes loop is the right primitive here. Aho-Corasick
  // would be needed only if the IOC list grew past ~10 K entries.
  const needles = stringIocs;

  // Walk: scan the package source (everything outside node_modules) AND
  // also walk node_modules (a malicious dep can carry the IOCs even if
  // the host package is clean). EXCLUDED_DIRS in utils.js skips
  // node_modules by default, so we do two findFiles passes with
  // explicit excludedDirs lists.
  const sourceFiles = findFiles(targetPath, { extensions: SCAN_EXTENSIONS });

  // node_modules sweep: same extensions, no recursion guard issues since
  // findFiles already handles symlink loops + maxDepth fallback on Windows.
  const nodeModulesPath = path.join(targetPath, 'node_modules');
  const nodeModulesFiles = fs.existsSync(nodeModulesPath)
    ? findFiles(nodeModulesPath, { extensions: SCAN_EXTENSIONS, excludedDirs: ['.git', '.muaddib-cache'] })
    : [];

  const allFiles = sourceFiles.concat(nodeModulesFiles);

  for (const filePath of allFiles) {
    if (threats.length >= MAX_TOTAL_FINDINGS) break;
    let content;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > getMaxFileSize()) continue;
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    if (!content) continue;

    const seenInFile = new Set();
    for (const ioc of needles) {
      if (seenInFile.size >= MAX_MATCHES_PER_FILE) break;
      if (seenInFile.has(ioc.string)) continue;
      if (!content.includes(ioc.string)) continue;
      seenInFile.add(ioc.string);
      const rel = path.relative(targetPath, filePath);
      threats.push({
        type: 'ioc_string_match',
        severity: ioc.severity || 'CRITICAL',
        message: `String IOC match: "${ioc.string}" (campaign: ${ioc.campaign || 'unknown'}) — ${ioc.description || 'see source'}`,
        file: rel,
        evidence: ioc.string,
        campaign: ioc.campaign,
        source: ioc.source
      });
      if (threats.length >= MAX_TOTAL_FINDINGS) break;
    }
  }

  return threats;
}

module.exports = { scanIocStrings, SCAN_EXTENSIONS, MAX_MATCHES_PER_FILE, MAX_TOTAL_FINDINGS };
