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
 *
 * ── text_payload_as_font_asset scanner (MUADDIB-BINSRC-002) ──
 * The INVERSE blind spot: a file with a FONT/ASSET extension (.woff2/.woff/.ttf/.otf/.eot)
 * whose bytes are actually plaintext JavaScript. A font is binary by definition; the text
 * scanners are extension-gated to code (.js/.cjs/.mjs/.ts…) and never read a `.woff2`, so a
 * loader dropped as `public/fonts/fa-solid-400.woff2` is invisible to AST / obfuscation /
 * entropy / ioc-strings alike. This is the PolinRider (DPRK) carrier: the malicious task in
 * `.vscode/tasks.json` runs `node ./public/fonts/fa-solid-400.woff2`, but only the trigger was
 * caught — the payload body was never scanned. Detection is structural, not signature-based:
 * font extension + NOT a real font (no font magic, content sniffs as text) + JS tokens.
 * FP≈0 by construction — a legitimate font file is never printable JavaScript source; there is
 * no benign reason for a `.woff2` to contain `require(`/`child_process`/`_0x…`. CRITICAL.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');
const { sniffBinaryBuffer } = require('../shared/binary-sniff.js');

const SOURCE_EXTS = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts'];
// Font / binary-asset extensions that are ALWAYS binary when legitimate. A plaintext-JS file
// under one of these is a payload carrier hiding where no text scanner looks (PolinRider).
//
// Variant-resistance (chantier 2026-08): the carrier is NOT tied to a font extension. PolinRider
// dropped `public/fonts/fa-solid-400.woff2`, but renaming it `icon.png` / `chunk.wasm` /
// `vendor.dat` / `addon.node` re-hides the loader from every text scanner exactly the same way —
// none of these extensions are code-gated, and the `.woff2`-only list left that trivial rename
// open. The detection is structural, not signature-based, so it generalises at FP≈0: a REAL asset
// of any of these types is dense binary (a leading high/control byte or magic), which
// `sniffBinaryBuffer` flags → skipped below; only a file that sniffs as printable text AND carries
// JS exec tokens trips. The printable-ASCII font magics (wOF2/OTTO/'true'/'ttcf') still need the
// explicit FONT_MAGICS skip because they slip past the binary sniff; the image/wasm/blob magics
// (0x89PNG, 0xFFD8, 0x00asm, …) are non-printable and the sniff already catches them, so no magic
// entry is required for the new extensions. DELIBERATELY EXCLUDES text-legitimate asset extensions
// (.map source-maps, .svg, .json, .csv) — those are printable by design and would risk a FP.
const FONT_ASSET_EXTS = [
  '.woff2', '.woff', '.ttf', '.otf', '.eot',
  '.wasm', '.node', '.dat', '.data', '.bin',
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp'
];
// Real-font magic bytes at offset 0. A prefix match ⇒ genuine font ⇒ skip.
//   woff2='wOF2'  woff='wOFF'  otf/ttf-cff='OTTO'  ttf=0x00010000 | 'true'  collection='ttcf'
// .eot has no clean ASCII magic (its header is a binary uint32 size); a real .eot is dense
// binary and is excluded by the `sniffBinaryBuffer(...).binary` check below, not by magic here.
const FONT_MAGICS = [
  [0x77, 0x4f, 0x46, 0x32], // wOF2
  [0x77, 0x4f, 0x46, 0x46], // wOFF
  [0x4f, 0x54, 0x54, 0x4f], // OTTO
  [0x00, 0x01, 0x00, 0x00], // TrueType outlines
  [0x74, 0x72, 0x75, 0x65], // 'true'
  [0x74, 0x74, 0x63, 0x66]  // 'ttcf' (TrueType collection)
];
// DECISIVE JS / execution tokens — each one alone is FP≈0 by construction. The list was
// broadened (FONT_ASSET_EXTS now covers text-PLAUSIBLE extensions like .dat/.data/.bin), so the
// gate had to be tightened accordingly: weak corroborating tokens (`=>`, bare `child_process`,
// `process.env`, `Buffer.from`, `global.X`) were REMOVED because each appears in benign prose /
// config / data files — a single such hit under a .dat would have falsely fired CRITICAL. What
// remains is exec/loader machinery that a data file never contains: a require() call, an
// obfuscator hex variable, a spawn/eval/new-Function/atob call, or a CommonJS export. The
// PolinRider loader carries require(+spawn(+_0x — several of these — so tightening loses no
// detection. (The campaign marker `global.i="A8-…"` is now caught by ioc-strings, not here.)
const JS_PAYLOAD_SIGNS = [
  /\brequire\s*\(/,
  /\bmodule\.exports\b/,
  /\beval\s*\(/,
  /\bnew\s+Function\b/,
  /\batob\s*\(/,
  /_0x[0-9a-fA-F]{4,}/,
  /\bspawn\s*\(/
];
// Keep node_modules/.git out, but INCLUDE dist/build/out/output — payloads hide there and
// the default EXCLUDED_DIRS skips them.
const SCAN_EXCLUDED_DIRS = ['node_modules', '.git', '.muaddib-cache'];
const SNIFF_BYTES = 8192;

function _startsWith(buf, sig) {
  if (buf.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (buf[i] !== sig[i]) return false;
  return true;
}

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

  // ── BINSRC-002: font/asset extension whose content is plaintext JavaScript ──
  let fontFiles;
  try {
    fontFiles = findFiles(targetPath, { extensions: FONT_ASSET_EXTS, excludedDirs: SCAN_EXCLUDED_DIRS });
  } catch { fontFiles = []; }

  for (const file of fontFiles) {
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
    if (!buf || buf.length === 0) continue;

    // Genuine font → skip (magic at offset 0).
    if (FONT_MAGICS.some(sig => _startsWith(buf, sig))) continue;
    // Real binary content (dense/leading control byte, e.g. a magic-less .eot) → not our
    // text-payload case; skip (a truly binary non-font asset is not this threat).
    if (sniffBinaryBuffer(buf).binary) continue;

    // Font/asset extension, not a real asset, printable text → confirm it is JavaScript, not
    // stray text. One decisive token is enough; `.some()` short-circuits on the first hit.
    const text = buf.toString('latin1');
    if (!JS_PAYLOAD_SIGNS.some(re => re.test(text))) continue;

    const rel = path.relative(targetPath, file).replace(/\\/g, '/');
    threats.push({
      type: 'text_payload_as_font_asset',
      severity: 'CRITICAL',
      confidence: 'high',
      file: rel,
      message: `File "${rel}" has a binary-asset extension (font/image/wasm/blob) but its content is plaintext JavaScript (not a real asset; exec tokens present). Such an asset is binary by definition — a .woff2/.png/.wasm/.dat that is source code is a payload carrier hidden where text scanners never look (PolinRider/NullReceiver drops its loader as public/fonts/fa-solid-400.woff2; a rename to icon.png/chunk.wasm re-hides it identically).`,
      mitre: 'T1027.009'
    });
  }

  return threats;
}

module.exports = { scanBinarySource, SOURCE_EXTS, FONT_ASSET_EXTS };
