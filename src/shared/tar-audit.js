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

/*
 * Tar member audit for PARTIAL extractions.
 *
 * Threat model (2026-11-14): a tarball carrying one member that the system `tar` refuses
 * (a `..` name, or a file written through a symlink member declared earlier) makes GNU tar
 * and bsdtar extract every other member and exit non-zero. Before this fix the non-zero exit
 * threw out of extractArchive, the monitor logged a generic scan error and the package was
 * NEVER scanned, while `npm install` skips the refused entry and installs the rest (verified
 * 2026-11-14 with a real install: npm 10.9.0 Linux and 11.14.1 Windows exit 0, require()
 * loads the package, nothing is written outside it).
 * The extractor now keeps what was extracted, and this module names the members that made
 * tar fail, from the raw headers, so the result does not depend on the tar implementation
 * (GNU and bsdtar word their refusals differently).
 *
 * Only called on the failure path: a tar that exits 0 extracted everything, which is then
 * scanned as before, so this costs nothing on normal packages.
 *
 * What is NOT flagged: a symlink whose TARGET is absolute or escapes (Python venvs ship
 * `bin/python -> /usr/bin/python3`; census of 3242 corpus tarballs, 2026-11-14). Only a member
 * NAME that escapes, a write through a symlink, or a hardlink to an escaping target is flagged:
 * `npm pack` and `python -m build` never produce those.
 */

const fs = require('fs');
const zlib = require('zlib');

// Bounded: the audit decompresses in memory. 256 MB covers any npm tarball the monitor scans
// (the 10 MB unpacked size cap applies first); above it the audit reports `truncated`.
const MAX_AUDIT_BYTES = 256 * 1024 * 1024;
const MAX_REPORTED_MEMBERS = 20;
const MAX_MEMBERS = 200000;

function cString(buf, start, len) {
  const slice = buf.subarray(start, start + len);
  const nul = slice.indexOf(0);
  return (nul === -1 ? slice : slice.subarray(0, nul)).toString('utf8');
}

// Octal size field, or GNU base-256 when the high bit of the first byte is set.
function parseSize(header) {
  const field = header.subarray(124, 136);
  if (field[0] & 0x80) {
    let n = 0;
    for (let i = 1; i < field.length; i++) n = n * 256 + field[i];
    return n;
  }
  const s = cString(header, 124, 12).trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) return NaN;
  return parseInt(s, 8);
}

// PAX extended header records: "<len> <key>=<value>\n".
function parsePax(data) {
  const out = {};
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp === -1) break;
    const len = parseInt(data.subarray(off, sp).toString('ascii'), 10);
    if (!Number.isFinite(len) || len <= 0 || off + len > data.length) break;
    const rec = data.subarray(sp + 1, off + len - 1).toString('utf8');
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    off += len;
  }
  return out;
}

function segmentsOf(name) {
  return name.replace(/\\/g, '/').split('/').filter(s => s !== '' && s !== '.');
}

function isAbsoluteName(name) {
  return /^[/\\]/.test(name) || /^[A-Za-z]:/.test(name);
}

/**
 * Audit the members of an uncompressed tar buffer.
 * @param {Buffer} buf
 * @returns {{ members: number, hostileMembers: Array<{name: string, reason: string, via?: string}>, truncated: boolean }}
 */
function auditTarBuffer(buf) {
  const hostileMembers = [];
  const symlinks = new Set();
  let members = 0;
  let truncated = false;
  let off = 0;
  let longName = null;
  let longLink = null;
  let pax = null;
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header[0] === 0 && header.every(b => b === 0)) break;
    const size = parseSize(header);
    if (!Number.isFinite(size) || size < 0) { truncated = true; break; }
    const typeByte = header[156];
    const type = typeByte === 0 ? '0' : String.fromCharCode(typeByte);
    const dataStart = off + 512;
    const data = buf.subarray(dataStart, Math.min(buf.length, dataStart + size));
    off = dataStart + Math.ceil(size / 512) * 512;

    if (type === 'L') { longName = cString(data, 0, data.length); continue; }
    if (type === 'K') { longLink = cString(data, 0, data.length); continue; }
    if (type === 'x') { pax = parsePax(data); continue; }
    if (type === 'g') continue;

    let name = cString(header, 0, 100);
    const isUstar = header.subarray(257, 262).toString('latin1') === 'ustar';
    if (isUstar) {
      const prefix = cString(header, 345, 155);
      if (prefix) name = prefix + '/' + name;
    }
    let linkname = cString(header, 157, 100);
    if (longName !== null) name = longName;
    if (longLink !== null) linkname = longLink;
    if (pax && typeof pax.path === 'string') name = pax.path;
    if (pax && typeof pax.linkpath === 'string') linkname = pax.linkpath;
    longName = null; longLink = null; pax = null;

    members++;
    if (members > MAX_MEMBERS) { truncated = true; break; }

    const segs = segmentsOf(name);
    const key = segs.join('/');
    let finding = null;
    if (isAbsoluteName(name)) {
      finding = { name, reason: 'absolute-name' };
    } else if (segs.includes('..')) {
      finding = { name, reason: 'dot-dot-name' };
    } else {
      for (let i = 1; i < segs.length; i++) {
        const parent = segs.slice(0, i).join('/');
        if (symlinks.has(parent)) { finding = { name, reason: 'write-through-symlink', via: parent }; break; }
      }
    }
    if (!finding && type === '1' && (isAbsoluteName(linkname) || segmentsOf(linkname).includes('..'))) {
      finding = { name, reason: 'hardlink-escape', via: linkname };
    }
    if (finding && hostileMembers.length < MAX_REPORTED_MEMBERS) hostileMembers.push(finding);

    // A later member with the same path replaces the symlink on disk.
    if (type === '2') symlinks.add(key);
    else symlinks.delete(key);
  }
  if (off > buf.length) truncated = true;
  return { members, hostileMembers, truncated };
}

/**
 * Audit a .tar.gz on disk. Never throws: an unreadable archive yields `error`.
 * Truncated gzip streams are decompressed as far as they go (Z_SYNC_FLUSH).
 * @param {string} tgzPath
 * @returns {{ members: number, hostileMembers: Array, truncated: boolean, error?: string }}
 */
function auditTarGz(tgzPath) {
  let buf;
  try {
    const raw = fs.readFileSync(tgzPath);
    buf = zlib.gunzipSync(raw, { maxOutputLength: MAX_AUDIT_BYTES, finishFlush: zlib.constants.Z_SYNC_FLUSH });
  } catch (err) {
    return { members: 0, hostileMembers: [], truncated: true, error: (err && err.message ? err.message : String(err)).slice(0, 200) };
  }
  return auditTarBuffer(buf);
}

module.exports = { auditTarGz, auditTarBuffer, MAX_AUDIT_BYTES };
