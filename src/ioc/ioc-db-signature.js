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
 * Authenticity of the downloaded IOC database (ioc-db release).
 *
 * Threat model: whoever can modify the release assets (a stolen token with contents:write, a
 * compromised action in another workflow) could otherwise remove the entries of their own
 * malware from every user's database, or add legitimate packages to cause false positives.
 * A format check cannot see that. The database is therefore described by a manifest
 * { format, asset, sha256, size, npmEntries, builtAt } signed with Ed25519; the private key
 * lives only in the `ioc-db` GitHub Environment (master only), used by the publish job alone.
 * Verification uses node:crypto, no dependency (a Sigstore attestation would need a verifier
 * library at runtime).
 *
 * Rollback: a validly signed but OLD manifest (a database without the latest IOCs) is refused
 * when it is older than MAX_MANIFEST_AGE_MS or older than the copy already installed.
 */

const crypto = require('crypto');
const fs = require('fs');
const { IOC_DB_PUBLIC_KEY } = require('./ioc-db-public-key.js');

const MANIFEST_FORMAT = 1;
// A database below this many npm entries is refused (truncated, emptied or replaced asset):
// keeping the previous copy is safer than scanning with a gutted list.
const MIN_COMPACT_PACKAGES = 10000;
const MAX_MANIFEST_AGE_MS = 30 * 24 * 60 * 60 * 1000;
// Content-addressed asset name: a new database is uploaded under a new name BEFORE its manifest,
// so a client never pairs a new manifest with an old asset mid-update.
const ASSET_NAME = /^iocs-compact-[0-9a-f]{12}\.json\.gz$/;

/**
 * Verify a manifest and its detached signature.
 * @param {Buffer} manifestBytes - exact bytes that were signed
 * @param {string|Buffer} signature - base64 (string) or raw signature bytes
 * @param {Object} [opts]
 * @param {string} [opts.publicKey] - PEM, defaults to the embedded key
 * @param {number} [opts.now]
 * @param {string|null} [opts.previousBuiltAt] - builtAt of the installed copy (anti-rollback)
 * @returns {Object} the parsed manifest
 * @throws {Error} on any failure
 */
function verifyManifest(manifestBytes, signature, opts = {}) {
  const publicKey = opts.publicKey || IOC_DB_PUBLIC_KEY;
  if (!publicKey) throw new Error('no IOC database public key configured');
  const sig = Buffer.isBuffer(signature) ? signature : Buffer.from(String(signature).trim(), 'base64');
  let ok;
  try {
    ok = crypto.verify(null, manifestBytes, crypto.createPublicKey(publicKey), sig);
  } catch (e) {
    throw new Error('IOC database signature check failed: ' + e.message, { cause: e });
  }
  if (!ok) throw new Error('IOC database signature is invalid');

  let m;
  try { m = JSON.parse(manifestBytes.toString('utf8')); } catch { throw new Error('IOC database manifest is not JSON'); }
  if (!m || m.format !== MANIFEST_FORMAT) throw new Error('unsupported IOC database manifest format');
  if (typeof m.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(m.sha256)) throw new Error('manifest sha256 missing');
  if (!Number.isInteger(m.size) || m.size <= 0) throw new Error('manifest size missing');
  if (typeof m.asset !== 'string' || !ASSET_NAME.test(m.asset)) throw new Error('manifest asset name invalid');
  if (!Number.isInteger(m.npmEntries) || m.npmEntries <= 0) throw new Error('manifest npmEntries missing');
  const built = Date.parse(m.builtAt);
  if (!Number.isFinite(built)) throw new Error('manifest builtAt missing');
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  if (now - built > MAX_MANIFEST_AGE_MS) throw new Error(`IOC database manifest is too old (${m.builtAt})`);
  if (built - now > 24 * 60 * 60 * 1000) throw new Error(`IOC database manifest is dated in the future (${m.builtAt})`);
  if (opts.previousBuiltAt) {
    const prev = Date.parse(opts.previousBuiltAt);
    if (Number.isFinite(prev) && built < prev) throw new Error(`IOC database manifest is older than the installed copy (${m.builtAt} < ${opts.previousBuiltAt})`);
  }
  return m;
}

/**
 * Sign a manifest (publish job only; the key comes from the ioc-db environment secret).
 * @param {Buffer} manifestBytes
 * @param {string} privateKeyPem
 * @returns {string} base64 signature
 */
function signManifest(manifestBytes, privateKeyPem) {
  return crypto.sign(null, manifestBytes, crypto.createPrivateKey(privateKeyPem)).toString('base64');
}

/**
 * Number of npm entries in a compact IOC file (wildcards + versioned), or -1 if unreadable.
 * @param {string} p
 * @returns {number}
 */
function countCompactPackages(p) {
  try {
    const data = JSON.parse(fs.readFileSync(p, 'utf8'));
    const size = v => Array.isArray(v) ? v.length : (v && typeof v === 'object' ? Object.keys(v).length : 0);
    return size(data.wildcards) + size(data.versioned);
  } catch {
    return -1;
  }
}

module.exports = { verifyManifest, signManifest, countCompactPackages, MIN_COMPACT_PACKAGES, MANIFEST_FORMAT, MAX_MANIFEST_AGE_MS, ASSET_NAME };
