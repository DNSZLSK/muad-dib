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

const fs = require('fs');

// Minimal .env loader — zero dependency (the project forbids new runtime deps, so
// no dotenv). Parses KEY=VALUE lines, ignores blanks / # comments / `export `
// prefixes, strips one pair of surrounding quotes, and by default NEVER overwrites
// a variable already present in process.env (the real environment / systemd
// EnvironmentFile always wins over the on-disk file).

function parseDotEnv(content) {
  const out = {};
  for (const rawLine of String(content).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith('export ')) key = key.slice(7).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue; // skip malformed keys
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

/**
 * Load a .env file into process.env. Missing / unreadable file is a silent no-op
 * (the file is optional). Returns { loaded, keys } where keys are the names that
 * were actually applied.
 * @param {string} filePath
 * @param {{override?: boolean}} [opts] override=true replaces existing vars (default false)
 */
function loadDotEnv(filePath, opts = {}) {
  const override = opts.override === true;
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return { loaded: false, keys: [] };
  }
  const parsed = parseDotEnv(content);
  const applied = [];
  for (const [k, v] of Object.entries(parsed)) {
    if (override || process.env[k] === undefined) {
      process.env[k] = v;
      applied.push(k);
    }
  }
  return { loaded: true, keys: applied };
}

module.exports = { parseDotEnv, loadDotEnv };
