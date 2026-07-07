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

/**
 * npm registry authentication (2026-06-13).
 *
 * A supply-chain scanner fetches thousands of brand-new, never-CDN-cached
 * packages; anonymous registry.npmjs.org traffic gets aggressively 429-throttled
 * per-IP (observed: ~500/h of 429s at <1 req/s, scans stalling 20-46s waiting on
 * metadata tokens). An authenticated token raises the per-account limit and
 * de-anonymizes us.
 *
 * Token resolution (first hit wins), memoized for the process lifetime:
 *   1. env MUADDIB_NPM_TOKEN  (canonical — set via systemd EnvironmentFile / drop-in)
 *   2. env NPM_TOKEN          (common fallback)
 *   3. .npmrc  //registry.npmjs.org/:_authToken=...  (npm-standard; cwd, $HOME, /home/muaddib)
 *
 * Auth is applied ONLY to registry.npmjs.org requests — other hosts (pypi.org,
 * api.npmjs.org, replicate.npmjs.com) get NO header, so the token can never leak
 * to a third-party host. With no token configured the header set is empty and
 * behaviour is identical to the previous anonymous path.
 */

const fs = require('fs');
const path = require('path');

const AUTH_HOSTS = new Set(['registry.npmjs.org']);

let _resolved = false;
let _token = null;
let _source = null;

function _fromNpmrc() {
  const files = [
    process.env.MUADDIB_NPMRC,
    path.join(process.cwd(), '.npmrc'),
    process.env.HOME ? path.join(process.env.HOME, '.npmrc') : null,
    '/home/muaddib/.npmrc',
  ].filter(Boolean);
  for (const f of files) {
    let txt;
    try { txt = fs.readFileSync(f, 'utf8'); } catch { continue; }
    // npm-standard line: //registry.npmjs.org/:_authToken=<token>
    const m = txt.match(/^\s*\/\/registry\.npmjs\.org\/:_authToken\s*=\s*(.+?)\s*$/m);
    if (m) return { token: m[1].replace(/^["']|["']$/g, ''), source: `npmrc:${f}` };
  }
  return null;
}

function getNpmToken() {
  if (_resolved) return _token;
  _resolved = true;
  const env = (process.env.MUADDIB_NPM_TOKEN || process.env.NPM_TOKEN || '').trim();
  if (env) {
    _token = env;
    _source = process.env.MUADDIB_NPM_TOKEN ? 'env:MUADDIB_NPM_TOKEN' : 'env:NPM_TOKEN';
    return _token;
  }
  const rc = _fromNpmrc();
  if (rc) { _token = rc.token; _source = rc.source; }
  return _token;
}

/** {enabled, source, last4} — for the one-time boot log. NEVER returns the token. */
function npmAuthStatus() {
  const t = getNpmToken();
  return { enabled: !!t, source: t ? _source : null, last4: t ? String(t).slice(-4) : null };
}

let _logged = false;
function logAuthStatusOnce(logger = console) {
  if (_logged) return;
  _logged = true;
  const s = npmAuthStatus();
  if (s.enabled) {
    logger.log(`[REGISTRY-AUTH] npm registry auth ENABLED (source=${s.source}, token …${s.last4})`);
  } else {
    logger.warn('[REGISTRY-AUTH] npm registry auth DISABLED — anonymous registry.npmjs.org (set MUADDIB_NPM_TOKEN); expect heavier 429 throttling.');
  }
}

/**
 * Headers to merge into a registry request. Empty object for non-npm hosts or
 * when no token is configured (→ anonymous, unchanged behaviour).
 */
function registryAuthHeaders(url) {
  // First call doubles as the boot confirmation in the journal.
  logAuthStatusOnce();
  let host;
  try { host = new URL(url).hostname; } catch { return {}; }
  if (!AUTH_HOSTS.has(host)) return {};
  const t = getNpmToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

// Test seam: reset memoized resolution (so a test can flip MUADDIB_NPM_TOKEN).
function _resetForTests() { _resolved = false; _token = null; _source = null; _logged = false; }

module.exports = { registryAuthHeaders, getNpmToken, npmAuthStatus, logAuthStatusOnce, _resetForTests };
