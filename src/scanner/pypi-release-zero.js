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
 * F2-PyPI — Release-Zero detection (PEP 440 variant of release-zero.js).
 *
 * Created v2.11.47 to mirror npm's release-zero.js for the PyPI ecosystem.
 *
 * Threat model: an attacker publishes a brand-new package with version 0.0.0
 * (or any 0.x.x variant) as a lure or as a ship-as-vulnerable placeholder.
 * On its own a v0.x.x is noise (many legit early-stage projects sit there
 * forever), so we conjunction-gate with `age_days < 30`: a recently-published
 * 0.x.x is suspicious; an abandoned 0.x.x from 2017 is not.
 *
 * PyPI-specific differences vs npm release-zero.js:
 *  - PEP 440 versions, not semver. We accept 0, 0.1, 0.0.0, 0.1.0a1,
 *    0.0.0.dev1, 0.1.0rc2, 0.1.0.post1 — anything that starts with "0"
 *    or "0.0..." in the release/pre/dev segment.
 *  - No `preinstall`/`postinstall` lifecycle hook concept in PyPI manifests.
 *    The functionally-equivalent vector — `setup.py cmdclass` override —
 *    is already covered by PYAST-001. We don't double-detect here.
 *  - Conjunction is just `recently published` (no script check).
 */

// Match a PEP 440 "release segment" that is exactly 0 in every component.
// Accepts: 0 | 0.0 | 0.0.0 | 0.0.0.0
// Optional pre/post/dev segment: a1 | b2 | rc3 | .dev1 | .post1
// Also allows the rare epoch prefix `0!` (PEP 440 §epoch).
const PYPI_RELEASE_ZERO_RE = /^(?:0!)?0(?:\.0)*(?:[abc]\d+|rc\d+|\.dev\d+|\.post\d+)?$/i;

const RECENT_PUBLISH_THRESHOLD_DAYS = 30;

/**
 * @param {string} version - PyPI version string from registry meta (latest_version).
 * @param {object} pypiRegistryMeta - { age_days: number | null, ... }.
 * @returns {object | null} threat object or null.
 */
function checkPyPIReleaseZero(version, pypiRegistryMeta) {
  if (typeof version !== 'string' || version.length === 0) return null;
  if (!PYPI_RELEASE_ZERO_RE.test(version)) return null;
  if (!pypiRegistryMeta || typeof pypiRegistryMeta !== 'object') return null;

  const ageDays = pypiRegistryMeta.age_days;
  if (typeof ageDays !== 'number' || ageDays >= RECENT_PUBLISH_THRESHOLD_DAYS) return null;

  return {
    type: 'pypi_release_zero',
    severity: 'MEDIUM',
    message: 'PyPI package latest version is "' + version + '" (release-zero) and was first published only ' + ageDays + ' day(s) ago — possible lure / ship-as-vulnerable / typosquat-staging pattern. setup.py cmdclass install-time hooks are covered separately by PYAST-001.',
    file: 'pyproject.toml',
    count: 1,
    version,
    age_days: ageDays
  };
}

module.exports = {
  checkPyPIReleaseZero,
  _internal: { PYPI_RELEASE_ZERO_RE, RECENT_PUBLISH_THRESHOLD_DAYS }
};
