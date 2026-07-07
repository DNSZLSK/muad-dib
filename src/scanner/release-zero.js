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

// F2 — release_zero detection.
//
// Threat model: a package published as version "0.0.0" / "0.0" / "0" combined
// with EITHER a recent publish (<30d) OR install scripts is a strong indicator
// of a placeholder rushed to claim a namespace or test before a real payload
// is dropped. The conjunction avoids FPs on abandoned-but-honest placeholders.
//
// Inspired by GuardDog's npm/release_zero.py heuristic, tightened with the
// recent/install-script conjunction to keep FPR flat.

/**
 * @param {string|null} packageVersion - From local package.json
 * @param {object|null} scripts - From local package.json
 * @param {object|null} registryMeta - From getPackageMetadata (may be null offline)
 * @returns {object|null} Threat object or null if no detection
 */
function checkReleaseZero(packageVersion, scripts, registryMeta) {
  if (!packageVersion || typeof packageVersion !== 'string') return null;
  // Match exactly "0", "0.0", or "0.0.0" — not "0.0.0-beta", not "v0.0.0"
  if (!/^0(?:\.0(?:\.0)?)?$/.test(packageVersion)) return null;

  const hasInstallScript = !!(
    scripts && (scripts.preinstall || scripts.install || scripts.postinstall)
  );
  const ageDays = registryMeta && registryMeta.age_days;
  const isRecent = typeof ageDays === 'number' && ageDays >= 0 && ageDays < 30;

  if (!hasInstallScript && !isRecent) return null;

  const reason = hasInstallScript ? 'install_scripts' : 'recent_publish';
  const detail = hasInstallScript
    ? 'install scripts present'
    : 'published ' + ageDays + 'd ago';

  return {
    type: 'release_zero_package',
    severity: 'MEDIUM',
    message: 'Package version "' + packageVersion + '" with ' + detail
      + ' — namespace squat / pre-payload placeholder',
    file: 'package.json',
    count: 1,
    reason
  };
}

module.exports = { checkReleaseZero };
