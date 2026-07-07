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

const { formatOutput } = require('../output-formatter.js');
let sendWebhook;
try {
  sendWebhook = require('../webhook.js').sendWebhook;
} catch {
  sendWebhook = async () => {}; // no-op quand webhook.js absent (npm package)
}

/**
 * Format and output scan results (CLI, webhook, exit code).
 * @param {object} result - Full scan result object
 * @param {object} options - CLI options
 * @param {object} processed - Processed data from processor
 * @returns {Promise<number>} Exit code (0 = clean, >0 = number of failing threats, max 125)
 */
async function output(result, options, processed) {
  const { deduped, enrichedThreats, sandboxData, pythonInfo, breakdown,
          mostSuspiciousFile, maxFileScore, packageScore, globalRiskScore } = processed;

  formatOutput(result, options, {
    spinner: null, sandboxData, mostSuspiciousFile, maxFileScore,
    packageScore, globalRiskScore, deduped, enrichedThreats,
    pythonInfo, breakdown, targetPath: result.target
  });

  // Send webhook if configured
  if (options.webhook && enrichedThreats.length > 0) {
    try {
      await sendWebhook(options.webhook, result);
      console.log(`[OK] Alert sent to webhook`);
    } catch (err) {
      console.log(`[WARN] Webhook send failed: ${err.message}`);
    }
  }

  // Calculate exit code based on fail level
  const failLevel = options.failLevel || 'high';
  if (failLevel === 'none') return 0;
  const severityLevels = {
    critical: ['CRITICAL'],
    high: ['CRITICAL', 'HIGH'],
    medium: ['CRITICAL', 'HIGH', 'MEDIUM'],
    low: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  };

  const levelsToCheck = severityLevels[failLevel] || severityLevels.high;
  const failingThreats = deduped.filter(t => levelsToCheck.includes(t.severity));

  return Math.min(failingThreats.length, 125);
}

module.exports = { output };
