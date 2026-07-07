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
 * Trusted dep-diff scanner — detects supply-chain injection via NEW dependencies
 * added between two adjacent published versions of an npm package.
 *
 * Threat model: a compromised maintainer account publishes a patch bump that
 * silently introduces a fresh (or unknown-aged) dependency carrying the actual
 * payload. Reference incident: axios 1.14.0 → 1.14.1 adding `plain-crypto-js`
 * on 2026-03-30. The hostile dep is short-aged and unrecognised, but the host
 * package itself is reputable, so popularity-based filters miss it.
 *
 * Opt-in by design: the scanner needs registry I/O for the previous version's
 * dependency list, which is meaningless for offline CLI audits of a frozen
 * node_modules. It only runs when explicitly enabled via
 *   options.trustedDepDiff === true  OR
 *   options.monitorMode === true
 * The monitor pipeline sets both via the worker thread context.
 *
 * Findings emitted (rule IDs already registered in src/rules/index.js:2598-2621):
 *   - trusted_new_unknown_dependency  (CRITICAL) — added dep < 7d old OR age unknown
 *   - trusted_new_dependency          (HIGH)     — added dep ≥ 7d old
 *
 * Both types are in HIGH_CONFIDENCE_MALICE_TYPES (classify.js:60), which means
 * downstream reputation attenuation is bypassed — the finding's severity reaches
 * the webhook decision uncapped.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { acquireRegistrySlot, releaseRegistrySlot, signal429 } = require('../shared/http-limiter.js');

const TRUSTED_DEP_AGE_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const PACKUMENT_TIMEOUT_MS = 10_000;
const DEP_AGE_TIMEOUT_MS = 5_000;

/**
 * Minimal HTTPS GET with follow-redirects and timeout.
 * Local copy (not shared with monitor/ingestion.js) to keep the scanner
 * self-contained — the monitor module pulls this scanner, not the reverse.
 */
function httpsGet(url, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        const location = res.headers.location;
        if (!location) return reject(new Error(`Redirect without Location for ${url}`));
        return httpsGet(location, timeoutMs).then(resolve, reject);
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout for ${url}`));
    });
  });
}

/**
 * Core dep-diff logic — extracted verbatim from monitor/ingestion.js#checkTrustedDepDiff
 * with no behavioural change: same findings shape, same rule_ids, same severity
 * mapping, same 7-day age cutoff. Tests covering the original implementation
 * (tests/integration/monitor.test.js:8929-9067) cover this directly via the
 * `checkTrustedDepDiff` alias export below.
 *
 * @param {string} name - Package name
 * @param {string} newVersion - Newly published version
 * @returns {Promise<Array>} findings (empty on error or no new deps)
 */
async function checkDepDiff(name, newVersion) {
  const findings = [];
  try {
    // Route through the shared http-limiter (concurrency + token bucket + 429
    // backoff) instead of a raw uncoordinated httpsGet — this scanner runs inside
    // the monitor worker_threads, where an unbounded fetch joins the per-worker
    // 429 storm. finally-release keeps the semaphore balanced even on reject.
    await acquireRegistrySlot();
    let body;
    try {
      body = await httpsGet(`https://registry.npmjs.org/${encodeURIComponent(name)}`, PACKUMENT_TIMEOUT_MS);
    } finally {
      releaseRegistrySlot();
    }
    const packument = JSON.parse(body);

    if (!packument.versions || !packument.time) return findings;

    // Sort versions by publish time (not semver — handles prereleases correctly)
    const timeMap = packument.time;
    const versionKeys = Object.keys(packument.versions)
      .filter(v => timeMap[v])
      .sort((a, b) => new Date(timeMap[a]) - new Date(timeMap[b]));

    const newIdx = versionKeys.indexOf(newVersion);
    if (newIdx <= 0) return findings; // First version or not found

    const prevVersion = versionKeys[newIdx - 1];

    const prevDeps = (packument.versions[prevVersion] && packument.versions[prevVersion].dependencies) || {};
    const newDeps = (packument.versions[newVersion] && packument.versions[newVersion].dependencies) || {};

    const addedDeps = Object.keys(newDeps).filter(dep => !(dep in prevDeps));
    if (addedDeps.length === 0) return findings;

    console.log(`[SCANNER] trusted-dep-diff: ${name} ${prevVersion} → ${newVersion}: +${addedDeps.length} new dep(s): ${addedDeps.join(', ')}`);

    for (const dep of addedDeps) {
      let ageMs = null;
      try {
        await acquireRegistrySlot();
        let depBody;
        try {
          depBody = await httpsGet(`https://registry.npmjs.org/${encodeURIComponent(dep)}`, DEP_AGE_TIMEOUT_MS);
        } finally {
          releaseRegistrySlot();
        }
        const depData = JSON.parse(depBody);
        const created = depData.time && depData.time.created;
        if (created) {
          ageMs = Date.now() - new Date(created).getTime();
        }
      } catch (err) {
        if (/HTTP 429/.test(err.message)) { try { signal429(); } catch { /* limiter best-effort */ } }
        console.log(`[SCANNER] trusted-dep-diff: could not check age of dependency ${dep}: ${err.message}`);
      }

      if (ageMs === null || ageMs < TRUSTED_DEP_AGE_THRESHOLD_MS) {
        const ageDays = ageMs !== null ? Math.floor(ageMs / 86400000) : 'unknown';
        findings.push({
          type: 'trusted_new_unknown_dependency',
          severity: 'CRITICAL',
          confidence: ageMs === null ? 'medium' : 'high',
          file: 'package.json',
          message: `TRUSTED package ${name} added unknown dependency ${dep} (age: ${ageDays}d) in version ${prevVersion} → ${newVersion}`,
          rule_id: 'MUADDIB-TRUSTED-001',
          mitre: 'T1195.002',
          dep,
          depAgeDays: ageDays,
          prevVersion,
          newVersion
        });
      } else {
        const ageDays = Math.floor(ageMs / 86400000);
        findings.push({
          type: 'trusted_new_dependency',
          // FPR audit 2026-06: a trusted package adding an ESTABLISHED (>=7d) dependency
          // is an audit/surface-change signal ("a verifier"), not malice — it produced
          // ~169 FPs. Downgraded HIGH->MEDIUM so it no longer alone meets the tier-1b
          // corroboration bar. The real account-takeover case (new/unknown dep <7d) is
          // the separate CRITICAL `trusted_new_unknown_dependency` (HC type) and is intact.
          severity: 'MEDIUM',
          confidence: 'medium',
          file: 'package.json',
          message: `TRUSTED package ${name} added new dependency ${dep} (age: ${ageDays}d) in version ${prevVersion} → ${newVersion}`,
          rule_id: 'MUADDIB-TRUSTED-002',
          mitre: 'T1195.002',
          dep,
          depAgeDays: ageDays,
          prevVersion,
          newVersion
        });
      }
    }

    return findings;
  } catch (err) {
    if (/HTTP 429/.test(err.message)) { try { signal429(); } catch { /* limiter best-effort */ } }
    console.log(`[SCANNER] trusted-dep-diff: check failed for ${name}@${newVersion}: ${err.message}`);
    return findings;
  }
}

/**
 * Pipeline entry point. Called by src/pipeline/executor.js alongside the other
 * 17 scanners (Promise.allSettled). Gated by an explicit opt-in option to keep
 * CLI audits offline-safe.
 *
 * @param {string} targetPath - Extracted package directory
 * @param {object} options    - Pipeline options. Honors:
 *   - options.trustedDepDiff  - explicit opt-in (preferred)
 *   - options.monitorMode     - opt-in for the monitor daemon path
 *   - options.name            - package name override (avoids re-reading package.json)
 *   - options.version         - version override
 *   - options.ecosystem       - 'npm' | 'pypi' | ... — scanner is npm-only
 * @returns {Promise<Array>}   findings array (always — never rejects)
 */
async function scanTrustedDepDiff(targetPath, options = {}) {
  if (!options.trustedDepDiff && !options.monitorMode) return [];
  if (options.ecosystem && options.ecosystem !== 'npm') return [];

  let name = options.name || null;
  let version = options.version || null;

  if (!name || !version) {
    const pkgJsonPath = path.join(targetPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return [];
    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    } catch {
      return [];
    }
    name = name || pkg.name;
    version = version || pkg.version;
  }

  if (!name || !version) return [];

  return await checkDepDiff(name, version);
}

module.exports = {
  scanTrustedDepDiff,
  checkDepDiff,
  // Backwards-compat alias for existing tests imported from monitor/ingestion.js
  checkTrustedDepDiff: checkDepDiff,
  TRUSTED_DEP_AGE_THRESHOLD_MS
};
