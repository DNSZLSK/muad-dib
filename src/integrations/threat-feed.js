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

const { loadDetections } = require('../monitor.js');
const { getRule } = require('../rules/index.js');
const pkg = require('../../package.json');

const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 3,
  LOW: 1
};

/**
 * Compute a score and breakdown for a single detection.
 * Each finding type is mapped to a rule, and the severity weight is summed.
 */
function computeDetectionScore(detection) {
  const breakdown = [];
  let total = 0;

  const findings = detection.findings || [];
  for (const findingType of findings) {
    const rule = getRule(findingType);
    let severity;
    if (rule.id !== 'MUADDIB-UNK-001') {
      severity = rule.severity.toUpperCase();
    } else {
      severity = (detection.severity || 'MEDIUM').toUpperCase();
    }
    const points = SEVERITY_WEIGHTS[severity] || SEVERITY_WEIGHTS.MEDIUM;
    breakdown.push({
      type: findingType,
      points,
      rule: rule.id,
      severity
    });
    total += points;
  }

  breakdown.sort((a, b) => b.points - a.points);

  return {
    score: Math.min(total, 100),
    breakdown
  };
}

/**
 * Get the threat feed: load detections, filter, enrich with scores.
 */
function getFeed(options = {}) {
  const limit = options.limit || 50;
  const severityFilter = options.severity ? options.severity.toUpperCase() : null;
  const sinceFilter = options.since ? new Date(options.since) : null;

  const data = loadDetections();
  let detections = data.detections || [];

  // Filter by severity
  if (severityFilter) {
    detections = detections.filter(d => (d.severity || '').toUpperCase() === severityFilter);
  }

  // Filter by since date
  if (sinceFilter && !isNaN(sinceFilter.getTime())) {
    detections = detections.filter(d => new Date(d.first_seen_at) >= sinceFilter);
  }

  // Newest first, then limit
  detections = detections.slice().reverse().slice(0, limit);

  // Enrich with scores
  const feed = detections.map(d => {
    const { score, breakdown } = computeDetectionScore(d);
    return {
      package: d.package,
      version: d.version,
      ecosystem: d.ecosystem,
      severity: d.severity,
      first_seen: d.first_seen_at,
      findings: d.findings,
      score,
      breakdown
    };
  });

  return {
    generated_at: new Date().toISOString(),
    version: pkg.version,
    feed
  };
}

module.exports = { getFeed, computeDetectionScore, SEVERITY_WEIGHTS };
