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
 * monitor-feed.js — Aggregator for /monitor HTTP endpoints.
 *
 * Reads the same persistent files the monitor writes to data/ and exposes
 * three views consumed by muad-api -> muad-front:
 *   - buildMonitorDaily()         today's stats from daily-stats.json
 *   - buildMonitorWindow(range)   per-day rollup from scan-stats.json
 *   - buildMonitorAll()           all-time totals + detection breakdown
 *
 * Defensive: every read is wrapped — missing files yield zeros, never throws.
 */

const fs = require('fs');

const {
  DAILY_STATS_FILE,
  LAST_DAILY_REPORT_FILE,
  loadScanStats,
  loadStateRaw,
  loadLastDailyReportDate,
  getDetectionStats,
  getParisDateString
} = require('../monitor/state.js');

const pkg = require('../../package.json');

const SUPPORTED_RANGES = new Set(['7d', '30d', 'all']);
const RANGE_DAYS = { '7d': 7, '30d': 30 };

function safeReadJson(file) {
  try {
    if (!fs.existsSync(file)) return null;
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function emptyToday(date) {
  return {
    date,
    scanned: 0,
    clean: 0,
    suspect: 0,
    suspectByTier: { t1: 0, t1a: 0, t1b: 0, t2: 0, t3: 0 },
    errors: 0,
    errorsByType: { too_large: 0, tar_failed: 0, http_error: 0, timeout: 0, static_timeout: 0, other: 0 },
    totalTimeMs: 0,
    mlFiltered: 0,
    llmAnalyzed: 0,
    llmSuppressed: 0,
    changesStreamPackages: 0
  };
}

function readToday() {
  const date = getParisDateString();
  const data = safeReadJson(DAILY_STATS_FILE);
  if (!data || typeof data.scanned !== 'number') return emptyToday(date);
  return {
    date,
    scanned: data.scanned || 0,
    clean: data.clean || 0,
    suspect: data.suspect || 0,
    suspectByTier: {
      t1: (data.suspectByTier && data.suspectByTier.t1) || 0,
      t1a: (data.suspectByTier && data.suspectByTier.t1a) || 0,
      t1b: (data.suspectByTier && data.suspectByTier.t1b) || 0,
      t2: (data.suspectByTier && data.suspectByTier.t2) || 0,
      t3: (data.suspectByTier && data.suspectByTier.t3) || 0
    },
    errors: data.errors || 0,
    errorsByType: {
      too_large: (data.errorsByType && data.errorsByType.too_large) || 0,
      tar_failed: (data.errorsByType && data.errorsByType.tar_failed) || 0,
      http_error: (data.errorsByType && data.errorsByType.http_error) || 0,
      timeout: (data.errorsByType && data.errorsByType.timeout) || 0,
      static_timeout: (data.errorsByType && data.errorsByType.static_timeout) || 0,
      other: (data.errorsByType && data.errorsByType.other) || 0
    },
    totalTimeMs: data.totalTimeMs || 0,
    mlFiltered: data.mlFiltered || 0,
    llmAnalyzed: data.llmAnalyzed || 0,
    llmSuppressed: data.llmSuppressed || 0,
    changesStreamPackages: data.changesStreamPackages || 0
  };
}

function readLastReportAt() {
  const fromFile = safeReadJson(LAST_DAILY_REPORT_FILE);
  if (fromFile && typeof fromFile.lastReportDate === 'string') return fromFile.lastReportDate;
  const date = loadLastDailyReportDate();
  return date || null;
}

function readMonitorState() {
  try {
    return loadStateRaw() || {};
  } catch {
    return {};
  }
}

/**
 * Build the /monitor/daily payload.
 */
function buildMonitorDaily() {
  const today = readToday();
  const lastReportAt = readLastReportAt();
  const monitorState = readMonitorState();

  return {
    generated_at: new Date().toISOString(),
    engineVersion: pkg.version,
    today,
    lastReportAt,
    monitor: {
      npmLastPackage: monitorState.npmLastPackage || null,
      pypiLastPackage: monitorState.pypiLastPackage || null,
      lastDailyReportDate: monitorState.lastDailyReportDate || null
    }
  };
}

function emptyDayEntry(date) {
  return {
    date,
    scanned: 0,
    clean: 0,
    suspect: 0,
    false_positive: 0,
    confirmed: 0,
    sandbox_inconclusive: 0,
    fp_rate: 0
  };
}

function aggregateDays(days) {
  const totals = { scanned: 0, clean: 0, suspect: 0, false_positive: 0, confirmed: 0, sandbox_inconclusive: 0 };
  let fpRateSum = 0;
  let fpRateCount = 0;
  for (const d of days) {
    totals.scanned += d.scanned || 0;
    totals.clean += d.clean || 0;
    totals.suspect += d.suspect || 0;
    totals.false_positive += d.false_positive || 0;
    totals.confirmed += d.confirmed || 0;
    totals.sandbox_inconclusive += d.sandbox_inconclusive || 0;
    if (typeof d.fp_rate === 'number' && d.fp_rate >= 0) {
      fpRateSum += d.fp_rate;
      fpRateCount++;
    }
  }
  const fp_rate_avg = fpRateCount > 0 ? fpRateSum / fpRateCount : 0;
  return { ...totals, fp_rate_avg: Math.round(fp_rate_avg * 1000) / 1000 };
}

/**
 * Build the /monitor/window payload for a given range ('7d' | '30d').
 */
function buildMonitorWindow(range) {
  if (!SUPPORTED_RANGES.has(range) || range === 'all') {
    throw new Error(`Unsupported range: ${range}. Use 7d or 30d.`);
  }
  const days = RANGE_DAYS[range];
  const data = loadScanStats();
  const allDaily = Array.isArray(data.daily) ? data.daily : [];

  const today = getParisDateString();
  const todayMs = Date.parse(`${today}T00:00:00Z`);
  const cutoffMs = todayMs - (days - 1) * 24 * 60 * 60 * 1000;

  const inRange = allDaily.filter(d => {
    if (!d || typeof d.date !== 'string') return false;
    const ms = Date.parse(`${d.date}T00:00:00Z`);
    return Number.isFinite(ms) && ms >= cutoffMs && ms <= todayMs;
  });

  const dateIndex = new Map(inRange.map(d => [d.date, d]));
  const byDay = [];
  for (let i = days - 1; i >= 0; i--) {
    const ms = todayMs - i * 24 * 60 * 60 * 1000;
    const dateStr = new Date(ms).toISOString().slice(0, 10);
    byDay.push(dateIndex.get(dateStr) || emptyDayEntry(dateStr));
  }

  return {
    generated_at: new Date().toISOString(),
    engineVersion: pkg.version,
    range,
    from: byDay[0].date,
    to: byDay[byDay.length - 1].date,
    totals: aggregateDays(byDay),
    byDay
  };
}

/**
 * Build the /monitor/stats payload (all-time totals + detection breakdown).
 */
function buildMonitorAll() {
  const data = loadScanStats();
  const stats = data.stats || {};
  let detection = { total: 0, bySeverity: {}, byEcosystem: {}, leadTime: null };
  try {
    detection = getDetectionStats();
  } catch {
    // keep defaults
  }
  return {
    generated_at: new Date().toISOString(),
    engineVersion: pkg.version,
    allTime: {
      total_scanned: stats.total_scanned || 0,
      clean: stats.clean || 0,
      suspect: stats.suspect || 0,
      false_positive: stats.false_positive || 0,
      confirmed_malicious: stats.confirmed_malicious || 0,
      sandbox_inconclusive: stats.sandbox_inconclusive || 0,
      sandbox_unconfirmed: stats.sandbox_unconfirmed || 0
    },
    detectionStats: detection
  };
}

module.exports = {
  buildMonitorDaily,
  buildMonitorWindow,
  buildMonitorAll,
  SUPPORTED_RANGES,
  // exported for tests
  _safeReadJson: safeReadJson,
  _readToday: readToday,
  _aggregateDays: aggregateDays
};
