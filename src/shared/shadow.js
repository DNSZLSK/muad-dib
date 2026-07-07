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
 * Shadow-mode divergence framework.
 *
 * Lets a detector compute a CANDIDATE new semantics (V2) alongside its live
 * semantics (V1) and log the cases where the two verdicts disagree — with ZERO
 * effect on emitted threats, scores, or tiers. The divergence log is the
 * adjudication input for flipping V1 → V2: replay historical alerts through
 * the shadow (backtest) or let it run live as a post-merge safety net, then
 * read the split with `muaddib shadow-report`.
 *
 * Contract (fail-safe by construction):
 *  - Nothing here returns a value the scan pipeline can act on. The framework
 *    cannot change a verdict even if misused.
 *  - recordShadowDivergence NEVER throws — a shadow failure must never break a
 *    scan (same posture as appendScanLedger).
 *  - Disabled by default. The daemon opts in via MUADDIB_SHADOW=1 in its
 *    service environment; CLI scans and tests stay inert unless they set it.
 *  - Bounded: the JSONL file is capped at MUADDIB_SHADOW_MAX entries (default
 *    50 000) with streaming FIFO compaction — same pattern as the scan-ledger.
 *
 * Concurrency: unlike the scan-ledger (main-thread-only writer), this module
 * is called from INSIDE scan workers (pipeline/processor.js runs there), so N
 * worker_threads may append concurrently. Each record is serialized to ONE
 * appendFileSync call of one full line (flag 'a' = O_APPEND; small writes are
 * serialized by the inode lock on ext4) — never two writes per line. The
 * reader skips unparsable lines (a crash mid-write can truncate at most the
 * final line).
 *
 * Env (all read at CALL time so tests can re-point after module load):
 *   MUADDIB_SHADOW=1          enable (default off)
 *   MUADDIB_SHADOW_FILE=path  divergence log override (tests)
 *   MUADDIB_SHADOW_MAX=n      entry cap (default 50000)
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_SHADOW_FILE = path.join(__dirname, '..', '..', 'data', 'shadow-divergence.jsonl');
const DEFAULT_MAX_ENTRIES = 50_000;
const EVIDENCE_MAX_BYTES = 2048;
// Count lines (cheap streaming pass) only every N appends, not on every write.
const COMPACT_CHECK_INTERVAL = 500;

let _appendsSinceCheck = 0;

function isShadowEnabled() {
  return globalThis.process.env.MUADDIB_SHADOW === '1';
}

function _shadowFile() {
  return globalThis.process.env.MUADDIB_SHADOW_FILE || DEFAULT_SHADOW_FILE;
}

function _maxEntries() {
  const raw = globalThis.process.env.MUADDIB_SHADOW_MAX;
  const n = raw ? parseInt(raw, 10) : NaN;
  return (Number.isFinite(n) && n >= 10 && n <= 5_000_000) ? n : DEFAULT_MAX_ENTRIES;
}

/**
 * Serialize evidence with a hard size cap. Oversized evidence is replaced by a
 * truncated string form — the log line must stay small so the single-write
 * append atomicity argument holds.
 */
function _capEvidence(evidence) {
  if (evidence === undefined || evidence === null) return null;
  let s;
  try {
    s = JSON.stringify(evidence);
  } catch {
    s = String(evidence);
  }
  if (s.length <= EVIDENCE_MAX_BYTES) {
    try { return JSON.parse(s); } catch { return s; }
  }
  return { _truncated: true, head: s.slice(0, EVIDENCE_MAX_BYTES) };
}

/**
 * Record one shadow divergence (oldVerdict !== newVerdict). Call sites are
 * expected to compare verdicts BEFORE calling — agreements are not logged
 * (the log captures the would-change population, not every scan).
 * Never throws. No-op when shadow mode is disabled.
 *
 * @param {object} d
 * @param {string} d.detector    e.g. 'compromised_email_domain'
 * @param {string} [d.package]
 * @param {string} [d.version]
 * @param {string} [d.ecosystem]
 * @param {*}      d.oldVerdict  live semantics result
 * @param {*}      d.newVerdict  candidate semantics result
 * @param {*}      [d.evidence]  capped at 2KB serialized
 */
function recordShadowDivergence(d) {
  try {
    if (!isShadowEnabled()) return;
    if (!d || !d.detector) return;
    const file = _shadowFile();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const entry = {
      ts: new Date().toISOString(),
      detector: String(d.detector),
      package: d.package || null,
      version: d.version || null,
      ecosystem: d.ecosystem || null,
      oldVerdict: d.oldVerdict !== undefined ? d.oldVerdict : null,
      newVerdict: d.newVerdict !== undefined ? d.newVerdict : null,
      evidence: _capEvidence(d.evidence)
    };
    // ONE write per line — see the concurrency note in the header.
    fs.appendFileSync(file, JSON.stringify(entry) + '\n', { encoding: 'utf8', flag: 'a' });
    _appendsSinceCheck++;
    if (_appendsSinceCheck >= COMPACT_CHECK_INTERVAL) {
      _appendsSinceCheck = 0;
      _compactShadowJsonl(file);
    }
  } catch {
    // Never throw, never log loudly — a shadow failure must not affect scans.
  }
}

/**
 * Streaming FIFO compaction: keep only the most recent max entries.
 * Local minimal implementation (not shared with state.js) so the worker-side
 * require graph stays free of the monitor state module.
 */
function _compactShadowJsonl(file) {
  try {
    const max = _maxEntries();
    const lines = _readLines(file);
    if (lines.length <= max) return;
    const kept = lines.slice(lines.length - max);
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, kept.join('\n') + '\n', 'utf8');
    fs.renameSync(tmp, file);
  } catch {
    // Best-effort; an oversized shadow log is preferable to a crashed scan.
  }
}

/** Read raw lines, dropping empties. Returns [] on any error. */
function _readLines(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(l => l.trim().length > 0);
  } catch {
    return [];
  }
}

/**
 * Read divergence entries, tolerant of corrupt lines (skipped silently).
 * @param {object} [opts]
 * @param {string} [opts.detector] filter by detector
 * @param {number|string} [opts.sinceTs] ms epoch or ISO — entries older are skipped
 * @returns {Array<object>}
 */
function readShadowDivergences(opts = {}) {
  let sinceMs = null;
  if (typeof opts.sinceTs === 'number' && Number.isFinite(opts.sinceTs)) sinceMs = opts.sinceTs;
  else if (typeof opts.sinceTs === 'string') {
    const p = Date.parse(opts.sinceTs);
    if (!Number.isNaN(p)) sinceMs = p;
  }
  const out = [];
  for (const line of _readLines(_shadowFile())) {
    let e;
    try { e = JSON.parse(line); } catch { continue; } // truncated/corrupt line
    if (!e || typeof e !== 'object' || !e.detector) continue;
    if (opts.detector && e.detector !== opts.detector) continue;
    if (sinceMs !== null) {
      const t = e.ts ? Date.parse(e.ts) : NaN;
      if (Number.isNaN(t) || t < sinceMs) continue;
    }
    out.push(e);
  }
  return out;
}

module.exports = {
  isShadowEnabled,
  recordShadowDivergence,
  readShadowDivergences,
  // test seams
  _capEvidence,
  _compactShadowJsonl,
  EVIDENCE_MAX_BYTES
};
