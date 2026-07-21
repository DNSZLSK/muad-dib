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

const http = require('http');
const url = require('url');
const crypto = require('crypto');
const { getFeed } = require('../threat-feed.js');
// Monitor-feed routes : optional out-of-tree dependency. Lazy-load so the
// /feed and /health routes still work when the file is absent. Missing-file
// case returns 503 on /monitor/* routes instead of crashing module load.
let _monitorFeedCache = null;
function _loadMonitorFeed() {
  if (_monitorFeedCache !== null) return _monitorFeedCache;
  try {
    _monitorFeedCache = require('./monitor-feed.js');
  } catch {
    _monitorFeedCache = {
      buildMonitorDaily: null,
      buildMonitorWindow: null,
      buildMonitorAll: null,
      SUPPORTED_RANGES: new Set(['7d', '30d'])
    };
  }
  return _monitorFeedCache;
}
function buildMonitorDaily() {
  const m = _loadMonitorFeed();
  if (!m.buildMonitorDaily) throw new Error('monitor-feed module not installed');
  return m.buildMonitorDaily();
}
function buildMonitorWindow(range) {
  const m = _loadMonitorFeed();
  if (!m.buildMonitorWindow) throw new Error('monitor-feed module not installed');
  return m.buildMonitorWindow(range);
}
function buildMonitorAll() {
  const m = _loadMonitorFeed();
  if (!m.buildMonitorAll) throw new Error('monitor-feed module not installed');
  return m.buildMonitorAll();
}
const SUPPORTED_RANGES = _loadMonitorFeed().SUPPORTED_RANGES;
const pkg = require('../../package.json');

const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store'
};

// Rate limiting: 60 requests per minute per IP (sliding window)
const RATE_LIMIT_MAX = 60;
const RATE_LIMIT_WINDOW_MS = 60_000;
const rateLimitMap = new Map();
// Sweep the map when it grows past this many keys, evicting entries whose window has fully
// expired. Bind is localhost-only so this is bounded in practice, but without a sweep the Map
// grows unbounded if the server is ever bound wider (one dead key per distinct client IP).
const RATE_LIMIT_MAX_KEYS = 10_000;

function sweepRateLimitMap(now) {
  const windowStart = now - RATE_LIMIT_WINDOW_MS;
  for (const [ip, timestamps] of rateLimitMap) {
    if (timestamps.length === 0 || timestamps[timestamps.length - 1] < windowStart) {
      rateLimitMap.delete(ip);
    }
  }
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, SECURITY_HEADERS);
  res.end(JSON.stringify(data));
}

/**
 * Check bearer token authentication.
 * If MUADDIB_FEED_TOKEN is set, require Authorization: Bearer <token> header.
 * @param {http.IncomingMessage} req
 * @returns {{ ok: boolean, error?: string }}
 */
function checkAuth(req) {
  const token = process.env.MUADDIB_FEED_TOKEN;
  if (!token) return { ok: true }; // No token configured = no auth required

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return { ok: false, error: 'Missing Authorization header' };
  }
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return { ok: false, error: 'Invalid Authorization format. Use: Bearer <token>' };
  }
  // Constant-time comparison to avoid a timing oracle on the token. Compare fixed-length
  // SHA-256 digests so timingSafeEqual never sees mismatched buffer lengths (which would
  // throw and leak length via the exception path).
  const a = crypto.createHash('sha256').update(parts[1]).digest();
  const b = crypto.createHash('sha256').update(token).digest();
  if (!crypto.timingSafeEqual(a, b)) {
    return { ok: false, error: 'Invalid token' };
  }
  return { ok: true };
}

/**
 * Rate limiter: sliding window, max RATE_LIMIT_MAX requests per RATE_LIMIT_WINDOW_MS per IP.
 * @param {string} ip - Client IP address
 * @returns {{ ok: boolean, remaining: number }}
 */
function checkRateLimit(ip) {
  const now = Date.now();
  // Opportunistic bounded sweep: only when the map is oversized, so the common path stays O(1).
  if (rateLimitMap.size > RATE_LIMIT_MAX_KEYS) {
    sweepRateLimitMap(now);
  }
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, [now]);
    return { ok: true, remaining: RATE_LIMIT_MAX - 1 };
  }
  const timestamps = rateLimitMap.get(ip);
  // Remove timestamps outside the window
  const windowStart = now - RATE_LIMIT_WINDOW_MS;
  while (timestamps.length > 0 && timestamps[0] < windowStart) {
    timestamps.shift();
  }
  if (timestamps.length >= RATE_LIMIT_MAX) {
    return { ok: false, remaining: 0 };
  }
  timestamps.push(now);
  return { ok: true, remaining: RATE_LIMIT_MAX - timestamps.length };
}

function startServer(options = {}) {
  const port = options.port || 3000;

  const server = http.createServer((req, res) => {
    if (req.method !== 'GET') {
      sendJson(res, 405, { error: 'Method not allowed. Use GET.' });
      return;
    }

    // Authentication check (if MUADDIB_FEED_TOKEN is set)
    const auth = checkAuth(req);
    if (!auth.ok) {
      sendJson(res, 401, { error: auth.error });
      return;
    }

    // Rate limiting
    const ip = req.socket.remoteAddress || '127.0.0.1';
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.ok) {
      sendJson(res, 429, { error: 'Rate limit exceeded. Max 60 requests per minute.' });
      return;
    }

    const parsed = url.parse(req.url, true);
    const pathname = parsed.pathname;

    if (pathname === '/feed') {
      const query = parsed.query;
      const feedOptions = {};
      if (query.limit) {
        const n = parseInt(query.limit, 10);
        if (!isNaN(n) && n > 0) feedOptions.limit = n;
      }
      if (query.severity) feedOptions.severity = query.severity;
      if (query.since) feedOptions.since = query.since;

      const result = getFeed(feedOptions);
      sendJson(res, 200, result);
    } else if (pathname === '/monitor/daily') {
      try {
        sendJson(res, 200, buildMonitorDaily());
      } catch (err) {
        // Don't leak err.message to the client — it can expose internal filesystem paths.
        // Log server-side, return a generic error.
        console.error('[SERVE] /monitor/daily failed:', err.message);
        sendJson(res, 500, { error: 'monitor_daily_failed' });
      }
    } else if (pathname === '/monitor/window') {
      const range = (parsed.query && parsed.query.range) ? String(parsed.query.range) : '7d';
      if (!SUPPORTED_RANGES.has(range) || range === 'all') {
        sendJson(res, 400, { error: 'invalid_range', message: 'range must be one of: 7d, 30d' });
        return;
      }
      try {
        sendJson(res, 200, buildMonitorWindow(range));
      } catch (err) {
        console.error('[SERVE] /monitor/window failed:', err.message);
        sendJson(res, 500, { error: 'monitor_window_failed' });
      }
    } else if (pathname === '/monitor/stats') {
      try {
        sendJson(res, 200, buildMonitorAll());
      } catch (err) {
        console.error('[SERVE] /monitor/stats failed:', err.message);
        sendJson(res, 500, { error: 'monitor_stats_failed' });
      }
    } else if (pathname === '/health') {
      sendJson(res, 200, { status: 'ok', version: pkg.version });
    } else {
      sendJson(res, 404, { error: 'Not found. Available: GET /feed, GET /monitor/daily, GET /monitor/window?range=7d|30d, GET /monitor/stats, GET /health' });
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[SERVE] Threat feed server listening on http://127.0.0.1:${port}`);
    console.log(`[SERVE] Endpoints: GET /feed, GET /monitor/daily, GET /monitor/window?range=7d|30d, GET /monitor/stats, GET /health`);
  });

  return server;
}

module.exports = { startServer, checkAuth, checkRateLimit, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS, rateLimitMap };
