'use strict';

const http = require('http');
const url = require('url');
const { getFeed } = require('../threat-feed.js');
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
  if (parts[1] !== token) {
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
    } else if (pathname === '/health') {
      sendJson(res, 200, { status: 'ok', version: pkg.version });
    } else {
      sendJson(res, 404, { error: 'Not found. Available: GET /feed, GET /health' });
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[SERVE] Threat feed server listening on http://127.0.0.1:${port}`);
    console.log(`[SERVE] Endpoints: GET /feed, GET /health`);
  });

  return server;
}

module.exports = { startServer, checkAuth, checkRateLimit, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS, rateLimitMap };
