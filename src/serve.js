'use strict';

const http = require('http');
const url = require('url');
const { getFeed } = require('./threat-feed.js');
const pkg = require('../package.json');

const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store'
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, SECURITY_HEADERS);
  res.end(JSON.stringify(data));
}

function startServer(options = {}) {
  const port = options.port || 3000;

  const server = http.createServer((req, res) => {
    if (req.method !== 'GET') {
      sendJson(res, 405, { error: 'Method not allowed. Use GET.' });
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

module.exports = { startServer };
