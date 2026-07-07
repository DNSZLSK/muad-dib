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

/**
 * api-ingest.js — Real-time alert push from monitor to muad-api.
 *
 * The monitor calls sendIngest() whenever it decides to fire a Discord
 * webhook. Fire-and-forget: errors are logged but never block the caller.
 *
 * Required env:
 *   MUADDIB_API_URL    Base URL of muad-api (e.g. https://api.example.com)
 *   MUADDIB_INGEST_TOKEN  Static shared secret matching the API's INGEST_TOKEN
 *
 * Both unset = ingest disabled silently (the monitor still works on its own).
 */

const https = require('https');
const http = require('http');
const dns = require('dns');

const PRIVATE_IP_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^::ffff:127\./,
  /^fc00:/,
  /^fe80:/
];

const REQUEST_TIMEOUT_MS = 5000;
const MAX_FINDINGS = 200;
const MAX_FINDING_LENGTH = 500;

function getApiUrl() {
  const url = process.env.MUADDIB_API_URL;
  return url && url.trim() ? url.replace(/\/$/, '') : null;
}

function getIngestToken() {
  return process.env.MUADDIB_INGEST_TOKEN || null;
}

function isIngestConfigured() {
  return Boolean(getApiUrl() && getIngestToken());
}

function isLocalHostname(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

function validateApiUrl(url) {
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    return { valid: false, error: `Invalid URL: ${e.message}` };
  }
  const hostname = urlObj.hostname.toLowerCase();
  const local = isLocalHostname(hostname);
  if (urlObj.protocol !== 'https:' && !local) {
    return { valid: false, error: 'HTTPS required for non-localhost API' };
  }
  if (urlObj.protocol !== 'https:' && urlObj.protocol !== 'http:') {
    return { valid: false, error: `Unsupported protocol: ${urlObj.protocol}` };
  }
  if (!local && PRIVATE_IP_PATTERNS.some(p => p.test(hostname))) {
    return { valid: false, error: 'Private IP not allowed' };
  }
  return { valid: true, urlObj, local };
}

/**
 * Normalize a threat severity into the API's allowed enum.
 * API accepts only CRITICAL|HIGH|MEDIUM|LOW. CLEAN/unknown -> LOW.
 */
function normalizeSeverity(level) {
  switch ((level || '').toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MEDIUM':
      return 'MEDIUM';
    default:
      return 'LOW';
  }
}

function computeSeverityFromSummary(summary) {
  if (!summary) return 'LOW';
  if (summary.riskLevel) return normalizeSeverity(summary.riskLevel);
  const score = summary.riskScore || 0;
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

function buildIngestPayload(name, version, result) {
  const summary = (result && result.summary) || {};
  const threats = (result && Array.isArray(result.threats)) ? result.threats : [];

  const findings = threats
    .slice(0, MAX_FINDINGS)
    .map(t => {
      const raw = t.message || t.rule_id || t.type || 'unknown';
      return String(raw).slice(0, MAX_FINDING_LENGTH);
    })
    .filter(s => s.length > 0);

  const breakdown = Array.isArray(summary.breakdown) ? summary.breakdown : undefined;

  const payload = {
    package: name,
    version: version || 'unknown',
    score: Math.max(0, Math.min(100, summary.riskScore || 0)),
    severity: computeSeverityFromSummary(summary),
    findings
  };
  if (breakdown !== undefined) payload.breakdown = breakdown;
  return payload;
}

async function resolveAndCheck(hostname, allowPrivate) {
  if (allowPrivate) {
    return null;
  }
  const [v4, v6] = await Promise.all([
    dns.promises.resolve4(hostname).catch(() => []),
    dns.promises.resolve6(hostname).catch(() => [])
  ]);
  const all = [...v4, ...v6];
  if (all.length === 0) {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }
  for (const addr of all) {
    if (PRIVATE_IP_PATTERNS.some(p => p.test(addr))) {
      throw new Error(`Hostname ${hostname} resolves to private IP ${addr}`);
    }
  }
  return v4[0] || null;
}

function postOnce(targetUrl, body, token, resolvedAddress) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(targetUrl);
    const proto = urlObj.protocol === 'https:' ? https : http;
    const options = {
      hostname: resolvedAddress || urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${token}`,
        'Host': urlObj.hostname
      },
      servername: urlObj.hostname
    };

    const req = proto.request(options, (res) => {
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 64 * 1024) res.destroy();
      });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode });
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    });
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy();
      reject(new Error(`Timeout after ${REQUEST_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Push an alert to muad-api. Fire-and-forget: never throws.
 * Returns { ok: true, status } or { ok: false, error }.
 */
async function sendIngest(name, version, result) {
  if (!isIngestConfigured()) return { ok: false, error: 'not_configured' };

  const apiUrl = getApiUrl();
  const token = getIngestToken();
  const validation = validateApiUrl(apiUrl);
  if (!validation.valid) {
    console.error(`[INGEST] Invalid MUADDIB_API_URL: ${validation.error}`);
    return { ok: false, error: validation.error };
  }

  const target = `${apiUrl}/alerts/ingest`;
  const payload = buildIngestPayload(name, version, result);
  const body = JSON.stringify(payload);

  try {
    const resolved = await resolveAndCheck(validation.urlObj.hostname, validation.local);
    const res = await postOnce(target, body, token, resolved);
    return { ok: true, status: res.status };
  } catch (err) {
    console.error(`[INGEST] ${name}@${version}: ${err.message}`);
    return { ok: false, error: err.message };
  }
}

module.exports = {
  sendIngest,
  buildIngestPayload,
  computeSeverityFromSummary,
  isIngestConfigured,
  validateApiUrl
};
